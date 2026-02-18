//! AgentHandler implementation for the Data Masking Agent.

use crate::buffer::ChunkBuffer;
use crate::config::{validate_config, DataMaskingConfig, TokenStoreConfig};
use crate::masking::MaskingEngine;
use crate::store::MemoryTokenStore;
use async_trait::async_trait;
use base64::Engine as _;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, BodyMutation, ConfigureEvent, HeaderOp,
    RequestBodyChunkEvent, RequestCompleteEvent, RequestHeadersEvent, ResponseBodyChunkEvent,
    ResponseHeadersEvent,
};

/// Per-request state.
struct RequestState {
    /// Content-Type from request headers.
    content_type: Option<String>,
    /// Request body buffer.
    request_buffer: ChunkBuffer,
    /// Response body buffer.
    response_buffer: ChunkBuffer,
}

/// Data Masking Agent handler.
pub struct DataMaskingAgent {
    /// Configuration.
    config: Arc<RwLock<DataMaskingConfig>>,
    /// Masking engine.
    engine: Arc<RwLock<Option<MaskingEngine>>>,
    /// Per-request state (correlation_id -> state).
    request_state: DashMap<String, RequestState>,
}

impl DataMaskingAgent {
    /// Create a new data masking agent with the given configuration.
    pub fn new(config: DataMaskingConfig) -> Result<Self, anyhow::Error> {
        let engine = create_engine(&config)?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            engine: Arc::new(RwLock::new(Some(engine))),
            request_state: DashMap::new(),
        })
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Result<Self, anyhow::Error> {
        Self::new(DataMaskingConfig::default())
    }
}

/// Create masking engine from configuration.
fn create_engine(config: &DataMaskingConfig) -> Result<MaskingEngine, anyhow::Error> {
    let store: Arc<dyn crate::store::TokenStore> = match &config.store {
        TokenStoreConfig::Memory {
            ttl_seconds,
            max_entries,
        } => Arc::new(MemoryTokenStore::new(*ttl_seconds, *max_entries)),
    };

    MaskingEngine::new(config.clone(), store).map_err(|e| anyhow::anyhow!("{}", e))
}

#[async_trait]
impl AgentHandler for DataMaskingAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        info!(agent_id = %event.agent_id, "Received configuration");

        // Parse agent-specific configuration
        match serde_json::from_value::<DataMaskingConfig>(event.config.clone()) {
            Ok(new_config) => {
                // Validate configuration
                if let Err(e) = validate_config(&new_config) {
                    error!(error = %e, "Invalid configuration");
                    return AgentResponse::block(
                        500,
                        Some(format!("Invalid configuration: {}", e)),
                    );
                }

                // Create new engine with updated config
                match create_engine(&new_config) {
                    Ok(engine) => {
                        let mut config_guard = self.config.write().await;
                        *config_guard = new_config;

                        let mut engine_guard = self.engine.write().await;
                        *engine_guard = Some(engine);

                        info!("Configuration updated successfully");
                        AgentResponse::default_allow()
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to create engine");
                        AgentResponse::block(500, Some(format!("Engine error: {}", e)))
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to parse configuration, using defaults");
                AgentResponse::default_allow()
            }
        }
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let correlation_id = &event.metadata.correlation_id;

        debug!(
            correlation_id = %correlation_id,
            method = %event.method,
            uri = %event.uri,
            "Processing request headers"
        );

        // Extract Content-Type
        let content_type = event
            .headers
            .get("content-type")
            .and_then(|v| v.first())
            .cloned();

        // Initialize request state
        let config = self.config.read().await;
        self.request_state.insert(
            correlation_id.to_string(),
            RequestState {
                content_type,
                request_buffer: ChunkBuffer::new(config.buffering.max_buffer_bytes),
                response_buffer: ChunkBuffer::new(config.buffering.max_buffer_bytes),
            },
        );

        // Mask headers if configured
        let mut response = AgentResponse::default_allow();
        let engine_guard = self.engine.read().await;

        if let Some(ref engine) = *engine_guard {
            for rule in &config.headers {
                if !rule.direction.applies_to_request() {
                    continue;
                }

                if let Some(values) = event.headers.get(&rule.name.to_lowercase()) {
                    for value in values {
                        match engine
                            .apply_header_action(correlation_id, value, &rule.action)
                            .await
                        {
                            Ok(new_value) if new_value != *value => {
                                response = response.add_request_header(HeaderOp::Set {
                                    name: rule.name.clone(),
                                    value: new_value,
                                });
                            }
                            Err(e) => {
                                warn!(
                                    header = %rule.name,
                                    error = %e,
                                    "Failed to mask header"
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Add audit metadata
        let audit = AuditMetadata {
            tags: vec!["data_masking".to_string(), "request_headers".to_string()],
            ..AuditMetadata::default()
        };
        response.with_audit(audit)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        debug!(
            correlation_id = %correlation_id,
            chunk_index = event.chunk_index,
            is_last = event.is_last,
            data_len = event.data.len(),
            "Processing request body chunk"
        );

        // Get mutable state
        let mut state = match self.request_state.get_mut(correlation_id) {
            Some(s) => s,
            None => {
                warn!(correlation_id = %correlation_id, "No state for request");
                return AgentResponse::default_allow()
                    .with_request_body_mutation(BodyMutation::pass_through(event.chunk_index));
            }
        };

        // Decode base64 body chunk
        let chunk_data = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                error!(error = %e, "Failed to decode body chunk");
                return AgentResponse::default_allow()
                    .with_request_body_mutation(BodyMutation::pass_through(event.chunk_index));
            }
        };

        // Buffer the chunk
        if let Err(e) = state.request_buffer.append(&chunk_data) {
            warn!(error = %e, "Buffer overflow, passing through");
            return AgentResponse::default_allow()
                .with_request_body_mutation(BodyMutation::pass_through(event.chunk_index));
        }

        // If not the last chunk, signal we need more data
        if !event.is_last {
            return AgentResponse::default_allow()
                .set_needs_more(true)
                .with_request_body_mutation(BodyMutation::drop_chunk(event.chunk_index));
        }

        // Last chunk - process the complete body
        let content_type = state.content_type.clone().unwrap_or_default();
        let complete_body = state.request_buffer.take();

        let engine_guard = self.engine.read().await;
        let engine = match &*engine_guard {
            Some(e) => e,
            None => {
                // No engine, pass through
                let encoded = base64::engine::general_purpose::STANDARD.encode(&complete_body);
                return AgentResponse::default_allow()
                    .with_request_body_mutation(BodyMutation::replace(event.chunk_index, encoded));
            }
        };

        match engine
            .mask_request_body(correlation_id, &complete_body, &content_type)
            .await
        {
            Ok(masked_body) => {
                let modified = masked_body != complete_body;

                // Base64 encode the masked body
                let encoded = base64::engine::general_purpose::STANDARD.encode(&masked_body);

                let response = AgentResponse::default_allow()
                    .with_request_body_mutation(BodyMutation::replace(event.chunk_index, encoded));

                // Add audit metadata
                let mut tags = vec!["data_masking".to_string(), "request_body".to_string()];
                if modified {
                    tags.push("modified".to_string());
                }
                let audit = AuditMetadata {
                    tags,
                    ..AuditMetadata::default()
                };

                response.with_audit(audit)
            }
            Err(e) => {
                error!(error = %e, "Failed to mask request body");

                // Re-encode original and pass through
                let encoded = base64::engine::general_purpose::STANDARD.encode(&complete_body);

                AgentResponse::default_allow()
                    .with_request_body_mutation(BodyMutation::replace(event.chunk_index, encoded))
            }
        }
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;
        let config = self.config.read().await;

        debug!(
            correlation_id = %correlation_id,
            status = event.status,
            "Processing response headers"
        );

        // Mask response headers
        let mut response = AgentResponse::default_allow();
        let engine_guard = self.engine.read().await;

        if let Some(ref engine) = *engine_guard {
            for rule in &config.headers {
                if !rule.direction.applies_to_response() {
                    continue;
                }

                if let Some(values) = event.headers.get(&rule.name.to_lowercase()) {
                    for value in values {
                        match engine
                            .apply_header_action(correlation_id, value, &rule.action)
                            .await
                        {
                            Ok(new_value) if new_value != *value => {
                                response = response.add_response_header(HeaderOp::Set {
                                    name: rule.name.clone(),
                                    value: new_value,
                                });
                            }
                            Err(e) => {
                                warn!(
                                    header = %rule.name,
                                    error = %e,
                                    "Failed to mask response header"
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        response
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        debug!(
            correlation_id = %correlation_id,
            chunk_index = event.chunk_index,
            is_last = event.is_last,
            data_len = event.data.len(),
            "Processing response body chunk"
        );

        // Get mutable state
        let mut state = match self.request_state.get_mut(correlation_id) {
            Some(s) => s,
            None => {
                return AgentResponse::default_allow()
                    .with_response_body_mutation(BodyMutation::pass_through(event.chunk_index));
            }
        };

        // Decode base64 body chunk
        let chunk_data = match base64::engine::general_purpose::STANDARD.decode(&event.data) {
            Ok(data) => data,
            Err(e) => {
                error!(error = %e, "Failed to decode response body chunk");
                return AgentResponse::default_allow()
                    .with_response_body_mutation(BodyMutation::pass_through(event.chunk_index));
            }
        };

        // Buffer the chunk
        if let Err(_e) = state.response_buffer.append(&chunk_data) {
            return AgentResponse::default_allow()
                .with_response_body_mutation(BodyMutation::pass_through(event.chunk_index));
        }

        // If not the last chunk, buffer and wait
        if !event.is_last {
            return AgentResponse::default_allow()
                .set_needs_more(true)
                .with_response_body_mutation(BodyMutation::drop_chunk(event.chunk_index));
        }

        // Last chunk - detokenize the complete body
        let content_type = state.content_type.clone().unwrap_or_default();
        let complete_body = state.response_buffer.take();

        let engine_guard = self.engine.read().await;
        let engine = match &*engine_guard {
            Some(e) => e,
            None => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&complete_body);
                return AgentResponse::default_allow().with_response_body_mutation(
                    BodyMutation::replace(event.chunk_index, encoded),
                );
            }
        };

        match engine
            .unmask_response_body(correlation_id, &complete_body, &content_type)
            .await
        {
            Ok(unmasked_body) => {
                let modified = unmasked_body != complete_body;

                let encoded = base64::engine::general_purpose::STANDARD.encode(&unmasked_body);

                let response = AgentResponse::default_allow()
                    .with_response_body_mutation(BodyMutation::replace(event.chunk_index, encoded));

                let mut tags = vec!["data_masking".to_string(), "response_body".to_string()];
                if modified {
                    tags.push("detokenized".to_string());
                }
                let audit = AuditMetadata {
                    tags,
                    ..AuditMetadata::default()
                };

                response.with_audit(audit)
            }
            Err(e) => {
                error!(error = %e, "Failed to unmask response body");

                let encoded = base64::engine::general_purpose::STANDARD.encode(&complete_body);

                AgentResponse::default_allow()
                    .with_response_body_mutation(BodyMutation::replace(event.chunk_index, encoded))
            }
        }
    }

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        let correlation_id = &event.correlation_id;

        info!(
            correlation_id = %correlation_id,
            status = event.status,
            duration_ms = event.duration_ms,
            "Request completed"
        );

        // Clean up token store entries for this request
        let engine_guard = self.engine.read().await;
        if let Some(ref engine) = *engine_guard {
            if let Err(e) = engine.store().cleanup(correlation_id).await {
                warn!(
                    correlation_id = %correlation_id,
                    error = %e,
                    "Failed to clean up tokens"
                );
            }
        }

        // Remove request state
        self.request_state.remove(correlation_id);

        AgentResponse::default_allow()
    }
}
