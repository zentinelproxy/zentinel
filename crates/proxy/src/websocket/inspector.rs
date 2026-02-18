//! WebSocket frame inspector for agent integration.
//!
//! Sends WebSocket frames to subscribed agents for inspection and applies
//! their decisions (allow, drop, or close).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, trace, warn};
use zentinel_agent_protocol::{WebSocketDecision, WebSocketFrameEvent};
use zentinel_common::observability::RequestMetrics;

use super::codec::WebSocketFrame;
use crate::agents::AgentManager;

/// Result of inspecting a WebSocket frame
#[derive(Debug, Clone)]
pub enum InspectionResult {
    /// Allow the frame to pass through
    Allow,
    /// Drop this frame (don't forward)
    Drop,
    /// Close the WebSocket connection
    Close { code: u16, reason: String },
}

impl From<WebSocketDecision> for InspectionResult {
    fn from(decision: WebSocketDecision) -> Self {
        match decision {
            WebSocketDecision::Allow => InspectionResult::Allow,
            WebSocketDecision::Drop => InspectionResult::Drop,
            WebSocketDecision::Close { code, reason } => InspectionResult::Close { code, reason },
        }
    }
}

/// WebSocket frame inspector
///
/// Handles bidirectional frame inspection by sending frames to agents
/// and applying their decisions.
pub struct WebSocketInspector {
    /// Agent manager for sending events
    agent_manager: Arc<AgentManager>,
    /// Route ID for this connection
    route_id: String,
    /// Correlation ID (from the original upgrade request)
    correlation_id: String,
    /// Client IP address
    client_ip: String,
    /// Frame index counter for client -> server direction
    client_frame_index: AtomicU64,
    /// Frame index counter for server -> client direction
    server_frame_index: AtomicU64,
    /// Timeout for agent calls in milliseconds
    timeout_ms: u64,
    /// Metrics collector
    metrics: Option<Arc<RequestMetrics>>,
}

impl WebSocketInspector {
    /// Create a new WebSocket inspector
    pub fn new(
        agent_manager: Arc<AgentManager>,
        route_id: String,
        correlation_id: String,
        client_ip: String,
        timeout_ms: u64,
    ) -> Self {
        Self::with_metrics(
            agent_manager,
            route_id,
            correlation_id,
            client_ip,
            timeout_ms,
            None,
        )
    }

    /// Create a new WebSocket inspector with metrics
    pub fn with_metrics(
        agent_manager: Arc<AgentManager>,
        route_id: String,
        correlation_id: String,
        client_ip: String,
        timeout_ms: u64,
        metrics: Option<Arc<RequestMetrics>>,
    ) -> Self {
        debug!(
            route_id = %route_id,
            correlation_id = %correlation_id,
            "Creating WebSocket inspector"
        );

        // Record the WebSocket connection
        if let Some(ref m) = metrics {
            m.record_websocket_connection(&route_id);
        }

        Self {
            agent_manager,
            route_id,
            correlation_id,
            client_ip,
            client_frame_index: AtomicU64::new(0),
            server_frame_index: AtomicU64::new(0),
            timeout_ms,
            metrics,
        }
    }

    /// Inspect a frame from client to server
    pub async fn inspect_client_frame(&self, frame: &WebSocketFrame) -> InspectionResult {
        let frame_index = self.client_frame_index.fetch_add(1, Ordering::SeqCst);

        trace!(
            correlation_id = %self.correlation_id,
            frame_index = frame_index,
            opcode = ?frame.opcode,
            "Inspecting client frame"
        );

        self.inspect_frame(frame, true, frame_index).await
    }

    /// Inspect a frame from server to client
    pub async fn inspect_server_frame(&self, frame: &WebSocketFrame) -> InspectionResult {
        let frame_index = self.server_frame_index.fetch_add(1, Ordering::SeqCst);

        trace!(
            correlation_id = %self.correlation_id,
            frame_index = frame_index,
            opcode = ?frame.opcode,
            "Inspecting server frame"
        );

        self.inspect_frame(frame, false, frame_index).await
    }

    /// Internal frame inspection
    async fn inspect_frame(
        &self,
        frame: &WebSocketFrame,
        client_to_server: bool,
        frame_index: u64,
    ) -> InspectionResult {
        let start = Instant::now();
        let direction = if client_to_server { "c2s" } else { "s2c" };
        let opcode = frame.opcode.as_str();

        // Record frame size metric
        if let Some(ref metrics) = self.metrics {
            metrics.record_websocket_frame_size(
                &self.route_id,
                direction,
                opcode,
                frame.payload.len(),
            );
        }

        let event = WebSocketFrameEvent {
            correlation_id: self.correlation_id.clone(),
            opcode: opcode.to_string(),
            data: STANDARD.encode(&frame.payload),
            client_to_server,
            frame_index,
            fin: frame.fin,
            route_id: Some(self.route_id.clone()),
            client_ip: self.client_ip.clone(),
        };

        // Send to agent manager for processing
        let result = match tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_ms),
            self.agent_manager
                .process_websocket_frame(&self.route_id, event),
        )
        .await
        {
            Ok(Ok(response)) => {
                if let Some(ws_decision) = response.websocket_decision {
                    let result = InspectionResult::from(ws_decision);
                    trace!(
                        correlation_id = %self.correlation_id,
                        frame_index = frame_index,
                        decision = ?result,
                        "Frame inspection complete"
                    );
                    result
                } else {
                    // No WebSocket decision means allow
                    InspectionResult::Allow
                }
            }
            Ok(Err(e)) => {
                warn!(
                    correlation_id = %self.correlation_id,
                    error = %e,
                    "Agent error during frame inspection, allowing frame"
                );
                // Fail-open: allow frame on agent error
                InspectionResult::Allow
            }
            Err(_) => {
                warn!(
                    correlation_id = %self.correlation_id,
                    timeout_ms = self.timeout_ms,
                    "Agent timeout during frame inspection, allowing frame"
                );
                // Fail-open: allow frame on timeout
                InspectionResult::Allow
            }
        };

        // Record metrics
        if let Some(ref metrics) = self.metrics {
            let duration = start.elapsed();
            metrics.record_websocket_inspection_duration(&self.route_id, duration);

            let decision_str = match &result {
                InspectionResult::Allow => "allow",
                InspectionResult::Drop => "drop",
                InspectionResult::Close { .. } => "close",
            };
            metrics.record_websocket_frame(&self.route_id, direction, opcode, decision_str);
        }

        result
    }

    /// Get the correlation ID
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Get the route ID
    pub fn route_id(&self) -> &str {
        &self.route_id
    }
}

/// Builder for WebSocketInspector
pub struct WebSocketInspectorBuilder {
    agent_manager: Option<Arc<AgentManager>>,
    route_id: Option<String>,
    correlation_id: Option<String>,
    client_ip: Option<String>,
    timeout_ms: u64,
    metrics: Option<Arc<RequestMetrics>>,
}

impl Default for WebSocketInspectorBuilder {
    fn default() -> Self {
        Self {
            agent_manager: None,
            route_id: None,
            correlation_id: None,
            client_ip: None,
            timeout_ms: 100, // 100ms default timeout
            metrics: None,
        }
    }
}

impl WebSocketInspectorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the agent manager
    pub fn agent_manager(mut self, manager: Arc<AgentManager>) -> Self {
        self.agent_manager = Some(manager);
        self
    }

    /// Set the route ID
    pub fn route_id(mut self, id: impl Into<String>) -> Self {
        self.route_id = Some(id.into());
        self
    }

    /// Set the correlation ID
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the client IP
    pub fn client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set the timeout in milliseconds
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set the metrics collector
    pub fn metrics(mut self, metrics: Arc<RequestMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Build the inspector
    pub fn build(self) -> Option<WebSocketInspector> {
        Some(WebSocketInspector::with_metrics(
            self.agent_manager?,
            self.route_id?,
            self.correlation_id?,
            self.client_ip?,
            self.timeout_ms,
            self.metrics,
        ))
    }
}
