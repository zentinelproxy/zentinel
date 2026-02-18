//! Semantic guardrails for inference routes.
//!
//! Provides content inspection via external agents:
//! - Prompt injection detection on requests
//! - PII detection on responses

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora_timeout::timeout;
use tracing::{debug, trace, warn};
use zentinel_agent_protocol::{
    Decision, GuardrailDetection, GuardrailInspectEvent, GuardrailInspectionType, GuardrailResponse,
};
use zentinel_config::{
    GuardrailAction, GuardrailFailureMode, PiiDetectionConfig, PromptInjectionConfig,
};

use crate::agents::AgentManager;

/// Result of a prompt injection check
#[derive(Debug)]
pub enum PromptInjectionResult {
    /// Content is clean (no injection detected)
    Clean,
    /// Injection detected, request should be blocked
    Blocked {
        status: u16,
        message: String,
        detections: Vec<GuardrailDetection>,
    },
    /// Injection detected but allowed (logged only)
    Detected { detections: Vec<GuardrailDetection> },
    /// Injection detected, add warning header
    Warning { detections: Vec<GuardrailDetection> },
    /// Agent error (behavior depends on failure mode)
    Error { message: String },
}

/// Result of a PII detection check
#[derive(Debug)]
pub enum PiiCheckResult {
    /// Content is clean (no PII detected)
    Clean,
    /// PII detected
    Detected {
        detections: Vec<GuardrailDetection>,
        redacted_content: Option<String>,
    },
    /// Agent error
    Error { message: String },
}

/// Trait for calling guardrail agents.
///
/// This trait allows for mocking agent calls in tests.
#[async_trait]
pub trait GuardrailAgentCaller: Send + Sync {
    /// Call a guardrail agent with an inspection event.
    async fn call_guardrail_agent(
        &self,
        agent_name: &str,
        event: GuardrailInspectEvent,
    ) -> Result<GuardrailResponse, String>;
}

/// Default implementation using the agent manager.
pub struct AgentManagerCaller {
    agent_manager: Arc<AgentManager>,
}

impl AgentManagerCaller {
    /// Create a new agent manager caller.
    pub fn new(agent_manager: Arc<AgentManager>) -> Self {
        Self { agent_manager }
    }
}

#[async_trait]
impl GuardrailAgentCaller for AgentManagerCaller {
    async fn call_guardrail_agent(
        &self,
        agent_name: &str,
        event: GuardrailInspectEvent,
    ) -> Result<GuardrailResponse, String> {
        trace!(
            agent = agent_name,
            inspection_type = ?event.inspection_type,
            "Calling guardrail agent via agent manager"
        );

        let response = self
            .agent_manager
            .call_guardrail_agent(agent_name, event)
            .await
            .map_err(|e| format!("Guardrail agent '{}' call failed: {}", agent_name, e))?;

        // Map AgentResponse → GuardrailResponse.
        //
        // If the agent puts a serialized GuardrailResponse in
        // routing_metadata["guardrail_response"], use that directly.
        // Otherwise, infer from the Decision field.
        if let Some(raw) = response.routing_metadata.get("guardrail_response") {
            serde_json::from_str::<GuardrailResponse>(raw).map_err(|e| {
                format!(
                    "Failed to parse guardrail response from agent '{}': {}",
                    agent_name, e
                )
            })
        } else {
            // Infer from decision
            match &response.decision {
                Decision::Allow => Ok(GuardrailResponse::default()),
                Decision::Block { body, .. } => Ok(GuardrailResponse {
                    detected: true,
                    confidence: 1.0,
                    detections: vec![GuardrailDetection {
                        category: "agent_block".to_string(),
                        description: body
                            .clone()
                            .unwrap_or_else(|| "Blocked by guardrail agent".to_string()),
                        severity: zentinel_agent_protocol::DetectionSeverity::High,
                        confidence: Some(1.0),
                        span: None,
                    }],
                    redacted_content: None,
                }),
                _ => Ok(GuardrailResponse::default()),
            }
        }
    }
}

/// Guardrail processor for semantic content analysis.
///
/// Uses external agents to inspect content for security issues
/// like prompt injection and PII leakage.
pub struct GuardrailProcessor {
    agent_caller: Arc<dyn GuardrailAgentCaller>,
}

impl GuardrailProcessor {
    /// Create a new guardrail processor with the default agent manager caller.
    pub fn new(agent_manager: Arc<AgentManager>) -> Self {
        Self {
            agent_caller: Arc::new(AgentManagerCaller::new(agent_manager)),
        }
    }

    /// Create a new guardrail processor with a custom agent caller.
    ///
    /// This is useful for testing with mock implementations.
    pub fn with_caller(agent_caller: Arc<dyn GuardrailAgentCaller>) -> Self {
        Self { agent_caller }
    }

    /// Check request content for prompt injection.
    ///
    /// # Arguments
    /// * `config` - Prompt injection detection configuration
    /// * `content` - Request body content to inspect
    /// * `model` - Model name if available
    /// * `route_id` - Route ID for context
    /// * `correlation_id` - Request correlation ID
    pub async fn check_prompt_injection(
        &self,
        config: &PromptInjectionConfig,
        content: &str,
        model: Option<&str>,
        route_id: Option<&str>,
        correlation_id: &str,
    ) -> PromptInjectionResult {
        if !config.enabled {
            return PromptInjectionResult::Clean;
        }

        trace!(
            correlation_id = correlation_id,
            agent = %config.agent,
            content_len = content.len(),
            "Checking content for prompt injection"
        );

        let event = GuardrailInspectEvent {
            correlation_id: correlation_id.to_string(),
            inspection_type: GuardrailInspectionType::PromptInjection,
            content: content.to_string(),
            model: model.map(String::from),
            categories: vec![],
            route_id: route_id.map(String::from),
            metadata: HashMap::new(),
        };

        let start = Instant::now();
        let timeout_duration = Duration::from_millis(config.timeout_ms);

        // Call the agent
        match timeout(
            timeout_duration,
            self.agent_caller.call_guardrail_agent(&config.agent, event),
        )
        .await
        {
            Ok(Ok(response)) => {
                let duration = start.elapsed();
                debug!(
                    correlation_id = correlation_id,
                    agent = %config.agent,
                    detected = response.detected,
                    confidence = response.confidence,
                    detection_count = response.detections.len(),
                    duration_ms = duration.as_millis(),
                    "Prompt injection check completed"
                );

                if response.detected {
                    match config.action {
                        GuardrailAction::Block => PromptInjectionResult::Blocked {
                            status: config.block_status,
                            message: config.block_message.clone().unwrap_or_else(|| {
                                "Request blocked: potential prompt injection detected".to_string()
                            }),
                            detections: response.detections,
                        },
                        GuardrailAction::Log => PromptInjectionResult::Detected {
                            detections: response.detections,
                        },
                        GuardrailAction::Warn => PromptInjectionResult::Warning {
                            detections: response.detections,
                        },
                    }
                } else {
                    PromptInjectionResult::Clean
                }
            }
            Ok(Err(e)) => {
                warn!(
                    correlation_id = correlation_id,
                    agent = %config.agent,
                    error = %e,
                    failure_mode = ?config.failure_mode,
                    "Prompt injection agent call failed"
                );

                match config.failure_mode {
                    GuardrailFailureMode::Open => PromptInjectionResult::Clean,
                    GuardrailFailureMode::Closed => PromptInjectionResult::Blocked {
                        status: 503,
                        message: "Guardrail check unavailable".to_string(),
                        detections: vec![],
                    },
                }
            }
            Err(_) => {
                warn!(
                    correlation_id = correlation_id,
                    agent = %config.agent,
                    timeout_ms = config.timeout_ms,
                    failure_mode = ?config.failure_mode,
                    "Prompt injection agent call timed out"
                );

                match config.failure_mode {
                    GuardrailFailureMode::Open => PromptInjectionResult::Clean,
                    GuardrailFailureMode::Closed => PromptInjectionResult::Blocked {
                        status: 504,
                        message: "Guardrail check timed out".to_string(),
                        detections: vec![],
                    },
                }
            }
        }
    }

    /// Check response content for PII.
    ///
    /// # Arguments
    /// * `config` - PII detection configuration
    /// * `content` - Response content to inspect
    /// * `route_id` - Route ID for context
    /// * `correlation_id` - Request correlation ID
    pub async fn check_pii(
        &self,
        config: &PiiDetectionConfig,
        content: &str,
        route_id: Option<&str>,
        correlation_id: &str,
    ) -> PiiCheckResult {
        if !config.enabled {
            return PiiCheckResult::Clean;
        }

        trace!(
            correlation_id = correlation_id,
            agent = %config.agent,
            content_len = content.len(),
            categories = ?config.categories,
            "Checking response for PII"
        );

        let event = GuardrailInspectEvent {
            correlation_id: correlation_id.to_string(),
            inspection_type: GuardrailInspectionType::PiiDetection,
            content: content.to_string(),
            model: None,
            categories: config.categories.clone(),
            route_id: route_id.map(String::from),
            metadata: HashMap::new(),
        };

        let start = Instant::now();
        let timeout_duration = Duration::from_millis(config.timeout_ms);

        match timeout(
            timeout_duration,
            self.agent_caller.call_guardrail_agent(&config.agent, event),
        )
        .await
        {
            Ok(Ok(response)) => {
                let duration = start.elapsed();
                debug!(
                    correlation_id = correlation_id,
                    agent = %config.agent,
                    detected = response.detected,
                    detection_count = response.detections.len(),
                    duration_ms = duration.as_millis(),
                    "PII check completed"
                );

                if response.detected {
                    PiiCheckResult::Detected {
                        detections: response.detections,
                        redacted_content: response.redacted_content,
                    }
                } else {
                    PiiCheckResult::Clean
                }
            }
            Ok(Err(e)) => {
                warn!(
                    correlation_id = correlation_id,
                    agent = %config.agent,
                    error = %e,
                    "PII detection agent call failed"
                );

                PiiCheckResult::Error {
                    message: e.to_string(),
                }
            }
            Err(_) => {
                warn!(
                    correlation_id = correlation_id,
                    agent = %config.agent,
                    timeout_ms = config.timeout_ms,
                    "PII detection agent call timed out"
                );

                PiiCheckResult::Error {
                    message: "Agent timeout".to_string(),
                }
            }
        }
    }
}

/// Extract message content from an inference request body.
///
/// Attempts to parse the body as JSON and extract message content
/// from common inference API formats (OpenAI, Anthropic, etc.)
pub fn extract_inference_content(body: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;

    // OpenAI format: {"messages": [{"content": "..."}]}
    if let Some(messages) = json.get("messages").and_then(|m| m.as_array()) {
        let content: Vec<String> = messages
            .iter()
            .filter_map(|msg| msg.get("content").and_then(|c| c.as_str()))
            .map(String::from)
            .collect();
        if !content.is_empty() {
            return Some(content.join("\n"));
        }
    }

    // Anthropic format: {"prompt": "..."}
    if let Some(prompt) = json.get("prompt").and_then(|p| p.as_str()) {
        return Some(prompt.to_string());
    }

    // Generic: look for common content fields
    for field in &["input", "text", "query", "question"] {
        if let Some(value) = json.get(*field).and_then(|v| v.as_str()) {
            return Some(value.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use zentinel_agent_protocol::{DetectionSeverity, TextSpan};

    // ==================== Mock Agent Caller ====================

    /// Mock agent caller for testing guardrail processor
    struct MockAgentCaller {
        response: Mutex<Option<Result<GuardrailResponse, String>>>,
        call_count: AtomicUsize,
    }

    impl MockAgentCaller {
        fn new() -> Self {
            Self {
                response: Mutex::new(None),
                call_count: AtomicUsize::new(0),
            }
        }

        fn with_response(response: Result<GuardrailResponse, String>) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                call_count: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl GuardrailAgentCaller for MockAgentCaller {
        async fn call_guardrail_agent(
            &self,
            _agent_name: &str,
            _event: GuardrailInspectEvent,
        ) -> Result<GuardrailResponse, String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);

            let guard = self.response.lock().await;
            match &*guard {
                Some(response) => response.clone(),
                None => Err("No mock response configured".to_string()),
            }
        }
    }

    // ==================== Test Helpers ====================

    fn create_prompt_injection_config(
        action: GuardrailAction,
        failure_mode: GuardrailFailureMode,
    ) -> PromptInjectionConfig {
        PromptInjectionConfig {
            enabled: true,
            agent: "test-agent".to_string(),
            action,
            block_status: 400,
            block_message: Some("Blocked: injection detected".to_string()),
            timeout_ms: 5000,
            failure_mode,
        }
    }

    fn create_pii_config() -> PiiDetectionConfig {
        PiiDetectionConfig {
            enabled: true,
            agent: "pii-scanner".to_string(),
            action: zentinel_config::PiiAction::Log,
            categories: vec!["ssn".to_string(), "email".to_string()],
            timeout_ms: 5000,
            failure_mode: GuardrailFailureMode::Open,
        }
    }

    fn create_detection(category: &str, description: &str) -> GuardrailDetection {
        GuardrailDetection {
            category: category.to_string(),
            description: description.to_string(),
            severity: DetectionSeverity::High,
            confidence: Some(0.95),
            span: Some(TextSpan { start: 0, end: 10 }),
        }
    }

    fn create_guardrail_response(
        detected: bool,
        detections: Vec<GuardrailDetection>,
    ) -> GuardrailResponse {
        GuardrailResponse {
            detected,
            confidence: if detected { 0.95 } else { 0.0 },
            detections,
            redacted_content: None,
        }
    }

    // ==================== extract_inference_content Tests ====================

    #[test]
    fn test_extract_openai_content() {
        let body = br#"{"messages": [{"role": "user", "content": "Hello world"}]}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("Hello world".to_string()));
    }

    #[test]
    fn test_extract_openai_multi_message() {
        let body = br#"{
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("You are helpful\nHello".to_string()));
    }

    #[test]
    fn test_extract_anthropic_content() {
        let body = br#"{"prompt": "Human: Hello\n\nAssistant:"}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("Human: Hello\n\nAssistant:".to_string()));
    }

    #[test]
    fn test_extract_generic_input() {
        let body = br#"{"input": "Test query"}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("Test query".to_string()));
    }

    #[test]
    fn test_extract_generic_text() {
        let body = br#"{"text": "Some text content"}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("Some text content".to_string()));
    }

    #[test]
    fn test_extract_generic_query() {
        let body = br#"{"query": "What is the weather?"}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("What is the weather?".to_string()));
    }

    #[test]
    fn test_extract_generic_question() {
        let body = br#"{"question": "How does this work?"}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("How does this work?".to_string()));
    }

    #[test]
    fn test_extract_invalid_json() {
        let body = b"not json";
        let content = extract_inference_content(body);
        assert_eq!(content, None);
    }

    #[test]
    fn test_extract_empty_messages() {
        let body = br#"{"messages": []}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, None);
    }

    #[test]
    fn test_extract_messages_without_content() {
        let body = br#"{"messages": [{"role": "user"}]}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, None);
    }

    #[test]
    fn test_extract_empty_object() {
        let body = br#"{}"#;
        let content = extract_inference_content(body);
        assert_eq!(content, None);
    }

    #[test]
    fn test_extract_nested_content() {
        // Messages with mixed content types (some with content, some without)
        let body = br#"{
            "messages": [
                {"role": "system"},
                {"role": "user", "content": "Valid content"},
                {"role": "assistant"}
            ]
        }"#;
        let content = extract_inference_content(body);
        assert_eq!(content, Some("Valid content".to_string()));
    }

    // ==================== Prompt Injection Tests ====================

    #[tokio::test]
    async fn test_prompt_injection_disabled() {
        let mock = Arc::new(MockAgentCaller::new());
        let processor = GuardrailProcessor::with_caller(mock.clone());

        let mut config =
            create_prompt_injection_config(GuardrailAction::Block, GuardrailFailureMode::Open);
        config.enabled = false;

        let result = processor
            .check_prompt_injection(&config, "test content", None, None, "corr-123")
            .await;

        assert!(matches!(result, PromptInjectionResult::Clean));
        assert_eq!(mock.call_count(), 0); // Agent should not be called
    }

    #[tokio::test]
    async fn test_prompt_injection_clean() {
        let response = create_guardrail_response(false, vec![]);
        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock.clone());

        let config =
            create_prompt_injection_config(GuardrailAction::Block, GuardrailFailureMode::Open);

        let result = processor
            .check_prompt_injection(
                &config,
                "normal content",
                Some("gpt-4"),
                Some("route-1"),
                "corr-123",
            )
            .await;

        assert!(matches!(result, PromptInjectionResult::Clean));
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn test_prompt_injection_detected_block_action() {
        let detection = create_detection("injection", "Attempt to override instructions");
        let response = create_guardrail_response(true, vec![detection]);
        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock);

        let config =
            create_prompt_injection_config(GuardrailAction::Block, GuardrailFailureMode::Open);

        let result = processor
            .check_prompt_injection(
                &config,
                "ignore previous instructions",
                None,
                None,
                "corr-123",
            )
            .await;

        match result {
            PromptInjectionResult::Blocked {
                status,
                message,
                detections,
            } => {
                assert_eq!(status, 400);
                assert_eq!(message, "Blocked: injection detected");
                assert_eq!(detections.len(), 1);
            }
            _ => panic!("Expected Blocked result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_prompt_injection_detected_log_action() {
        let detection = create_detection("injection", "Suspicious pattern");
        let response = create_guardrail_response(true, vec![detection]);
        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock);

        let config =
            create_prompt_injection_config(GuardrailAction::Log, GuardrailFailureMode::Open);

        let result = processor
            .check_prompt_injection(&config, "suspicious content", None, None, "corr-123")
            .await;

        match result {
            PromptInjectionResult::Detected { detections } => {
                assert_eq!(detections.len(), 1);
            }
            _ => panic!("Expected Detected result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_prompt_injection_detected_warn_action() {
        let detection = create_detection("injection", "Possible injection");
        let response = create_guardrail_response(true, vec![detection]);
        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock);

        let config =
            create_prompt_injection_config(GuardrailAction::Warn, GuardrailFailureMode::Open);

        let result = processor
            .check_prompt_injection(&config, "maybe suspicious", None, None, "corr-123")
            .await;

        match result {
            PromptInjectionResult::Warning { detections } => {
                assert_eq!(detections.len(), 1);
            }
            _ => panic!("Expected Warning result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_prompt_injection_agent_error_fail_open() {
        let mock = Arc::new(MockAgentCaller::with_response(Err(
            "Agent unavailable".to_string()
        )));
        let processor = GuardrailProcessor::with_caller(mock);

        let config =
            create_prompt_injection_config(GuardrailAction::Block, GuardrailFailureMode::Open);

        let result = processor
            .check_prompt_injection(&config, "test content", None, None, "corr-123")
            .await;

        // Fail-open: allow the request despite agent error
        assert!(matches!(result, PromptInjectionResult::Clean));
    }

    #[tokio::test]
    async fn test_prompt_injection_agent_error_fail_closed() {
        let mock = Arc::new(MockAgentCaller::with_response(Err(
            "Agent unavailable".to_string()
        )));
        let processor = GuardrailProcessor::with_caller(mock);

        let config =
            create_prompt_injection_config(GuardrailAction::Block, GuardrailFailureMode::Closed);

        let result = processor
            .check_prompt_injection(&config, "test content", None, None, "corr-123")
            .await;

        // Fail-closed: block the request on agent error
        match result {
            PromptInjectionResult::Blocked {
                status, message, ..
            } => {
                assert_eq!(status, 503);
                assert_eq!(message, "Guardrail check unavailable");
            }
            _ => panic!("Expected Blocked result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_prompt_injection_default_block_message() {
        let detection = create_detection("injection", "Test");
        let response = create_guardrail_response(true, vec![detection]);
        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock);

        let mut config =
            create_prompt_injection_config(GuardrailAction::Block, GuardrailFailureMode::Open);
        config.block_message = None; // Use default message

        let result = processor
            .check_prompt_injection(&config, "injection attempt", None, None, "corr-123")
            .await;

        match result {
            PromptInjectionResult::Blocked { message, .. } => {
                assert_eq!(
                    message,
                    "Request blocked: potential prompt injection detected"
                );
            }
            _ => panic!("Expected Blocked result"),
        }
    }

    // ==================== PII Detection Tests ====================

    #[tokio::test]
    async fn test_pii_disabled() {
        let mock = Arc::new(MockAgentCaller::new());
        let processor = GuardrailProcessor::with_caller(mock.clone());

        let mut config = create_pii_config();
        config.enabled = false;

        let result = processor
            .check_pii(&config, "content with SSN 123-45-6789", None, "corr-123")
            .await;

        assert!(matches!(result, PiiCheckResult::Clean));
        assert_eq!(mock.call_count(), 0);
    }

    #[tokio::test]
    async fn test_pii_clean() {
        let response = create_guardrail_response(false, vec![]);
        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock.clone());

        let config = create_pii_config();

        let result = processor
            .check_pii(
                &config,
                "No sensitive data here",
                Some("route-1"),
                "corr-123",
            )
            .await;

        assert!(matches!(result, PiiCheckResult::Clean));
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn test_pii_detected() {
        let ssn_detection = create_detection("ssn", "Social Security Number detected");
        let email_detection = create_detection("email", "Email address detected");
        let mut response = create_guardrail_response(true, vec![ssn_detection, email_detection]);
        response.redacted_content =
            Some("My SSN is [REDACTED] and email is [REDACTED]".to_string());

        let mock = Arc::new(MockAgentCaller::with_response(Ok(response)));
        let processor = GuardrailProcessor::with_caller(mock);

        let config = create_pii_config();

        let result = processor
            .check_pii(
                &config,
                "My SSN is 123-45-6789 and email is test@example.com",
                None,
                "corr-123",
            )
            .await;

        match result {
            PiiCheckResult::Detected {
                detections,
                redacted_content,
            } => {
                assert_eq!(detections.len(), 2);
                assert!(redacted_content.is_some());
                assert!(redacted_content.unwrap().contains("[REDACTED]"));
            }
            _ => panic!("Expected Detected result, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_pii_agent_error() {
        let mock = Arc::new(MockAgentCaller::with_response(Err(
            "PII scanner unavailable".to_string(),
        )));
        let processor = GuardrailProcessor::with_caller(mock);

        let config = create_pii_config();

        let result = processor
            .check_pii(&config, "test content", None, "corr-123")
            .await;

        match result {
            PiiCheckResult::Error { message } => {
                assert!(message.contains("unavailable"));
            }
            _ => panic!("Expected Error result, got {:?}", result),
        }
    }

    // ==================== Result Type Tests ====================

    #[test]
    fn test_prompt_injection_result_debug() {
        let result = PromptInjectionResult::Clean;
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Clean"));

        let result = PromptInjectionResult::Blocked {
            status: 400,
            message: "test".to_string(),
            detections: vec![],
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Blocked"));
    }

    #[test]
    fn test_pii_check_result_debug() {
        let result = PiiCheckResult::Clean;
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Clean"));

        let result = PiiCheckResult::Error {
            message: "test error".to_string(),
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Error"));
    }
}
