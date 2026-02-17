//! Inference-specific health check for LLM backends.
//!
//! This module provides a Pingora-compatible health check that verifies:
//! - The inference server is responding (HTTP 200)
//! - Expected models are available in the `/v1/models` response
//!
//! # Example Configuration
//!
//! ```kdl
//! upstream "llm-pool" {
//!     targets {
//!         target { address "gpu-1:8080" }
//!     }
//!     health-check {
//!         type "inference" {
//!             endpoint "/v1/models"
//!             expected-models "gpt-4" "llama-3"
//!         }
//!         interval-secs 30
//!     }
//! }
//! ```

use async_trait::async_trait;
use pingora_core::{Error, ErrorType::CustomCode, Result};
use pingora_load_balancing::health_check::HealthCheck as PingoraHealthCheck;
use pingora_load_balancing::Backend;
use serde::Deserialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};

/// Inference health check for LLM/AI backends.
///
/// Implements Pingora's HealthCheck trait to integrate with the load balancing
/// infrastructure. Verifies both server availability and model availability.
pub struct InferenceHealthCheck {
    /// Endpoint to probe (default: /v1/models)
    endpoint: String,
    /// Models that must be present for the backend to be healthy
    expected_models: Vec<String>,
    /// Connection/response timeout
    timeout: Duration,
    /// Consecutive successes needed to mark healthy
    pub consecutive_success: usize,
    /// Consecutive failures needed to mark unhealthy
    pub consecutive_failure: usize,
}

/// OpenAI-compatible models list response.
#[derive(Debug, Deserialize)]
struct ModelsResponse {
    data: Vec<ModelInfo>,
}

/// Individual model info in the response.
#[derive(Debug, Deserialize)]
struct ModelInfo {
    id: String,
    #[serde(default)]
    object: String,
}

impl InferenceHealthCheck {
    /// Create a new inference health check.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The models endpoint path (e.g., "/v1/models")
    /// * `expected_models` - List of model IDs that must be available
    /// * `timeout` - Connection and response timeout
    pub fn new(endpoint: String, expected_models: Vec<String>, timeout: Duration) -> Self {
        Self {
            endpoint,
            expected_models,
            timeout,
            consecutive_success: 1,
            consecutive_failure: 1,
        }
    }

    /// Perform the actual health check against a target.
    async fn check_backend(&self, addr: &str) -> Result<(), String> {
        // Parse address
        let socket_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| format!("Invalid address '{}': {}", addr, e))?;

        // Connect with timeout
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        // Build HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Zentinel-HealthCheck/1.0\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\r\n",
            self.endpoint, addr
        );

        // Send request
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response with timeout
        let mut response = vec![0u8; 65536]; // 64KB buffer for models list
        let n = tokio::time::timeout(self.timeout, stream.read(&mut response))
            .await
            .map_err(|_| "Response timeout".to_string())?
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err("Empty response".to_string());
        }

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Parse HTTP status
        let status_code = self.parse_status_code(&response_str)?;
        if status_code != 200 {
            return Err(format!("HTTP {} (expected 200)", status_code));
        }

        // If no expected models specified, just check HTTP 200
        if self.expected_models.is_empty() {
            trace!(
                addr = %addr,
                endpoint = %self.endpoint,
                "Inference health check passed (no model verification)"
            );
            return Ok(());
        }

        // Extract JSON body
        let body = self.extract_body(&response_str)?;

        // Parse models response
        let models = self.parse_models_response(body)?;

        // Verify expected models are present
        self.verify_models(&models)?;

        trace!(
            addr = %addr,
            endpoint = %self.endpoint,
            model_count = models.len(),
            expected_models = ?self.expected_models,
            "Inference health check passed"
        );

        Ok(())
    }

    /// Parse HTTP status code from response.
    fn parse_status_code(&self, response: &str) -> Result<u16, String> {
        response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| "Failed to parse HTTP status".to_string())
    }

    /// Extract body from HTTP response.
    fn extract_body<'a>(&self, response: &'a str) -> Result<&'a str, String> {
        response
            .find("\r\n\r\n")
            .map(|pos| &response[pos + 4..])
            .ok_or_else(|| "Could not find response body".to_string())
    }

    /// Parse the models list from JSON response.
    fn parse_models_response(&self, body: &str) -> Result<Vec<String>, String> {
        // Handle chunked encoding - find the actual JSON
        let json_body = if body.starts_with(|c: char| c.is_ascii_hexdigit()) {
            // Chunked encoding: skip the chunk size line
            body.lines()
                .skip(1)
                .take_while(|line| !line.is_empty() && *line != "0")
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            body.to_string()
        };

        // Try parsing as OpenAI-compatible format
        if let Ok(response) = serde_json::from_str::<ModelsResponse>(&json_body) {
            return Ok(response.data.into_iter().map(|m| m.id).collect());
        }

        // Fallback: try parsing as simple array of model objects
        if let Ok(models) = serde_json::from_str::<Vec<ModelInfo>>(&json_body) {
            return Ok(models.into_iter().map(|m| m.id).collect());
        }

        // Last fallback: extract model IDs from any JSON with "id" fields
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_body) {
            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                let models: Vec<String> = data
                    .iter()
                    .filter_map(|m| m.get("id").and_then(|id| id.as_str()))
                    .map(String::from)
                    .collect();
                if !models.is_empty() {
                    return Ok(models);
                }
            }

            // Check for models array directly
            if let Some(models_arr) = json.get("models").and_then(|m| m.as_array()) {
                let models: Vec<String> = models_arr
                    .iter()
                    .filter_map(|m| {
                        m.get("id")
                            .or_else(|| m.get("name"))
                            .and_then(|id| id.as_str())
                    })
                    .map(String::from)
                    .collect();
                if !models.is_empty() {
                    return Ok(models);
                }
            }
        }

        Err(format!(
            "Failed to parse models response. Body preview: {}",
            &json_body[..json_body.len().min(200)]
        ))
    }

    /// Verify that all expected models are present.
    fn verify_models(&self, available_models: &[String]) -> Result<(), String> {
        let mut missing = Vec::new();

        for expected in &self.expected_models {
            // Check for exact match or prefix match (for versioned models)
            let found = available_models
                .iter()
                .any(|m| m == expected || m.starts_with(expected) || expected.starts_with(m));

            if !found {
                missing.push(expected.as_str());
            }
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Missing models: {}. Available: {:?}",
                missing.join(", "),
                available_models
            ))
        }
    }
}

#[async_trait]
impl PingoraHealthCheck for InferenceHealthCheck {
    /// Check if the backend is healthy.
    ///
    /// Returns Ok(()) if healthy, Err with message if not.
    async fn check(&self, backend: &Backend) -> Result<()> {
        let addr = backend.addr.to_string();

        match self.check_backend(&addr).await {
            Ok(()) => {
                trace!(
                    addr = %addr,
                    endpoint = %self.endpoint,
                    expected_models = ?self.expected_models,
                    "Inference health check passed"
                );
                Ok(())
            }
            Err(error) => {
                debug!(
                    addr = %addr,
                    endpoint = %self.endpoint,
                    error = %error,
                    "Inference health check failed"
                );
                Err(Error::explain(
                    CustomCode("inference health check", 1),
                    error,
                ))
            }
        }
    }

    /// Return the health threshold for flipping health status.
    ///
    /// * `success: true` - returns consecutive_success (unhealthy -> healthy)
    /// * `success: false` - returns consecutive_failure (healthy -> unhealthy)
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openai_models_response() {
        let check = InferenceHealthCheck::new(
            "/v1/models".to_string(),
            vec!["gpt-4".to_string()],
            Duration::from_secs(5),
        );

        let body = r#"{"object":"list","data":[{"id":"gpt-4","object":"model"},{"id":"gpt-3.5-turbo","object":"model"}]}"#;
        let models = check.parse_models_response(body).unwrap();

        assert_eq!(models.len(), 2);
        assert!(models.contains(&"gpt-4".to_string()));
        assert!(models.contains(&"gpt-3.5-turbo".to_string()));
    }

    #[test]
    fn test_parse_ollama_models_response() {
        let check = InferenceHealthCheck::new(
            "/api/tags".to_string(),
            vec!["llama3".to_string()],
            Duration::from_secs(5),
        );

        // Ollama uses "models" array with "name" field
        let body = r#"{"models":[{"name":"llama3:latest"},{"name":"codellama:7b"}]}"#;
        let models = check.parse_models_response(body).unwrap();

        assert_eq!(models.len(), 2);
        assert!(models.contains(&"llama3:latest".to_string()));
    }

    #[test]
    fn test_verify_models_exact_match() {
        let check = InferenceHealthCheck::new(
            "/v1/models".to_string(),
            vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()],
            Duration::from_secs(5),
        );

        let available = vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()];
        assert!(check.verify_models(&available).is_ok());
    }

    #[test]
    fn test_verify_models_prefix_match() {
        let check = InferenceHealthCheck::new(
            "/v1/models".to_string(),
            vec!["gpt-4".to_string()],
            Duration::from_secs(5),
        );

        // Should match "gpt-4-turbo" when looking for "gpt-4"
        let available = vec!["gpt-4-turbo".to_string(), "gpt-3.5-turbo".to_string()];
        assert!(check.verify_models(&available).is_ok());
    }

    #[test]
    fn test_verify_models_missing() {
        let check = InferenceHealthCheck::new(
            "/v1/models".to_string(),
            vec!["gpt-4".to_string(), "claude-3".to_string()],
            Duration::from_secs(5),
        );

        let available = vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()];
        let result = check.verify_models(&available);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("claude-3"));
    }

    #[test]
    fn test_parse_status_code() {
        let check =
            InferenceHealthCheck::new("/v1/models".to_string(), vec![], Duration::from_secs(5));

        assert_eq!(check.parse_status_code("HTTP/1.1 200 OK\r\n"), Ok(200));
        assert_eq!(
            check.parse_status_code("HTTP/1.1 404 Not Found\r\n"),
            Ok(404)
        );
    }

    #[test]
    fn test_extract_body() {
        let check =
            InferenceHealthCheck::new("/v1/models".to_string(), vec![], Duration::from_secs(5));

        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"data\":[]}";
        let body = check.extract_body(response).unwrap();
        assert_eq!(body, "{\"data\":[]}");
    }
}
