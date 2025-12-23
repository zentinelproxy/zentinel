//! Error handling module for Sentinel proxy
//!
//! This module provides customizable error page generation for different
//! service types (web, API, static) and formats (HTML, JSON, text, XML).

use anyhow::Result;
use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, warn};

use sentinel_config::{ErrorFormat, ErrorPage, ErrorPageConfig, ServiceType};

/// Error response generator
pub struct ErrorHandler {
    /// Service type for this handler
    service_type: ServiceType,
    /// Error page configuration
    config: Option<ErrorPageConfig>,
    /// Cached error templates
    templates: Arc<HashMap<u16, String>>,
}

/// Error response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// HTTP status code
    pub status: u16,
    /// Error title
    pub title: String,
    /// Error message
    pub message: String,
    /// Request ID for tracking
    pub request_id: String,
    /// Timestamp
    pub timestamp: i64,
    /// Additional details (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Stack trace (development only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<Vec<String>>,
}

impl ErrorHandler {
    /// Create a new error handler
    pub fn new(service_type: ServiceType, config: Option<ErrorPageConfig>) -> Self {
        let templates = if let Some(ref cfg) = config {
            Self::load_templates(cfg)
        } else {
            Arc::new(HashMap::new())
        };

        Self {
            service_type,
            config,
            templates,
        }
    }

    /// Generate an error response
    pub fn generate_response(
        &self,
        status: StatusCode,
        message: Option<String>,
        request_id: &str,
        details: Option<serde_json::Value>,
    ) -> Result<Response<Full<Bytes>>> {
        let status_code = status.as_u16();
        let error_data = ErrorResponse {
            status: status_code,
            title: Self::status_title(status),
            message: message.unwrap_or_else(|| Self::default_message(status)),
            request_id: request_id.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            details,
            stack_trace: self.get_stack_trace(),
        };

        // Determine the format to use
        let format = self.determine_format(status_code);

        // Generate the response body
        let (body, content_type) = match format {
            ErrorFormat::Json => self.generate_json_response(&error_data)?,
            ErrorFormat::Html => self.generate_html_response(&error_data, status_code)?,
            ErrorFormat::Text => self.generate_text_response(&error_data)?,
            ErrorFormat::Xml => self.generate_xml_response(&error_data)?,
        };

        // Build the response
        let mut response = Response::builder()
            .status(status)
            .header("Content-Type", content_type)
            .header("X-Request-Id", request_id);

        // Add custom headers if configured
        if let Some(page) = self.get_error_page(status_code) {
            for (key, value) in &page.headers {
                response = response.header(key, value);
            }
        }

        Ok(response.body(Full::new(Bytes::from(body)))?)
    }

    /// Determine the error format based on service type and configuration
    fn determine_format(&self, status_code: u16) -> ErrorFormat {
        // Check if there's a specific configuration for this status code
        if let Some(page) = self.get_error_page(status_code) {
            return page.format;
        }

        // Use default format based on service type
        match self.service_type {
            ServiceType::Api => ErrorFormat::Json,
            ServiceType::Web | ServiceType::Static => self
                .config
                .as_ref()
                .map(|c| c.default_format)
                .unwrap_or(ErrorFormat::Html),
        }
    }

    /// Get error page configuration for a specific status code
    fn get_error_page(&self, status_code: u16) -> Option<&ErrorPage> {
        self.config.as_ref().and_then(|c| c.pages.get(&status_code))
    }

    /// Generate JSON error response
    fn generate_json_response(&self, error: &ErrorResponse) -> Result<(Vec<u8>, &'static str)> {
        let json = serde_json::to_vec_pretty(error)?;
        Ok((json, "application/json; charset=utf-8"))
    }

    /// Generate HTML error response
    fn generate_html_response(
        &self,
        error: &ErrorResponse,
        status_code: u16,
    ) -> Result<(Vec<u8>, &'static str)> {
        // Check for custom template
        if let Some(template) = self.templates.get(&status_code) {
            let html = self.render_template(template, error)?;
            return Ok((html.into_bytes(), "text/html; charset=utf-8"));
        }

        // Generate default HTML
        let html = self.generate_default_html(error);
        Ok((html.into_bytes(), "text/html; charset=utf-8"))
    }

    /// Generate text error response
    fn generate_text_response(&self, error: &ErrorResponse) -> Result<(Vec<u8>, &'static str)> {
        let text = format!(
            "{} {}\n\n{}\n\nRequest ID: {}\nTimestamp: {}",
            error.status, error.title, error.message, error.request_id, error.timestamp
        );
        Ok((text.into_bytes(), "text/plain; charset=utf-8"))
    }

    /// Generate XML error response
    fn generate_xml_response(&self, error: &ErrorResponse) -> Result<(Vec<u8>, &'static str)> {
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<error>
    <status>{}</status>
    <title>{}</title>
    <message>{}</message>
    <requestId>{}</requestId>
    <timestamp>{}</timestamp>
</error>"#,
            error.status,
            Self::escape_xml(&error.title),
            Self::escape_xml(&error.message),
            Self::escape_xml(&error.request_id),
            error.timestamp
        );
        Ok((xml.into_bytes(), "application/xml; charset=utf-8"))
    }

    /// Generate default HTML error page
    fn generate_default_html(&self, error: &ErrorResponse) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} {}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        .error-container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
            text-align: center;
        }}
        h1 {{
            color: #764ba2;
            font-size: 72px;
            margin: 0;
            font-weight: bold;
        }}
        h2 {{
            color: #666;
            font-size: 24px;
            margin: 10px 0;
            font-weight: normal;
        }}
        p {{
            color: #777;
            font-size: 16px;
            line-height: 1.6;
            margin: 20px 0;
        }}
        .request-id {{
            background: #f5f5f5;
            border-radius: 4px;
            padding: 8px 12px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #999;
            margin-top: 30px;
        }}
        .back-link {{
            display: inline-block;
            margin-top: 20px;
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }}
        .back-link:hover {{
            color: #764ba2;
        }}
    </style>
</head>
<body>
    <div class="error-container">
        <h1>{}</h1>
        <h2>{}</h2>
        <p>{}</p>
        <div class="request-id">Request ID: {}</div>
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>"#,
            error.status, error.title, error.status, error.title, error.message, error.request_id
        )
    }

    /// Load custom templates from disk
    fn load_templates(config: &ErrorPageConfig) -> Arc<HashMap<u16, String>> {
        let mut templates = HashMap::new();

        if let Some(ref template_dir) = config.template_dir {
            for (status_code, page) in &config.pages {
                if let Some(ref template_path) = page.template {
                    let full_path = if template_path.is_absolute() {
                        template_path.clone()
                    } else {
                        template_dir.join(template_path)
                    };

                    match std::fs::read_to_string(&full_path) {
                        Ok(content) => {
                            templates.insert(*status_code, content);
                            debug!(
                                "Loaded error template for status {}: {:?}",
                                status_code, full_path
                            );
                        }
                        Err(e) => {
                            warn!("Failed to load error template {:?}: {}", full_path, e);
                        }
                    }
                }
            }
        }

        Arc::new(templates)
    }

    /// Render a template with error data
    fn render_template(&self, template: &str, error: &ErrorResponse) -> Result<String> {
        // Simple template rendering - replace placeholders
        let rendered = template
            .replace("{{status}}", &error.status.to_string())
            .replace("{{title}}", &error.title)
            .replace("{{message}}", &error.message)
            .replace("{{request_id}}", &error.request_id)
            .replace("{{timestamp}}", &error.timestamp.to_string());

        Ok(rendered)
    }

    /// Get stack trace if enabled (development only)
    fn get_stack_trace(&self) -> Option<Vec<String>> {
        if let Some(ref config) = self.config {
            if config.include_stack_trace {
                // In production, we would capture the actual stack trace
                // For now, return None
                return None;
            }
        }
        None
    }

    /// Get default status title
    fn status_title(status: StatusCode) -> String {
        status
            .canonical_reason()
            .unwrap_or("Unknown Error")
            .to_string()
    }

    /// Get default error message for status code
    fn default_message(status: StatusCode) -> String {
        match status {
            StatusCode::BAD_REQUEST => {
                "The request could not be understood by the server.".to_string()
            }
            StatusCode::UNAUTHORIZED => {
                "You are not authorized to access this resource.".to_string()
            }
            StatusCode::FORBIDDEN => "Access to this resource is forbidden.".to_string(),
            StatusCode::NOT_FOUND => "The requested resource could not be found.".to_string(),
            StatusCode::METHOD_NOT_ALLOWED => {
                "The requested method is not allowed for this resource.".to_string()
            }
            StatusCode::REQUEST_TIMEOUT => "The request took too long to process.".to_string(),
            StatusCode::PAYLOAD_TOO_LARGE => "The request payload is too large.".to_string(),
            StatusCode::TOO_MANY_REQUESTS => {
                "Too many requests. Please try again later.".to_string()
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                "An internal server error occurred. Please try again later.".to_string()
            }
            StatusCode::BAD_GATEWAY => {
                "The gateway received an invalid response from the upstream server.".to_string()
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                "The service is temporarily unavailable. Please try again later.".to_string()
            }
            StatusCode::GATEWAY_TIMEOUT => {
                "The gateway timed out waiting for a response from the upstream server.".to_string()
            }
            _ => format!("An error occurred (HTTP {})", status.as_u16()),
        }
    }

    /// Escape XML special characters
    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// Reload templates (for hot reload)
    pub fn reload_templates(&mut self) {
        if let Some(ref config) = self.config {
            self.templates = Self::load_templates(config);
            debug!("Reloaded error templates");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_handler_json() {
        let handler = ErrorHandler::new(ServiceType::Api, None);
        let response = handler
            .generate_response(
                StatusCode::NOT_FOUND,
                Some("Resource not found".to_string()),
                "test-123",
                None,
            )
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let headers = response.headers();
        assert_eq!(
            headers.get("Content-Type").unwrap(),
            "application/json; charset=utf-8"
        );
    }

    #[test]
    fn test_error_handler_html() {
        let handler = ErrorHandler::new(ServiceType::Web, None);
        let response = handler
            .generate_response(StatusCode::INTERNAL_SERVER_ERROR, None, "test-456", None)
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let headers = response.headers();
        assert_eq!(
            headers.get("Content-Type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn test_custom_error_format() {
        let mut config = ErrorPageConfig {
            pages: HashMap::new(),
            default_format: ErrorFormat::Xml,
            include_stack_trace: false,
            template_dir: None,
        };

        config.pages.insert(
            404,
            ErrorPage {
                format: ErrorFormat::Text,
                template: None,
                message: Some("Custom 404 message".to_string()),
                headers: HashMap::new(),
            },
        );

        let handler = ErrorHandler::new(ServiceType::Web, Some(config));
        let response = handler
            .generate_response(StatusCode::NOT_FOUND, None, "test-789", None)
            .unwrap();

        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/plain; charset=utf-8"
        );
    }
}
