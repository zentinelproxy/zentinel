//! Integration tests for service type functionality
//!
//! Tests static file serving, API validation, and custom error pages

use anyhow::Result;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use sentinel_config::{
    ApiSchemaConfig, ErrorFormat, ErrorPage, ErrorPageConfig, ServiceType, StaticFileConfig,
};
use sentinel_proxy::{ErrorHandler, SchemaValidator, StaticFileServer};
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;
use tokio::fs;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test static file serving functionality
    #[tokio::test]
    async fn test_static_file_serving() -> Result<()> {
        // Create a temporary directory with test files
        let temp_dir = TempDir::new()?;
        let static_root = temp_dir.path().to_path_buf();

        // Create test files
        let index_content = b"<html><body>Hello World</body></html>";
        let css_content = b"body { margin: 0; }";
        let js_content = b"console.log('test');";

        fs::write(static_root.join("index.html"), index_content).await?;
        fs::write(static_root.join("style.css"), css_content).await?;
        fs::create_dir(static_root.join("js")).await?;
        fs::write(static_root.join("js/app.js"), js_content).await?;

        // Configure static file server
        let config = StaticFileConfig {
            root: static_root.clone(),
            index: "index.html".to_string(),
            directory_listing: false,
            cache_control: "public, max-age=3600".to_string(),
            compress: true,
            mime_types: HashMap::new(),
            fallback: None,
        };

        let server = StaticFileServer::new(config);

        // Test serving index file
        let req = Request::get("/").body(()).unwrap();
        let response = server.serve(&req, "/").await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], index_content);

        // Test serving CSS file
        let req = Request::get("/style.css").body(()).unwrap();
        let response = server.serve(&req, "/style.css").await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()?
            .contains("text/css"));

        // Test serving JS file from subdirectory
        let req = Request::get("/js/app.js").body(()).unwrap();
        let response = server.serve(&req, "/js/app.js").await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()?
            .contains("javascript"));

        // Test 404 for non-existent file
        let req = Request::get("/nonexistent.txt").body(()).unwrap();
        let response = server.serve(&req, "/nonexistent.txt").await;
        assert!(response.is_err() || response.unwrap().status() == StatusCode::NOT_FOUND);

        Ok(())
    }

    /// Test SPA fallback functionality
    #[tokio::test]
    async fn test_spa_fallback() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let static_root = temp_dir.path().to_path_buf();

        // Create SPA index file
        let spa_content = b"<html><body>SPA App</body></html>";
        fs::write(static_root.join("index.html"), spa_content).await?;

        // Configure with fallback
        let config = StaticFileConfig {
            root: static_root.clone(),
            index: "index.html".to_string(),
            directory_listing: false,
            cache_control: "public, max-age=3600".to_string(),
            compress: false,
            mime_types: HashMap::new(),
            fallback: Some("index.html".to_string()),
        };

        let server = StaticFileServer::new(config);

        // Test that non-existent route falls back to index.html
        let req = Request::get("/app/route/123").body(()).unwrap();
        let response = server.serve(&req, "/app/route/123").await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], spa_content);

        Ok(())
    }

    /// Test API schema validation
    #[tokio::test]
    async fn test_api_validation() -> Result<()> {
        // Define a simple schema
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 50
                },
                "age": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 150
                },
                "email": {
                    "type": "string",
                    "format": "email"
                }
            },
            "required": ["name", "email"]
        });

        let config = ApiSchemaConfig {
            schema_file: None,
            request_schema: Some(schema),
            response_schema: None,
            validate_requests: true,
            validate_responses: false,
            strict_mode: false,
        };

        let validator = SchemaValidator::new(config)?;

        // Test valid request
        let valid_body = json!({
            "name": "John Doe",
            "age": 30,
            "email": "john@example.com"
        });

        let req = Request::post("/api/users")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        let result = validator
            .validate_request(
                &req,
                &serde_json::to_vec(&valid_body)?,
                "/api/users",
                "req-123",
            )
            .await;
        assert!(result.is_ok());

        // Test invalid request (missing required field)
        let invalid_body = json!({
            "name": "John",
            // Missing email
            "age": 30
        });

        let result = validator
            .validate_request(
                &req,
                &serde_json::to_vec(&invalid_body)?,
                "/api/users",
                "req-124",
            )
            .await;
        assert!(result.is_err());

        // Test invalid request (wrong type)
        let invalid_body = json!({
            "name": "Jo", // Too short
            "email": "not-an-email", // Invalid format
            "age": "thirty" // Wrong type
        });

        let result = validator
            .validate_request(
                &req,
                &serde_json::to_vec(&invalid_body)?,
                "/api/users",
                "req-125",
            )
            .await;
        assert!(result.is_err());

        Ok(())
    }

    /// Test custom error page generation
    #[tokio::test]
    async fn test_error_pages() -> Result<()> {
        // Test JSON error pages for API
        let mut api_pages = HashMap::new();
        api_pages.insert(
            404,
            ErrorPage {
                format: ErrorFormat::Json,
                template: None,
                message: Some("Resource not found".to_string()),
                headers: {
                    let mut h = HashMap::new();
                    h.insert("X-Error-Code".to_string(), "NOT_FOUND".to_string());
                    h
                },
            },
        );

        let api_error_config = ErrorPageConfig {
            pages: api_pages,
            default_format: ErrorFormat::Json,
            include_stack_trace: false,
            template_dir: None,
        };

        let api_handler = ErrorHandler::new(ServiceType::Api, Some(api_error_config));

        // Generate 404 error
        let response = api_handler.generate_response(
            StatusCode::NOT_FOUND,
            Some("User not found".to_string()),
            "req-001",
            None,
        )?;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json; charset=utf-8"
        );
        assert_eq!(response.headers().get("X-Error-Code").unwrap(), "NOT_FOUND");

        // Verify JSON response body
        let body = response.into_body().collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["status"], 404);
        assert_eq!(json["request_id"], "req-001");

        // Test HTML error pages for Web
        let mut web_pages = HashMap::new();
        web_pages.insert(
            500,
            ErrorPage {
                format: ErrorFormat::Html,
                template: None,
                message: Some("Internal server error".to_string()),
                headers: HashMap::new(),
            },
        );

        let web_error_config = ErrorPageConfig {
            pages: web_pages,
            default_format: ErrorFormat::Html,
            include_stack_trace: false,
            template_dir: None,
        };

        let web_handler = ErrorHandler::new(ServiceType::Web, Some(web_error_config));

        // Generate 500 error
        let response = web_handler.generate_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "req-002",
            None,
        )?;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/html; charset=utf-8"
        );

        // Verify HTML response contains expected elements
        let body = response.into_body().collect().await?.to_bytes();
        let html = String::from_utf8(body.to_vec())?;
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("500"));
        assert!(html.contains("req-002"));

        Ok(())
    }

    /// Test different error formats
    #[tokio::test]
    async fn test_error_formats() -> Result<()> {
        // Test Text format
        let text_config = ErrorPageConfig {
            pages: HashMap::new(),
            default_format: ErrorFormat::Text,
            include_stack_trace: false,
            template_dir: None,
        };

        let text_handler = ErrorHandler::new(ServiceType::Api, Some(text_config));
        let response = text_handler.generate_response(
            StatusCode::BAD_REQUEST,
            Some("Invalid input".to_string()),
            "req-003",
            None,
        )?;

        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/plain; charset=utf-8"
        );

        // Test XML format
        let xml_config = ErrorPageConfig {
            pages: HashMap::new(),
            default_format: ErrorFormat::Xml,
            include_stack_trace: false,
            template_dir: None,
        };

        let xml_handler = ErrorHandler::new(ServiceType::Api, Some(xml_config));
        let response = xml_handler.generate_response(
            StatusCode::FORBIDDEN,
            Some("Access denied".to_string()),
            "req-004",
            None,
        )?;

        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/xml; charset=utf-8"
        );

        let body = response.into_body().collect().await?.to_bytes();
        let xml = String::from_utf8(body.to_vec())?;
        assert!(xml.contains("<?xml version="));
        assert!(xml.contains("<error>"));
        assert!(xml.contains("<status>403</status>"));

        Ok(())
    }

    /// Test cache headers for static files
    #[tokio::test]
    async fn test_static_cache_headers() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let static_root = temp_dir.path().to_path_buf();

        fs::write(static_root.join("test.txt"), b"test content").await?;

        let config = StaticFileConfig {
            root: static_root.clone(),
            index: "index.html".to_string(),
            directory_listing: false,
            cache_control: "public, max-age=86400, immutable".to_string(),
            compress: false,
            mime_types: HashMap::new(),
            fallback: None,
        };

        let server = StaticFileServer::new(config);

        let req = Request::get("/test.txt").body(()).unwrap();
        let response = server.serve(&req, "/test.txt").await?;

        assert_eq!(
            response.headers().get("Cache-Control").unwrap(),
            "public, max-age=86400, immutable"
        );
        assert!(response.headers().contains_key("ETag"));
        assert!(response.headers().contains_key("Last-Modified"));

        Ok(())
    }

    /// Test validation error response structure
    #[tokio::test]
    async fn test_validation_error_response() -> Result<()> {
        let schema = json!({
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "minLength": 3
                }
            },
            "required": ["username"]
        });

        let config = ApiSchemaConfig {
            schema_file: None,
            request_schema: Some(schema),
            response_schema: None,
            validate_requests: true,
            validate_responses: false,
            strict_mode: false,
        };

        let validator = SchemaValidator::new(config)?;

        // Invalid request with too short username
        let invalid_body = json!({
            "username": "ab"
        });

        let req = Request::post("/api/login").body(()).unwrap();

        let result = validator
            .validate_request(
                &req,
                &serde_json::to_vec(&invalid_body)?,
                "/api/login",
                "req-005",
            )
            .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        let error_str = error.to_string();
        assert!(error_str.contains("Validation"));

        Ok(())
    }
}
