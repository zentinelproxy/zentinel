//! Shared test utilities for integration tests
//!
//! This module provides common fixtures, helpers, and utilities
//! used across multiple integration test files.

use zentinel_config::{
    Config, ListenerConfig, MatchCondition, RouteConfig, ServiceType, UpstreamConfig,
    UpstreamTarget,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::fs;

/// Default test port for listeners
pub const TEST_PORT: u16 = 18080;

/// Default admin port for testing
pub const TEST_ADMIN_PORT: u16 = 19090;

/// Create a minimal test configuration
pub fn minimal_config() -> Config {
    Config {
        listeners: vec![ListenerConfig {
            address: format!("127.0.0.1:{}", TEST_PORT).parse().unwrap(),
            tls: None,
            http2: false,
        }],
        admin: None,
        routes: vec![],
        upstreams: vec![],
        agents: vec![],
        global: Default::default(),
    }
}

/// Create a test upstream configuration
pub fn test_upstream(id: &str, targets: Vec<&str>) -> UpstreamConfig {
    UpstreamConfig {
        id: id.to_string(),
        targets: targets
            .into_iter()
            .map(|t| UpstreamTarget {
                address: t.to_string(),
                weight: 100,
            })
            .collect(),
        load_balancing: Default::default(),
        health_check: None,
        connection_pool: Default::default(),
        tls: None,
    }
}

/// Create a test route configuration
pub fn test_route(id: &str, path: &str, upstream: &str) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        priority: Default::default(),
        matches: vec![MatchCondition::Path {
            pattern: path.to_string(),
            match_type: Default::default(),
        }],
        upstream: Some(upstream.to_string()),
        service_type: ServiceType::Api,
        static_files: None,
        api_schema: None,
        error_pages: None,
        timeout_ms: None,
        retry: None,
        agents: vec![],
        policies: Default::default(),
    }
}

/// Test fixture for static file tests
pub struct StaticFilesFixture {
    pub temp_dir: TempDir,
    pub root: std::path::PathBuf,
}

impl StaticFilesFixture {
    /// Create a new static files fixture with common test files
    pub async fn new() -> anyhow::Result<Self> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path().to_path_buf();

        // Create common test files
        fs::write(root.join("index.html"), "<html><body>Test</body></html>").await?;
        fs::write(root.join("style.css"), "body { margin: 0; }").await?;
        fs::write(root.join("app.js"), "console.log('test');").await?;

        // Create subdirectory
        fs::create_dir_all(root.join("assets")).await?;
        fs::write(root.join("assets/image.txt"), "fake image data").await?;

        Ok(Self { temp_dir, root })
    }

    /// Add a custom file to the fixture
    pub async fn add_file(&self, path: &str, content: &[u8]) -> anyhow::Result<()> {
        let file_path = self.root.join(path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(file_path, content).await?;
        Ok(())
    }
}

/// Generate a unique request ID for testing
pub fn test_request_id() -> String {
    format!("test-{}", uuid::Uuid::new_v4())
}

/// Assert that a response has the expected content type
pub fn assert_content_type(headers: &http::HeaderMap, expected: &str) {
    let content_type = headers
        .get("Content-Type")
        .expect("missing Content-Type header")
        .to_str()
        .expect("invalid Content-Type header");
    assert!(
        content_type.contains(expected),
        "expected Content-Type to contain '{}', got '{}'",
        expected,
        content_type
    );
}

/// Assert that a response has a specific header
pub fn assert_has_header(headers: &http::HeaderMap, name: &str) {
    assert!(
        headers.contains_key(name),
        "expected header '{}' to be present",
        name
    );
}
