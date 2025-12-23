//! Integration example for service types and error handling
//!
//! This example demonstrates how to configure Sentinel with:
//! - Different service types (web, api, static)
//! - Custom error pages
//! - API schema validation
//! - Static file serving

use anyhow::Result;
use sentinel_config::{
    ApiSchemaConfig, Config, ErrorFormat, ErrorPage, ErrorPageConfig, ListenerConfig,
    RouteConfig, ServiceType, StaticFileConfig, UpstreamConfig,
};
use sentinel_proxy::{ErrorHandler, SchemaValidator, SentinelProxy, StaticFileServer};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sentinel=debug".parse()?),
        )
        .init();

    info!("Starting Sentinel with service type examples");

    // Create configuration
    let config = create_example_config()?;

    // Initialize components
    let components = initialize_components(&config).await?;

    // Start the proxy
    run_proxy(config, components).await
}

/// Create example configuration with different service types
fn create_example_config() -> Result<Config> {
    let mut config = Config::default();

    // Configure listeners
    config.listeners.push(ListenerConfig {
        id: "main".to_string(),
        address: "0.0.0.0:8080".to_string(),
        protocol: sentinel_config::ListenerProtocol::Http,
        tls: None,
        default_route: Some("web-app".to_string()),
        request_timeout_secs: 30,
        keepalive_timeout_secs: 60,
        max_concurrent_streams: 100,
    });

    // Configure routes with different service types
    config.routes = vec![
        // Web application route
        create_web_route()?,
        // API route with schema validation
        create_api_route()?,
        // Static file serving route
        create_static_route()?,
        // SPA route
        create_spa_route()?,
    ];

    // Configure upstreams
    config.upstreams = vec![
        create_upstream("web-backend", vec!["127.0.0.1:3000"])?,
        create_upstream("api-backend", vec!["127.0.0.1:3001"])?,
    ];

    Ok(config)
}

/// Create a web application route
fn create_web_route() -> Result<RouteConfig> {
    // HTML error pages for web routes
    let mut error_pages = HashMap::new();
    error_pages.insert(
        404,
        ErrorPage {
            format: ErrorFormat::Html,
            template: Some(PathBuf::from("/etc/sentinel/templates/404.html")),
            message: Some("Page not found".to_string()),
            headers: HashMap::new(),
        },
    );
    error_pages.insert(
        500,
        ErrorPage {
            format: ErrorFormat::Html,
            template: Some(PathBuf::from("/etc/sentinel/templates/500.html")),
            message: Some("Internal server error".to_string()),
            headers: HashMap::new(),
        },
    );

    let error_config = ErrorPageConfig {
        pages: error_pages,
        default_format: ErrorFormat::Html,
        include_stack_trace: false,
        template_dir: Some(PathBuf::from("/etc/sentinel/templates")),
    };

    Ok(RouteConfig {
        id: "web-app".to_string(),
        priority: 100,
        service_type: ServiceType::Web,
        matches: vec![
            sentinel_config::MatchCondition::Host("www.example.com".to_string()),
            sentinel_config::MatchCondition::PathPrefix("/app".to_string()),
        ],
        upstream: Some("web-backend".to_string()),
        policies: Default::default(),
        agents: vec![],
        waf_enabled: true,
        circuit_breaker: None,
        retry_policy: None,
        static_files: None,
        api_schema: None,
        error_pages: Some(error_config),
    })
}

/// Create an API route with schema validation
fn create_api_route() -> Result<RouteConfig> {
    // JSON error pages for API routes
    let mut error_pages = HashMap::new();

    let mut headers_400 = HashMap::new();
    headers_400.insert("X-Error-Code".to_string(), "INVALID_REQUEST".to_string());
    error_pages.insert(
        400,
        ErrorPage {
            format: ErrorFormat::Json,
            template: None,
            message: Some("Invalid request".to_string()),
            headers: headers_400,
        },
    );

    let mut headers_401 = HashMap::new();
    headers_401.insert("WWW-Authenticate".to_string(), "Bearer".to_string());
    error_pages.insert(
        401,
        ErrorPage {
            format: ErrorFormat::Json,
            template: None,
            message: Some("Authentication required".to_string()),
            headers: headers_401,
        },
    );

    let mut headers_429 = HashMap::new();
    headers_429.insert("X-RateLimit-Limit".to_string(), "100".to_string());
    headers_429.insert("X-RateLimit-Remaining".to_string(), "0".to_string());
    headers_429.insert("X-RateLimit-Reset".to_string(), "3600".to_string());
    error_pages.insert(
        429,
        ErrorPage {
            format: ErrorFormat::Json,
            template: None,
            message: Some("Rate limit exceeded".to_string()),
            headers: headers_429,
        },
    );

    let error_config = ErrorPageConfig {
        pages: error_pages,
        default_format: ErrorFormat::Json,
        include_stack_trace: false,
        template_dir: None,
    };

    // API schema validation
    let api_schema = ApiSchemaConfig {
        schema_file: Some(PathBuf::from("/etc/sentinel/schemas/api-v1.yaml")),
        request_schema: Some(json!({
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9]{32}$"
                }
            },
            "required": ["api_key"]
        })),
        response_schema: None,
        validate_requests: true,
        validate_responses: false, // Enable in development
        strict_mode: false,
    };

    Ok(RouteConfig {
        id: "api-v1".to_string(),
        priority: 90,
        service_type: ServiceType::Api,
        matches: vec![
            sentinel_config::MatchCondition::Host("api.example.com".to_string()),
            sentinel_config::MatchCondition::PathPrefix("/v1".to_string()),
        ],
        upstream: Some("api-backend".to_string()),
        policies: Default::default(),
        agents: vec![],
        waf_enabled: false, // Different WAF rules for API
        circuit_breaker: None,
        retry_policy: None,
        static_files: None,
        api_schema: Some(api_schema),
        error_pages: Some(error_config),
    })
}

/// Create a static file serving route
fn create_static_route() -> Result<RouteConfig> {
    let static_config = StaticFileConfig {
        root: PathBuf::from("/var/www/static"),
        index: "index.html".to_string(),
        directory_listing: false,
        cache_control: "public, max-age=86400".to_string(),
        compress: true,
        mime_types: {
            let mut types = HashMap::new();
            types.insert("wasm".to_string(), "application/wasm".to_string());
            types.insert("mjs".to_string(), "application/javascript".to_string());
            types
        },
        fallback: None,
    };

    Ok(RouteConfig {
        id: "static-assets".to_string(),
        priority: 80,
        service_type: ServiceType::Static,
        matches: vec![sentinel_config::MatchCondition::PathPrefix("/static".to_string())],
        upstream: None, // No upstream for static files
        policies: Default::default(),
        agents: vec![],
        waf_enabled: false,
        circuit_breaker: None,
        retry_policy: None,
        static_files: Some(static_config),
        api_schema: None,
        error_pages: None,
    })
}

/// Create a SPA (Single Page Application) route
fn create_spa_route() -> Result<RouteConfig> {
    let static_config = StaticFileConfig {
        root: PathBuf::from("/var/www/spa"),
        index: "index.html".to_string(),
        directory_listing: false,
        cache_control: "public, max-age=3600".to_string(),
        compress: true,
        mime_types: HashMap::new(),
        fallback: Some("index.html".to_string()), // Important for SPA routing
    };

    Ok(RouteConfig {
        id: "spa".to_string(),
        priority: 70,
        service_type: ServiceType::Static,
        matches: vec![
            sentinel_config::MatchCondition::Host("app.example.com".to_string()),
            sentinel_config::MatchCondition::PathPrefix("/".to_string()),
        ],
        upstream: None,
        policies: Default::default(),
        agents: vec![],
        waf_enabled: false,
        circuit_breaker: None,
        retry_policy: None,
        static_files: Some(static_config),
        api_schema: None,
        error_pages: None,
    })
}

/// Create an upstream configuration
fn create_upstream(id: &str, addresses: Vec<&str>) -> Result<UpstreamConfig> {
    Ok(UpstreamConfig {
        id: id.to_string(),
        targets: addresses
            .into_iter()
            .map(|addr| sentinel_config::UpstreamTarget {
                address: addr.to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            })
            .collect(),
        load_balancing: sentinel_common::types::LoadBalancingAlgorithm::RoundRobin,
        health_check: None,
        connection_pool: Default::default(),
        timeouts: Default::default(),
        tls: None,
    })
}

/// Initialize service components
async fn initialize_components(config: &Config) -> Result<ServiceComponents> {
    let mut error_handlers = HashMap::new();
    let mut validators = HashMap::new();
    let mut static_servers = HashMap::new();

    for route in &config.routes {
        info!("Initializing route: {} with service type: {:?}", route.id, route.service_type);

        // Initialize error handler for each route
        if let Some(ref error_config) = route.error_pages {
            let handler = ErrorHandler::new(route.service_type.clone(), Some(error_config.clone()));
            error_handlers.insert(route.id.clone(), Arc::new(handler));
            info!("Initialized error handler for route: {}", route.id);
        }

        // Initialize schema validator for API routes
        if route.service_type == ServiceType::Api {
            if let Some(ref api_schema) = route.api_schema {
                match SchemaValidator::new(api_schema.clone()) {
                    Ok(validator) => {
                        validators.insert(route.id.clone(), Arc::new(validator));
                        info!("Initialized schema validator for route: {}", route.id);
                    }
                    Err(e) => {
                        warn!("Failed to initialize schema validator for route {}: {}", route.id, e);
                    }
                }
            }
        }

        // Initialize static file server for static routes
        if route.service_type == ServiceType::Static {
            if let Some(ref static_config) = route.static_files {
                let server = StaticFileServer::new(static_config.clone());
                static_servers.insert(route.id.clone(), Arc::new(server));
                info!("Initialized static file server for route: {}", route.id);
            }
        }
    }

    Ok(ServiceComponents {
        error_handlers,
        validators,
        static_servers,
    })
}

/// Service components container
struct ServiceComponents {
    error_handlers: HashMap<String, Arc<ErrorHandler>>,
    validators: HashMap<String, Arc<SchemaValidator>>,
    static_servers: HashMap<String, Arc<StaticFileServer>>,
}

/// Run the proxy with configured components
async fn run_proxy(config: Config, components: ServiceComponents) -> Result<()> {
    info!("Starting Sentinel proxy with service type support");

    // In a real implementation, this would:
    // 1. Initialize the Pingora server
    // 2. Register the route handlers with appropriate service types
    // 3. Apply error handlers, validators, and static servers to routes
    // 4. Start the server

    // Example of how components would be used:
    for (route_id, handler) in &components.error_handlers {
        info!("Route {} configured with custom error handler", route_id);
    }

    for (route_id, validator) in &components.validators {
        info!("Route {} configured with schema validation", route_id);
    }

    for (route_id, server) in &components.static_servers {
        info!("Route {} configured for static file serving", route_id);
    }

    // Simulate running
    info!("Proxy started successfully");
    info!("Listening on configured addresses...");

    // In production, this would block and run the actual server
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    info!("Example completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = create_example_config().unwrap();
        assert_eq!(config.routes.len(), 4);

        // Check service types
        assert_eq!(config.routes[0].service_type, ServiceType::Web);
        assert_eq!(config.routes[1].service_type, ServiceType::Api);
        assert_eq!(config.routes[2].service_type, ServiceType::Static);
        assert_eq!(config.routes[3].service_type, ServiceType::Static);
    }

    #[test]
    fn test_error_pages_configuration() {
        let route = create_web_route().unwrap();
        let error_config = route.error_pages.unwrap();

        assert_eq!(error_config.default_format, ErrorFormat::Html);
        assert!(error_config.pages.contains_key(&404));
        assert!(error_config.pages.contains_key(&500));
    }

    #[test]
    fn test_api_validation_configuration() {
        let route = create_api_route().unwrap();
        let api_schema = route.api_schema.unwrap();

        assert!(api_schema.validate_requests);
        assert!(!api_schema.validate_responses);
        assert!(api_schema.request_schema.is_some());
    }

    #[test]
    fn test_static_file_configuration() {
        let route = create_static_route().unwrap();
        let static_config = route.static_files.unwrap();

        assert!(!static_config.directory_listing);
        assert!(static_config.compress);
        assert_eq!(static_config.index, "index.html");
    }

    #[test]
    fn test_spa_configuration() {
        let route = create_spa_route().unwrap();
        let static_config = route.static_files.unwrap();

        // SPA should have fallback configured
        assert_eq!(static_config.fallback, Some("index.html".to_string()));
    }
}
