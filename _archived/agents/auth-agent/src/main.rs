//! Sentinel Authentication/Authorization Agent
//!
//! This agent provides flexible authentication and authorization for the Sentinel proxy,
//! supporting JWT/OIDC, API keys, basic auth, and policy-based access control.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, jwk, Algorithm, DecodingKey, TokenData, Validation,
};
use moka::future::Cache;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sentinel_agent_protocol::{
    AgentRequest, AgentResponse, Decision, Header as ProtoHeader, Mutation,
};
use sentinel_common::config::ByteSize;

mod cache;
mod config;
mod jwt;
mod oidc;
mod policy;
mod session;
mod validation;

use crate::cache::AuthCache;
use crate::config::{AuthAgentConfig, AuthMethod, PolicyEngine};
use crate::jwt::{JwtClaims, JwtValidator};
use crate::oidc::OidcValidator;
use crate::policy::{PolicyContext, PolicyEvaluator};
use crate::session::SessionManager;
use crate::validation::{ApiKeyValidator, BasicAuthValidator};

/// Main authentication agent service
pub struct AuthAgent {
    config: Arc<AuthAgentConfig>,
    jwt_validator: Arc<JwtValidator>,
    oidc_validator: Arc<OidcValidator>,
    api_key_validator: Arc<ApiKeyValidator>,
    basic_auth_validator: Arc<BasicAuthValidator>,
    policy_evaluator: Arc<PolicyEvaluator>,
    session_manager: Arc<SessionManager>,
    cache: Arc<AuthCache>,
    metrics: Arc<Metrics>,
}

impl AuthAgent {
    /// Create a new auth agent
    pub async fn new(config: AuthAgentConfig) -> Result<Self> {
        info!("Initializing auth agent with config: {:?}", config);

        // Initialize validators based on configuration
        let jwt_validator = Arc::new(JwtValidator::new(&config.jwt).await?);
        let oidc_validator = Arc::new(OidcValidator::new(&config.oidc).await?);
        let api_key_validator = Arc::new(ApiKeyValidator::new(&config.api_keys));
        let basic_auth_validator = Arc::new(BasicAuthValidator::new(&config.basic_auth));

        // Initialize policy evaluator
        let policy_evaluator = Arc::new(PolicyEvaluator::new(&config.policy).await?);

        // Initialize session manager
        let session_manager = Arc::new(SessionManager::new(
            config.session.ttl,
            config.session.max_sessions,
        ));

        // Initialize cache
        let cache = Arc::new(AuthCache::new(
            config.cache.max_entries,
            config.cache.ttl,
        ));

        let metrics = Arc::new(Metrics::default());

        Ok(Self {
            config: Arc::new(config),
            jwt_validator,
            oidc_validator,
            api_key_validator,
            basic_auth_validator,
            policy_evaluator,
            session_manager,
            cache,
            metrics,
        })
    }

    /// Process an authentication request
    pub async fn authenticate(&self, request: &AgentRequest) -> Result<AuthResponse> {
        let start = Instant::now();
        self.metrics.requests_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check cache first
        let cache_key = self.generate_cache_key(request);
        if let Some(cached) = self.cache.get(&cache_key).await {
            self.metrics.cache_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Cache hit for request");
            return Ok(cached);
        }

        // Extract authentication credentials
        let auth_result = self.extract_and_validate_credentials(request).await;

        let response = match auth_result {
            Ok(identity) => {
                // Evaluate authorization policy
                let policy_result = self.evaluate_policy(&identity, request).await;

                match policy_result {
                    Ok(authorized) => {
                        if authorized {
                            self.metrics.auth_success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            AuthResponse {
                                decision: Decision::Allow,
                                identity: Some(identity.clone()),
                                headers: self.generate_headers(&identity),
                                metadata: HashMap::new(),
                            }
                        } else {
                            self.metrics.auth_denied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            AuthResponse {
                                decision: Decision::Deny,
                                identity: Some(identity),
                                headers: vec![],
                                metadata: HashMap::from([
                                    ("reason".to_string(), "authorization_failed".to_string())
                                ]),
                            }
                        }
                    }
                    Err(e) => {
                        error!("Policy evaluation error: {}", e);
                        self.metrics.auth_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        AuthResponse {
                            decision: Decision::Deny,
                            identity: None,
                            headers: vec![],
                            metadata: HashMap::from([
                                ("error".to_string(), e.to_string())
                            ]),
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Authentication failed: {}", e);
                self.metrics.auth_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Check if we should issue a challenge
                if self.config.challenge_enabled {
                    AuthResponse {
                        decision: Decision::Challenge,
                        identity: None,
                        headers: self.generate_challenge_headers(),
                        metadata: HashMap::from([
                            ("error".to_string(), e.to_string())
                        ]),
                    }
                } else {
                    AuthResponse {
                        decision: Decision::Deny,
                        identity: None,
                        headers: vec![],
                        metadata: HashMap::from([
                            ("error".to_string(), e.to_string())
                        ]),
                    }
                }
            }
        };

        // Cache the response
        if response.decision == Decision::Allow {
            self.cache.insert(cache_key, response.clone()).await;
        }

        // Record metrics
        let duration = start.elapsed();
        self.metrics.auth_duration_ms.fetch_add(
            duration.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        Ok(response)
    }

    /// Extract and validate credentials from the request
    async fn extract_and_validate_credentials(&self, request: &AgentRequest) -> Result<Identity> {
        // Try each authentication method in order of preference

        // 1. Check for JWT bearer token
        if let Some(auth_header) = request.headers.get("authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                if let Ok(identity) = self.validate_jwt(token).await {
                    return Ok(identity);
                }
            }

            // 2. Check for Basic auth
            if auth_header.starts_with("Basic ") {
                let credentials = &auth_header[6..];
                if let Ok(identity) = self.validate_basic_auth(credentials).await {
                    return Ok(identity);
                }
            }
        }

        // 3. Check for API key
        if let Some(api_key) = request.headers.get(&self.config.api_keys.header_name) {
            if let Ok(identity) = self.validate_api_key(api_key).await {
                return Ok(identity);
            }
        }

        // 4. Check for session cookie
        if let Some(cookie_header) = request.headers.get("cookie") {
            if let Ok(identity) = self.validate_session(cookie_header).await {
                return Ok(identity);
            }
        }

        Err(anyhow!("No valid authentication credentials found"))
    }

    /// Validate JWT token
    async fn validate_jwt(&self, token: &str) -> Result<Identity> {
        let claims = self.jwt_validator.validate(token).await?;

        Ok(Identity {
            id: claims.sub.clone(),
            auth_method: AuthMethod::Jwt,
            claims: claims.into(),
            attributes: HashMap::new(),
        })
    }

    /// Validate Basic auth credentials
    async fn validate_basic_auth(&self, credentials: &str) -> Result<Identity> {
        let decoded = BASE64.decode(credentials)?;
        let auth_str = String::from_utf8(decoded)?;

        let parts: Vec<&str> = auth_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid Basic auth format"));
        }

        let (username, password) = (parts[0], parts[1]);
        let user = self.basic_auth_validator.validate(username, password).await?;

        Ok(Identity {
            id: user.id.clone(),
            auth_method: AuthMethod::Basic,
            claims: HashMap::from([
                ("username".to_string(), serde_json::Value::String(username.to_string())),
            ]),
            attributes: user.attributes,
        })
    }

    /// Validate API key
    async fn validate_api_key(&self, api_key: &str) -> Result<Identity> {
        let key_info = self.api_key_validator.validate(api_key).await?;

        Ok(Identity {
            id: key_info.id.clone(),
            auth_method: AuthMethod::ApiKey,
            claims: HashMap::from([
                ("api_key_id".to_string(), serde_json::Value::String(key_info.id.clone())),
                ("api_key_name".to_string(), serde_json::Value::String(key_info.name.clone())),
            ]),
            attributes: key_info.attributes,
        })
    }

    /// Validate session cookie
    async fn validate_session(&self, cookie_header: &str) -> Result<Identity> {
        let session_id = self.extract_session_id(cookie_header)?;
        let session = self.session_manager.get_session(&session_id).await?;

        Ok(Identity {
            id: session.user_id.clone(),
            auth_method: AuthMethod::Session,
            claims: session.claims,
            attributes: session.attributes,
        })
    }

    /// Evaluate authorization policy
    async fn evaluate_policy(&self, identity: &Identity, request: &AgentRequest) -> Result<bool> {
        let context = PolicyContext {
            identity: identity.clone(),
            path: request.path.clone(),
            method: request.method.clone(),
            headers: request.headers.clone(),
            source_ip: request.source_ip.clone(),
        };

        self.policy_evaluator.evaluate(&context).await
    }

    /// Generate headers to add to the request
    fn generate_headers(&self, identity: &Identity) -> Vec<ProtoHeader> {
        let mut headers = Vec::new();

        // Add user ID header
        headers.push(ProtoHeader {
            name: self.config.headers.user_id_header.clone(),
            value: identity.id.clone(),
        });

        // Add configured claim headers
        for (claim, header) in &self.config.headers.claim_headers {
            if let Some(value) = identity.claims.get(claim) {
                headers.push(ProtoHeader {
                    name: header.clone(),
                    value: value.to_string(),
                });
            }
        }

        // Add roles header if present
        if let Some(roles) = identity.claims.get("roles") {
            if let Some(roles_arr) = roles.as_array() {
                let roles_str = roles_arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                headers.push(ProtoHeader {
                    name: self.config.headers.roles_header.clone(),
                    value: roles_str,
                });
            }
        }

        headers
    }

    /// Generate challenge headers for 401 response
    fn generate_challenge_headers(&self) -> Vec<ProtoHeader> {
        vec![
            ProtoHeader {
                name: "WWW-Authenticate".to_string(),
                value: format!("Bearer realm=\"{}\"", self.config.realm),
            },
        ]
    }

    /// Generate cache key for request
    fn generate_cache_key(&self, request: &AgentRequest) -> String {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Include auth-relevant headers in cache key
        if let Some(auth) = request.headers.get("authorization") {
            std::hash::Hash::hash(&auth, &mut hasher);
        }
        if let Some(api_key) = request.headers.get(&self.config.api_keys.header_name) {
            std::hash::Hash::hash(&api_key, &mut hasher);
        }
        if let Some(cookie) = request.headers.get("cookie") {
            std::hash::Hash::hash(&cookie, &mut hasher);
        }

        // Include path and method for policy evaluation
        std::hash::Hash::hash(&request.path, &mut hasher);
        std::hash::Hash::hash(&request.method, &mut hasher);

        format!("{:x}", std::hash::Hasher::finish(&hasher))
    }

    /// Extract session ID from cookie header
    fn extract_session_id(&self, cookie_header: &str) -> Result<String> {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if cookie.starts_with(&format!("{}=", self.config.session.cookie_name)) {
                let value = &cookie[self.config.session.cookie_name.len() + 1..];
                return Ok(value.to_string());
            }
        }
        Err(anyhow!("Session cookie not found"))
    }
}

/// Identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub auth_method: AuthMethod,
    pub claims: HashMap<String, serde_json::Value>,
    pub attributes: HashMap<String, String>,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub decision: Decision,
    pub identity: Option<Identity>,
    pub headers: Vec<ProtoHeader>,
    pub metadata: HashMap<String, String>,
}

/// Metrics for the auth agent
#[derive(Debug, Default)]
struct Metrics {
    requests_total: std::sync::atomic::AtomicU64,
    auth_success: std::sync::atomic::AtomicU64,
    auth_failed: std::sync::atomic::AtomicU64,
    auth_denied: std::sync::atomic::AtomicU64,
    auth_errors: std::sync::atomic::AtomicU64,
    cache_hits: std::sync::atomic::AtomicU64,
    auth_duration_ms: std::sync::atomic::AtomicU64,
}

/// Health check handler
async fn health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Process authentication request
async fn process_auth(
    State(agent): State<Arc<AuthAgent>>,
    Json(request): Json<AgentRequest>,
) -> impl IntoResponse {
    match agent.authenticate(&request).await {
        Ok(response) => {
            let agent_response = AgentResponse {
                decision: response.decision,
                mutations: if response.decision == Decision::Allow {
                    response
                        .headers
                        .into_iter()
                        .map(|h| Mutation::AddHeader(h))
                        .collect()
                } else {
                    vec![]
                },
                metadata: response.metadata,
            };
            (StatusCode::OK, Json(agent_response))
        }
        Err(e) => {
            error!("Authentication error: {}", e);
            let response = AgentResponse {
                decision: Decision::Deny,
                mutations: vec![],
                metadata: HashMap::from([("error".to_string(), e.to_string())]),
            };
            (StatusCode::OK, Json(response))
        }
    }
}

/// Metrics endpoint
async fn metrics() -> impl IntoResponse {
    // Return Prometheus-formatted metrics
    let metrics = prometheus::TextEncoder::new()
        .encode_to_string(&prometheus::gather())
        .unwrap_or_default();
    (StatusCode::OK, metrics)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("info,auth_agent=debug")
        .json()
        .init();

    info!("Starting Sentinel Auth Agent");

    // Load configuration
    let config = AuthAgentConfig::from_file("config/auth-agent.kdl")
        .await
        .context("Failed to load configuration")?;

    // Create auth agent
    let agent = Arc::new(AuthAgent::new(config.clone()).await?);

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/auth", post(process_auth))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(agent);

    // Start server
    let addr = config.server.listen_address.parse::<SocketAddr>()?;
    info!("Auth agent listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
