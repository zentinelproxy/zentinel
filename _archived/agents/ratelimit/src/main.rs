//! Rate Limit Agent - Token bucket rate limiting for Sentinel
//!
//! This agent provides distributed rate limiting using token bucket algorithm
//! with support for multiple rate limit keys and configurable limits.

#![allow(dead_code)]

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use nonzero_ext::nonzero;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, Decision, HeaderOp, RequestHeadersEvent,
};

/// Rate limit agent command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Unix socket path to listen on
    #[arg(
        short,
        long,
        env = "RATELIMIT_AGENT_SOCKET",
        default_value = "/tmp/ratelimit-agent.sock"
    )]
    socket: PathBuf,

    /// Configuration file path
    #[arg(short, long, env = "RATELIMIT_AGENT_CONFIG")]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, env = "RATELIMIT_AGENT_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Default requests per second limit
    #[arg(long, env = "RATELIMIT_AGENT_DEFAULT_RPS", default_value = "100")]
    default_rps: u32,

    /// Default burst size
    #[arg(long, env = "RATELIMIT_AGENT_DEFAULT_BURST", default_value = "200")]
    default_burst: u32,

    /// Enable dry-run mode (log but don't block)
    #[arg(long, env = "RATELIMIT_AGENT_DRY_RUN")]
    dry_run: bool,

    /// Cleanup interval for expired rate limiters (seconds)
    #[arg(long, env = "RATELIMIT_AGENT_CLEANUP_INTERVAL", default_value = "60")]
    cleanup_interval: u64,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimitConfig {
    /// Rate limit rules
    rules: Vec<RateLimitRule>,
    /// Default rule if no specific rule matches
    default: RateLimitRule,
    /// Enable dry-run mode
    dry_run: bool,
}

/// Individual rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimitRule {
    /// Rule name/ID
    name: String,
    /// Rate limit key type
    key: RateLimitKey,
    /// Requests per second
    requests_per_second: u32,
    /// Burst size
    burst: u32,
    /// Match conditions
    #[serde(default)]
    conditions: Vec<MatchCondition>,
    /// Custom response message when rate limited
    #[serde(default)]
    message: Option<String>,
    /// Custom status code (default 429)
    #[serde(default)]
    status_code: Option<u16>,
}

/// Rate limit key types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RateLimitKey {
    /// Rate limit by client IP
    ClientIp,
    /// Rate limit by header value
    Header(String),
    /// Rate limit by path
    Path,
    /// Rate limit by method
    Method,
    /// Global rate limit (all requests)
    Global,
    /// Composite key
    Composite(Vec<RateLimitKey>),
}

/// Match conditions for applying rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatchCondition {
    /// Match path prefix
    PathPrefix(String),
    /// Match exact path
    Path(String),
    /// Match header presence
    Header { name: String, value: Option<String> },
    /// Match method
    Method(Vec<String>),
}

/// Rate limiter entry
struct RateLimiterEntry {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    last_used: Instant,
    rule_name: String,
}

/// Rate limit agent implementation
#[derive(Clone)]
struct RateLimitAgent {
    /// Configuration
    config: Arc<RwLock<RateLimitConfig>>,
    /// Rate limiters by key
    limiters: Arc<DashMap<String, RateLimiterEntry>>,
    /// Request counter
    request_count: Arc<std::sync::atomic::AtomicU64>,
    /// Rate limited counter
    limited_count: Arc<std::sync::atomic::AtomicU64>,
    /// Metrics
    metrics: Arc<RateLimitMetrics>,
}

/// Rate limit metrics
struct RateLimitMetrics {
    requests_total: std::sync::atomic::AtomicU64,
    requests_allowed: std::sync::atomic::AtomicU64,
    requests_limited: std::sync::atomic::AtomicU64,
    active_limiters: std::sync::atomic::AtomicUsize,
}

impl RateLimitAgent {
    /// Create new rate limit agent
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            limiters: Arc::new(DashMap::new()),
            request_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            limited_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics: Arc::new(RateLimitMetrics {
                requests_total: std::sync::atomic::AtomicU64::new(0),
                requests_allowed: std::sync::atomic::AtomicU64::new(0),
                requests_limited: std::sync::atomic::AtomicU64::new(0),
                active_limiters: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Find matching rule for request
    fn find_matching_rule(&self, event: &RequestHeadersEvent) -> RateLimitRule {
        let config = self.config.read();

        for rule in &config.rules {
            if self.matches_conditions(&rule.conditions, event) {
                return rule.clone();
            }
        }

        config.default.clone()
    }

    /// Check if conditions match
    fn matches_conditions(
        &self,
        conditions: &[MatchCondition],
        event: &RequestHeadersEvent,
    ) -> bool {
        if conditions.is_empty() {
            return true;
        }

        conditions.iter().all(|condition| match condition {
            MatchCondition::PathPrefix(prefix) => event.uri.starts_with(prefix),
            MatchCondition::Path(path) => event.uri == *path,
            MatchCondition::Header { name, value } => {
                if let Some(header_values) = event.headers.get(name) {
                    if let Some(expected) = value {
                        header_values.iter().any(|v| v == expected)
                    } else {
                        true // Just check presence
                    }
                } else {
                    false
                }
            }
            MatchCondition::Method(methods) => methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&event.method)),
        })
    }

    /// Generate rate limit key
    fn generate_key(&self, key_type: &RateLimitKey, event: &RequestHeadersEvent) -> String {
        match key_type {
            RateLimitKey::ClientIp => event.metadata.client_ip.clone(),
            RateLimitKey::Header(name) => event
                .headers
                .get(name)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| format!("unknown_{}", name)),
            RateLimitKey::Path => event.uri.clone(),
            RateLimitKey::Method => event.method.clone(),
            RateLimitKey::Global => "global".to_string(),
            RateLimitKey::Composite(keys) => keys
                .iter()
                .map(|k| self.generate_key(k, event))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }

    /// Get or create rate limiter
    fn get_or_create_limiter(
        &self,
        key: String,
        rule: &RateLimitRule,
    ) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        if let Some(entry) = self.limiters.get(&key) {
            entry.limiter.clone()
        } else {
            // Create new limiter
            let quota = Quota::per_second(
                NonZeroU32::new(rule.requests_per_second).unwrap_or(nonzero!(100u32)),
            );

            let limiter = Arc::new(RateLimiter::direct_with_clock(
                quota,
                &DefaultClock::default(),
            ));

            let entry = RateLimiterEntry {
                limiter: limiter.clone(),
                last_used: Instant::now(),
                rule_name: rule.name.clone(),
            };

            self.limiters.insert(key, entry);
            self.metrics
                .active_limiters
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            limiter
        }
    }

    /// Clean up expired limiters
    async fn cleanup_expired_limiters(&self, max_age: Duration) {
        let now = Instant::now();
        let mut expired = Vec::new();

        // Find expired entries
        for entry in self.limiters.iter() {
            if now.duration_since(entry.last_used) > max_age {
                expired.push(entry.key().clone());
            }
        }

        // Remove expired entries
        let expired_count = expired.len();
        for key in expired {
            self.limiters.remove(&key);
            self.metrics
                .active_limiters
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        debug!("Cleaned up {} expired rate limiters", expired_count);
    }
}

#[async_trait]
impl AgentHandler for RateLimitAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.request_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.metrics
            .requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        debug!(
            correlation_id = %event.metadata.correlation_id,
            method = %event.method,
            uri = %event.uri,
            client_ip = %event.metadata.client_ip,
            "Processing rate limit check"
        );

        // Find matching rule
        let rule = self.find_matching_rule(&event);

        // Generate rate limit key
        let key = self.generate_key(&rule.key, &event);

        debug!(
            rule = %rule.name,
            key = %key,
            rps = rule.requests_per_second,
            burst = rule.burst,
            "Applying rate limit rule"
        );

        // Get or create limiter
        let limiter = self.get_or_create_limiter(key.clone(), &rule);

        // Check rate limit
        let limited = match limiter.check() {
            Ok(_) => {
                self.metrics
                    .requests_allowed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
            Err(_) => {
                self.limited_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics
                    .requests_limited
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                true
            }
        };

        // Create response
        let mut response = if limited && !self.config.read().dry_run {
            let status = rule.status_code.unwrap_or(429);
            let message = rule.message.clone().unwrap_or_else(|| {
                format!(
                    "Rate limit exceeded: {} requests per second allowed",
                    rule.requests_per_second
                )
            });

            warn!(
                correlation_id = %event.metadata.correlation_id,
                rule = %rule.name,
                key = %key,
                "Rate limit exceeded, blocking request"
            );

            let mut headers = HashMap::new();
            headers.insert(
                "X-RateLimit-Limit".to_string(),
                rule.requests_per_second.to_string(),
            );
            headers.insert("X-RateLimit-Remaining".to_string(), "0".to_string());
            headers.insert(
                "X-RateLimit-Reset".to_string(),
                (chrono::Utc::now() + chrono::Duration::seconds(1))
                    .timestamp()
                    .to_string(),
            );
            headers.insert("Retry-After".to_string(), "1".to_string());

            AgentResponse {
                version: sentinel_agent_protocol::PROTOCOL_VERSION,
                decision: Decision::Block {
                    status,
                    body: Some(message),
                    headers: Some(headers),
                },
                request_headers: vec![],
                response_headers: vec![],
                routing_metadata: HashMap::new(),
                audit: AuditMetadata::default(),
            }
        } else {
            if limited {
                info!(
                    correlation_id = %event.metadata.correlation_id,
                    rule = %rule.name,
                    key = %key,
                    "Rate limit exceeded (dry-run mode)"
                );
            }

            AgentResponse::default_allow()
        };

        // Add rate limit headers
        response = response
            .add_request_header(HeaderOp::Set {
                name: "X-RateLimit-Rule".to_string(),
                value: rule.name.clone(),
            })
            .add_request_header(HeaderOp::Set {
                name: "X-RateLimit-Key".to_string(),
                value: key.clone(),
            });

        // Add audit metadata
        let mut audit = AuditMetadata::default();
        audit.tags = vec!["ratelimit".to_string()];
        if limited {
            audit.tags.push("limited".to_string());
        }
        audit
            .custom
            .insert("rule".to_string(), serde_json::Value::String(rule.name));
        audit
            .custom
            .insert("key".to_string(), serde_json::Value::String(key));
        audit
            .custom
            .insert("limited".to_string(), serde_json::Value::Bool(limited));
        audit.custom.insert(
            "rps".to_string(),
            serde_json::Value::Number(rule.requests_per_second.into()),
        );

        response.with_audit(audit)
    }
}

/// Default configuration
impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rules: vec![],
            default: RateLimitRule {
                name: "default".to_string(),
                key: RateLimitKey::ClientIp,
                requests_per_second: 100,
                burst: 200,
                conditions: vec![],
                message: None,
                status_code: None,
            },
            dry_run: false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = ?args.socket,
        "Starting rate limit agent"
    );

    // Load configuration
    let config = if let Some(config_path) = args.config {
        info!("Loading configuration from {:?}", config_path);
        let config_str = tokio::fs::read_to_string(&config_path)
            .await
            .context("Failed to read configuration file")?;
        serde_yaml::from_str(&config_str).context("Failed to parse configuration")?
    } else {
        // Use default config with command-line overrides
        RateLimitConfig {
            default: RateLimitRule {
                name: "default".to_string(),
                key: RateLimitKey::ClientIp,
                requests_per_second: args.default_rps,
                burst: args.default_burst,
                conditions: vec![],
                message: None,
                status_code: None,
            },
            dry_run: args.dry_run,
            ..Default::default()
        }
    };

    info!(
        rules = config.rules.len(),
        default_rps = config.default.requests_per_second,
        dry_run = config.dry_run,
        "Rate limit configuration loaded"
    );

    // Create rate limit agent
    let agent = RateLimitAgent::new(config);

    // Create a clone for the cleanup task
    let cleanup_agent = agent.clone();
    let cleanup_interval = Duration::from_secs(args.cleanup_interval);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            cleanup_agent
                .cleanup_expired_limiters(Duration::from_secs(300))
                .await;
        }
    });

    // Create and run server
    let server = AgentServer::new("ratelimit-agent", args.socket, Box::new(agent));

    info!("Rate limit agent ready and listening");

    // Run server (blocks forever)
    server
        .run()
        .await
        .context("Failed to run rate limit agent server")?;

    Ok(())
}
