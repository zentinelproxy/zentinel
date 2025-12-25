use agent_protocol::{
    AgentClient, AgentError, AgentResponse, Decision, EventType, RequestEvent, ResponseEvent,
    TransportConfig,
};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use prometheus::{
    register_counter_vec, register_histogram_vec, register_int_gauge, CounterVec, HistogramVec,
    IntGauge,
};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod config;
mod modsecurity;

use config::{Config, ExclusionCondition};
use modsecurity::{ModSecurity, RulesSet, Transaction};

/// WAF agent metrics
struct Metrics {
    /// Total requests processed
    requests_total: CounterVec,
    /// Requests blocked
    requests_blocked: CounterVec,
    /// Requests allowed
    requests_allowed: CounterVec,
    /// Processing latency
    processing_duration_seconds: HistogramVec,
    /// Active transactions
    active_transactions: IntGauge,
    /// Rule hits by rule ID
    rule_hits: CounterVec,
    /// Audit logs written
    audit_logs_total: CounterVec,
}

impl Metrics {
    fn new() -> Result<Self> {
        Ok(Metrics {
            requests_total: register_counter_vec!(
                "waf_requests_total",
                "Total requests processed by WAF",
                &["route", "method"]
            )?,
            requests_blocked: register_counter_vec!(
                "waf_requests_blocked_total",
                "Requests blocked by WAF",
                &["route", "method", "rule_id"]
            )?,
            requests_allowed: register_counter_vec!(
                "waf_requests_allowed_total",
                "Requests allowed by WAF",
                &["route", "method"]
            )?,
            processing_duration_seconds: register_histogram_vec!(
                "waf_processing_duration_seconds",
                "WAF processing latency",
                &["phase"],
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )?,
            active_transactions: register_int_gauge!(
                "waf_active_transactions",
                "Number of active WAF transactions"
            )?,
            rule_hits: register_counter_vec!(
                "waf_rule_hits_total",
                "WAF rule hits by rule ID",
                &["rule_id", "severity"]
            )?,
            audit_logs_total: register_counter_vec!(
                "waf_audit_logs_total",
                "Total audit logs written",
                &["type"]
            )?,
        })
    }
}

/// WAF agent state
struct WafAgent {
    /// Configuration
    config: Arc<ArcSwap<Config>>,
    /// ModSecurity instance
    modsec: Arc<ModSecurity>,
    /// Rules set
    rules: Arc<RwLock<RulesSet>>,
    /// Metrics
    metrics: Arc<Metrics>,
    /// Transaction pool
    transaction_pool: Arc<Semaphore>,
    /// Audit logger
    audit_logger: Arc<AuditLogger>,
}

impl WafAgent {
    /// Create a new WAF agent
    async fn new(config: Config) -> Result<Self> {
        // Initialize ModSecurity
        info!("Initializing ModSecurity {}", ModSecurity::version());
        let modsec = Arc::new(ModSecurity::new()?);

        // Create rules set
        let rules = RulesSet::new()?;

        // Load rules
        Self::load_rules(&config, &rules).await?;

        // Initialize metrics
        let metrics = Arc::new(Metrics::new()?);

        // Create transaction pool
        let transaction_pool = Arc::new(Semaphore::new(
            config.performance.max_concurrent_transactions,
        ));

        // Initialize audit logger
        let audit_logger = Arc::new(AuditLogger::new(&config.audit)?);

        Ok(WafAgent {
            config: Arc::new(ArcSwap::from_pointee(config)),
            modsec,
            rules: Arc::new(RwLock::new(rules)),
            metrics,
            transaction_pool,
            audit_logger,
        })
    }

    /// Load rules from configuration
    async fn load_rules(config: &Config, rules: &RulesSet) -> Result<()> {
        // Load CRS if enabled
        if config.rules.load_crs {
            let crs_path = config
                .find_crs_path()
                .context("Could not find CRS installation")?;

            info!("Loading CRS from {:?}", crs_path);

            // Load CRS setup
            let setup_file = crs_path.join("crs-setup.conf.example");
            if setup_file.exists() {
                rules.load_file(&setup_file.to_string_lossy())?;
            }

            // Load CRS rules
            let rules_dir = crs_path.join("rules");
            if rules_dir.exists() {
                let mut entries: Vec<_> = std::fs::read_dir(&rules_dir)?
                    .filter_map(Result::ok)
                    .filter(|e| {
                        e.path()
                            .extension()
                            .map(|ext| ext == "conf")
                            .unwrap_or(false)
                    })
                    .collect();

                entries.sort_by_key(|e| e.path());

                for entry in entries {
                    let path = entry.path();
                    debug!("Loading CRS rules from {:?}", path);
                    rules.load_file(&path.to_string_lossy())?;
                }
            }
        }

        // Load custom rules files
        for rule_file in &config.rules.custom_rules_files {
            info!("Loading custom rules from {:?}", rule_file);
            rules.load_file(&rule_file.to_string_lossy())?;
        }

        // Load inline custom rules
        for rule in &config.rules.custom_rules {
            debug!("Loading inline custom rule");
            rules.load_rules(rule)?;
        }

        // Apply configuration overrides
        let config_rules = format!(
            r#"
# Sentinel WAF Configuration
SecRuleEngine {}
SecRequestBodyAccess {}
SecResponseBodyAccess {}
SecDebugLogLevel {}
SecAuditEngine {}

# Paranoia level
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level={}"

# Anomaly scoring threshold
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.anomaly_score_threshold={}"

# Body limits
SecRequestBodyLimit {}
SecResponseBodyLimit {}

# PCRE settings
{}
"#,
            if config.engine.detection_only {
                "DetectionOnly"
            } else if config.engine.enabled {
                "On"
            } else {
                "Off"
            },
            if config.engine.request_body_access {
                "On"
            } else {
                "Off"
            },
            if config.engine.response_body_access {
                "On"
            } else {
                "Off"
            },
            config.engine.debug_level,
            if config.audit.enabled {
                "RelevantOnly"
            } else {
                "Off"
            },
            config.engine.paranoia_level,
            config.engine.anomaly_threshold,
            config.body_inspection.max_request_body_size,
            config.body_inspection.max_response_body_size,
            if config.engine.pcre_jit {
                "SecPcreMatchLimit 100000\nSecPcreMatchLimitRecursion 100000"
            } else {
                ""
            },
        );

        rules.load_rules(&config_rules)?;

        // Apply rule exclusions
        for rule_id in &config.rules.exclude_rule_ids {
            let exclusion_rule = format!("SecRuleRemoveById {}", rule_id);
            rules.load_rules(&exclusion_rule)?;
        }

        for tag in &config.rules.exclude_rule_tags {
            let exclusion_rule = format!("SecRuleRemoveByTag \"{}\"", tag);
            rules.load_rules(&exclusion_rule)?;
        }

        info!("Loaded {} rules", rules.rules_count());

        Ok(())
    }

    /// Process a request through WAF
    async fn process_request(&self, event: &RequestEvent) -> Result<AgentResponse> {
        let start = Instant::now();
        let config = self.config.load();

        // Check exclusions
        if self.should_exclude(event, &config) {
            debug!("Request excluded from WAF processing");
            return Ok(AgentResponse {
                decision: Decision::Allow,
                headers_to_add: HashMap::new(),
                headers_to_remove: Vec::new(),
                metadata: HashMap::from([("waf_excluded".to_string(), "true".to_string())]),
            });
        }

        // Acquire transaction permit
        let _permit = self
            .transaction_pool
            .acquire()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to acquire transaction permit: {}", e))?;

        self.metrics.active_transactions.inc();
        let _guard = scopeguard::guard((), |_| {
            self.metrics.active_transactions.dec();
        });

        // Create transaction
        let mut transaction = Transaction::new(&self.modsec, &self.rules.read())?;
        let transaction_id = transaction.id().to_string();

        debug!("Processing request with transaction {}", transaction_id);

        // Process connection
        let client_ip = event
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.split(',').next())
            .unwrap_or(&event.client_addr)
            .trim();

        transaction.process_connection(
            client_ip,
            0, // Client port not available
            &event.server_addr,
            event.server_port,
        )?;

        // Process URI
        let uri = format!("{}{}", event.path, event.query);
        transaction.process_uri(&uri, &event.method, &event.http_version)?;

        // Add headers
        for (name, value) in &event.headers {
            transaction.add_request_header(name, value)?;
        }

        // Process headers phase
        let headers_timer = self
            .metrics
            .processing_duration_seconds
            .with_label_values(&["request_headers"])
            .start_timer();

        let mut blocked = transaction.process_request_headers()?;
        headers_timer.observe_duration();

        // Process body if present and not already blocked
        if !blocked && !event.body.is_empty() && config.engine.request_body_access {
            // Check if we should inspect this content type
            let content_type = event
                .headers
                .get("content-type")
                .map(|s| s.as_str())
                .unwrap_or("");

            let should_inspect = config
                .body_inspection
                .inspect_request_content_types
                .iter()
                .any(|ct| content_type.starts_with(ct));

            if should_inspect {
                let body_timer = self
                    .metrics
                    .processing_duration_seconds
                    .with_label_values(&["request_body"])
                    .start_timer();

                // Limit body size
                let max_size = config.body_inspection.max_request_body_size;
                let body_to_inspect = if event.body.len() > max_size {
                    &event.body[..max_size]
                } else {
                    &event.body
                };

                transaction.append_request_body(body_to_inspect)?;
                blocked = transaction.process_request_body()?;

                body_timer.observe_duration();
            }
        }

        // Get intervention details if blocked
        let response = if blocked {
            if let Some(intervention) = transaction.get_intervention() {
                // Record metrics
                self.metrics
                    .requests_blocked
                    .with_label_values(&[&event.route_name, &event.method, "unknown"])
                    .inc();

                // Log audit event
                if config.audit.enabled && config.audit.log_relevant {
                    self.audit_logger
                        .log_blocked(&transaction, &intervention, event)
                        .await?;
                    self.metrics
                        .audit_logs_total
                        .with_label_values(&["blocked"])
                        .inc();
                }

                // Build response
                if intervention.is_redirect() {
                    AgentResponse {
                        decision: Decision::Redirect,
                        headers_to_add: HashMap::from([(
                            "Location".to_string(),
                            intervention.url.unwrap_or_default(),
                        )]),
                        headers_to_remove: Vec::new(),
                        metadata: HashMap::from([
                            ("waf_blocked".to_string(), "true".to_string()),
                            ("waf_transaction_id".to_string(), transaction_id),
                            ("waf_action".to_string(), "redirect".to_string()),
                        ]),
                    }
                } else {
                    AgentResponse {
                        decision: Decision::Block,
                        headers_to_add: HashMap::new(),
                        headers_to_remove: Vec::new(),
                        metadata: HashMap::from([
                            ("waf_blocked".to_string(), "true".to_string()),
                            ("waf_transaction_id".to_string(), transaction_id),
                            (
                                "waf_status".to_string(),
                                intervention.http_status().to_string(),
                            ),
                            (
                                "waf_message".to_string(),
                                intervention
                                    .log
                                    .unwrap_or_else(|| "Blocked by WAF".to_string()),
                            ),
                        ]),
                    }
                }
            } else {
                // Blocked but no intervention details
                AgentResponse {
                    decision: Decision::Block,
                    headers_to_add: HashMap::new(),
                    headers_to_remove: Vec::new(),
                    metadata: HashMap::from([
                        ("waf_blocked".to_string(), "true".to_string()),
                        ("waf_transaction_id".to_string(), transaction_id),
                    ]),
                }
            }
        } else {
            // Allowed
            self.metrics
                .requests_allowed
                .with_label_values(&[&event.route_name, &event.method])
                .inc();

            // Process logging
            transaction.process_logging()?;

            AgentResponse {
                decision: Decision::Allow,
                headers_to_add: HashMap::from([(
                    "X-WAF-Transaction-Id".to_string(),
                    transaction_id.clone(),
                )]),
                headers_to_remove: Vec::new(),
                metadata: HashMap::from([
                    ("waf_processed".to_string(), "true".to_string()),
                    ("waf_transaction_id".to_string(), transaction_id),
                ]),
            }
        };

        // Record total processing time
        let elapsed = start.elapsed();
        debug!(
            "WAF processing completed in {:?}, decision: {:?}",
            elapsed, response.decision
        );

        self.metrics
            .requests_total
            .with_label_values(&[&event.route_name, &event.method])
            .inc();

        Ok(response)
    }

    /// Check if request should be excluded from WAF
    fn should_exclude(&self, event: &RequestEvent, config: &Config) -> bool {
        for exclusion in &config.exclusions {
            if !exclusion.enabled {
                continue;
            }

            let mut all_match = true;
            for condition in &exclusion.conditions {
                if !self.matches_condition(event, condition) {
                    all_match = false;
                    break;
                }
            }

            if all_match {
                debug!("Request matches exclusion rule: {}", exclusion.name);
                return exclusion.bypass_waf;
            }
        }

        false
    }

    /// Check if request matches an exclusion condition
    fn matches_condition(&self, event: &RequestEvent, condition: &ExclusionCondition) -> bool {
        match condition {
            ExclusionCondition::ClientIp { value } => {
                let client_ip = event
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.split(',').next())
                    .unwrap_or(&event.client_addr)
                    .trim();

                if value.contains('/') {
                    // CIDR match - simplified implementation
                    client_ip.starts_with(&value.split('/').next().unwrap_or(""))
                } else {
                    client_ip == value
                }
            }
            ExclusionCondition::Path { pattern, regex } => {
                if *regex {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(&event.path))
                        .unwrap_or(false)
                } else {
                    event.path == *pattern || event.path.starts_with(pattern)
                }
            }
            ExclusionCondition::Header { name, value, regex } => {
                if let Some(header_value) = event.headers.get(name) {
                    if *regex {
                        regex::Regex::new(value)
                            .map(|re| re.is_match(header_value))
                            .unwrap_or(false)
                    } else {
                        header_value == value
                    }
                } else {
                    false
                }
            }
            ExclusionCondition::QueryParam { name, value } => {
                // Parse query string
                let query_pairs: Vec<_> = event
                    .query
                    .trim_start_matches('?')
                    .split('&')
                    .filter_map(|pair| {
                        let mut parts = pair.split('=');
                        Some((parts.next()?, parts.next()))
                    })
                    .collect();

                for (param_name, param_value) in query_pairs {
                    if param_name == name {
                        if let Some(expected_value) = value {
                            return param_value.map(|v| v == expected_value).unwrap_or(false);
                        } else {
                            return true;
                        }
                    }
                }
                false
            }
            ExclusionCondition::Method { value } => event.method.eq_ignore_ascii_case(value),
            ExclusionCondition::Host { value } => event
                .headers
                .get("host")
                .map(|h| h == value)
                .unwrap_or(false),
        }
    }

    /// Reload rules if configuration has changed
    async fn reload_rules_if_needed(&self) -> Result<()> {
        let config = self.config.load();

        if !config.rules.hot_reload {
            return Ok(());
        }

        // In production, we'd watch files for changes
        // For now, just reload periodically
        info!("Checking for rule updates...");

        // Create new rules set
        let new_rules = RulesSet::new()?;
        Self::load_rules(&config, &new_rules).await?;

        // Swap rules atomically
        *self.rules.write() = new_rules;

        info!("Rules reloaded successfully");
        Ok(())
    }
}

/// Audit logger
struct AuditLogger {
    log_dir: PathBuf,
}

impl AuditLogger {
    fn new(config: &config::AuditConfig) -> Result<Self> {
        // Create audit log directory if it doesn't exist
        std::fs::create_dir_all(&config.log_dir)?;

        Ok(AuditLogger {
            log_dir: config.log_dir.clone(),
        })
    }

    async fn log_blocked(
        &self,
        transaction: &Transaction,
        intervention: &modsecurity::Intervention,
        event: &RequestEvent,
    ) -> Result<()> {
        let timestamp = chrono::Utc::now();
        let transaction_id = transaction.id();

        let audit_log = json!({
            "timestamp": timestamp.to_rfc3339(),
            "transaction_id": transaction_id,
            "action": "blocked",
            "client_ip": event.client_addr,
            "method": event.method,
            "uri": format!("{}{}", event.path, event.query),
            "headers": event.headers,
            "status": intervention.http_status(),
            "message": intervention.log,
            "redirect_url": intervention.url,
        });

        // Write to file
        let log_file = self
            .log_dir
            .join(format!("audit_{}.json", timestamp.format("%Y%m%d")));

        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .await?
            .write_all(format!("{}\n", audit_log).as_bytes())
            .await?;

        Ok(())
    }
}

/// Start metrics server
async fn start_metrics_server(config: &config::MetricsConfig) -> Result<()> {
    use prometheus::{Encoder, TextEncoder};
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;

    if !config.enabled {
        return Ok(());
    }

    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Metrics server listening on {}", addr);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    let encoder = TextEncoder::new();
                    let metric_families = prometheus::gather();
                    let mut buffer = vec![];

                    if encoder.encode(&metric_families, &mut buffer).is_ok() {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
                            buffer.len()
                        );

                        let _ = socket.write_all(response.as_bytes()).await;
                        let _ = socket.write_all(&buffer).await;
                    }
                }
                Err(e) => {
                    error!("Failed to accept metrics connection: {}", e);
                }
            }
        }
    });

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sentinel_waf_agent=debug".parse()?),
        )
        .json()
        .init();

    info!("Starting Sentinel WAF Agent");
    info!("ModSecurity version: {}", ModSecurity::version());

    // Load configuration
    let config_path =
        std::env::var("WAF_CONFIG").unwrap_or_else(|_| "/etc/sentinel/waf.yaml".to_string());

    let config = if PathBuf::from(&config_path).exists() {
        Config::from_file(&config_path)?
    } else {
        info!("Config file not found, using defaults");
        Config::default()
    };

    // Validate configuration
    config.validate()?;

    // Create WAF agent
    let agent = Arc::new(WafAgent::new(config.clone()).await?);

    // Start metrics server
    start_metrics_server(&config.metrics).await?;

    // Start rule reload task
    if config.rules.hot_reload {
        let agent_clone = agent.clone();
        let reload_interval = Duration::from_secs(config.rules.reload_interval_seconds as u64);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(reload_interval);
            loop {
                interval.tick().await;
                if let Err(e) = agent_clone.reload_rules_if_needed().await {
                    error!("Failed to reload rules: {}", e);
                }
            }
        });
    }

    // Set up agent transport
    let transport_config = TransportConfig::UnixSocket {
        path: config.listener.socket_path.clone(),
        permissions: Some(config.listener.socket_permissions),
    };

    // Create agent client
    let mut client = AgentClient::new(transport_config).await?;

    info!(
        "WAF agent ready, listening on {:?}",
        config.listener.socket_path
    );

    // Main event loop
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Received shutdown signal");
                break;
            }
            result = client.next_event() => {
                match result {
                    Ok(Some(event)) => {
                        let agent = agent.clone();

                        // Process event asynchronously
                        tokio::spawn(async move {
                            let response = match event.event_type {
                                EventType::RequestHeaders(ref request) => {
                                    match agent.process_request(request).await {
                                        Ok(resp) => resp,
                                        Err(e) => {
                                            error!("Error processing request: {}", e);
                                            AgentResponse {
                                                decision: Decision::Allow,
                                                headers_to_add: HashMap::new(),
                                                headers_to_remove: Vec::new(),
                                                metadata: HashMap::from([
                                                    ("waf_error".to_string(), e.to_string()),
                                                ]),
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    // We only process request headers for now
                                    AgentResponse {
                                        decision: Decision::Allow,
                                        headers_to_add: HashMap::new(),
                                        headers_to_remove: Vec::new(),
                                        metadata: HashMap::new(),
                                    }
                                }
                            };

                            if let Err(e) = event.respond(response).await {
                                error!("Failed to send response: {}", e);
                            }
                        });
                    }
                    Ok(None) => {
                        // No event available
                        sleep(Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        error!("Error receiving event: {}", e);
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }

    info!("WAF agent shutting down");
    Ok(())
}
