//! Observability infrastructure for Protocol v2.
//!
//! This module provides:
//! - Metrics collection from agents
//! - Metrics aggregation across agents
//! - Prometheus-compatible export
//! - Config update handling

use crate::v2::control::{ConfigUpdateRequest, ConfigUpdateResponse, ConfigUpdateType};
use crate::v2::metrics::{HistogramBucket, MetricsReport};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Metrics collector that receives and aggregates metrics from agents.
#[derive(Debug)]
pub struct MetricsCollector {
    /// Aggregated counters by (agent_id, metric_name, labels_key)
    counters: RwLock<HashMap<MetricKey, AggregatedCounter>>,
    /// Aggregated gauges by (agent_id, metric_name, labels_key)
    gauges: RwLock<HashMap<MetricKey, AggregatedGauge>>,
    /// Aggregated histograms by (agent_id, metric_name, labels_key)
    histograms: RwLock<HashMap<MetricKey, AggregatedHistogram>>,
    /// Last report time per agent
    last_report: RwLock<HashMap<String, Instant>>,
    /// Configuration
    config: MetricsCollectorConfig,
}

/// Configuration for the metrics collector.
#[derive(Debug, Clone)]
pub struct MetricsCollectorConfig {
    /// Maximum age of metrics before expiry
    pub max_age: Duration,
    /// Maximum number of unique metric series
    pub max_series: usize,
    /// Whether to include agent_id as a label
    pub include_agent_id_label: bool,
}

impl Default for MetricsCollectorConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(300), // 5 minutes
            max_series: 10_000,
            include_agent_id_label: true,
        }
    }
}

/// Key for identifying a unique metric series.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct MetricKey {
    agent_id: String,
    name: String,
    labels_key: String,
}

impl MetricKey {
    fn new(agent_id: &str, name: &str, labels: &HashMap<String, String>) -> Self {
        let labels_key = Self::labels_to_key(labels);
        Self {
            agent_id: agent_id.to_string(),
            name: name.to_string(),
            labels_key,
        }
    }

    fn labels_to_key(labels: &HashMap<String, String>) -> String {
        let mut pairs: Vec<_> = labels.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        pairs
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Aggregated counter value.
#[derive(Debug, Clone)]
struct AggregatedCounter {
    name: String,
    help: Option<String>,
    labels: HashMap<String, String>,
    value: u64,
    last_updated: Instant,
}

/// Aggregated gauge value.
#[derive(Debug, Clone)]
struct AggregatedGauge {
    name: String,
    help: Option<String>,
    labels: HashMap<String, String>,
    value: f64,
    last_updated: Instant,
}

/// Aggregated histogram.
#[derive(Debug, Clone)]
struct AggregatedHistogram {
    name: String,
    help: Option<String>,
    labels: HashMap<String, String>,
    sum: f64,
    count: u64,
    buckets: Vec<HistogramBucket>,
    last_updated: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector with default configuration.
    pub fn new() -> Self {
        Self::with_config(MetricsCollectorConfig::default())
    }

    /// Create a new metrics collector with custom configuration.
    pub fn with_config(config: MetricsCollectorConfig) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            last_report: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Record a metrics report from an agent.
    pub fn record(&self, report: &MetricsReport) {
        let now = Instant::now();

        // Update last report time
        self.last_report
            .write()
            .insert(report.agent_id.clone(), now);

        // Process counters
        for counter in &report.counters {
            let mut labels = counter.labels.clone();
            if self.config.include_agent_id_label {
                labels.insert("agent_id".to_string(), report.agent_id.clone());
            }

            let key = MetricKey::new(&report.agent_id, &counter.name, &labels);

            let mut counters = self.counters.write();
            counters.insert(
                key,
                AggregatedCounter {
                    name: counter.name.clone(),
                    help: counter.help.clone(),
                    labels,
                    value: counter.value,
                    last_updated: now,
                },
            );
        }

        // Process gauges
        for gauge in &report.gauges {
            let mut labels = gauge.labels.clone();
            if self.config.include_agent_id_label {
                labels.insert("agent_id".to_string(), report.agent_id.clone());
            }

            let key = MetricKey::new(&report.agent_id, &gauge.name, &labels);

            let mut gauges = self.gauges.write();
            gauges.insert(
                key,
                AggregatedGauge {
                    name: gauge.name.clone(),
                    help: gauge.help.clone(),
                    labels,
                    value: gauge.value,
                    last_updated: now,
                },
            );
        }

        // Process histograms
        for histogram in &report.histograms {
            let mut labels = histogram.labels.clone();
            if self.config.include_agent_id_label {
                labels.insert("agent_id".to_string(), report.agent_id.clone());
            }

            let key = MetricKey::new(&report.agent_id, &histogram.name, &labels);

            let mut histograms = self.histograms.write();
            histograms.insert(
                key,
                AggregatedHistogram {
                    name: histogram.name.clone(),
                    help: histogram.help.clone(),
                    labels,
                    sum: histogram.sum,
                    count: histogram.count,
                    buckets: histogram.buckets.clone(),
                    last_updated: now,
                },
            );
        }
    }

    /// Remove expired metrics.
    pub fn expire_old_metrics(&self) {
        let now = Instant::now();
        let max_age = self.config.max_age;

        self.counters
            .write()
            .retain(|_, v| now.duration_since(v.last_updated) < max_age);
        self.gauges
            .write()
            .retain(|_, v| now.duration_since(v.last_updated) < max_age);
        self.histograms
            .write()
            .retain(|_, v| now.duration_since(v.last_updated) < max_age);
    }

    /// Get the number of active metric series.
    pub fn series_count(&self) -> usize {
        self.counters.read().len() + self.gauges.read().len() + self.histograms.read().len()
    }

    /// Get active agent IDs.
    pub fn active_agents(&self) -> Vec<String> {
        self.last_report.read().keys().cloned().collect()
    }

    /// Export metrics in Prometheus text format.
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Export counters
        let counters = self.counters.read();
        let mut counter_names: Vec<_> = counters.values().map(|c| &c.name).collect();
        counter_names.sort();
        counter_names.dedup();

        for name in counter_names {
            let metrics: Vec<_> = counters.values().filter(|c| &c.name == name).collect();
            if let Some(first) = metrics.first() {
                if let Some(help) = &first.help {
                    output.push_str(&format!("# HELP {} {}\n", name, help));
                }
                output.push_str(&format!("# TYPE {} counter\n", name));
            }
            for metric in metrics {
                output.push_str(&format_metric_line(
                    name,
                    &metric.labels,
                    metric.value as f64,
                ));
            }
        }

        // Export gauges
        let gauges = self.gauges.read();
        let mut gauge_names: Vec<_> = gauges.values().map(|g| &g.name).collect();
        gauge_names.sort();
        gauge_names.dedup();

        for name in gauge_names {
            let metrics: Vec<_> = gauges.values().filter(|g| &g.name == name).collect();
            if let Some(first) = metrics.first() {
                if let Some(help) = &first.help {
                    output.push_str(&format!("# HELP {} {}\n", name, help));
                }
                output.push_str(&format!("# TYPE {} gauge\n", name));
            }
            for metric in metrics {
                output.push_str(&format_metric_line(name, &metric.labels, metric.value));
            }
        }

        // Export histograms
        let histograms = self.histograms.read();
        let mut histogram_names: Vec<_> = histograms.values().map(|h| &h.name).collect();
        histogram_names.sort();
        histogram_names.dedup();

        for name in histogram_names {
            let metrics: Vec<_> = histograms.values().filter(|h| &h.name == name).collect();
            if let Some(first) = metrics.first() {
                if let Some(help) = &first.help {
                    output.push_str(&format!("# HELP {} {}\n", name, help));
                }
                output.push_str(&format!("# TYPE {} histogram\n", name));
            }
            for metric in metrics {
                // Buckets
                for bucket in &metric.buckets {
                    let mut labels = metric.labels.clone();
                    labels.insert(
                        "le".to_string(),
                        if bucket.le.is_infinite() {
                            "+Inf".to_string()
                        } else {
                            bucket.le.to_string()
                        },
                    );
                    output.push_str(&format_metric_line(
                        &format!("{}_bucket", name),
                        &labels,
                        bucket.count as f64,
                    ));
                }
                // Sum and count
                output.push_str(&format_metric_line(
                    &format!("{}_sum", name),
                    &metric.labels,
                    metric.sum,
                ));
                output.push_str(&format_metric_line(
                    &format!("{}_count", name),
                    &metric.labels,
                    metric.count as f64,
                ));
            }
        }

        output
    }

    /// Get a snapshot of all metrics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            counters: self.counters.read().values().cloned().collect(),
            gauges: self.gauges.read().values().cloned().collect(),
            histograms: self.histograms.read().values().cloned().collect(),
            timestamp: Instant::now(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all metrics at a point in time.
#[derive(Debug)]
pub struct MetricsSnapshot {
    counters: Vec<AggregatedCounter>,
    gauges: Vec<AggregatedGauge>,
    histograms: Vec<AggregatedHistogram>,
    timestamp: Instant,
}

impl MetricsSnapshot {
    /// Get counter values.
    pub fn counter_count(&self) -> usize {
        self.counters.len()
    }

    /// Get gauge values.
    pub fn gauge_count(&self) -> usize {
        self.gauges.len()
    }

    /// Get histogram count.
    pub fn histogram_count(&self) -> usize {
        self.histograms.len()
    }
}

/// Unified metrics aggregator that combines metrics from multiple sources.
///
/// This aggregator collects metrics from:
/// - The proxy itself (request counts, latencies, etc.)
/// - Connected agents (via MetricsCollector)
/// - System metrics (optional)
#[derive(Debug)]
pub struct UnifiedMetricsAggregator {
    /// Proxy-level counters
    proxy_counters: RwLock<HashMap<String, ProxyCounter>>,
    /// Proxy-level gauges
    proxy_gauges: RwLock<HashMap<String, ProxyGauge>>,
    /// Proxy-level histograms
    proxy_histograms: RwLock<HashMap<String, ProxyHistogram>>,
    /// Agent metrics collector
    agent_collector: MetricsCollector,
    /// Service name for labeling
    service_name: String,
    /// Instance identifier
    instance_id: String,
}

/// Proxy-level counter metric.
#[derive(Debug, Clone)]
struct ProxyCounter {
    name: String,
    help: String,
    labels: HashMap<String, String>,
    value: u64,
}

/// Proxy-level gauge metric.
#[derive(Debug, Clone)]
struct ProxyGauge {
    name: String,
    help: String,
    labels: HashMap<String, String>,
    value: f64,
}

/// Proxy-level histogram metric.
#[derive(Debug, Clone)]
struct ProxyHistogram {
    name: String,
    help: String,
    labels: HashMap<String, String>,
    sum: f64,
    count: u64,
    buckets: Vec<(f64, u64)>,
}

impl UnifiedMetricsAggregator {
    /// Create a new unified metrics aggregator.
    pub fn new(service_name: impl Into<String>, instance_id: impl Into<String>) -> Self {
        Self {
            proxy_counters: RwLock::new(HashMap::new()),
            proxy_gauges: RwLock::new(HashMap::new()),
            proxy_histograms: RwLock::new(HashMap::new()),
            agent_collector: MetricsCollector::new(),
            service_name: service_name.into(),
            instance_id: instance_id.into(),
        }
    }

    /// Create with custom agent collector config.
    pub fn with_agent_config(
        service_name: impl Into<String>,
        instance_id: impl Into<String>,
        agent_config: MetricsCollectorConfig,
    ) -> Self {
        Self {
            proxy_counters: RwLock::new(HashMap::new()),
            proxy_gauges: RwLock::new(HashMap::new()),
            proxy_histograms: RwLock::new(HashMap::new()),
            agent_collector: MetricsCollector::with_config(agent_config),
            service_name: service_name.into(),
            instance_id: instance_id.into(),
        }
    }

    /// Get the agent metrics collector.
    pub fn agent_collector(&self) -> &MetricsCollector {
        &self.agent_collector
    }

    /// Increment a proxy counter.
    pub fn increment_counter(
        &self,
        name: &str,
        help: &str,
        labels: HashMap<String, String>,
        delta: u64,
    ) {
        let key = Self::metric_key(name, &labels);
        let mut counters = self.proxy_counters.write();

        if let Some(counter) = counters.get_mut(&key) {
            counter.value += delta;
        } else {
            counters.insert(
                key,
                ProxyCounter {
                    name: name.to_string(),
                    help: help.to_string(),
                    labels,
                    value: delta,
                },
            );
        }
    }

    /// Set a proxy gauge.
    pub fn set_gauge(&self, name: &str, help: &str, labels: HashMap<String, String>, value: f64) {
        let key = Self::metric_key(name, &labels);
        self.proxy_gauges.write().insert(
            key,
            ProxyGauge {
                name: name.to_string(),
                help: help.to_string(),
                labels,
                value,
            },
        );
    }

    /// Record a histogram observation.
    pub fn observe_histogram(
        &self,
        name: &str,
        help: &str,
        labels: HashMap<String, String>,
        bucket_boundaries: &[f64],
        value: f64,
    ) {
        let key = Self::metric_key(name, &labels);
        let mut histograms = self.proxy_histograms.write();

        if let Some(histogram) = histograms.get_mut(&key) {
            histogram.sum += value;
            histogram.count += 1;
            // Update bucket counts
            for (boundary, count) in histogram.buckets.iter_mut() {
                if value <= *boundary {
                    *count += 1;
                }
            }
        } else {
            // Initialize buckets
            let mut buckets: Vec<(f64, u64)> = bucket_boundaries
                .iter()
                .map(|&b| (b, if value <= b { 1 } else { 0 }))
                .collect();
            buckets.push((f64::INFINITY, 1)); // +Inf bucket always includes all observations

            histograms.insert(
                key,
                ProxyHistogram {
                    name: name.to_string(),
                    help: help.to_string(),
                    labels,
                    sum: value,
                    count: 1,
                    buckets,
                },
            );
        }
    }

    /// Record agent metrics.
    pub fn record_agent_metrics(&self, report: &MetricsReport) {
        self.agent_collector.record(report);
    }

    /// Export all metrics in Prometheus text format.
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Add service info metric
        output.push_str(
            "# HELP zentinel_info Zentinel proxy information\n# TYPE zentinel_info gauge\n",
        );
        output.push_str(&format!(
            "zentinel_info{{service=\"{}\",instance=\"{}\"}} 1\n",
            escape_label_value(&self.service_name),
            escape_label_value(&self.instance_id)
        ));

        // Export proxy counters
        let counters = self.proxy_counters.read();
        let mut counter_names: Vec<_> = counters.values().map(|c| &c.name).collect();
        counter_names.sort();
        counter_names.dedup();

        for name in counter_names {
            let metrics: Vec<_> = counters.values().filter(|c| &c.name == name).collect();
            if let Some(first) = metrics.first() {
                output.push_str(&format!("# HELP {} {}\n", name, first.help));
                output.push_str(&format!("# TYPE {} counter\n", name));
            }
            for metric in metrics {
                output.push_str(&format_metric_line(
                    name,
                    &metric.labels,
                    metric.value as f64,
                ));
            }
        }

        // Export proxy gauges
        let gauges = self.proxy_gauges.read();
        let mut gauge_names: Vec<_> = gauges.values().map(|g| &g.name).collect();
        gauge_names.sort();
        gauge_names.dedup();

        for name in gauge_names {
            let metrics: Vec<_> = gauges.values().filter(|g| &g.name == name).collect();
            if let Some(first) = metrics.first() {
                output.push_str(&format!("# HELP {} {}\n", name, first.help));
                output.push_str(&format!("# TYPE {} gauge\n", name));
            }
            for metric in metrics {
                output.push_str(&format_metric_line(name, &metric.labels, metric.value));
            }
        }

        // Export proxy histograms
        let histograms = self.proxy_histograms.read();
        let mut histogram_names: Vec<_> = histograms.values().map(|h| &h.name).collect();
        histogram_names.sort();
        histogram_names.dedup();

        for name in histogram_names {
            let metrics: Vec<_> = histograms.values().filter(|h| &h.name == name).collect();
            if let Some(first) = metrics.first() {
                output.push_str(&format!("# HELP {} {}\n", name, first.help));
                output.push_str(&format!("# TYPE {} histogram\n", name));
            }
            for metric in metrics {
                // Buckets
                for (le, count) in &metric.buckets {
                    let mut labels = metric.labels.clone();
                    labels.insert(
                        "le".to_string(),
                        if le.is_infinite() {
                            "+Inf".to_string()
                        } else {
                            le.to_string()
                        },
                    );
                    output.push_str(&format_metric_line(
                        &format!("{}_bucket", name),
                        &labels,
                        *count as f64,
                    ));
                }
                // Sum and count
                output.push_str(&format_metric_line(
                    &format!("{}_sum", name),
                    &metric.labels,
                    metric.sum,
                ));
                output.push_str(&format_metric_line(
                    &format!("{}_count", name),
                    &metric.labels,
                    metric.count as f64,
                ));
            }
        }

        // Export agent metrics
        output.push_str("\n# Agent metrics\n");
        output.push_str(&self.agent_collector.export_prometheus());

        output
    }

    /// Get total metric series count.
    pub fn series_count(&self) -> usize {
        self.proxy_counters.read().len()
            + self.proxy_gauges.read().len()
            + self.proxy_histograms.read().len()
            + self.agent_collector.series_count()
    }

    fn metric_key(name: &str, labels: &HashMap<String, String>) -> String {
        let mut pairs: Vec<_> = labels.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        let labels_str = pairs
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}|{}", name, labels_str)
    }
}

impl Default for UnifiedMetricsAggregator {
    fn default() -> Self {
        Self::new("zentinel", "default")
    }
}

/// Format a single metric line in Prometheus format.
fn format_metric_line(name: &str, labels: &HashMap<String, String>, value: f64) -> String {
    if labels.is_empty() {
        format!("{} {}\n", name, format_value(value))
    } else {
        let mut pairs: Vec<_> = labels.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        let labels_str = pairs
            .into_iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}{{{}}} {}\n", name, labels_str, format_value(value))
    }
}

/// Format a value for Prometheus output.
fn format_value(v: f64) -> String {
    if v.is_infinite() {
        if v.is_sign_positive() {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        }
    } else if v.is_nan() {
        "NaN".to_string()
    } else if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

/// Escape a label value for Prometheus format.
fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Handler for config updates from agents.
pub struct ConfigUpdateHandler {
    /// Pending updates awaiting acknowledgment
    pending: RwLock<HashMap<String, PendingUpdate>>,
    /// Callback for rule updates
    #[allow(clippy::type_complexity)]
    on_rule_update: Option<
        Box<dyn Fn(&str, &[crate::v2::control::RuleDefinition], &[String]) -> bool + Send + Sync>,
    >,
    /// Callback for list updates
    #[allow(clippy::type_complexity)]
    on_list_update: Option<Box<dyn Fn(&str, &[String], &[String]) -> bool + Send + Sync>>,
}

struct PendingUpdate {
    request: ConfigUpdateRequest,
    received_at: Instant,
}

impl ConfigUpdateHandler {
    /// Create a new config update handler.
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            on_rule_update: None,
            on_list_update: None,
        }
    }

    /// Set the rule update callback.
    pub fn on_rule_update<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &[crate::v2::control::RuleDefinition], &[String]) -> bool
            + Send
            + Sync
            + 'static,
    {
        self.on_rule_update = Some(Box::new(f));
        self
    }

    /// Set the list update callback.
    pub fn on_list_update<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &[String], &[String]) -> bool + Send + Sync + 'static,
    {
        self.on_list_update = Some(Box::new(f));
        self
    }

    /// Handle a config update request.
    pub fn handle(&self, request: ConfigUpdateRequest) -> ConfigUpdateResponse {
        let request_id = request.request_id.clone();

        match &request.update_type {
            ConfigUpdateType::RequestReload => {
                // Store pending and return success - actual reload happens asynchronously
                self.pending.write().insert(
                    request_id.clone(),
                    PendingUpdate {
                        request,
                        received_at: Instant::now(),
                    },
                );
                ConfigUpdateResponse::success(request_id)
            }
            ConfigUpdateType::RuleUpdate {
                rule_set,
                rules,
                remove_rules,
            } => {
                if let Some(ref callback) = self.on_rule_update {
                    if callback(rule_set, rules, remove_rules) {
                        ConfigUpdateResponse::success(request_id)
                    } else {
                        ConfigUpdateResponse::failure(request_id, "Rule update rejected")
                    }
                } else {
                    ConfigUpdateResponse::failure(request_id, "Rule updates not supported")
                }
            }
            ConfigUpdateType::ListUpdate {
                list_id,
                add,
                remove,
            } => {
                if let Some(ref callback) = self.on_list_update {
                    if callback(list_id, add, remove) {
                        ConfigUpdateResponse::success(request_id)
                    } else {
                        ConfigUpdateResponse::failure(request_id, "List update rejected")
                    }
                } else {
                    ConfigUpdateResponse::failure(request_id, "List updates not supported")
                }
            }
            ConfigUpdateType::RestartRequired {
                reason,
                grace_period_ms,
            } => {
                // Log and acknowledge - actual restart is handled by orchestrator
                tracing::warn!(
                    reason = reason,
                    grace_period_ms = grace_period_ms,
                    "Agent requested restart"
                );
                ConfigUpdateResponse::success(request_id)
            }
            ConfigUpdateType::ConfigError { error, field } => {
                tracing::error!(
                    error = error,
                    field = ?field,
                    "Agent reported configuration error"
                );
                ConfigUpdateResponse::success(request_id)
            }
        }
    }

    /// Get pending update count.
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Clear old pending updates.
    pub fn clear_old_pending(&self, max_age: Duration) {
        let now = Instant::now();
        self.pending
            .write()
            .retain(|_, v| now.duration_since(v.received_at) < max_age);
    }
}

impl Default for ConfigUpdateHandler {
    fn default() -> Self {
        Self::new()
    }
}

// Debug implementation for ConfigUpdateHandler
impl std::fmt::Debug for ConfigUpdateHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigUpdateHandler")
            .field("pending_count", &self.pending.read().len())
            .field("has_rule_callback", &self.on_rule_update.is_some())
            .field("has_list_callback", &self.on_list_update.is_some())
            .finish()
    }
}

/// Configuration pusher for distributing config updates to agents.
///
/// This allows the proxy to push configuration changes (rules, lists, etc.)
/// to connected agents and track acknowledgments.
#[derive(Debug)]
pub struct ConfigPusher {
    /// Connected agents indexed by agent_id
    agents: RwLock<HashMap<String, AgentConnection>>,
    /// Pending pushes awaiting acknowledgment
    pending_pushes: RwLock<HashMap<String, PendingPush>>,
    /// Configuration
    config: ConfigPusherConfig,
    /// Sequence counter for push IDs
    sequence: std::sync::atomic::AtomicU64,
}

/// Configuration for the config pusher.
#[derive(Debug, Clone)]
pub struct ConfigPusherConfig {
    /// Maximum time to wait for acknowledgment
    pub ack_timeout: Duration,
    /// Maximum number of retry attempts
    pub max_retries: usize,
    /// Time between retries
    pub retry_interval: Duration,
    /// Maximum pending pushes per agent
    pub max_pending_per_agent: usize,
}

impl Default for ConfigPusherConfig {
    fn default() -> Self {
        Self {
            ack_timeout: Duration::from_secs(10),
            max_retries: 3,
            retry_interval: Duration::from_secs(2),
            max_pending_per_agent: 100,
        }
    }
}

/// Information about a connected agent.
#[derive(Debug, Clone)]
pub struct AgentConnection {
    /// Agent identifier
    pub agent_id: String,
    /// Agent name
    pub name: String,
    /// Connection time
    pub connected_at: Instant,
    /// Last message time
    pub last_seen: Instant,
    /// Number of successful config pushes
    pub successful_pushes: u64,
    /// Number of failed config pushes
    pub failed_pushes: u64,
    /// Whether the agent supports config push
    pub supports_push: bool,
}

/// A pending configuration push.
#[derive(Debug)]
struct PendingPush {
    push_id: String,
    agent_id: String,
    update: ConfigUpdateRequest,
    created_at: Instant,
    last_attempt: Instant,
    attempts: usize,
    status: PushStatus,
}

/// Status of a config push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushStatus {
    Pending,
    Sent,
    Acknowledged,
    Failed { reason: String },
    Expired,
}

/// Result of a push operation.
#[derive(Debug)]
pub struct PushResult {
    pub push_id: String,
    pub agent_id: String,
    pub status: PushStatus,
    pub attempts: usize,
}

impl ConfigPusher {
    /// Create a new config pusher with default configuration.
    pub fn new() -> Self {
        Self::with_config(ConfigPusherConfig::default())
    }

    /// Create a new config pusher with custom configuration.
    pub fn with_config(config: ConfigPusherConfig) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            pending_pushes: RwLock::new(HashMap::new()),
            config,
            sequence: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Register a connected agent.
    pub fn register_agent(
        &self,
        agent_id: impl Into<String>,
        name: impl Into<String>,
        supports_push: bool,
    ) {
        let agent_id = agent_id.into();
        let now = Instant::now();
        self.agents.write().insert(
            agent_id.clone(),
            AgentConnection {
                agent_id,
                name: name.into(),
                connected_at: now,
                last_seen: now,
                successful_pushes: 0,
                failed_pushes: 0,
                supports_push,
            },
        );
    }

    /// Unregister a disconnected agent.
    pub fn unregister_agent(&self, agent_id: &str) {
        self.agents.write().remove(agent_id);
        // Remove any pending pushes for this agent
        self.pending_pushes
            .write()
            .retain(|_, p| p.agent_id != agent_id);
    }

    /// Update agent's last seen time.
    pub fn touch_agent(&self, agent_id: &str) {
        if let Some(agent) = self.agents.write().get_mut(agent_id) {
            agent.last_seen = Instant::now();
        }
    }

    /// Get all connected agents.
    pub fn connected_agents(&self) -> Vec<AgentConnection> {
        self.agents.read().values().cloned().collect()
    }

    /// Get agents that support config push.
    pub fn pushable_agents(&self) -> Vec<AgentConnection> {
        self.agents
            .read()
            .values()
            .filter(|a| a.supports_push)
            .cloned()
            .collect()
    }

    /// Push a configuration update to a specific agent.
    pub fn push_to_agent(&self, agent_id: &str, update_type: ConfigUpdateType) -> Option<String> {
        let agents = self.agents.read();
        let agent = agents.get(agent_id)?;

        if !agent.supports_push {
            return None;
        }

        let push_id = self.next_push_id();
        let now = Instant::now();

        let update = ConfigUpdateRequest {
            update_type,
            request_id: push_id.clone(),
            timestamp_ms: now_ms(),
        };

        self.pending_pushes.write().insert(
            push_id.clone(),
            PendingPush {
                push_id: push_id.clone(),
                agent_id: agent_id.to_string(),
                update,
                created_at: now,
                last_attempt: now,
                attempts: 1,
                status: PushStatus::Sent,
            },
        );

        Some(push_id)
    }

    /// Push a configuration update to all pushable agents.
    pub fn push_to_all(&self, update_type: ConfigUpdateType) -> Vec<String> {
        let pushable = self.pushable_agents();
        let mut push_ids = Vec::with_capacity(pushable.len());

        for agent in pushable {
            if let Some(push_id) = self.push_to_agent(&agent.agent_id, update_type.clone()) {
                push_ids.push(push_id);
            }
        }

        push_ids
    }

    /// Acknowledge a config push.
    pub fn acknowledge(&self, push_id: &str, accepted: bool, error: Option<String>) {
        let mut pending = self.pending_pushes.write();
        if let Some(push) = pending.get_mut(push_id) {
            if accepted {
                push.status = PushStatus::Acknowledged;
                // Update agent stats
                if let Some(agent) = self.agents.write().get_mut(&push.agent_id) {
                    agent.successful_pushes += 1;
                }
            } else {
                push.status = PushStatus::Failed {
                    reason: error.unwrap_or_else(|| "Unknown error".to_string()),
                };
                // Update agent stats
                if let Some(agent) = self.agents.write().get_mut(&push.agent_id) {
                    agent.failed_pushes += 1;
                }
            }
        }
    }

    /// Get pushes that need to be retried.
    pub fn get_retryable(&self) -> Vec<(String, ConfigUpdateRequest)> {
        let now = Instant::now();
        let mut retryable = Vec::new();
        let mut pending = self.pending_pushes.write();

        for push in pending.values_mut() {
            if push.status == PushStatus::Sent
                && now.duration_since(push.last_attempt) >= self.config.retry_interval
                && push.attempts < self.config.max_retries
            {
                push.attempts += 1;
                push.last_attempt = now;
                retryable.push((push.agent_id.clone(), push.update.clone()));
            }
        }

        retryable
    }

    /// Expire old pending pushes.
    pub fn expire_old(&self) {
        let now = Instant::now();
        let mut pending = self.pending_pushes.write();

        for push in pending.values_mut() {
            if push.status == PushStatus::Sent
                && (now.duration_since(push.created_at) >= self.config.ack_timeout
                    || push.attempts >= self.config.max_retries)
            {
                push.status = PushStatus::Expired;
                // Update agent stats
                if let Some(agent) = self.agents.write().get_mut(&push.agent_id) {
                    agent.failed_pushes += 1;
                }
            }
        }

        // Remove completed or expired pushes older than 1 minute
        let cleanup_age = Duration::from_secs(60);
        pending.retain(|_, p| {
            now.duration_since(p.created_at) < cleanup_age
                || matches!(p.status, PushStatus::Pending | PushStatus::Sent)
        });
    }

    /// Get push results.
    pub fn get_results(&self) -> Vec<PushResult> {
        self.pending_pushes
            .read()
            .values()
            .map(|p| PushResult {
                push_id: p.push_id.clone(),
                agent_id: p.agent_id.clone(),
                status: p.status.clone(),
                attempts: p.attempts,
            })
            .collect()
    }

    /// Get pending push count.
    pub fn pending_count(&self) -> usize {
        self.pending_pushes
            .read()
            .values()
            .filter(|p| matches!(p.status, PushStatus::Pending | PushStatus::Sent))
            .count()
    }

    fn next_push_id(&self) -> String {
        let seq = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("push-{}", seq)
    }
}

impl Default for ConfigPusher {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::metrics::{standard, CounterMetric, GaugeMetric, HistogramMetric};

    #[test]
    fn test_metrics_collector_basic() {
        let collector = MetricsCollector::new();

        let mut report = MetricsReport::new("test-agent", 10_000);
        report
            .counters
            .push(CounterMetric::new(standard::REQUESTS_TOTAL, 100));
        report
            .gauges
            .push(GaugeMetric::new(standard::IN_FLIGHT_REQUESTS, 5.0));

        collector.record(&report);

        assert_eq!(collector.series_count(), 2);
        assert_eq!(collector.active_agents(), vec!["test-agent"]);
    }

    #[test]
    fn test_metrics_collector_with_labels() {
        let collector = MetricsCollector::new();

        let mut report = MetricsReport::new("agent-1", 10_000);
        let mut counter = CounterMetric::new(standard::REQUESTS_TOTAL, 50);
        counter
            .labels
            .insert("route".to_string(), "/api".to_string());
        report.counters.push(counter);

        collector.record(&report);

        let prometheus = collector.export_prometheus();
        assert!(prometheus.contains("agent_requests_total"));
        assert!(prometheus.contains("route=\"/api\""));
        assert!(prometheus.contains("agent_id=\"agent-1\""));
    }

    #[test]
    fn test_prometheus_export() {
        let collector = MetricsCollector::new();

        let mut report = MetricsReport::new("test", 10_000);
        let mut counter = CounterMetric::new("http_requests_total", 123);
        counter.help = Some("Total HTTP requests".to_string());
        report.counters.push(counter);

        collector.record(&report);

        let output = collector.export_prometheus();
        assert!(output.contains("# HELP http_requests_total Total HTTP requests"));
        assert!(output.contains("# TYPE http_requests_total counter"));
        assert!(output.contains("123"));
    }

    #[test]
    fn test_histogram_export() {
        // Use config without agent_id label for simpler assertions
        let config = MetricsCollectorConfig {
            include_agent_id_label: false,
            ..MetricsCollectorConfig::default()
        };
        let collector = MetricsCollector::with_config(config);

        let mut report = MetricsReport::new("test", 10_000);
        report.histograms.push(HistogramMetric {
            name: "request_duration_seconds".to_string(),
            help: Some("Request duration".to_string()),
            labels: HashMap::new(),
            sum: 10.5,
            count: 100,
            buckets: vec![
                HistogramBucket { le: 0.1, count: 50 },
                HistogramBucket { le: 0.5, count: 80 },
                HistogramBucket { le: 1.0, count: 95 },
                HistogramBucket::infinity(),
            ],
        });

        collector.record(&report);

        let output = collector.export_prometheus();
        assert!(output.contains("request_duration_seconds_bucket"));
        assert!(output.contains("le=\"0.1\""));
        assert!(output.contains("le=\"+Inf\""));
        assert!(output.contains("request_duration_seconds_sum 10.5"));
        assert!(output.contains("request_duration_seconds_count 100"));
    }

    #[test]
    fn test_config_update_handler() {
        let handler = ConfigUpdateHandler::new();

        let request = ConfigUpdateRequest {
            update_type: ConfigUpdateType::RequestReload,
            request_id: "req-1".to_string(),
            timestamp_ms: 0,
        };

        let response = handler.handle(request);
        assert!(response.accepted);
        assert_eq!(handler.pending_count(), 1);
    }

    #[test]
    fn test_escape_label_value() {
        assert_eq!(escape_label_value("simple"), "simple");
        assert_eq!(escape_label_value("with\"quotes"), "with\\\"quotes");
        assert_eq!(escape_label_value("with\\backslash"), "with\\\\backslash");
        assert_eq!(escape_label_value("with\nnewline"), "with\\nnewline");
    }

    #[test]
    fn test_config_pusher_basic() {
        let pusher = ConfigPusher::new();

        // Register an agent
        pusher.register_agent("agent-1", "Test Agent", true);

        let agents = pusher.connected_agents();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_id, "agent-1");
        assert!(agents[0].supports_push);
    }

    #[test]
    fn test_config_pusher_push_to_agent() {
        let pusher = ConfigPusher::new();
        pusher.register_agent("agent-1", "Test Agent", true);

        let update_type = ConfigUpdateType::RuleUpdate {
            rule_set: "default".to_string(),
            rules: vec![],
            remove_rules: vec![],
        };

        let push_id = pusher.push_to_agent("agent-1", update_type);
        assert!(push_id.is_some());

        let push_id = push_id.unwrap();
        assert!(push_id.starts_with("push-"));
        assert_eq!(pusher.pending_count(), 1);
    }

    #[test]
    fn test_config_pusher_acknowledge() {
        let pusher = ConfigPusher::new();
        pusher.register_agent("agent-1", "Test Agent", true);

        let push_id = pusher
            .push_to_agent("agent-1", ConfigUpdateType::RequestReload)
            .unwrap();

        // Acknowledge success
        pusher.acknowledge(&push_id, true, None);

        let results = pusher.get_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, PushStatus::Acknowledged);

        // Check agent stats
        let agents = pusher.connected_agents();
        assert_eq!(agents[0].successful_pushes, 1);
    }

    #[test]
    fn test_config_pusher_push_to_non_pushable() {
        let pusher = ConfigPusher::new();
        pusher.register_agent("agent-1", "Test Agent", false);

        let push_id = pusher.push_to_agent("agent-1", ConfigUpdateType::RequestReload);
        assert!(push_id.is_none());
    }

    #[test]
    fn test_config_pusher_push_to_all() {
        let pusher = ConfigPusher::new();
        pusher.register_agent("agent-1", "Agent 1", true);
        pusher.register_agent("agent-2", "Agent 2", true);
        pusher.register_agent("agent-3", "Agent 3", false); // Not pushable

        let push_ids = pusher.push_to_all(ConfigUpdateType::RequestReload);
        assert_eq!(push_ids.len(), 2);
        assert_eq!(pusher.pending_count(), 2);
    }

    #[test]
    fn test_config_pusher_unregister() {
        let pusher = ConfigPusher::new();
        pusher.register_agent("agent-1", "Test Agent", true);

        let _push_id = pusher.push_to_agent("agent-1", ConfigUpdateType::RequestReload);
        assert_eq!(pusher.pending_count(), 1);

        pusher.unregister_agent("agent-1");

        assert_eq!(pusher.connected_agents().len(), 0);
        assert_eq!(pusher.pending_count(), 0); // Pending pushes should be removed
    }

    #[test]
    fn test_metrics_snapshot() {
        let collector = MetricsCollector::new();

        let mut report = MetricsReport::new("test", 10_000);
        report
            .counters
            .push(CounterMetric::new("requests_total", 100));
        report.gauges.push(GaugeMetric::new("connections", 5.0));

        collector.record(&report);

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.counter_count(), 1);
        assert_eq!(snapshot.gauge_count(), 1);
    }

    #[test]
    fn test_unified_aggregator_basic() {
        let aggregator = UnifiedMetricsAggregator::new("test-service", "instance-1");

        // Add proxy counter
        aggregator.increment_counter(
            "http_requests_total",
            "Total HTTP requests",
            HashMap::new(),
            100,
        );

        // Add proxy gauge
        aggregator.set_gauge(
            "active_connections",
            "Active connections",
            HashMap::new(),
            42.0,
        );

        assert_eq!(aggregator.series_count(), 2);
    }

    #[test]
    fn test_unified_aggregator_counter_increment() {
        let aggregator = UnifiedMetricsAggregator::new("test", "1");

        aggregator.increment_counter("requests", "Total requests", HashMap::new(), 10);
        aggregator.increment_counter("requests", "Total requests", HashMap::new(), 5);

        let output = aggregator.export_prometheus();
        assert!(output.contains("requests 15"));
    }

    #[test]
    fn test_unified_aggregator_labeled_metrics() {
        let aggregator = UnifiedMetricsAggregator::new("test", "1");

        let mut labels = HashMap::new();
        labels.insert("method".to_string(), "GET".to_string());
        aggregator.increment_counter("requests", "Total requests", labels.clone(), 100);

        let mut labels2 = HashMap::new();
        labels2.insert("method".to_string(), "POST".to_string());
        aggregator.increment_counter("requests", "Total requests", labels2, 50);

        let output = aggregator.export_prometheus();
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("method=\"POST\""));
    }

    #[test]
    fn test_unified_aggregator_histogram() {
        let aggregator = UnifiedMetricsAggregator::new("test", "1");
        let buckets = vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        // Record some observations
        aggregator.observe_histogram(
            "request_duration",
            "Request duration",
            HashMap::new(),
            &buckets,
            0.05,
        );
        aggregator.observe_histogram(
            "request_duration",
            "Request duration",
            HashMap::new(),
            &buckets,
            0.2,
        );
        aggregator.observe_histogram(
            "request_duration",
            "Request duration",
            HashMap::new(),
            &buckets,
            1.5,
        );

        let output = aggregator.export_prometheus();
        assert!(output.contains("request_duration_bucket"));
        assert!(output.contains("request_duration_sum"));
        assert!(output.contains("request_duration_count 3"));
    }

    #[test]
    fn test_unified_aggregator_with_agent_metrics() {
        let aggregator = UnifiedMetricsAggregator::new("test", "1");

        // Add proxy metric
        aggregator.increment_counter("proxy_requests", "Proxy requests", HashMap::new(), 1000);

        // Add agent metrics
        let mut report = MetricsReport::new("waf-agent", 5_000);
        report.counters.push(CounterMetric::new("waf_blocked", 50));
        aggregator.record_agent_metrics(&report);

        let output = aggregator.export_prometheus();
        assert!(output.contains("proxy_requests 1000"));
        assert!(output.contains("waf_blocked"));
        assert!(output.contains("Agent metrics"));
    }

    #[test]
    fn test_unified_aggregator_service_info() {
        let aggregator = UnifiedMetricsAggregator::new("my-service", "node-42");

        let output = aggregator.export_prometheus();
        assert!(output.contains("zentinel_info"));
        assert!(output.contains("service=\"my-service\""));
        assert!(output.contains("instance=\"node-42\""));
    }
}
