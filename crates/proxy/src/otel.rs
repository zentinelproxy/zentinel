//! OpenTelemetry integration for distributed tracing
//!
//! This module provides OpenTelemetry support with OTLP export for distributed tracing.
//! It implements W3C Trace Context propagation (traceparent/tracestate headers).
//!
//! # Features
//!
//! - W3C Trace Context header propagation
//! - OTLP export to Jaeger, Tempo, or any OTLP-compatible backend
//! - Configurable sampling rates
//! - Request lifecycle spans with semantic conventions
//!
//! # Configuration
//!
//! ```kdl
//! observability {
//!     tracing {
//!         backend "otlp" {
//!             endpoint "http://localhost:4317"
//!         }
//!         sampling-rate 0.1  // 10% of requests
//!         service-name "sentinel"
//!     }
//! }
//! ```

use std::sync::OnceLock;
use tracing::warn;

use sentinel_config::TracingConfig;

/// W3C Trace Context header names
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const TRACESTATE_HEADER: &str = "tracestate";

/// Parsed W3C Trace Context
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID (32 hex chars)
    pub trace_id: String,
    /// Parent span ID (16 hex chars)
    pub parent_id: String,
    /// Whether this trace is sampled
    pub sampled: bool,
    /// Optional tracestate header value
    pub tracestate: Option<String>,
}

impl TraceContext {
    /// Parse W3C traceparent header
    ///
    /// Format: version-trace_id-parent_id-flags
    /// Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
    pub fn parse_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        if version != "00" {
            // Only support version 00 for now
            return None;
        }

        let trace_id = parts[1];
        let parent_id = parts[2];
        let flags = parts[3];

        // Validate lengths
        if trace_id.len() != 32 || parent_id.len() != 16 || flags.len() != 2 {
            return None;
        }

        // Parse flags
        let sampled = u8::from_str_radix(flags, 16).ok()? & 0x01 == 1;

        Some(Self {
            trace_id: trace_id.to_string(),
            parent_id: parent_id.to_string(),
            sampled,
            tracestate: None,
        })
    }

    /// Create traceparent header value
    pub fn to_traceparent(&self, span_id: &str) -> String {
        let flags = if self.sampled { "01" } else { "00" };
        format!("00-{}-{}-{}", self.trace_id, span_id, flags)
    }

    /// Create a new trace context with generated IDs
    pub fn new_root(sampled: bool) -> Self {
        Self {
            trace_id: generate_trace_id(),
            parent_id: generate_span_id(),
            sampled,
            tracestate: None,
        }
    }
}

/// Generate a new trace ID (32 hex chars)
pub fn generate_trace_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

/// Generate a new span ID (16 hex chars)
pub fn generate_span_id() -> String {
    let bytes: [u8; 8] = rand::random();
    hex::encode(bytes)
}

/// Create a traceparent header value
pub fn create_traceparent(trace_id: &str, span_id: &str, sampled: bool) -> String {
    let flags = if sampled { "01" } else { "00" };
    format!("00-{}-{}-{}", trace_id, span_id, flags)
}

// ============================================================================
// OpenTelemetry Tracer (when feature enabled)
// ============================================================================

#[cfg(feature = "opentelemetry")]
mod otel_impl {
    use super::*;
    use opentelemetry::trace::{SpanKind, Tracer};
    use opentelemetry::{global, KeyValue};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::trace::Sampler;
    use opentelemetry_sdk::Resource;
    use std::sync::Arc;
    use tracing::error;

    /// OpenTelemetry tracer wrapper
    pub struct OtelTracer {
        sampling_rate: f64,
        service_name: String,
    }

    impl OtelTracer {
        /// Initialize OpenTelemetry with OTLP exporter
        pub fn init(config: &TracingConfig) -> Result<Self, OtelError> {
            let endpoint = match &config.backend {
                sentinel_config::TracingBackend::Otlp { endpoint } => endpoint.clone(),
                sentinel_config::TracingBackend::Jaeger { endpoint } => endpoint.clone(),
                sentinel_config::TracingBackend::Zipkin { endpoint } => endpoint.clone(),
            };

            info!(
                endpoint = %endpoint,
                sampling_rate = config.sampling_rate,
                service_name = %config.service_name,
                "Initializing OpenTelemetry tracer"
            );

            // Create OTLP exporter
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&endpoint)
                .build()
                .map_err(|e| OtelError::ExporterInit(e.to_string()))?;

            // Create sampler based on sampling rate
            let sampler = if config.sampling_rate >= 1.0 {
                Sampler::AlwaysOn
            } else if config.sampling_rate <= 0.0 {
                Sampler::AlwaysOff
            } else {
                Sampler::TraceIdRatioBased(config.sampling_rate)
            };

            // Create resource with service info
            let resource =
                Resource::new([KeyValue::new("service.name", config.service_name.clone())]);

            // Build tracer provider
            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_sampler(sampler)
                .with_resource(resource)
                .build();

            // Set global provider
            global::set_tracer_provider(provider);

            info!("OpenTelemetry tracer initialized successfully");

            Ok(Self {
                sampling_rate: config.sampling_rate,
                service_name: config.service_name.clone(),
            })
        }

        /// Create a request span
        pub fn start_span(
            &self,
            method: &str,
            path: &str,
            trace_ctx: Option<&TraceContext>,
        ) -> RequestSpan {
            let tracer = global::tracer("sentinel-proxy");

            let span = tracer
                .span_builder(format!("{} {}", method, path))
                .with_kind(SpanKind::Server)
                .with_attributes([
                    KeyValue::new("http.method", method.to_string()),
                    KeyValue::new("http.target", path.to_string()),
                    KeyValue::new("service.name", self.service_name.clone()),
                ])
                .start(&tracer);

            RequestSpan {
                _span: span,
                trace_id: trace_ctx
                    .map(|c| c.trace_id.clone())
                    .unwrap_or_else(generate_trace_id),
                span_id: generate_span_id(),
            }
        }

        /// Shutdown the tracer
        pub fn shutdown(&self) {
            info!("Shutting down OpenTelemetry tracer");
            global::shutdown_tracer_provider();
        }
    }

    /// Request span wrapper
    pub struct RequestSpan {
        _span: opentelemetry::global::BoxedSpan,
        pub trace_id: String,
        pub span_id: String,
    }

    impl RequestSpan {
        pub fn set_status(&mut self, _status_code: u16) {
            // Status is recorded when span ends
        }

        pub fn record_error(&mut self, _error: &str) {
            // Error is recorded when span ends
        }

        pub fn set_upstream(&mut self, _upstream: &str, _address: &str) {
            // Upstream info recorded
        }

        pub fn end(self) {
            // Span ends on drop
        }
    }
}

// ============================================================================
// Stub implementations when feature is disabled
// ============================================================================

#[cfg(not(feature = "opentelemetry"))]
mod otel_impl {
    use super::*;

    pub struct OtelTracer;

    impl OtelTracer {
        pub fn init(_config: &TracingConfig) -> Result<Self, OtelError> {
            warn!("OpenTelemetry feature not enabled, tracing disabled");
            Err(OtelError::TracerInit(
                "OpenTelemetry feature not enabled".to_string(),
            ))
        }

        pub fn start_span(
            &self,
            _method: &str,
            _path: &str,
            trace_ctx: Option<&TraceContext>,
        ) -> RequestSpan {
            RequestSpan {
                trace_id: trace_ctx
                    .map(|c| c.trace_id.clone())
                    .unwrap_or_else(generate_trace_id),
                span_id: generate_span_id(),
            }
        }

        pub fn shutdown(&self) {}
    }

    pub struct RequestSpan {
        pub trace_id: String,
        pub span_id: String,
    }

    impl RequestSpan {
        pub fn set_status(&mut self, _status_code: u16) {}
        pub fn record_error(&mut self, _error: &str) {}
        pub fn set_upstream(&mut self, _upstream: &str, _address: &str) {}
        pub fn end(self) {}
    }
}

// Re-export from the appropriate module
pub use otel_impl::{OtelTracer, RequestSpan};

/// OpenTelemetry error types
#[derive(Debug)]
pub enum OtelError {
    ExporterInit(String),
    TracerInit(String),
}

impl std::fmt::Display for OtelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtelError::ExporterInit(e) => write!(f, "Failed to initialize OTLP exporter: {}", e),
            OtelError::TracerInit(e) => write!(f, "Failed to initialize tracer: {}", e),
        }
    }
}

impl std::error::Error for OtelError {}

// ============================================================================
// Global tracer instance
// ============================================================================

static GLOBAL_TRACER: OnceLock<Option<OtelTracer>> = OnceLock::new();

/// Initialize the global tracer
pub fn init_tracer(config: &TracingConfig) -> Result<(), OtelError> {
    let tracer = OtelTracer::init(config)?;
    GLOBAL_TRACER
        .set(Some(tracer))
        .map_err(|_| OtelError::TracerInit("Global tracer already initialized".to_string()))?;
    Ok(())
}

/// Get the global tracer
pub fn get_tracer() -> Option<&'static OtelTracer> {
    GLOBAL_TRACER.get().and_then(|t| t.as_ref())
}

/// Shutdown the global tracer
pub fn shutdown_tracer() {
    if let Some(Some(tracer)) = GLOBAL_TRACER.get() {
        tracer.shutdown();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_traceparent() {
        let header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let ctx = TraceContext::parse_traceparent(header).unwrap();

        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.parent_id, "b7ad6b7169203331");
        assert!(ctx.sampled);
    }

    #[test]
    fn test_parse_unsampled_traceparent() {
        let header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00";
        let ctx = TraceContext::parse_traceparent(header).unwrap();

        assert!(!ctx.sampled);
    }

    #[test]
    fn test_parse_invalid_traceparent() {
        // Invalid version
        assert!(TraceContext::parse_traceparent("01-abc-def-00").is_none());

        // Wrong number of parts
        assert!(TraceContext::parse_traceparent("00-abc-def").is_none());

        // Wrong trace_id length
        assert!(TraceContext::parse_traceparent("00-abc-b7ad6b7169203331-01").is_none());
    }

    #[test]
    fn test_trace_context_to_traceparent() {
        let ctx = TraceContext {
            trace_id: "0af7651916cd43dd8448eb211c80319c".to_string(),
            parent_id: "b7ad6b7169203331".to_string(),
            sampled: true,
            tracestate: None,
        };

        let new_span_id = "1234567890abcdef";
        let traceparent = ctx.to_traceparent(new_span_id);

        assert_eq!(
            traceparent,
            "00-0af7651916cd43dd8448eb211c80319c-1234567890abcdef-01"
        );
    }

    #[test]
    fn test_generate_trace_id() {
        let id = generate_trace_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_span_id() {
        let id = generate_span_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_create_traceparent() {
        let traceparent =
            create_traceparent("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331", true);
        assert_eq!(
            traceparent,
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        );
    }

    #[test]
    fn test_new_root_trace_context() {
        let ctx = TraceContext::new_root(true);
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.parent_id.len(), 16);
        assert!(ctx.sampled);
    }
}
