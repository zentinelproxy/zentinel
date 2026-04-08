//! Filter dispatch for route-level filters (Headers, Compress, CORS, Timeout, Log).
//!
//! These filters are applied per-request based on the route configuration.
//! Each filter type hooks into the appropriate phase of the request lifecycle.

use std::sync::Arc;

use pingora::http::ResponseHeader;
use pingora_proxy::Session;
use tracing::{debug, trace};
use zentinel_config::{
    CompressFilter, Config, CorsFilter, Filter, FilterPhase, HeadersFilter, LogFilter,
    PathModifier, RedirectFilter, TimeoutFilter, UrlRewriteFilter,
};

use super::context::RequestContext;

/// Apply request-phase filters (CORS preflight, Timeout, Log, Headers).
///
/// Returns `Ok(true)` if a response was already sent (e.g. CORS preflight),
/// meaning the request should not continue to upstream.
pub async fn apply_request_filters(
    session: &mut Session,
    ctx: &mut RequestContext,
    config: &Config,
) -> pingora::Result<bool> {
    let route_config = match ctx.route_config.as_ref() {
        Some(rc) => Arc::clone(rc),
        None => return Ok(false),
    };

    for filter_id in &route_config.filters {
        let filter_config = match config.filters.get(filter_id) {
            Some(fc) => fc,
            None => continue,
        };

        match &filter_config.filter {
            Filter::Redirect(redirect) => {
                if apply_redirect(session, ctx, redirect).await? {
                    return Ok(true); // Redirect sent, short-circuit
                }
            }
            Filter::UrlRewrite(rewrite) => {
                apply_url_rewrite(session, ctx, rewrite);
            }
            Filter::Cors(cors) => {
                if apply_cors_preflight(session, ctx, cors).await? {
                    return Ok(true); // Preflight handled, short-circuit
                }
            }
            Filter::Timeout(timeout) => {
                apply_timeout_override(ctx, timeout);
            }
            Filter::Log(log) if log.log_request => {
                emit_request_log(ctx, log);
            }
            _ => {} // Other filter types handled in other phases
        }
    }

    Ok(false)
}

/// Apply request-phase header modifications to the upstream request.
pub fn apply_request_headers_filters(
    upstream_request: &mut pingora::http::RequestHeader,
    ctx: &RequestContext,
    config: &Config,
) {
    let route_config = match ctx.route_config.as_ref() {
        Some(rc) => rc,
        None => return,
    };

    for filter_id in &route_config.filters {
        let filter_config = match config.filters.get(filter_id) {
            Some(fc) => fc,
            None => continue,
        };

        if let Filter::Headers(h) = &filter_config.filter {
            if matches!(h.phase, FilterPhase::Request | FilterPhase::Both) {
                apply_headers_to_request(upstream_request, h, &ctx.trace_id);
            }
        }
    }
}

/// Apply response-phase filters (Headers, CORS, Compress setup, Log).
pub fn apply_response_filters(
    upstream_response: &mut ResponseHeader,
    ctx: &mut RequestContext,
    config: &Config,
) {
    let route_config = match ctx.route_config.as_ref() {
        Some(rc) => Arc::clone(rc),
        None => return,
    };

    for filter_id in &route_config.filters {
        let filter_config = match config.filters.get(filter_id) {
            Some(fc) => fc,
            None => continue,
        };

        match &filter_config.filter {
            Filter::Headers(h) => {
                if matches!(h.phase, FilterPhase::Response | FilterPhase::Both) {
                    apply_headers_to_response(upstream_response, h, &ctx.trace_id);
                }
            }
            Filter::Cors(cors) => {
                apply_cors_response_headers(upstream_response, ctx, cors);
            }
            Filter::Compress(compress) => {
                apply_compress_setup(upstream_response, ctx, compress);
            }
            Filter::Log(log) if log.log_response => {
                emit_response_log(ctx, log, upstream_response.status.as_u16());
            }
            _ => {}
        }
    }
}

// =============================================================================
// Headers Filter
// =============================================================================

fn apply_headers_to_request(
    req: &mut pingora::http::RequestHeader,
    filter: &HeadersFilter,
    trace_id: &str,
) {
    // Rename runs before set/add/remove
    for (old_name, new_name) in &filter.rename {
        if let Some(value) = req.headers.get(old_name).and_then(|v| v.to_str().ok()) {
            let owned = value.to_string();
            req.insert_header(new_name.clone(), &owned).ok();
            req.remove_header(old_name);
        }
    }
    for (name, value) in &filter.set {
        req.insert_header(name.clone(), value.as_str()).ok();
    }
    for (name, value) in &filter.add {
        req.append_header(name.clone(), value.as_str()).ok();
    }
    for name in &filter.remove {
        req.remove_header(name);
    }

    trace!(
        correlation_id = %trace_id,
        rename_count = filter.rename.len(),
        set_count = filter.set.len(),
        add_count = filter.add.len(),
        remove_count = filter.remove.len(),
        "Applied headers filter to request"
    );
}

fn apply_headers_to_response(resp: &mut ResponseHeader, filter: &HeadersFilter, trace_id: &str) {
    // Rename runs before set/add/remove
    for (old_name, new_name) in &filter.rename {
        if let Some(value) = resp.headers.get(old_name).and_then(|v| v.to_str().ok()) {
            let owned = value.to_string();
            resp.insert_header(new_name.clone(), &owned).ok();
            resp.remove_header(old_name);
        }
    }
    for (name, value) in &filter.set {
        resp.insert_header(name.clone(), value.as_str()).ok();
    }
    for (name, value) in &filter.add {
        resp.append_header(name.clone(), value.as_str()).ok();
    }
    for name in &filter.remove {
        resp.remove_header(name);
    }

    trace!(
        correlation_id = %trace_id,
        rename_count = filter.rename.len(),
        set_count = filter.set.len(),
        add_count = filter.add.len(),
        remove_count = filter.remove.len(),
        "Applied headers filter to response"
    );
}

// =============================================================================
// Redirect Filter
// =============================================================================

/// Apply a redirect filter by sending a redirect response. Returns true (short-circuit).
async fn apply_redirect(
    session: &mut Session,
    ctx: &RequestContext,
    redirect: &RedirectFilter,
) -> pingora::Result<bool> {
    let req = session.req_header();

    // Build Location URL from the original request, applying overrides
    let orig_scheme = if req.uri.scheme().is_some_and(|s| s.as_str() == "https") {
        "https"
    } else {
        "http"
    };
    let scheme = redirect.scheme.as_deref().unwrap_or(orig_scheme);

    let orig_host = req
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    // Strip port from host if present (we'll add port separately)
    let orig_host_no_port = orig_host.split(':').next().unwrap_or(orig_host);
    let host = redirect.hostname.as_deref().unwrap_or(orig_host_no_port);

    let orig_path = req.uri.path();
    let path = match &redirect.path {
        Some(PathModifier::ReplaceFullPath { value }) => value.to_string(),
        Some(PathModifier::ReplacePrefixMatch { value }) => {
            replace_matched_prefix(orig_path, ctx, value)
        }
        None => orig_path.to_string(),
    };

    let port_suffix = match redirect.port {
        Some(port) => {
            let is_default = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
            if is_default {
                String::new()
            } else {
                format!(":{port}")
            }
        }
        None => String::new(),
    };

    let location = format!("{scheme}://{host}{port_suffix}{path}");

    debug!(
        correlation_id = %ctx.trace_id,
        status = redirect.status_code,
        location = %location,
        "Applying redirect filter"
    );

    let mut header = ResponseHeader::build(redirect.status_code, None)?;
    header.insert_header("Location", &location)?;
    header.insert_header("Content-Length", "0")?;

    session
        .write_response_header(Box::new(header), true)
        .await?;
    Ok(true)
}

// =============================================================================
// URL Rewrite Filter
// =============================================================================

/// Apply a URL rewrite filter by modifying the request URI and/or Host header.
fn apply_url_rewrite(session: &mut Session, ctx: &RequestContext, rewrite: &UrlRewriteFilter) {
    // Rewrite hostname (Host header)
    if let Some(ref hostname) = rewrite.hostname {
        session
            .req_header_mut()
            .insert_header("Host", hostname.as_str())
            .ok();
    }

    // Rewrite path
    if let Some(ref path_mod) = rewrite.path {
        let orig_path = session.req_header().uri.path().to_string();
        let new_path = match path_mod {
            PathModifier::ReplaceFullPath { value } => value.clone(),
            PathModifier::ReplacePrefixMatch { value } => {
                replace_matched_prefix(&orig_path, ctx, value)
            }
        };
        // Rebuild the URI with the new path, preserving query string
        let query = session.req_header().uri.query();
        let new_uri = if let Some(q) = query {
            format!("{new_path}?{q}")
        } else {
            new_path
        };
        if let Ok(uri) = new_uri.parse::<http::Uri>() {
            session.req_header_mut().set_uri(uri);
        }
    }

    trace!(
        correlation_id = %ctx.trace_id,
        hostname = ?rewrite.hostname,
        path = ?rewrite.path,
        "Applied URL rewrite filter"
    );
}

/// Replace the matched path prefix, preserving the suffix.
///
/// Finds the longest `PathPrefix` from the route's match conditions, strips it
/// from the request path, and prepends the replacement value.
///
/// Example: prefix="/foo", request="/foo/bar", replacement="/baz" → "/baz/bar"
fn replace_matched_prefix(request_path: &str, ctx: &RequestContext, replacement: &str) -> String {
    // Find the matched prefix from the route's match conditions
    let matched_prefix = ctx
        .route_config
        .as_ref()
        .map(|rc| {
            rc.matches
                .iter()
                .filter_map(|m| match m {
                    zentinel_config::MatchCondition::PathPrefix(p) => Some(p.as_str()),
                    _ => None,
                })
                // Use the longest prefix that actually matches the request path
                .filter(|p| request_path.starts_with(p) || *p == "/")
                .max_by_key(|p| p.len())
                .unwrap_or("/")
        })
        .unwrap_or("/");

    // Strip the prefix and join with replacement
    let suffix = if matched_prefix == "/" {
        request_path
    } else {
        request_path
            .strip_prefix(matched_prefix)
            .unwrap_or(request_path)
    };

    // Normalize: avoid double slashes or missing slash
    let replacement = replacement.trim_end_matches('/');
    if suffix.is_empty() || suffix == "/" {
        if replacement.is_empty() {
            "/".to_string()
        } else {
            format!("{replacement}/")
        }
    } else if suffix.starts_with('/') {
        format!("{replacement}{suffix}")
    } else {
        format!("{replacement}/{suffix}")
    }
}

// =============================================================================
// CORS Filter
// =============================================================================

/// Handle CORS preflight (OPTIONS) requests. Returns true if handled.
async fn apply_cors_preflight(
    session: &mut Session,
    ctx: &mut RequestContext,
    cors: &CorsFilter,
) -> pingora::Result<bool> {
    let origin = match session
        .req_header()
        .headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
    {
        Some(o) => o.to_string(),
        None => return Ok(false), // No Origin header, not a CORS request
    };

    // Validate origin
    if !is_origin_allowed(&origin, &cors.allowed_origins) {
        return Ok(false); // Origin not allowed, continue normal processing
    }

    ctx.cors_origin = Some(origin.clone());

    // Check if this is a preflight OPTIONS request
    let is_preflight = session.req_header().method == http::Method::OPTIONS
        && session
            .req_header()
            .headers
            .get("access-control-request-method")
            .is_some();

    if !is_preflight {
        return Ok(false); // Not a preflight, CORS response headers applied later
    }

    debug!(
        correlation_id = %ctx.trace_id,
        origin = %origin,
        "Handling CORS preflight request"
    );

    // Build preflight response
    let mut header = ResponseHeader::build(204, None)?;
    header.insert_header("Access-Control-Allow-Origin", &origin)?;
    header.insert_header(
        "Access-Control-Allow-Methods",
        cors.allowed_methods.join(", "),
    )?;

    if !cors.allowed_headers.is_empty() {
        header.insert_header(
            "Access-Control-Allow-Headers",
            cors.allowed_headers.join(", "),
        )?;
    } else if let Some(requested) = session
        .req_header()
        .headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
    {
        // Mirror the requested headers
        header.insert_header("Access-Control-Allow-Headers", requested)?;
    }

    if cors.allow_credentials {
        header.insert_header("Access-Control-Allow-Credentials", "true")?;
    }

    header.insert_header("Access-Control-Max-Age", cors.max_age_secs.to_string())?;
    header.insert_header("Content-Length", "0")?;

    session
        .write_response_header(Box::new(header), true)
        .await?;
    Ok(true) // Preflight handled, short-circuit
}

/// Add CORS headers to a normal (non-preflight) response.
fn apply_cors_response_headers(resp: &mut ResponseHeader, ctx: &RequestContext, cors: &CorsFilter) {
    let origin = match &ctx.cors_origin {
        Some(o) => o.clone(),
        None => return, // No CORS origin matched
    };

    resp.insert_header("Access-Control-Allow-Origin", &origin)
        .ok();

    if cors.allow_credentials {
        resp.insert_header("Access-Control-Allow-Credentials", "true")
            .ok();
    }

    if !cors.exposed_headers.is_empty() {
        resp.insert_header(
            "Access-Control-Expose-Headers",
            cors.exposed_headers.join(", "),
        )
        .ok();
    }

    // Vary header to indicate origin-dependent responses
    resp.append_header("Vary", "Origin").ok();

    trace!(
        correlation_id = %ctx.trace_id,
        origin = %origin,
        "Applied CORS response headers"
    );
}

fn is_origin_allowed(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| a == "*" || a == origin)
}

// =============================================================================
// Compress Filter
// =============================================================================

/// Set up compression by modifying response headers.
///
/// We remove Content-Length (since compressed size differs) and add
/// Content-Encoding if the client supports it and the response is compressible.
fn apply_compress_setup(
    resp: &mut ResponseHeader,
    ctx: &mut RequestContext,
    compress: &CompressFilter,
) {
    // Check if response content type is compressible
    let content_type = resp
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_compressible = compress.content_types.iter().any(|ct| {
        // Match on the MIME type prefix (ignore charset/params)
        content_type.starts_with(ct.as_str())
    });

    if !is_compressible {
        return;
    }

    // Check Content-Length against min_size (if present)
    if let Some(cl) = resp
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if cl < compress.min_size {
            return;
        }
    }

    // Check if response is already encoded
    if resp.headers.get("content-encoding").is_some() {
        return;
    }

    // Mark that compression should be applied (Pingora handles actual compression
    // via its built-in compression module when downstream_compression is enabled)
    ctx.compress_enabled = true;

    trace!(
        correlation_id = %ctx.trace_id,
        content_type = %content_type,
        "Compression eligible, delegating to Pingora compression module"
    );
}

// =============================================================================
// Timeout Filter
// =============================================================================

fn apply_timeout_override(ctx: &mut RequestContext, timeout: &TimeoutFilter) {
    if let Some(connect) = timeout.connect_timeout_secs {
        ctx.filter_connect_timeout_secs = Some(connect);
    }
    if let Some(upstream) = timeout.upstream_timeout_secs {
        ctx.filter_upstream_timeout_secs = Some(upstream);
    }

    trace!(
        correlation_id = %ctx.trace_id,
        connect_timeout_secs = ?timeout.connect_timeout_secs,
        upstream_timeout_secs = ?timeout.upstream_timeout_secs,
        "Applied timeout filter overrides"
    );
}

// =============================================================================
// Log Filter
// =============================================================================

fn emit_request_log(ctx: &RequestContext, log: &LogFilter) {
    match log.level.as_str() {
        "trace" => trace!(
            correlation_id = %ctx.trace_id,
            method = %ctx.method,
            path = %ctx.path,
            client_ip = %ctx.client_ip,
            host = ?ctx.host,
            user_agent = ?ctx.user_agent,
            filter = "log",
            "Log filter: incoming request"
        ),
        "debug" => debug!(
            correlation_id = %ctx.trace_id,
            method = %ctx.method,
            path = %ctx.path,
            client_ip = %ctx.client_ip,
            host = ?ctx.host,
            user_agent = ?ctx.user_agent,
            filter = "log",
            "Log filter: incoming request"
        ),
        _ => tracing::info!(
            correlation_id = %ctx.trace_id,
            method = %ctx.method,
            path = %ctx.path,
            client_ip = %ctx.client_ip,
            host = ?ctx.host,
            user_agent = ?ctx.user_agent,
            filter = "log",
            "Log filter: incoming request"
        ),
    }
}

fn emit_response_log(ctx: &RequestContext, log: &LogFilter, status: u16) {
    let duration_ms = ctx.elapsed().as_millis();

    match log.level.as_str() {
        "trace" => trace!(
            correlation_id = %ctx.trace_id,
            status = status,
            duration_ms = duration_ms,
            response_bytes = ctx.response_bytes,
            upstream = ?ctx.upstream,
            filter = "log",
            "Log filter: response"
        ),
        "debug" => debug!(
            correlation_id = %ctx.trace_id,
            status = status,
            duration_ms = duration_ms,
            response_bytes = ctx.response_bytes,
            upstream = ?ctx.upstream,
            filter = "log",
            "Log filter: response"
        ),
        _ => tracing::info!(
            correlation_id = %ctx.trace_id,
            status = status,
            duration_ms = duration_ms,
            response_bytes = ctx.response_bytes,
            upstream = ?ctx.upstream,
            filter = "log",
            "Log filter: response"
        ),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use pingora::http::RequestHeader as PingoraRequestHeader;
    use zentinel_config::{
        filters::FilterConfig, CompressFilter, CorsFilter, FilterPhase, HeadersFilter, LogFilter,
        TimeoutFilter,
    };

    // =========================================================================
    // Test helpers
    // =========================================================================

    /// Build a minimal Config + RouteConfig with a single filter for testing.
    fn test_config_with_filter(
        filter_id: &str,
        filter: Filter,
    ) -> (Arc<Config>, Arc<zentinel_config::RouteConfig>) {
        let mut config = Config::default_for_testing();
        config
            .filters
            .insert(filter_id.to_string(), FilterConfig::new(filter_id, filter));
        config.routes[0].filters = vec![filter_id.to_string()];
        let route = Arc::new(config.routes[0].clone());
        (Arc::new(config), route)
    }

    fn new_ctx_with_route(route: &Arc<zentinel_config::RouteConfig>) -> RequestContext {
        let mut ctx = RequestContext::new();
        ctx.trace_id = "test-trace-id".to_string();
        ctx.method = "GET".to_string();
        ctx.path = "/test".to_string();
        ctx.client_ip = "127.0.0.1".to_string();
        ctx.route_config = Some(Arc::clone(route));
        ctx
    }

    // =========================================================================
    // Headers filter tests
    // =========================================================================

    #[test]
    fn headers_filter_sets_request_headers() {
        let mut set = HashMap::new();
        set.insert("X-Custom".to_string(), "value".to_string());
        let mut add = HashMap::new();
        add.insert("X-Added".to_string(), "added-value".to_string());

        let headers_filter = HeadersFilter {
            phase: FilterPhase::Request,
            set,
            add,
            remove: vec!["X-Remove-Me".to_string()],
            ..Default::default()
        };

        let (config, route) = test_config_with_filter("hdr", Filter::Headers(headers_filter));
        let ctx = new_ctx_with_route(&route);

        let mut req = PingoraRequestHeader::build("GET", b"/test", None).unwrap();
        req.insert_header("X-Remove-Me", "should-be-gone").unwrap();

        apply_request_headers_filters(&mut req, &ctx, &config);

        assert_eq!(
            req.headers.get("X-Custom").map(|v| v.to_str().unwrap()),
            Some("value")
        );
        assert_eq!(
            req.headers.get("X-Added").map(|v| v.to_str().unwrap()),
            Some("added-value")
        );
        assert!(req.headers.get("X-Remove-Me").is_none());
    }

    #[test]
    fn headers_filter_sets_response_headers() {
        let mut set = HashMap::new();
        set.insert("X-Resp".to_string(), "resp-val".to_string());

        let headers_filter = HeadersFilter {
            phase: FilterPhase::Response,
            set,
            add: HashMap::new(),
            remove: vec!["Server".to_string()],
            ..Default::default()
        };

        let (config, route) = test_config_with_filter("hdr", Filter::Headers(headers_filter));
        let mut ctx = new_ctx_with_route(&route);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Server", "hidden").unwrap();

        apply_response_filters(&mut resp, &mut ctx, &config);

        assert_eq!(
            resp.headers.get("X-Resp").map(|v| v.to_str().unwrap()),
            Some("resp-val")
        );
        assert!(resp.headers.get("Server").is_none());
    }

    #[test]
    fn headers_filter_both_phase_applies_to_both() {
        let mut set = HashMap::new();
        set.insert("X-Both".to_string(), "present".to_string());

        let headers_filter = HeadersFilter {
            phase: FilterPhase::Both,
            set,
            add: HashMap::new(),
            remove: vec![],
            ..Default::default()
        };

        let (config, route) = test_config_with_filter("hdr", Filter::Headers(headers_filter));
        let mut ctx = new_ctx_with_route(&route);

        // Request phase
        let mut req = PingoraRequestHeader::build("GET", b"/test", None).unwrap();
        apply_request_headers_filters(&mut req, &ctx, &config);
        assert_eq!(
            req.headers.get("X-Both").map(|v| v.to_str().unwrap()),
            Some("present")
        );

        // Response phase
        let mut resp = ResponseHeader::build(200, None).unwrap();
        apply_response_filters(&mut resp, &mut ctx, &config);
        assert_eq!(
            resp.headers.get("X-Both").map(|v| v.to_str().unwrap()),
            Some("present")
        );
    }

    // =========================================================================
    // CORS filter tests
    // =========================================================================

    #[test]
    fn cors_response_headers_added_for_allowed_origin() {
        let cors = CorsFilter {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec![],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_secs: 3600,
        };

        let (config, route) = test_config_with_filter("cors", Filter::Cors(cors));
        let mut ctx = new_ctx_with_route(&route);
        ctx.cors_origin = Some("https://example.com".to_string());

        let mut resp = ResponseHeader::build(200, None).unwrap();
        apply_response_filters(&mut resp, &mut ctx, &config);

        assert_eq!(
            resp.headers
                .get("Access-Control-Allow-Origin")
                .map(|v| v.to_str().unwrap()),
            Some("https://example.com")
        );
        assert_eq!(
            resp.headers.get("Vary").map(|v| v.to_str().unwrap()),
            Some("Origin")
        );
    }

    #[test]
    fn cors_credentials_header_when_enabled() {
        let cors = CorsFilter {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            exposed_headers: vec![],
            allow_credentials: true,
            max_age_secs: 3600,
        };

        let (config, route) = test_config_with_filter("cors", Filter::Cors(cors));
        let mut ctx = new_ctx_with_route(&route);
        ctx.cors_origin = Some("https://app.test".to_string());

        let mut resp = ResponseHeader::build(200, None).unwrap();
        apply_response_filters(&mut resp, &mut ctx, &config);

        assert_eq!(
            resp.headers
                .get("Access-Control-Allow-Credentials")
                .map(|v| v.to_str().unwrap()),
            Some("true")
        );
    }

    #[test]
    fn cors_exposed_headers_set() {
        let cors = CorsFilter {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            exposed_headers: vec!["X-Request-Id".to_string(), "X-Trace-Id".to_string()],
            allow_credentials: false,
            max_age_secs: 3600,
        };

        let (config, route) = test_config_with_filter("cors", Filter::Cors(cors));
        let mut ctx = new_ctx_with_route(&route);
        ctx.cors_origin = Some("https://app.test".to_string());

        let mut resp = ResponseHeader::build(200, None).unwrap();
        apply_response_filters(&mut resp, &mut ctx, &config);

        assert_eq!(
            resp.headers
                .get("Access-Control-Expose-Headers")
                .map(|v| v.to_str().unwrap()),
            Some("X-Request-Id, X-Trace-Id")
        );
    }

    #[test]
    fn cors_no_headers_when_no_origin_matched() {
        let cors = CorsFilter {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_secs: 3600,
        };

        let (config, route) = test_config_with_filter("cors", Filter::Cors(cors));
        let mut ctx = new_ctx_with_route(&route);
        // cors_origin is None — origin did not match

        let mut resp = ResponseHeader::build(200, None).unwrap();
        apply_response_filters(&mut resp, &mut ctx, &config);

        assert!(resp.headers.get("Access-Control-Allow-Origin").is_none());
    }

    #[test]
    fn cors_origin_validation_wildcard() {
        assert!(is_origin_allowed(
            "https://anything.test",
            &["*".to_string()]
        ));
    }

    #[test]
    fn cors_origin_validation_exact_match() {
        let allowed = vec!["https://example.com".to_string()];
        assert!(is_origin_allowed("https://example.com", &allowed));
        assert!(!is_origin_allowed("https://other.com", &allowed));
    }

    #[test]
    fn cors_origin_validation_empty_list() {
        assert!(!is_origin_allowed("https://example.com", &[]));
    }

    // =========================================================================
    // Compress filter tests
    // =========================================================================

    #[test]
    fn compress_enables_for_compressible_content() {
        let compress = CompressFilter {
            algorithms: vec![],
            min_size: 1024,
            content_types: vec!["text/".to_string()],
            level: 6,
        };

        let (config, route) = test_config_with_filter("gz", Filter::Compress(compress));
        let mut ctx = new_ctx_with_route(&route);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "text/html; charset=utf-8")
            .unwrap();
        resp.insert_header("Content-Length", "5000").unwrap();

        apply_response_filters(&mut resp, &mut ctx, &config);

        assert!(
            ctx.compress_enabled,
            "Should enable compression for text/html > 1024 bytes"
        );
    }

    #[test]
    fn compress_skips_small_responses() {
        let compress = CompressFilter {
            algorithms: vec![],
            min_size: 1024,
            content_types: vec!["text/".to_string()],
            level: 6,
        };

        let (config, route) = test_config_with_filter("gz", Filter::Compress(compress));
        let mut ctx = new_ctx_with_route(&route);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "text/html").unwrap();
        resp.insert_header("Content-Length", "100").unwrap();

        apply_response_filters(&mut resp, &mut ctx, &config);

        assert!(
            !ctx.compress_enabled,
            "Should skip compression for responses smaller than min_size"
        );
    }

    #[test]
    fn compress_skips_non_compressible_types() {
        let compress = CompressFilter {
            algorithms: vec![],
            min_size: 1024,
            content_types: vec!["text/".to_string(), "application/json".to_string()],
            level: 6,
        };

        let (config, route) = test_config_with_filter("gz", Filter::Compress(compress));
        let mut ctx = new_ctx_with_route(&route);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "image/png").unwrap();
        resp.insert_header("Content-Length", "50000").unwrap();

        apply_response_filters(&mut resp, &mut ctx, &config);

        assert!(
            !ctx.compress_enabled,
            "Should skip compression for non-compressible content types"
        );
    }

    #[test]
    fn compress_skips_already_encoded() {
        let compress = CompressFilter {
            algorithms: vec![],
            min_size: 1024,
            content_types: vec!["text/".to_string()],
            level: 6,
        };

        let (config, route) = test_config_with_filter("gz", Filter::Compress(compress));
        let mut ctx = new_ctx_with_route(&route);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("Content-Type", "text/html").unwrap();
        resp.insert_header("Content-Length", "5000").unwrap();
        resp.insert_header("Content-Encoding", "gzip").unwrap();

        apply_response_filters(&mut resp, &mut ctx, &config);

        assert!(
            !ctx.compress_enabled,
            "Should skip compression for already-encoded responses"
        );
    }

    // =========================================================================
    // Timeout filter tests
    // =========================================================================

    #[test]
    fn timeout_filter_sets_connect_override() {
        let timeout = TimeoutFilter {
            request_timeout_secs: None,
            upstream_timeout_secs: None,
            connect_timeout_secs: Some(5),
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "test".to_string();
        apply_timeout_override(&mut ctx, &timeout);

        assert_eq!(ctx.filter_connect_timeout_secs, Some(5));
        assert_eq!(ctx.filter_upstream_timeout_secs, None);
    }

    #[test]
    fn timeout_filter_sets_upstream_override() {
        let timeout = TimeoutFilter {
            request_timeout_secs: None,
            upstream_timeout_secs: Some(30),
            connect_timeout_secs: None,
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "test".to_string();
        apply_timeout_override(&mut ctx, &timeout);

        assert_eq!(ctx.filter_upstream_timeout_secs, Some(30));
        assert_eq!(ctx.filter_connect_timeout_secs, None);
    }

    #[test]
    fn timeout_filter_sets_both_overrides() {
        let timeout = TimeoutFilter {
            request_timeout_secs: Some(60),
            upstream_timeout_secs: Some(30),
            connect_timeout_secs: Some(5),
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "test".to_string();
        apply_timeout_override(&mut ctx, &timeout);

        assert_eq!(ctx.filter_connect_timeout_secs, Some(5));
        assert_eq!(ctx.filter_upstream_timeout_secs, Some(30));
    }

    // =========================================================================
    // Log filter tests (smoke tests — verify no panics)
    // =========================================================================

    #[test]
    fn log_filter_emits_at_request_phase() {
        let log = LogFilter {
            log_request: true,
            log_response: false,
            log_body: false,
            max_body_log_size: 1024,
            fields: vec![],
            level: "info".to_string(),
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "log-test".to_string();
        ctx.method = "POST".to_string();
        ctx.path = "/api/data".to_string();
        ctx.client_ip = "10.0.0.1".to_string();
        ctx.host = Some("example.com".to_string());
        ctx.user_agent = Some("test-agent/1.0".to_string());

        // Should not panic
        emit_request_log(&ctx, &log);
    }

    #[test]
    fn log_filter_emits_at_response_phase() {
        let log = LogFilter {
            log_request: false,
            log_response: true,
            log_body: false,
            max_body_log_size: 1024,
            fields: vec![],
            level: "debug".to_string(),
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "log-test".to_string();
        ctx.response_bytes = 4096;
        ctx.upstream = Some("backend".to_string());

        // Should not panic
        emit_response_log(&ctx, &log, 200);
    }

    #[test]
    fn log_filter_trace_level() {
        let log = LogFilter {
            log_request: true,
            log_response: true,
            log_body: false,
            max_body_log_size: 1024,
            fields: vec![],
            level: "trace".to_string(),
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "trace-test".to_string();
        ctx.method = "GET".to_string();
        ctx.path = "/".to_string();
        ctx.client_ip = "::1".to_string();

        // Both should not panic
        emit_request_log(&ctx, &log);
        emit_response_log(&ctx, &log, 404);
    }

    // =========================================================================
    // ReplacePrefixMatch tests
    // =========================================================================

    fn ctx_with_prefix(prefix: &str) -> RequestContext {
        use zentinel_common::types::Priority;
        use zentinel_config::{MatchCondition, RouteConfig, RoutePolicies, ServiceType};

        let route = RouteConfig {
            id: "test".to_string(),
            priority: Priority::NORMAL,
            matches: vec![MatchCondition::PathPrefix(prefix.to_string())],
            upstream: None,
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            circuit_breaker: None,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            inference: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            shadow: None,
            fallback: None,
        };

        let mut ctx = RequestContext::new();
        ctx.trace_id = "test".to_string();
        ctx.route_config = Some(Arc::new(route));
        ctx
    }

    #[test]
    fn replace_prefix_basic() {
        let ctx = ctx_with_prefix("/foo");
        assert_eq!(replace_matched_prefix("/foo/bar", &ctx, "/baz"), "/baz/bar");
    }

    #[test]
    fn replace_prefix_exact_match() {
        let ctx = ctx_with_prefix("/foo");
        assert_eq!(replace_matched_prefix("/foo", &ctx, "/baz"), "/baz/");
    }

    #[test]
    fn replace_prefix_root() {
        let ctx = ctx_with_prefix("/");
        assert_eq!(
            replace_matched_prefix("/anything", &ctx, "/new"),
            "/new/anything"
        );
    }

    #[test]
    fn replace_prefix_empty_replacement() {
        let ctx = ctx_with_prefix("/old");
        assert_eq!(replace_matched_prefix("/old/path", &ctx, ""), "/path");
    }

    #[test]
    fn replace_prefix_trailing_slash() {
        let ctx = ctx_with_prefix("/api");
        assert_eq!(
            replace_matched_prefix("/api/v1/users", &ctx, "/v2"),
            "/v2/v1/users"
        );
    }
}
