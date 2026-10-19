//! Configuration validation functions
//!
//! This module contains all validation logic for the configuration,
//! including semantic validation and cross-reference checking.
//!
//! # Scoped Validation
//!
//! The [`ValidationContext`] provides scope-aware validation for namespaced
//! configurations. It tracks resources by scope and validates cross-references
//! using the resolution rules (local → parent → exported → global).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use tracing::{debug, trace, warn};

use crate::{
    Config, Filter, ListenerProtocol, NamespaceConfig, ServiceConfig, ServiceType, WafMode,
};
use zentinel_common::ids::Scope;
use zentinel_common::types::Priority;

/// Whether checks that look at the local disk can run.
///
/// The playground builds this crate for `wasm32-unknown-unknown`, where there
/// is no filesystem and every path reports as missing. Skipping those checks
/// there lets the rest of the semantic validation run in the browser instead
/// of failing every config that names a path.
pub(crate) const HAS_FILESYSTEM: bool = !cfg!(all(target_arch = "wasm32", target_os = "unknown"));

// ============================================================================
// Field Validators
// ============================================================================

/// Validate socket address format
pub fn validate_socket_addr(addr: &str) -> Result<(), validator::ValidationError> {
    check_listen_address(addr).map_err(|message| {
        let mut err = validator::ValidationError::new("invalid_socket_address");
        err.message = Some(std::borrow::Cow::Owned(message));
        err
    })
}

/// Check that `addr` is a literal socket address a listener can bind to.
///
/// Returns a human-readable message on failure. Values containing `${` get an
/// extra hint, because the docs once advertised environment-variable
/// substitution that the config loader does not perform (#520).
pub fn check_listen_address(addr: &str) -> Result<(), String> {
    if addr.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let mut message = format!(
        "invalid socket address '{}'. Expected format: IP:PORT (e.g., '127.0.0.1:8080' or '0.0.0.0:443')",
        addr
    );
    if addr.contains("${") {
        message.push_str("; ");
        message.push_str(NO_ENV_SUBSTITUTION);
    }
    Err(message)
}

/// Hint for a value containing `${`: there is no substitution step.
pub const NO_ENV_SUBSTITUTION: &str =
    "contains '${...}', but environment variables are not substituted in configuration values";

// ============================================================================
// Validation Context
// ============================================================================

/// Context for scope-aware configuration validation.
///
/// This struct tracks all resources by scope and enables validation of
/// cross-references between scopes following the resolution rules.
#[derive(Debug, Default)]
pub struct ValidationContext {
    /// All canonical IDs for duplicate detection (e.g., "api:payments:checkout")
    pub all_ids: HashSet<String>,

    /// Upstreams indexed by scope
    upstreams_by_scope: HashMap<Scope, HashSet<String>>,

    /// Agents indexed by scope
    agents_by_scope: HashMap<Scope, HashSet<String>>,

    /// Filters indexed by scope
    filters_by_scope: HashMap<Scope, HashSet<String>>,

    /// Routes indexed by scope
    routes_by_scope: HashMap<Scope, HashSet<String>>,

    /// Exported upstream names (local name only)
    exported_upstreams: HashSet<String>,

    /// Exported agent names (local name only)
    exported_agents: HashSet<String>,

    /// Exported filter names (local name only)
    exported_filters: HashSet<String>,
}

impl ValidationContext {
    /// Create a new validation context from a configuration.
    pub fn from_config(config: &Config) -> Self {
        let mut ctx = Self::default();

        // Register global resources
        ctx.register_global_resources(config);

        // Register namespace and service resources
        for ns in &config.namespaces {
            ctx.register_namespace_resources(ns);
        }

        ctx
    }

    fn register_global_resources(&mut self, config: &Config) {
        let scope = Scope::Global;

        // Global upstreams
        for id in config.upstreams.keys() {
            self.upstreams_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(id.clone());
        }

        // Global agents
        for agent in &config.agents {
            self.agents_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(agent.id.clone());
            self.all_ids.insert(agent.id.clone());
        }

        // Global filters
        for id in config.filters.keys() {
            self.filters_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(id.clone());
        }

        // Global routes
        for route in &config.routes {
            self.routes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(route.id.clone());
            self.all_ids.insert(route.id.clone());
        }
    }

    fn register_namespace_resources(&mut self, ns: &NamespaceConfig) {
        let scope = Scope::Namespace(ns.id.clone());

        // Namespace upstreams
        for id in ns.upstreams.keys() {
            self.upstreams_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, id));

            // Track exports
            if ns.exports.upstreams.contains(id) {
                self.exported_upstreams.insert(id.clone());
            }
        }

        // Namespace agents
        for agent in &ns.agents {
            self.agents_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(agent.id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, agent.id));

            // Track exports
            if ns.exports.agents.contains(&agent.id) {
                self.exported_agents.insert(agent.id.clone());
            }
        }

        // Namespace filters
        for id in ns.filters.keys() {
            self.filters_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, id));

            // Track exports
            if ns.exports.filters.contains(id) {
                self.exported_filters.insert(id.clone());
            }
        }

        // Namespace routes
        for route in &ns.routes {
            self.routes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(route.id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, route.id));
        }

        // Register services within namespace
        for svc in &ns.services {
            self.register_service_resources(&ns.id, svc);
        }
    }

    fn register_service_resources(&mut self, ns_id: &str, svc: &ServiceConfig) {
        let scope = Scope::Service {
            namespace: ns_id.to_string(),
            service: svc.id.clone(),
        };

        // Service upstreams
        for id in svc.upstreams.keys() {
            self.upstreams_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}:{}", ns_id, svc.id, id));
        }

        // Service agents
        for agent in &svc.agents {
            self.agents_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(agent.id.clone());
            self.all_ids
                .insert(format!("{}:{}:{}", ns_id, svc.id, agent.id));
        }

        // Service filters
        for id in svc.filters.keys() {
            self.filters_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}:{}", ns_id, svc.id, id));
        }

        // Service routes
        for route in &svc.routes {
            self.routes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(route.id.clone());
            self.all_ids
                .insert(format!("{}:{}:{}", ns_id, svc.id, route.id));
        }
    }

    /// Check if an upstream reference can be resolved from the given scope.
    ///
    /// Resolution order: local scope → parent scope → exported → global
    pub fn can_resolve_upstream(&self, reference: &str, from_scope: &Scope) -> bool {
        // Check if it's a qualified reference (contains ':')
        if reference.contains(':') {
            // Qualified references must match exactly
            return self.all_ids.contains(reference);
        }

        // Unqualified reference - search scope chain
        for scope in from_scope.chain() {
            if let Some(upstreams) = self.upstreams_by_scope.get(&scope) {
                if upstreams.contains(reference) {
                    return true;
                }
            }
        }

        // Check exports (for cross-namespace access)
        if self.exported_upstreams.contains(reference) {
            return true;
        }

        false
    }

    /// Check if an agent reference can be resolved from the given scope.
    pub fn can_resolve_agent(&self, reference: &str, from_scope: &Scope) -> bool {
        if reference.contains(':') {
            return self.all_ids.contains(reference);
        }

        for scope in from_scope.chain() {
            if let Some(agents) = self.agents_by_scope.get(&scope) {
                if agents.contains(reference) {
                    return true;
                }
            }
        }

        if self.exported_agents.contains(reference) {
            return true;
        }

        false
    }

    /// Check if a filter reference can be resolved from the given scope.
    pub fn can_resolve_filter(&self, reference: &str, from_scope: &Scope) -> bool {
        if reference.contains(':') {
            return self.all_ids.contains(reference);
        }

        for scope in from_scope.chain() {
            if let Some(filters) = self.filters_by_scope.get(&scope) {
                if filters.contains(reference) {
                    return true;
                }
            }
        }

        if self.exported_filters.contains(reference) {
            return true;
        }

        false
    }

    /// Get all upstreams available from a given scope.
    pub fn available_upstreams(&self, from_scope: &Scope) -> HashSet<String> {
        let mut available = HashSet::new();

        for scope in from_scope.chain() {
            if let Some(upstreams) = self.upstreams_by_scope.get(&scope) {
                available.extend(upstreams.iter().cloned());
            }
        }

        available.extend(self.exported_upstreams.iter().cloned());
        available
    }

    /// Get all agents available from a given scope.
    pub fn available_agents(&self, from_scope: &Scope) -> HashSet<String> {
        let mut available = HashSet::new();

        for scope in from_scope.chain() {
            if let Some(agents) = self.agents_by_scope.get(&scope) {
                available.extend(agents.iter().cloned());
            }
        }

        available.extend(self.exported_agents.iter().cloned());
        available
    }

    /// Get all filters available from a given scope.
    pub fn available_filters(&self, from_scope: &Scope) -> HashSet<String> {
        let mut available = HashSet::new();

        for scope in from_scope.chain() {
            if let Some(filters) = self.filters_by_scope.get(&scope) {
                available.extend(filters.iter().cloned());
            }
        }

        available.extend(self.exported_filters.iter().cloned());
        available
    }
}

// ============================================================================
// Semantic Validation
// ============================================================================

/// Comprehensive semantic validation for the entire configuration
pub fn validate_config_semantics(config: &Config) -> Result<(), validator::ValidationError> {
    trace!(
        routes = config.routes.len(),
        upstreams = config.upstreams.len(),
        agents = config.agents.len(),
        filters = config.filters.len(),
        listeners = config.listeners.len(),
        "Starting semantic validation"
    );

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Collect IDs for cross-reference validation
    let route_ids: HashSet<_> = config.routes.iter().map(|r| r.id.as_str()).collect();
    let upstream_ids: HashSet<_> = config.upstreams.keys().map(|s| s.as_str()).collect();
    let agent_ids: HashSet<_> = config.agents.iter().map(|a| a.id.as_str()).collect();
    let filter_ids: HashSet<_> = config.filters.keys().map(|s| s.as_str()).collect();

    trace!(
        route_count = route_ids.len(),
        upstream_count = upstream_ids.len(),
        agent_count = agent_ids.len(),
        filter_count = filter_ids.len(),
        "Collected IDs for cross-reference validation"
    );

    // Validate server-wide settings
    if config.server.route_cache_size == 0 {
        errors.push(
            "server.route-cache-size must be greater than 0 (the route cache cannot be disabled \
             by setting it to zero)"
                .to_string(),
        );
    }

    // Validate routes
    trace!("Validating routes");
    validate_routes(config, &route_ids, &upstream_ids, &filter_ids, &mut errors);

    // Validate inline API schemas compile
    #[cfg(feature = "runtime")]
    validate_api_schemas(config, &mut errors);

    // Validate listeners
    trace!("Validating listeners");
    validate_listeners(config, &route_ids, &mut errors);

    // Validate ACME domains (global uniqueness)
    trace!("Validating ACME domains");
    validate_acme_domains(config, &mut errors);

    // Validate filters
    trace!("Validating filters");
    validate_filters(config, &agent_ids, &mut errors);

    // Validate upstreams
    trace!("Validating upstreams");
    validate_upstreams(config, &mut errors);

    // Validate agents
    trace!("Validating agents");
    validate_agents(config, &mut errors);

    // Validate duplicates
    trace!("Checking for duplicates");
    validate_duplicates(config, &mut errors);

    // Validate namespaces and services
    trace!("Validating namespaces");
    let ctx = ValidationContext::from_config(config);
    validate_namespaces(config, &ctx, &mut errors);

    // Warn about orphaned upstreams
    warn_orphaned_upstreams(config, &upstream_ids);

    // Validate implementation status (detect configured-but-unwired features)
    trace!("Validating implementation status");
    validate_implementation_status(config, &mut errors, &mut warnings);

    // Emit warnings for partially-implemented features
    for warning in &warnings {
        warn!("Unwired feature: {}", warning);
    }

    // Build final error
    if errors.is_empty() {
        debug!("Semantic validation passed");
    } else {
        debug!(
            error_count = errors.len(),
            "Semantic validation found errors"
        );
    }

    build_validation_result(errors)
}

/// Compile every inline `request-schema` / `response-schema` the way the proxy
/// will.
///
/// The proxy compiles them when it builds a route, and a schema that did not
/// compile used to cost only a startup warning: the route then ran with no
/// validation at all, so `api-schema` failed open on a security control while
/// `zentinel test` reported the file fine (#524). Rejecting it here makes
/// `test`, startup and reload all refuse it.
#[cfg(feature = "runtime")]
fn validate_api_schemas(config: &Config, errors: &mut Vec<String>) {
    for route in &config.routes {
        let Some(api_schema) = &route.api_schema else {
            continue;
        };
        for (kind, schema) in [
            ("request-schema", &api_schema.request_schema),
            ("response-schema", &api_schema.response_schema),
        ] {
            if let Some(schema) = schema {
                if let Err(e) = jsonschema::draft7::new(schema) {
                    errors.push(format!(
                        "Route '{}' {} is not a valid JSON Schema: {}. \
                         The route would run without validation.",
                        route.id, kind, e
                    ));
                }
            }
        }
    }
}

fn validate_routes(
    config: &Config,
    _route_ids: &HashSet<&str>,
    upstream_ids: &HashSet<&str>,
    filter_ids: &HashSet<&str>,
    errors: &mut Vec<String>,
) {
    trace!(
        route_count = config.routes.len(),
        "Validating route configurations"
    );

    // Routes needing upstreams
    let routes_needing_upstreams: Vec<_> = config
        .routes
        .iter()
        .filter(|r| r.service_type != ServiceType::Static && r.upstream.is_some())
        .collect();

    let routes_missing_upstream_config: Vec<_> = config
        .routes
        .iter()
        .filter(|r| {
            r.service_type != ServiceType::Static
                && r.service_type != ServiceType::Builtin
                && r.upstream.is_none()
                && r.static_files.is_none()
                // Routes with redirect/rewrite filters don't need an upstream
                // (the filter short-circuits before upstream selection)
                && !r.filters.iter().any(|fid| {
                    config.filters.get(fid).is_some_and(|fc| {
                        matches!(
                            fc.filter,
                            crate::Filter::Redirect(_) | crate::Filter::UrlRewrite(_)
                        )
                    })
                })
        })
        .collect();

    trace!(
        routes_with_upstreams = routes_needing_upstreams.len(),
        routes_missing_config = routes_missing_upstream_config.len(),
        "Categorized routes for validation"
    );

    // Validate routes have valid upstream references
    for route in &routes_needing_upstreams {
        if let Some(ref upstream_id) = route.upstream {
            if !upstream_ids.contains(upstream_id.as_str()) {
                errors.push(format!(
                    "Route '{}' references upstream '{}' which doesn't exist.\n\
                     Available upstreams: {}\n\
                     Hint: Add an upstream block or fix the reference.",
                    route.id,
                    upstream_id,
                    format_available(upstream_ids)
                ));
            }
        }
    }

    // Warn about non-static routes without upstream or static-files.
    // These routes are valid in Gateway API mode (e.g. invalid backend refs
    // that should return 500), so we only warn rather than error.
    for route in &routes_missing_upstream_config {
        warn!(
            route_id = %route.id,
            "Route has no upstream and no static-files configuration (will return 500)"
        );
    }

    // Validate filter references in routes
    for route in &config.routes {
        for filter_id in &route.filters {
            if !filter_ids.contains(filter_id.as_str()) {
                errors.push(format!(
                    "Route '{}' references filter '{}' which doesn't exist.\n\
                     Available filters: {}",
                    route.id,
                    filter_id,
                    format_available(filter_ids)
                ));
            }
        }
    }

    // Validate routes have at least one match condition
    for route in &config.routes {
        if route.matches.is_empty() && route.priority != Priority::LOW {
            errors.push(format!(
                "Route '{}' has no match conditions.\n\
                 Add at least one match condition or set priority to \"low\" for catch-all routes.",
                route.id
            ));
        }
    }

    // Validate static file configurations
    for route in &config.routes {
        if let Some(ref static_config) = route.static_files {
            if !HAS_FILESYSTEM {
                // No disk to check the root against.
            } else if !static_config.root.exists() {
                errors.push(format!(
                    "Route '{}' static files root directory '{}' does not exist.",
                    route.id,
                    static_config.root.display()
                ));
            } else if !static_config.root.is_dir() {
                errors.push(format!(
                    "Route '{}' static files root '{}' exists but is not a directory.",
                    route.id,
                    static_config.root.display()
                ));
            }

            if route.upstream.is_some() {
                errors.push(format!(
                    "Route '{}' has both 'upstream' and 'static-files' configured.\n\
                     A route can only serve one type of content.",
                    route.id
                ));
            }
        }
    }
}

/// Whether two bind addresses contend for the same socket.
///
/// Compares parsed addresses rather than strings: `0.0.0.0:9090` and
/// `127.0.0.1:9090` are different strings that cannot both be bound, because a
/// wildcard bind covers every interface on that port. Unparseable addresses are
/// treated as non-colliding — they are rejected elsewhere with a better message.
fn addresses_collide(a: &str, b: &str) -> bool {
    use std::net::SocketAddr;

    let (Ok(a), Ok(b)) = (a.parse::<SocketAddr>(), b.parse::<SocketAddr>()) else {
        return false;
    };
    if a.port() != b.port() {
        return false;
    }
    a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified()
}

fn validate_listeners(config: &Config, route_ids: &HashSet<&str>, errors: &mut Vec<String>) {
    trace!(
        listener_count = config.listeners.len(),
        "Validating listener configurations"
    );

    for listener in &config.listeners {
        trace!(listener_id = %listener.id, "Validating listener");
        if let Some(ref default_route) = listener.default_route {
            if !route_ids.contains(default_route.as_str()) {
                warn!(
                    listener_id = %listener.id,
                    default_route = %default_route,
                    "Listener references non-existent default route"
                );
                errors.push(format!(
                    "Listener '{}' references default-route '{}' which doesn't exist.\n\
                     Available routes: {}",
                    listener.id,
                    default_route,
                    format_available(route_ids)
                ));
            }
        }

        if let Some(ref namespace) = listener.namespace {
            if !config.namespaces.iter().any(|ns| &ns.id == namespace) {
                warn!(
                    listener_id = %listener.id,
                    namespace = %namespace,
                    "Listener references non-existent namespace route set"
                );
                let available: Vec<&str> =
                    config.namespaces.iter().map(|ns| ns.id.as_str()).collect();
                errors.push(format!(
                    "Listener '{}' references namespace '{}' which doesn't exist.\n\
                     Define a `namespace \"{}\" {{ routes {{ ... }} }}` block, \
                     or remove the reference to serve the global routes.\n\
                     Available namespaces: {}",
                    listener.id,
                    namespace,
                    namespace,
                    if available.is_empty() {
                        "(none)".to_string()
                    } else {
                        available.join(", ")
                    }
                ));
            }
        }
    }
}

/// Validate ACME domains across all configurations (global uniqueness)
fn validate_acme_domains(config: &Config, errors: &mut Vec<String>) {
    let mut domain_source: HashMap<String, String> = HashMap::new();

    for listener in &config.listeners {
        // Mutual TLS with nothing to verify against is not mutual TLS. The
        // proxy used to log a warning and serve without client
        // authentication, so an operator could configure mTLS, pass
        // `zentinel validate`, start the proxy, and be accepting
        // unauthenticated clients while believing otherwise. Rejecting here
        // means the mistake surfaces before traffic does.
        // HTTP/3 parses but there is no QUIC in the runtime. This used to fall
        // through to a catch-all that logged a warning and bound no socket, so
        // the proxy started, reported healthy, and served nothing on that
        // address (#377). A config naming a transport the proxy does not have
        // should fail before it is deployed, not after.
        if listener.protocol == ListenerProtocol::Http3 {
            errors.push(format!(
                "Listener '{}' requests protocol \"h3\", which is not implemented — \
                 there is no QUIC support in the proxy. Previously this bound no \
                 socket at all. Use \"https\", which negotiates HTTP/2 via ALPN.",
                listener.id
            ));
        }

        if let Some(ref tls) = listener.tls {
            if tls.client_auth && tls.ca_file.is_none() {
                errors.push(format!(
                    "Listener '{}' sets client-auth but no ca-file. Client certificates \
                     cannot be verified without a CA to verify them against, so this would \
                     serve ordinary TLS while appearing to require client certificates. \
                     Add ca-file, or remove client-auth.",
                    listener.id
                ));
            }
        }

        // 1. Root-level ACME for listener
        if let Some(ref tls) = listener.tls {
            if let Some(ref acme) = tls.acme {
                for domain in &acme.domains {
                    let domain_lower = domain.to_lowercase();
                    let source = format!("listener '{}' (root acme)", listener.id);
                    if let Some(prev_source) = domain_source.insert(domain_lower, source.clone()) {
                        errors.push(format!(
                            "Domain '{}' is configured in multiple ACME blocks: {} and {}.\n\
                             Each domain must be managed by exactly one ACME block to avoid conflicts.",
                            domain, prev_source, source
                        ));
                    }
                }
            }

            // 2. SNI-level ACME certificates
            for (i, sni) in tls.additional_certs.iter().enumerate() {
                if let Some(ref acme) = sni.acme {
                    for domain in &acme.domains {
                        let domain_lower = domain.to_lowercase();
                        let source = format!("listener '{}' (sni cert #{})", listener.id, i);
                        if let Some(prev_source) =
                            domain_source.insert(domain_lower, source.clone())
                        {
                            errors.push(format!(
                                "Domain '{}' is configured in multiple ACME blocks: {} and {}.\n\
                                 Each domain must be managed by exactly one ACME block to avoid conflicts.",
                                domain, prev_source, source
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn validate_filters(config: &Config, agent_ids: &HashSet<&str>, errors: &mut Vec<String>) {
    trace!(
        filter_count = config.filters.len(),
        "Validating filter configurations"
    );

    for (filter_id, filter_config) in &config.filters {
        trace!(filter_id = %filter_id, "Validating filter");
        if let Filter::Agent(agent_filter) = &filter_config.filter {
            if !agent_ids.contains(agent_filter.agent.as_str()) {
                warn!(
                    filter_id = %filter_id,
                    agent_id = %agent_filter.agent,
                    "Filter references non-existent agent"
                );
                errors.push(format!(
                    "Filter '{}' references agent '{}' which doesn't exist.\n\
                     Available agents: {}",
                    filter_id,
                    agent_filter.agent,
                    format_available(agent_ids)
                ));
            }
        }
    }
}

fn validate_upstreams(config: &Config, errors: &mut Vec<String>) {
    trace!(
        upstream_count = config.upstreams.len(),
        "Validating upstream configurations"
    );

    for (upstream_id, upstream) in &config.upstreams {
        trace!(
            upstream_id = %upstream_id,
            target_count = upstream.targets.len(),
            "Validating upstream"
        );

        // An upstream backed by service discovery gets its targets at runtime,
        // so an empty list here is expected rather than a misconfiguration.
        if upstream.targets.is_empty() && upstream.discovery.is_none() {
            warn!(upstream_id = %upstream_id, "Upstream has no targets");
            errors.push(format!(
                "Upstream '{}' has no targets defined.\n\
                 Each upstream must have at least one target, or a discovery \
                 block that supplies them.",
                upstream_id
            ));
        }

        for (i, target) in upstream.targets.iter().enumerate() {
            if target.address.parse::<SocketAddr>().is_err() {
                let parts: Vec<&str> = target.address.rsplitn(2, ':').collect();
                if parts.len() != 2 || parts[0].parse::<u16>().is_err() {
                    warn!(
                        upstream_id = %upstream_id,
                        target_index = i,
                        address = %target.address,
                        "Invalid target address format"
                    );
                    errors.push(format!(
                        "Upstream '{}' target #{} has invalid address '{}'.\n\
                         Expected format: HOST:PORT",
                        upstream_id,
                        i + 1,
                        target.address
                    ));
                }
            }
        }
    }
}

fn validate_agents(config: &Config, errors: &mut Vec<String>) {
    trace!(agent_count = config.agents.len(), "Validating agents");

    for agent in &config.agents {
        if agent.timeout_ms == 0 {
            warn!(agent_id = %agent.id, "Agent has zero timeout");
            errors.push(format!(
                "Agent '{}' has timeout_ms 0. Timeouts must be greater than 0.",
                agent.id
            ));
        }

        if agent.chunk_timeout_ms == 0 {
            warn!(agent_id = %agent.id, "Agent has zero chunk timeout");
            errors.push(format!(
                "Agent '{}' has chunk_timeout_ms 0. Timeouts must be greater than 0.",
                agent.id
            ));
        }

        if agent.max_request_body_bytes == Some(0) {
            warn!(agent_id = %agent.id, "Agent has zero request body limit");
            errors.push(format!(
                "Agent '{}' has max_request_body_bytes 0. Use a positive limit, or omit the field for the default.",
                agent.id
            ));
        }

        if agent.max_response_body_bytes == Some(0) {
            warn!(agent_id = %agent.id, "Agent has zero response body limit");
            errors.push(format!(
                "Agent '{}' has max_response_body_bytes 0. Use a positive limit, or omit the field for the default.",
                agent.id
            ));
        }
    }
}

fn validate_duplicates(config: &Config, errors: &mut Vec<String>) {
    trace!("Checking for duplicate identifiers");

    // Duplicate route IDs
    let mut seen_routes = HashSet::new();
    for route in &config.routes {
        if !seen_routes.insert(&route.id) {
            warn!(route_id = %route.id, "Duplicate route ID found");
            errors.push(format!(
                "Duplicate route ID '{}'. Each route must have a unique identifier.",
                route.id
            ));
        }
    }

    // Duplicate agent IDs
    let mut seen_agents = HashSet::new();
    for agent in &config.agents {
        if !seen_agents.insert(&agent.id) {
            warn!(agent_id = %agent.id, "Duplicate agent ID found");
            errors.push(format!(
                "Duplicate agent ID '{}'. Each agent must have a unique identifier.",
                agent.id
            ));
        }
    }

    // Duplicate listener IDs
    let mut seen_listeners = HashSet::new();
    for listener in &config.listeners {
        if !seen_listeners.insert(&listener.id) {
            warn!(listener_id = %listener.id, "Duplicate listener ID found");
            errors.push(format!(
                "Duplicate listener ID '{}'. Each listener must have a unique identifier.",
                listener.id
            ));
        }
    }

    // Duplicate listener addresses
    let mut seen_addresses = HashSet::new();
    for listener in &config.listeners {
        if !seen_addresses.insert(&listener.address) {
            warn!(address = %listener.address, "Duplicate listener address found");
            errors.push(format!(
                "Duplicate listener address '{}'. Multiple listeners cannot bind to the same address.",
                listener.address
            ));
        }
    }

    // The standalone metrics server binds its own socket, outside Pingora's
    // listeners, so a collision with one is not caught as a duplicate listener
    // address. It is not reported as an error at bind time either: the metrics
    // server wins the race and Pingora retries the listener forever, logging
    // "address is in use, will try again" once a second and never starting.
    // That was zentinelproxy/zentinel#432, hit by simply running with no config.
    if config.observability.metrics.enabled {
        let metrics_addr = &config.observability.metrics.address;
        for listener in &config.listeners {
            if addresses_collide(&listener.address, metrics_addr) {
                warn!(
                    listener_id = %listener.id,
                    address = %listener.address,
                    metrics_address = %metrics_addr,
                    "Listener collides with the metrics server address"
                );
                errors.push(format!(
                    "Listener '{}' binds '{}', which the metrics server also binds \
                     (observability.metrics.address = '{}').\n\
                     Both cannot have the port: the metrics server binds first and the \
                     listener retries forever.\n\
                     Give the metrics server a port of its own, or set \
                     observability.metrics.enabled to #false if a route already serves \
                     /metrics on this listener.",
                    listener.id, listener.address, metrics_addr
                ));
            }
        }
    }

    trace!(
        unique_routes = seen_routes.len(),
        unique_listeners = seen_listeners.len(),
        unique_addresses = seen_addresses.len(),
        "Duplicate check complete"
    );
}

fn warn_orphaned_upstreams(config: &Config, upstream_ids: &HashSet<&str>) {
    let referenced_upstreams: HashSet<_> = config
        .routes
        .iter()
        .filter_map(|r| r.upstream.as_ref())
        .map(|s| s.as_str())
        .collect();

    for upstream_id in upstream_ids {
        if !referenced_upstreams.contains(*upstream_id) {
            tracing::warn!(
                upstream_id = %upstream_id,
                "Upstream '{}' is defined but not referenced by any route.",
                upstream_id
            );
        }
    }
}

fn format_available(ids: &HashSet<&str>) -> String {
    if ids.is_empty() {
        "(none defined)".to_string()
    } else {
        ids.iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ============================================================================
// Namespace Validation
// ============================================================================

fn validate_namespaces(config: &Config, ctx: &ValidationContext, errors: &mut Vec<String>) {
    trace!(
        namespace_count = config.namespaces.len(),
        "Validating namespace configurations"
    );

    // Check for duplicate namespace IDs
    let mut seen_ns_ids = HashSet::new();
    for ns in &config.namespaces {
        if !seen_ns_ids.insert(&ns.id) {
            errors.push(format!(
                "Duplicate namespace ID '{}'. Each namespace must have a unique identifier.",
                ns.id
            ));
        }

        // Validate IDs don't contain reserved ':' character
        if ns.id.contains(':') {
            errors.push(format!(
                "Namespace ID '{}' contains reserved character ':'. \
                 The colon is reserved for qualified references.",
                ns.id
            ));
        }

        validate_namespace_resources(ns, ctx, errors);
    }
}

fn validate_namespace_resources(
    ns: &NamespaceConfig,
    ctx: &ValidationContext,
    errors: &mut Vec<String>,
) {
    let scope = Scope::Namespace(ns.id.clone());

    // Validate namespace routes reference valid upstreams/filters
    for route in &ns.routes {
        if let Some(ref upstream) = route.upstream {
            if !ctx.can_resolve_upstream(upstream, &scope) {
                let available = ctx.available_upstreams(&scope);
                errors.push(format!(
                    "Route '{}' in namespace '{}' references upstream '{}' which cannot be resolved.\n\
                     Available upstreams: {}",
                    route.id,
                    ns.id,
                    upstream,
                    format_available_owned(&available)
                ));
            }
        }

        for filter_id in &route.filters {
            if !ctx.can_resolve_filter(filter_id, &scope) {
                let available = ctx.available_filters(&scope);
                errors.push(format!(
                    "Route '{}' in namespace '{}' references filter '{}' which cannot be resolved.\n\
                     Available filters: {}",
                    route.id,
                    ns.id,
                    filter_id,
                    format_available_owned(&available)
                ));
            }
        }
    }

    // Validate exports reference existing resources
    for export_name in &ns.exports.upstreams {
        if !ns.upstreams.contains_key(export_name) {
            errors.push(format!(
                "Namespace '{}' exports upstream '{}' which doesn't exist in this namespace.",
                ns.id, export_name
            ));
        }
    }

    for export_name in &ns.exports.agents {
        if !ns.agents.iter().any(|a| &a.id == export_name) {
            errors.push(format!(
                "Namespace '{}' exports agent '{}' which doesn't exist in this namespace.",
                ns.id, export_name
            ));
        }
    }

    for export_name in &ns.exports.filters {
        if !ns.filters.contains_key(export_name) {
            errors.push(format!(
                "Namespace '{}' exports filter '{}' which doesn't exist in this namespace.",
                ns.id, export_name
            ));
        }
    }

    // Validate services within namespace
    let mut seen_svc_ids = HashSet::new();
    for svc in &ns.services {
        if !seen_svc_ids.insert(&svc.id) {
            errors.push(format!(
                "Duplicate service ID '{}' in namespace '{}'. Each service must have a unique identifier.",
                svc.id, ns.id
            ));
        }

        if svc.id.contains(':') {
            errors.push(format!(
                "Service ID '{}' in namespace '{}' contains reserved character ':'.",
                svc.id, ns.id
            ));
        }

        validate_service_resources(&ns.id, svc, ctx, errors);
    }
}

fn validate_service_resources(
    ns_id: &str,
    svc: &ServiceConfig,
    ctx: &ValidationContext,
    errors: &mut Vec<String>,
) {
    let scope = Scope::Service {
        namespace: ns_id.to_string(),
        service: svc.id.clone(),
    };

    // Validate service routes reference valid upstreams/filters
    for route in &svc.routes {
        if let Some(ref upstream) = route.upstream {
            if !ctx.can_resolve_upstream(upstream, &scope) {
                let available = ctx.available_upstreams(&scope);
                errors.push(format!(
                    "Route '{}' in service '{}:{}' references upstream '{}' which cannot be resolved.\n\
                     Available upstreams: {}",
                    route.id,
                    ns_id,
                    svc.id,
                    upstream,
                    format_available_owned(&available)
                ));
            }
        }

        for filter_id in &route.filters {
            if !ctx.can_resolve_filter(filter_id, &scope) {
                let available = ctx.available_filters(&scope);
                errors.push(format!(
                    "Route '{}' in service '{}:{}' references filter '{}' which cannot be resolved.\n\
                     Available filters: {}",
                    route.id,
                    ns_id,
                    svc.id,
                    filter_id,
                    format_available_owned(&available)
                ));
            }
        }
    }
}

fn format_available_owned(ids: &HashSet<String>) -> String {
    if ids.is_empty() {
        "(none defined)".to_string()
    } else {
        let mut sorted: Vec<_> = ids.iter().collect();
        sorted.sort();
        sorted
            .iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ============================================================================
// Implementation Status Validation
// ============================================================================

/// Validate that configured features are actually wired into the runtime.
///
/// Features that are parsed successfully but silently ignored at runtime are
/// dangerous — especially security features. This function produces:
///
/// - **Hard errors** for security-critical features (WAF mode) that would give
///   a false sense of protection if ignored.
/// - **Warnings** for convenience features (filters, policies, listener settings)
///   that won't cause security issues but may surprise operators.
///
/// An entry here must not outlive its feature: once a field is wired, its
/// warning becomes a false alarm. `unwired_fields_are_not_read_by_the_proxy`
/// checks the entries whose field names are distinctive enough to search for.
fn validate_implementation_status(
    config: &Config,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    // ========================================================================
    // Hard errors: Security-critical features that MUST NOT be silently ignored
    // ========================================================================

    // WAF mode: Detection/Prevention configured but WAF engine not consumed
    if let Some(ref waf) = config.waf {
        if waf.mode != WafMode::Off {
            let mode_str = match waf.mode {
                WafMode::Detection => "detection",
                WafMode::Prevention => "prevention",
                WafMode::Off => unreachable!(),
            };
            errors.push(format!(
                "WAF mode is set to '{}' but the WAF engine is not yet wired into the proxy runtime. \
                 Requests are NOT being inspected. \
                 Set waf mode to 'off' or remove the waf block until WAF support is implemented.",
                mode_str
            ));
        }
    }

    // Listener TLS `cipher-suite`, `min-version` and `max-version` used to be
    // warned about here as unwired. They reach the listener since #303
    // (`build_server_config`, applied through `TlsSettings::with_server_config`),
    // and the stale warning taught people to distrust lint's output (#526).

    // ========================================================================
    // Warnings: Convenience features that are configured but not yet wired
    // ========================================================================

    // Listener settings: max_concurrent_streams not yet wired to H2
    for listener in &config.listeners {
        if listener.max_concurrent_streams != crate::server::default_max_concurrent_streams() {
            warnings.push(format!(
                "Listener '{}' has max_concurrent_streams={} but Pingora's H2 settings \
                 do not yet support per-listener configuration.",
                listener.id, listener.max_concurrent_streams
            ));
        }
    }

    // Logging: level/format are controlled by RUST_LOG env var and --verbose flag,
    // not yet by the config file. File output also not yet wired.
    let logging = &config.observability.logging;
    if logging.file.is_some() {
        warnings.push(
            "logging.file is configured but application log file routing is not yet implemented. \
             Logs go to stdout/stderr. Use shell redirection as a workaround."
                .to_string(),
        );
    }
    if logging.level != "info" || logging.format != "json" {
        warnings.push(format!(
            "Logging level='{}' and format='{}' are configured but the tracing subscriber uses \
             RUST_LOG env var and --verbose flag instead. Set RUST_LOG={} as a workaround.",
            logging.level, logging.format, logging.level
        ));
    }
}

// ============================================================================
// Result Building
// ============================================================================

fn build_validation_result(errors: Vec<String>) -> Result<(), validator::ValidationError> {
    if errors.is_empty() {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("config_validation_failed");
        let error_summary = if errors.len() == 1 {
            errors[0].clone()
        } else {
            format!(
                "Configuration has {} issues:\n\n{}",
                errors.len(),
                errors
                    .iter()
                    .enumerate()
                    .map(|(i, e)| format!("{}. {}", i + 1, e))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            )
        };
        err.message = Some(std::borrow::Cow::Owned(error_summary));
        Err(err)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::{ExportConfig, NamespaceConfig, ServiceConfig};
    use zentinel_common::types::TlsVersion;

    /// A listener address that is not `IP:PORT` used to pass `validate()`
    /// (the field's `validate_socket_addr` attribute never ran, `listeners`
    /// not being nested) and then panic inside Pingora at bind time (#520).
    mod listener_address_validation {
        use super::*;

        fn config_with_address(address: &str) -> Config {
            let kdl = format!(
                "system {{\n  worker-threads 1\n}}\n\
                 listeners {{\n  listener \"http\" {{\n    address \"{address}\"\n\
                 \x20   protocol \"http\"\n  }}\n}}\n\
                 upstreams {{\n  upstream \"b\" {{\n    target \"127.0.0.1:9000\"\n  }}\n}}\n\
                 routes {{\n  route \"r\" {{\n    matches {{\n      path-prefix \"/\"\n    }}\n\
                 \x20   upstream \"b\"\n  }}\n}}\n"
            );
            Config::from_kdl(&kdl).expect("should parse")
        }

        #[test]
        fn an_env_var_placeholder_is_rejected_and_explained() {
            let message = config_with_address("${ZT_ADDR}")
                .validate()
                .expect_err("an unsubstituted placeholder is not an address")
                .to_string();
            assert!(message.contains("Listener 'http'"), "{message}");
            assert!(message.contains("'${ZT_ADDR}'"), "{message}");
            assert!(
                message.contains("environment variables are not substituted"),
                "{message}"
            );
        }

        #[test]
        fn a_hostname_or_missing_port_is_rejected() {
            for bad in ["localhost:8080", "127.0.0.1", "0.0.0.0:http", ""] {
                let message = config_with_address(bad)
                    .validate()
                    .expect_err(bad)
                    .to_string();
                assert!(message.contains("invalid socket address"), "{message}");
                assert!(
                    !message.contains("environment variables"),
                    "no env hint without ${{: {message}"
                );
            }
        }

        /// Neither of these panicked, but both passed `zentinel test` and then
        /// failed at runtime: DNS errors on every request, or a metrics server
        /// that logged one error and never started.
        #[test]
        fn placeholders_in_upstream_targets_and_metrics_address_are_rejected() {
            let mut config = config_with_address("127.0.0.1:8080");
            config.upstreams.get_mut("b").unwrap().targets[0].address = "${BACKEND}:80".to_string();
            let message = config
                .validate()
                .expect_err("placeholder target")
                .to_string();
            assert!(message.contains("Upstream 'b'"), "{message}");
            assert!(message.contains("not substituted"), "{message}");

            let mut config = config_with_address("127.0.0.1:8080");
            config.observability.metrics.enabled = true;
            config.observability.metrics.address = "${METRICS_ADDR}".to_string();
            let message = config
                .validate()
                .expect_err("placeholder metrics")
                .to_string();
            assert!(message.contains("observability.metrics"), "{message}");
            assert!(message.contains("not substituted"), "{message}");
        }

        #[test]
        fn literal_v4_and_v6_addresses_are_accepted() {
            for good in ["127.0.0.1:8080", "0.0.0.0:443", "[::1]:8080", "[::]:80"] {
                config_with_address(good)
                    .validate()
                    .unwrap_or_else(|e| panic!("{good}: {e}"));
            }
        }
    }

    /// `h2` and `h3` used to fall into a catch-all that logged a warning and
    /// bound no socket, while the documentation marked both supported. `h2` is
    /// now the same setup as `https` (which already negotiates h2 via ALPN);
    /// `h3` is rejected, because there is no QUIC in the runtime (#377).
    mod listener_protocol_support {
        use super::*;

        fn config_with_protocol(protocol: &str) -> String {
            format!(
                "system {{\n  workers 2\n}}\n\
                 listeners {{\n  listener \"edge\" {{\n    address \"127.0.0.1:8443\"\n\
                 \x20   protocol \"{protocol}\"\n    tls {{\n      cert-file \"/tmp/x.crt\"\n\
                 \x20     key-file \"/tmp/x.key\"\n    }}\n  }}\n}}\n\
                 upstreams {{\n  upstream \"b\" {{\n    target \"127.0.0.1:9000\"\n  }}\n}}\n\
                 routes {{\n  route \"r\" {{\n    matches {{\n      path-prefix \"/\"\n    }}\n\
                 \x20   upstream \"b\"\n  }}\n}}\n"
            )
        }

        #[test]
        fn h3_is_rejected_because_there_is_no_quic() {
            let config = Config::from_kdl(&config_with_protocol("h3")).expect("should parse");
            let err = config
                .validate()
                .expect_err("h3 must not validate while unimplemented");
            let message = err.to_string();
            assert!(
                message.contains("h3") && message.contains("not implemented"),
                "error should say h3 is unimplemented, got: {message}"
            );
        }

        /// The failure this replaces was silent, so the test asserts the
        /// operator is pointed somewhere that works.
        #[test]
        fn the_h3_rejection_suggests_https() {
            let config = Config::from_kdl(&config_with_protocol("h3")).expect("should parse");
            let message = config.validate().expect_err("rejected").to_string();
            assert!(
                message.contains("https"),
                "error should point at a working alternative, got: {message}"
            );
        }

        #[test]
        fn h2_is_accepted() {
            let config = Config::from_kdl(&config_with_protocol("h2")).expect("should parse");
            assert!(
                config.validate().is_ok(),
                "h2 should validate: {:?}",
                config.validate()
            );
        }

        #[test]
        fn https_is_unaffected() {
            let config = Config::from_kdl(&config_with_protocol("https")).expect("should parse");
            assert!(config.validate().is_ok());
        }
    }
    use crate::{
        ConnectionPoolConfig, HttpVersionConfig, MatchCondition, RouteConfig, RoutePolicies,
        UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
    };
    use zentinel_common::types::LoadBalancingAlgorithm;

    /// mTLS with no CA to verify against is not mTLS. The proxy used to warn
    /// and serve without client authentication, so a config requesting mutual
    /// TLS could pass validation, start, and accept unauthenticated clients.
    mod client_auth_requires_a_ca {
        use super::*;

        fn config_with_tls(tls_body: &str) -> String {
            format!(
                "system {{\n  workers 2\n}}\n\
                 listeners {{\n  listener \"https\" {{\n    address \"127.0.0.1:8443\"\n\
                 \x20   tls {{\n{tls_body}\n    }}\n  }}\n}}\n\
                 upstreams {{\n  upstream \"b\" {{\n    target \"127.0.0.1:9000\"\n  }}\n}}\n\
                 routes {{\n  route \"r\" {{\n    matches {{\n      path-prefix \"/\"\n    }}\n\
                 \x20   upstream \"b\"\n  }}\n}}\n"
            )
        }

        const CERTS: &str = "      cert-file \"/tmp/x.crt\"\n      key-file \"/tmp/x.key\"";

        #[test]
        fn client_auth_without_a_ca_file_is_rejected() {
            let kdl = config_with_tls(&format!("{CERTS}\n      client-auth #true"));
            let config = Config::from_kdl(&kdl).expect("should parse");
            let err = config
                .validate()
                .expect_err("mTLS without a CA must not validate");
            let message = err.to_string();
            assert!(
                message.contains("client-auth") && message.contains("ca-file"),
                "error should name both settings, got: {message}"
            );
        }

        #[test]
        fn client_auth_with_a_ca_file_is_accepted() {
            let kdl = config_with_tls(&format!(
                "{CERTS}\n      client-auth #true\n      ca-file \"/tmp/ca.crt\""
            ));
            let config = Config::from_kdl(&kdl).expect("should parse");
            assert!(
                config.validate().is_ok(),
                "mTLS with a CA should validate: {:?}",
                config.validate()
            );
        }

        /// Ordinary one-way TLS is untouched.
        #[test]
        fn tls_without_client_auth_is_accepted() {
            let kdl = config_with_tls(CERTS);
            let config = Config::from_kdl(&kdl).expect("should parse");
            assert!(config.validate().is_ok());
        }

        /// A CA with no client-auth is harmless — it just goes unused.
        #[test]
        fn a_ca_file_without_client_auth_is_accepted() {
            let kdl = config_with_tls(&format!("{CERTS}\n      ca-file \"/tmp/ca.crt\""));
            let config = Config::from_kdl(&kdl).expect("should parse");
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn listener_referencing_unknown_namespace_fails_validation() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners {
                listener "admin" {
                    address "127.0.0.1:9000"
                    namespace "ghost"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:3000"
                }
            }
        "#;
        let config = crate::Config::from_kdl(kdl).expect("config parses");
        assert!(
            config.validate().is_err(),
            "listener referencing an undefined namespace must fail validation"
        );
    }

    #[test]
    fn listener_with_defined_namespace_passes_validation() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                }
                listener "admin" {
                    address "127.0.0.1:9000"
                    namespace "ops"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:3000"
                }
            }
            namespace "ops" {
                routes {
                    route "metrics" {
                        matches { path "/metrics" }
                        service-type "builtin"
                        builtin-handler "metrics"
                    }
                }
            }
        "#;
        let config = crate::Config::from_kdl(kdl).expect("config parses");
        assert!(
            config.validate().is_ok(),
            "listener referencing a defined namespace must pass validation"
        );
    }

    fn test_upstream(id: &str) -> UpstreamConfig {
        UpstreamConfig {
            id: id.to_string(),
            targets: vec![UpstreamTarget {
                address: "127.0.0.1:8080".to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            }],
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: None,
            circuit_breaker: None,
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
            discovery: None,
        }
    }

    fn test_route(id: &str, upstream: Option<&str>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::NORMAL,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: upstream.map(String::from),
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            mcp: None,
            a2a: None,
            shadow: None,
            fallback: None,
        }
    }

    fn config_with_agent_block(agent_block: &str) -> crate::Config {
        let kdl = format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "public" {{
                    address "0.0.0.0:8080"
                }}
            }}
            routes {{
                route "api" {{
                    matches {{ path-prefix "/" }}
                    upstream "backend"
                }}
            }}
            upstreams {{
                upstream "backend" {{
                    target "127.0.0.1:3000"
                }}
            }}
            agents {{
                {agent_block}
            }}
        "#
        );
        crate::Config::from_kdl(&kdl).expect("config parses")
    }

    fn validation_errors(config: &crate::Config) -> String {
        match config.validate() {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn duplicate_agent_ids_fail_validation() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:3000"
                }
            }
            agents {
                agent "waf" type="waf" {
                    unix-socket path="/tmp/waf-a.sock"
                }
                agent "waf" type="waf" {
                    unix-socket path="/tmp/waf-b.sock"
                }
            }
        "#;
        let err = crate::Config::from_kdl(kdl).unwrap_err();
        assert!(
            err.to_string().contains("Duplicate agent ID 'waf'"),
            "expected duplicate agent ID error, got: {err}"
        );
    }

    #[test]
    fn agent_zero_timeout_fails_validation() {
        let config = config_with_agent_block(
            r#"
            agent "waf" type="waf" {
                unix-socket path="/tmp/waf.sock"
                timeout-ms 0
            }
            "#,
        );
        let errors = validation_errors(&config);
        assert!(
            errors.contains("Agent 'waf' has timeout_ms 0"),
            "expected zero timeout error, got: {errors}"
        );
    }

    #[test]
    fn agent_zero_chunk_timeout_fails_validation() {
        let config = config_with_agent_block(
            r#"
            agent "waf" type="waf" {
                unix-socket path="/tmp/waf.sock"
                chunk-timeout-ms 0
            }
            "#,
        );
        let errors = validation_errors(&config);
        assert!(
            errors.contains("Agent 'waf' has chunk_timeout_ms 0"),
            "expected zero chunk timeout error, got: {errors}"
        );
    }

    #[test]
    fn agent_zero_body_limits_fail_validation() {
        let config = config_with_agent_block(
            r#"
            agent "waf" type="waf" {
                unix-socket path="/tmp/waf.sock"
                max-request-body-bytes 0
                max-response-body-bytes 0
            }
            "#,
        );
        let errors = validation_errors(&config);
        assert!(
            errors.contains("Agent 'waf' has max_request_body_bytes 0"),
            "expected zero request body limit error, got: {errors}"
        );
        assert!(
            errors.contains("Agent 'waf' has max_response_body_bytes 0"),
            "expected zero response body limit error, got: {errors}"
        );
    }

    #[test]
    fn valid_agent_passes_validation() {
        let config = config_with_agent_block(
            r#"
            agent "waf" type="waf" {
                unix-socket path="/tmp/waf.sock"
                timeout-ms 500
            }
            "#,
        );
        let errors = validation_errors(&config);
        assert!(
            errors.is_empty(),
            "valid agent config must pass validation, got: {errors}"
        );
    }

    #[test]
    fn test_validation_context_from_config() {
        let mut config = Config::default_for_testing();

        // Add a namespace with an upstream
        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));
        ns.routes.push(test_route("ns-route", Some("ns-backend")));
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Should have global upstream
        assert!(ctx.can_resolve_upstream("default", &Scope::Global));

        // Should have namespace upstream from namespace scope
        let ns_scope = Scope::Namespace("api".to_string());
        assert!(ctx.can_resolve_upstream("ns-backend", &ns_scope));

        // Should also see global from namespace scope
        assert!(ctx.can_resolve_upstream("default", &ns_scope));

        // Global scope should NOT see namespace-local upstream
        assert!(!ctx.can_resolve_upstream("ns-backend", &Scope::Global));
    }

    #[test]
    fn test_validation_context_exports() {
        let mut config = Config::default_for_testing();

        // Add a namespace with exported upstream
        let mut ns = NamespaceConfig::new("shared");
        ns.upstreams.insert(
            "shared-backend".to_string(),
            test_upstream("shared-backend"),
        );
        ns.exports = ExportConfig {
            upstreams: vec!["shared-backend".to_string()],
            agents: vec![],
            filters: vec![],
        };
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Exported upstream should be visible from global scope
        assert!(ctx.can_resolve_upstream("shared-backend", &Scope::Global));

        // And from other namespaces
        let other_ns = Scope::Namespace("other".to_string());
        assert!(ctx.can_resolve_upstream("shared-backend", &other_ns));
    }

    #[test]
    fn test_validation_context_service_scope() {
        let mut config = Config::default_for_testing();

        // Add a namespace with a service
        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));

        let mut svc = ServiceConfig::new("payments");
        svc.upstreams
            .insert("svc-backend".to_string(), test_upstream("svc-backend"));
        ns.services.push(svc);

        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        // Service should see its own upstream
        assert!(ctx.can_resolve_upstream("svc-backend", &svc_scope));

        // Service should see namespace upstream
        assert!(ctx.can_resolve_upstream("ns-backend", &svc_scope));

        // Service should see global upstream
        assert!(ctx.can_resolve_upstream("default", &svc_scope));

        // Namespace scope should NOT see service-local upstream
        let ns_scope = Scope::Namespace("api".to_string());
        assert!(!ctx.can_resolve_upstream("svc-backend", &ns_scope));
    }

    #[test]
    fn test_validation_context_qualified_references() {
        let mut config = Config::default_for_testing();

        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("backend".to_string(), test_upstream("backend"));
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Qualified reference should work
        assert!(ctx.can_resolve_upstream("api:backend", &Scope::Global));

        // Wrong qualified reference should fail
        assert!(!ctx.can_resolve_upstream("other:backend", &Scope::Global));
    }

    #[test]
    fn test_available_upstreams() {
        let mut config = Config::default_for_testing();

        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));
        ns.exports = ExportConfig {
            upstreams: vec!["ns-backend".to_string()],
            agents: vec![],
            filters: vec![],
        };
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Global scope should see: default (global) + ns-backend (exported)
        let global_available = ctx.available_upstreams(&Scope::Global);
        assert!(global_available.contains("default"));
        assert!(global_available.contains("ns-backend"));

        // Namespace scope should see: default (global) + ns-backend (local) + exported
        let ns_scope = Scope::Namespace("api".to_string());
        let ns_available = ctx.available_upstreams(&ns_scope);
        assert!(ns_available.contains("default"));
        assert!(ns_available.contains("ns-backend"));
    }

    // ========================================================================
    // Implementation status validation tests
    // ========================================================================

    #[test]
    fn waf_prevention_mode_produces_hard_error() {
        let mut config = Config::default_for_testing();
        config.waf = Some(crate::WafConfig {
            engine: crate::WafEngine::Coraza,
            ruleset: crate::WafRuleset {
                crs_version: "4.0".to_string(),
                custom_rules_dir: None,
                paranoia_level: 1,
                anomaly_threshold: 5,
                exclusions: vec![],
            },
            mode: WafMode::Prevention,
            audit_log: true,
            body_inspection: crate::BodyInspectionPolicy::default(),
        });

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(
            !errors.is_empty(),
            "WAF prevention mode should produce a hard error"
        );
        assert!(
            errors[0].contains("WAF mode is set to 'prevention'"),
            "Error should mention prevention mode, got: {}",
            errors[0]
        );
    }

    #[test]
    fn waf_detection_mode_produces_hard_error() {
        let mut config = Config::default_for_testing();
        config.waf = Some(crate::WafConfig {
            engine: crate::WafEngine::Coraza,
            ruleset: crate::WafRuleset {
                crs_version: "4.0".to_string(),
                custom_rules_dir: None,
                paranoia_level: 1,
                anomaly_threshold: 5,
                exclusions: vec![],
            },
            mode: WafMode::Detection,
            audit_log: true,
            body_inspection: crate::BodyInspectionPolicy::default(),
        });

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(
            !errors.is_empty(),
            "WAF detection mode should produce a hard error"
        );
        assert!(errors[0].contains("detection"));
    }

    #[test]
    fn waf_off_mode_produces_no_error() {
        let mut config = Config::default_for_testing();
        config.waf = Some(crate::WafConfig {
            engine: crate::WafEngine::Coraza,
            ruleset: crate::WafRuleset {
                crs_version: "4.0".to_string(),
                custom_rules_dir: None,
                paranoia_level: 1,
                anomaly_threshold: 5,
                exclusions: vec![],
            },
            mode: WafMode::Off,
            audit_log: true,
            body_inspection: crate::BodyInspectionPolicy::default(),
        });

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty(), "WAF off mode should not produce errors");
    }

    /// Both were reported as unwired long after #303 wired them (#526).
    #[test]
    fn listener_tls_versions_and_ciphers_produce_no_warnings() {
        let mut config = Config::default_for_testing();
        config.listeners[0].tls = Some(crate::TlsConfig {
            cert_folders: Vec::new(),
            allow_sni_overlaps: false,
            cert_file: Some("/tmp/cert.pem".into()),
            key_file: Some("/tmp/key.pem".into()),
            additional_certs: vec![],
            ca_file: None,
            min_version: TlsVersion::Tls13,
            max_version: Some(TlsVersion::Tls13),
            cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
            client_auth: false,
            ocsp_stapling: true,
            session_resumption: true,
            acme: None,
        });

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty(), "{errors:?}");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// Each field `validate_implementation_status` calls unwired, searched
    /// for in the proxy's source. Finding one means the feature has been
    /// wired and its warning is now a false alarm: remove the warning, and
    /// the name from this list.
    ///
    /// Only names distinctive enough to search for are listed. The logging
    /// warnings are about `level`, `format` and `file`, which appear all over
    /// the proxy for unrelated reasons, so they are not.
    #[test]
    fn unwired_fields_are_not_read_by_the_proxy() {
        const UNWIRED: &[&str] = &["max_concurrent_streams"];

        let proxy_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../proxy/src");
        if !proxy_src.is_dir() {
            // Built outside the workspace, e.g. from a published crate.
            return;
        }

        let mut files = vec![proxy_src];
        let mut readers = Vec::new();
        while let Some(path) = files.pop() {
            if path.is_dir() {
                for entry in std::fs::read_dir(&path).unwrap() {
                    files.push(entry.unwrap().path());
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for field in UNWIRED {
                    if text.contains(field) {
                        readers.push(format!("{field} in {}", path.display()));
                    }
                }
            }
        }

        assert!(
            readers.is_empty(),
            "a field reported as unwired is used by the proxy; if it is now wired, \
             drop its warning from validate_implementation_status:\n{}",
            readers.join("\n")
        );
    }

    #[test]
    fn compress_filter_produces_no_warnings() {
        use crate::filters::{CompressFilter, FilterConfig};

        let mut config = Config::default_for_testing();
        config.filters.insert(
            "gzip".to_string(),
            FilterConfig::new("gzip", Filter::Compress(CompressFilter::default())),
        );
        config.routes[0].filters.push("gzip".to_string());

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(
            errors.is_empty(),
            "Compress filter should not produce errors"
        );
        assert!(
            !warnings.iter().any(|w| w.contains("compress")),
            "Compress filter is wired and should not produce warnings"
        );
    }

    #[test]
    fn cors_filter_produces_no_warnings() {
        use crate::filters::{CorsFilter, FilterConfig};

        let mut config = Config::default_for_testing();
        config.filters.insert(
            "cors".to_string(),
            FilterConfig::new("cors", Filter::Cors(CorsFilter::default())),
        );
        config.routes[0].filters.push("cors".to_string());

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty(), "CORS filter should not produce errors");
        assert!(
            !warnings.iter().any(|w| w.contains("cors")),
            "CORS filter is wired and should not produce warnings"
        );
    }

    #[test]
    fn response_headers_policy_produces_no_warnings() {
        let mut config = Config::default_for_testing();
        config.routes[0]
            .policies
            .response_headers
            .set
            .insert("X-Custom".to_string(), "value".to_string());

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty());
        assert!(
            !warnings.iter().any(|w| w.contains("response_headers")),
            "response_headers is wired and should not produce warnings"
        );
    }

    #[test]
    fn route_cache_enabled_produces_no_warnings() {
        let mut config = Config::default_for_testing();
        config.routes[0].policies.cache = Some(crate::RouteCacheConfig {
            enabled: true,
            ..Default::default()
        });

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty());
        assert!(
            !warnings.iter().any(|w| w.contains("caching")),
            "Per-route cache is wired and should not produce warnings"
        );
    }

    #[test]
    fn server_pid_file_produces_no_warnings() {
        let mut config = Config::default_for_testing();
        config.server.pid_file = Some("/run/zentinel.pid".into());

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty());
        assert!(
            !warnings.iter().any(|w| w.contains("pid_file")),
            "pid_file is now wired and should not produce warnings"
        );
    }

    #[test]
    fn default_config_produces_no_errors_or_warnings() {
        let config = Config::default_for_testing();

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(
            errors.is_empty(),
            "Default config should produce no errors: {:?}",
            errors
        );
        assert!(
            warnings.is_empty(),
            "Default config should produce no warnings: {:?}",
            warnings
        );
    }

    #[test]
    fn logging_file_produces_warning() {
        let mut config = Config::default_for_testing();
        config.observability.logging.file = Some("/var/log/zentinel/app.log".into());

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty());
        assert!(warnings.iter().any(|w| w.contains("logging.file")));
    }

    #[test]
    fn non_default_listener_timeout_produces_no_warnings() {
        let mut config = Config::default_for_testing();
        config.listeners[0].request_timeout_secs = 30;

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        assert!(errors.is_empty());
        assert!(
            !warnings.iter().any(|w| w.contains("request_timeout_secs")),
            "request_timeout_secs is now wired and should not produce warnings"
        );
    }

    // ========================================================================
    // Config field coverage tests
    // ========================================================================

    /// Exhaustive construction test for config structs.
    ///
    /// This test constructs every config struct with fully explicit field
    /// initialization (no `..Default::default()`). When a developer adds a
    /// new field to any config struct, **this test fails to compile** until
    /// they add the field — forcing them to consider wiring.
    ///
    /// If this fails to compile, you MUST either:
    ///   1. Wire the field to runtime behavior AND add a test, OR
    ///   2. Add a warning in `validate_implementation_status()`
    #[test]
    fn config_field_coverage_exhaustive_construction() {
        use crate::filters::{
            CompressFilter, CompressionAlgorithm, CorsFilter, FilterPhase, GlobalRateLimitConfig,
            HeadersFilter, LogFilter, RateLimitKey, TimeoutFilter,
        };
        use crate::observability::{LoggingConfig, MetricsConfig, ObservabilityConfig};
        use crate::routes::{
            CacheBackend, CacheStorageConfig, FailureMode, HeaderModifications, RouteCacheConfig,
        };
        use crate::server::{ListenerConfig, ListenerProtocol, ServerConfig, TlsConfig};
        use crate::waf::{BodyInspectionPolicy, WafConfig, WafEngine, WafRuleset};
        use zentinel_common::types::LoadBalancingAlgorithm;

        // --- ServerConfig ---
        let _server = ServerConfig {
            worker_threads: 4,
            max_connections: 1000,
            graceful_shutdown_timeout_secs: 30,
            daemon: false,
            pid_file: None,
            user: None,
            group: None,
            working_directory: None,
            trace_id_format: Default::default(),
            auto_reload: false,
            route_cache_size: 1000,
        };

        // --- ListenerConfig ---
        let _listener = ListenerConfig {
            id: "http".to_string(),
            address: "0.0.0.0:8080".to_string(),
            protocol: ListenerProtocol::Http,
            tls: None,
            default_route: Some("default".to_string()),
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            trusted_proxies: Vec::new(),
        };

        // --- TlsConfig ---
        let _tls = TlsConfig {
            cert_folders: Vec::new(),
            allow_sni_overlaps: false,
            cert_file: Some("/tmp/cert.pem".into()),
            key_file: Some("/tmp/key.pem".into()),
            additional_certs: vec![],
            ca_file: None,
            min_version: TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: true,
            session_resumption: true,
            acme: None,
        };

        // --- RouteConfig ---
        let _route = RouteConfig {
            id: "test".to_string(),
            priority: Priority::NORMAL,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: Some("default".to_string()),
            service_type: ServiceType::Web,
            policies: RoutePolicies {
                request_headers: HeaderModifications {
                    rename: HashMap::new(),
                    set: HashMap::new(),
                    add: HashMap::new(),
                    remove: vec![],
                },
                response_headers: HeaderModifications {
                    rename: HashMap::new(),
                    set: HashMap::new(),
                    add: HashMap::new(),
                    remove: vec![],
                },
                timeout_secs: None,
                max_body_size: None,
                rate_limit: None,
                failure_mode: FailureMode::Closed,
                cache: None,
            },
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            inference: None,
            mcp: None,
            a2a: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            shadow: None,
            fallback: None,
        };

        // --- UpstreamConfig ---
        let _upstream = UpstreamConfig {
            id: "default".to_string(),
            targets: vec![UpstreamTarget {
                address: "127.0.0.1:8081".to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            }],
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: None,
            circuit_breaker: None,
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
            discovery: None,
        };

        // --- Filter types ---
        let _headers = HeadersFilter {
            phase: FilterPhase::Request,
            rename: HashMap::new(),
            set: HashMap::new(),
            add: HashMap::new(),
            remove: vec![],
        };

        let _compress = CompressFilter {
            algorithms: vec![CompressionAlgorithm::Gzip],
            min_size: 1024,
            content_types: vec!["text/html".to_string()],
            level: 6,
        };

        let _cors = CorsFilter {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_secs: 3600,
        };

        let _timeout = TimeoutFilter {
            request_timeout_secs: None,
            upstream_timeout_secs: None,
            connect_timeout_secs: None,
        };

        let _log = LogFilter {
            log_request: true,
            log_response: true,
            log_body: false,
            max_body_log_size: 1024,
            fields: vec![],
            level: "info".to_string(),
        };

        // --- WafConfig ---
        let _waf = WafConfig {
            engine: WafEngine::Coraza,
            ruleset: WafRuleset {
                crs_version: "4.0".to_string(),
                custom_rules_dir: None,
                paranoia_level: 1,
                anomaly_threshold: 5,
                exclusions: vec![],
            },
            mode: WafMode::Off,
            audit_log: true,
            body_inspection: BodyInspectionPolicy {
                inspect_request_body: true,
                inspect_response_body: false,
                max_inspection_bytes: 1024 * 1024,
                content_types: vec![],
                decompress: false,
                max_decompression_ratio: 100.0,
            },
        };

        // --- ObservabilityConfig ---
        let _obs = ObservabilityConfig {
            metrics: MetricsConfig {
                enabled: true,
                address: "0.0.0.0:9090".to_string(),
                path: "/metrics".to_string(),
                high_cardinality: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                timestamps: true,
                file: None,
                access_log: None,
                error_log: None,
                audit_log: None,
            },
            tracing: None,
        };

        // --- RouteCacheConfig ---
        let _cache = RouteCacheConfig {
            enabled: true,
            default_ttl_secs: 3600,
            max_size_bytes: 10 * 1024 * 1024,
            cache_private: false,
            stale_while_revalidate_secs: 60,
            stale_if_error_secs: 300,
            cacheable_methods: vec!["GET".to_string()],
            cacheable_status_codes: vec![200],
            vary_headers: vec![],
            ignore_query_params: vec![],
            exclude_extensions: vec![],
            exclude_paths: vec![],
        };

        // --- CacheStorageConfig ---
        let _cache_storage = CacheStorageConfig {
            enabled: true,
            backend: CacheBackend::Memory,
            max_size_bytes: 100 * 1024 * 1024,
            eviction_limit_bytes: None,
            lock_timeout_secs: 10,
            disk_path: None,
            disk_shards: 16,
            disk_max_size_bytes: None,
            status_header: false,
            status_header_name: "zentinel".to_string(),
        };

        // --- GlobalRateLimitConfig ---
        let _rl = GlobalRateLimitConfig {
            default_rps: None,
            default_burst: None,
            key: RateLimitKey::ClientIp,
            global: None,
        };

        // If this test compiles, all config struct fields are accounted for.
    }

    // ========================================================================
    // Validation warnings snapshot test
    // ========================================================================

    /// Snapshot test for validation warnings from `validate_implementation_status`.
    ///
    /// This test constructs a config with every partially-wired feature enabled
    /// and asserts the exact set of warnings. When someone wires a feature or
    /// adds a new warning, this test fails and they must update the expected list.
    #[test]
    fn validation_warnings_snapshot() {
        let mut config = Config::default_for_testing();

        // Enable all features that currently produce warnings:

        // max_concurrent_streams (unwired — Pingora H2 per-listener config)
        config.listeners[0].max_concurrent_streams = 200; // non-default → produces warning

        // Logging file (unwired — goes to stdout/stderr)
        config.observability.logging.file = Some("/var/log/zentinel/app.log".into());

        // Logging level/format (unwired — controlled by RUST_LOG env var)
        config.observability.logging.level = "debug".to_string();
        config.observability.logging.format = "pretty".to_string();

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        validate_implementation_status(&config, &mut errors, &mut warnings);

        // No errors expected (WAF is not enabled)
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);

        // Exact expected warnings — update when features are wired or new warnings added.
        //
        // Each entry is a substring that must appear in exactly one warning.
        let expected_warning_fragments =
            vec!["max_concurrent_streams", "logging.file", "Logging level"];

        assert_eq!(
            warnings.len(),
            expected_warning_fragments.len(),
            "Warning count changed!\n\
             Expected {} warnings but got {}.\n\
             If you wired a feature, remove its expected warning.\n\
             If you added a new unwired feature, add its warning here.\n\
             Actual warnings:\n{:#?}",
            expected_warning_fragments.len(),
            warnings.len(),
            warnings
        );

        for expected in &expected_warning_fragments {
            assert!(
                warnings.iter().any(|w| w.contains(expected)),
                "Expected warning containing '{}' not found.\nActual warnings:\n{:#?}",
                expected,
                warnings
            );
        }
    }
}

#[cfg(test)]
mod metrics_collision_tests {
    use super::addresses_collide;
    use crate::Config;

    fn config_with(metrics: &str, listener_addr: &str) -> anyhow::Result<Config> {
        let kdl = format!(
            r#"
schema-version "1.0"
system {{ worker-threads 1 }}
observability {{
    metrics {{
{metrics}
    }}
}}
listeners {{
    listener "admin" {{
        address "{listener_addr}"
    }}
}}
routes {{
    route "r" {{
        matches {{ path "/" }}
        service-type "builtin"
        builtin-handler "health"
    }}
}}
"#
        );
        Config::from_kdl(&kdl)
    }

    /// The regression: running with no configuration at all started the metrics
    /// server and a listener on the same port, and the listener retried forever.
    #[test]
    fn a_listener_on_the_metrics_port_is_rejected() {
        let config = config_with(
            "        enabled #true\n        address \"0.0.0.0:9090\"",
            "0.0.0.0:9090",
        )
        .expect("parses");
        let message = config
            .validate()
            .expect_err("a self-conflicting configuration must not validate")
            .to_string();
        assert!(
            message.contains("metrics server also binds"),
            "the error should explain the collision, got: {message}"
        );
    }

    /// A wildcard bind takes the port on every interface, so it collides with a
    /// specific address that a string comparison would call different.
    #[test]
    fn wildcard_and_specific_addresses_collide() {
        assert!(addresses_collide("0.0.0.0:9090", "127.0.0.1:9090"));
        assert!(addresses_collide("127.0.0.1:9090", "0.0.0.0:9090"));
        assert!(addresses_collide("0.0.0.0:9090", "0.0.0.0:9090"));
    }

    #[test]
    fn different_ports_do_not_collide() {
        assert!(!addresses_collide("0.0.0.0:9090", "0.0.0.0:9091"));
        assert!(!addresses_collide("127.0.0.1:9090", "127.0.0.2:9090"));
    }

    /// Disabling the metrics server frees the port, which is how the shipped
    /// default configuration resolves this.
    #[test]
    fn a_disabled_metrics_server_does_not_collide() {
        let config = config_with("        enabled #false", "0.0.0.0:9090").expect("parses");
        config
            .validate()
            .expect("a disabled metrics server leaves the port to the listener");
    }

    /// The embedded default is what `zentinel` with no arguments runs.
    #[test]
    fn the_embedded_default_configuration_has_no_collision() {
        let config = Config::default_embedded().expect("the shipped default must load");
        config
            .validate()
            .expect("the shipped default must also validate cleanly");
    }
}
