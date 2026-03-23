//! Translates Gateway API resources into Zentinel `Config`.
//!
//! This is the core mapping layer: it reads all Gateways and HTTPRoutes
//! from the cluster and produces a complete `zentinel_config::Config` that
//! the proxy can hot-reload via `ArcSwap`.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use gateway_api::common::{HTTPFilterType, ParentReference};
use gateway_api::experimental::tlsroutes::TLSRoute;
use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use gateway_api::grpcroutes::GRPCRoute;
use gateway_api::httproutes::{
    HTTPBackendReference, HTTPRoute, HttpRouteFilter, HttpRouteRulesMatchesPathType, RouteMatch,
};
use kube::api::ListParams;
use kube::{Api, Client, ResourceExt};
use tracing::{debug, error, info, warn};

use zentinel_common::types::{HealthCheckType, LoadBalancingAlgorithm, Priority, TlsVersion};
use zentinel_config::{
    Config, ConnectionPoolConfig, Filter, FilterConfig, HeaderModifications, HealthCheck,
    HttpVersionConfig, ListenerConfig, ListenerProtocol, MatchCondition, PathModifier,
    RedirectFilter, RouteConfig, RoutePolicies, ServerConfig, ServiceType, SniCertificate,
    TlsConfig, UpstreamConfig, UpstreamTarget, UpstreamTimeouts, UrlRewriteFilter,
};

use crate::config_writer::ConfigWriter;
use crate::error::GatewayError;
use crate::reconcilers::gateway_class::CONTROLLER_NAME;
use crate::reconcilers::ingress::translate_ingresses;
use crate::reconcilers::{ReferenceGrantIndex, ReferenceQuery};
use crate::tls::{SecretCertificateManager, SecretRef};

/// Translates Gateway API resources into Zentinel configuration.
///
/// Maintains a shared `ArcSwap<Config>` that the proxy data plane reads
/// from. Each call to `rebuild` reads the full cluster state and atomically
/// swaps the config.
pub struct ConfigTranslator {
    config: Arc<ArcSwap<Config>>,
    reference_grants: Arc<ReferenceGrantIndex>,
    cert_manager: Arc<SecretCertificateManager>,
    config_writer: Option<ConfigWriter>,
}

impl ConfigTranslator {
    pub fn new(
        config: Arc<ArcSwap<Config>>,
        reference_grants: Arc<ReferenceGrantIndex>,
        cert_manager: Arc<SecretCertificateManager>,
    ) -> Self {
        Self {
            config,
            reference_grants,
            cert_manager,
            config_writer: None,
        }
    }

    /// Enable writing translated config to a KDL file for the proxy sidecar.
    ///
    /// When set, each `rebuild()` call writes the translated config to disk
    /// in addition to storing it in the ArcSwap. The proxy reads this file
    /// with `auto-reload: true`.
    pub fn with_config_writer(mut self, writer: ConfigWriter) -> Self {
        self.config_writer = Some(writer);
        self
    }

    /// Get the current config (for reading).
    pub fn current_config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Rebuild the full Zentinel config from cluster state.
    ///
    /// Reads all Gateway and HTTPRoute resources, filters to those owned
    /// by our GatewayClass, and translates them into a `Config`.
    pub async fn rebuild(&self, client: &Client) -> Result<(), GatewayError> {
        // List all GatewayClasses to find ours
        let gc_api: Api<GatewayClass> = Api::all(client.clone());
        let gateway_classes = gc_api.list(&ListParams::default()).await?;

        let our_classes: Vec<String> = gateway_classes
            .items
            .iter()
            .filter(|gc: &&GatewayClass| gc.spec.controller_name == CONTROLLER_NAME)
            .map(|gc: &GatewayClass| gc.name_any())
            .collect();

        if our_classes.is_empty() {
            debug!("No GatewayClasses owned by us");
            return Ok(());
        }

        // List all Gateways
        let gw_api: Api<Gateway> = Api::all(client.clone());
        let all_gateways = gw_api.list(&ListParams::default()).await?;

        let our_gateways: Vec<&Gateway> = all_gateways
            .items
            .iter()
            .filter(|gw: &&Gateway| our_classes.contains(&gw.spec.gateway_class_name))
            .collect();

        // List all HTTPRoutes
        let route_api: Api<HTTPRoute> = Api::all(client.clone());
        let all_routes = route_api.list(&ListParams::default()).await?;

        // Build config
        let mut listeners = Vec::new();
        let mut routes = Vec::new();
        let mut upstreams = HashMap::new();
        let mut filters = HashMap::new();

        // Translate Gateways → Listeners (with TLS resolution)
        // Multiple Gateway listeners may map to the same bind port after
        // remapping (e.g. ports 80 and 8080 both map to PROXY_HTTP_PORT).
        // Deduplicate by bind address, keeping the first seen.
        let mut seen_addresses = std::collections::HashSet::new();
        for gw in &our_gateways {
            let gw_listeners = self.translate_gateway(gw, client).await;
            for listener in gw_listeners {
                if seen_addresses.insert(listener.address.clone()) {
                    listeners.push(listener);
                } else {
                    debug!(
                        id = %listener.id,
                        address = %listener.address,
                        "Skipping duplicate listener bind address"
                    );
                }
            }
        }

        // Translate HTTPRoutes → Routes + Upstreams
        for route in &all_routes.items {
            let route_ns = route.namespace().unwrap_or_default();
            let parent_refs = match route.spec.parent_refs.as_ref() {
                Some(refs) => refs,
                None => continue,
            };

            // Collect listener hostnames from all matching parent Gateways
            let mut listener_hostnames: Vec<String> = Vec::new();
            let mut has_parent = false;

            for pr in parent_refs {
                let gw_ns = pr.namespace.as_deref().unwrap_or(&route_ns);
                let gw_name = pr.name.as_str();

                if let Some(gw) = our_gateways
                    .iter()
                    .find(|g| g.name_any() == gw_name && g.namespace().unwrap_or_default() == gw_ns)
                {
                    // Check if route namespace is allowed by listener's allowedRoutes
                    let gw_namespace = gw.namespace().unwrap_or_default();
                    let route_allowed = self
                        .is_route_namespace_allowed(gw, &route_ns, &gw_namespace, client)
                        .await;
                    if !route_allowed {
                        debug!(
                            route = %route.name_any(),
                            route_ns = %route_ns,
                            gateway = %gw_name,
                            "Route namespace not allowed by Gateway listeners"
                        );
                        continue;
                    }

                    has_parent = true;
                    // Collect hostnames from matching listeners
                    for listener in &gw.spec.listeners {
                        // If parentRef specifies a sectionName, only use that listener
                        if let Some(ref section) = pr.section_name {
                            if listener.name != *section {
                                continue;
                            }
                        }
                        if let Some(ref hostname) = listener.hostname {
                            listener_hostnames.push(hostname.clone());
                        }
                        // No hostname on listener = accepts all hostnames (don't add filter)
                    }
                }
            }

            if !has_parent {
                continue;
            }

            let (route_configs, upstream_configs, filter_configs) = self
                .translate_httproute(route, &listener_hostnames, client)
                .await?;
            routes.extend(route_configs);
            upstreams.extend(upstream_configs);
            filters.extend(filter_configs);
        }

        // Translate GRPCRoutes → Routes + Upstreams
        let grpc_api: Api<GRPCRoute> = Api::all(client.clone());
        let all_grpc_routes = grpc_api.list(&ListParams::default()).await?;

        for route in &all_grpc_routes.items {
            let route_ns = route.namespace().unwrap_or_default();
            let parent_refs = route.spec.parent_refs.as_ref();
            let is_ours = parent_refs.is_some_and(|refs: &Vec<ParentReference>| {
                refs.iter().any(|pr: &ParentReference| {
                    let gw_ns = pr.namespace.as_deref().unwrap_or(&route_ns);
                    let gw_name = pr.name.as_str();
                    our_gateways.iter().any(|g: &&Gateway| {
                        g.name_any() == gw_name && g.namespace().unwrap_or_default() == gw_ns
                    })
                })
            });

            if !is_ours {
                continue;
            }

            let (route_configs, upstream_configs) = self.translate_grpcroute(route)?;
            routes.extend(route_configs);
            upstreams.extend(upstream_configs);
        }

        // Translate TLSRoutes → Routes + Upstreams (SNI passthrough)
        // Non-fatal: TLSRoute is experimental and the CRD may not be installed
        let tls_api: Api<TLSRoute> = Api::all(client.clone());
        let all_tls_routes = match tls_api.list(&ListParams::default()).await {
            Ok(routes) => routes.items,
            Err(e) => {
                debug!(error = %e, "TLSRoute listing failed (experimental CRD may not be available)");
                vec![]
            }
        };

        for route in &all_tls_routes {
            let route_ns = route.namespace().unwrap_or_default();
            let parent_refs = route.spec.parent_refs.as_ref();
            let is_ours = parent_refs.is_some_and(
                |refs: &Vec<gateway_api::experimental::common::ParentReference>| {
                    refs.iter()
                        .any(|pr: &gateway_api::experimental::common::ParentReference| {
                            let gw_ns = pr.namespace.as_deref().unwrap_or(&route_ns);
                            let gw_name = pr.name.as_str();
                            our_gateways.iter().any(|g: &&Gateway| {
                                g.name_any() == gw_name
                                    && g.namespace().unwrap_or_default() == gw_ns
                            })
                        })
                },
            );

            if !is_ours {
                continue;
            }

            let (route_configs, upstream_configs) = self.translate_tlsroute(route)?;
            routes.extend(route_configs);
            upstreams.extend(upstream_configs);
        }

        // Translate legacy Ingress resources (compatibility shim)
        let ingress_api: Api<k8s_openapi::api::networking::v1::Ingress> = Api::all(client.clone());
        let ingress_items = match ingress_api.list(&ListParams::default()).await {
            Ok(list) => list.items,
            Err(e) => {
                debug!(error = %e, "Ingress listing failed");
                vec![]
            }
        };
        let (ingress_routes, ingress_upstreams) = translate_ingresses(&ingress_items);
        routes.extend(ingress_routes);
        upstreams.extend(ingress_upstreams);

        if listeners.is_empty() {
            debug!("No listeners produced, keeping existing config");
            return Ok(());
        }

        let new_config = Config {
            schema_version: zentinel_config::CURRENT_SCHEMA_VERSION.to_string(),
            server: ServerConfig {
                worker_threads: 0, // auto-detect
                max_connections: 10000,
                graceful_shutdown_timeout_secs: 30,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                working_directory: None,
                trace_id_format: Default::default(),
                auto_reload: true,
            },
            listeners,
            routes,
            upstreams,
            filters,
            agents: vec![],
            waf: None,
            namespaces: vec![],
            limits: Default::default(),
            observability: Default::default(),
            rate_limits: Default::default(),
            cache: None,
            default_upstream: None,
        };

        info!(
            listeners = new_config.listeners.len(),
            routes = new_config.routes.len(),
            upstreams = new_config.upstreams.len(),
            "Config rebuilt from Gateway API resources"
        );

        self.config.store(Arc::new(new_config.clone()));

        // Write config to disk for the proxy sidecar
        if let Some(ref writer) = self.config_writer {
            if let Err(e) = writer.write(&new_config) {
                error!(error = %e, "Failed to write config to disk");
            }
        }

        Ok(())
    }

    /// Translate a Gateway into Zentinel listener configs.
    ///
    /// Logical ports from the Gateway spec are remapped to the proxy's actual
    /// bind ports using `PROXY_HTTP_PORT` / `PROXY_HTTPS_PORT` env vars
    /// (defaulting to 8080/8443). This is necessary because the proxy runs as
    /// non-root and cannot bind privileged ports like 80/443.
    async fn translate_gateway(&self, gateway: &Gateway, _client: &Client) -> Vec<ListenerConfig> {
        let gw_name = gateway.name_any();
        let gw_ns = gateway.namespace().unwrap_or_default();

        let http_port: u16 = std::env::var("PROXY_HTTP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);
        let https_port: u16 = std::env::var("PROXY_HTTPS_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8443);

        let mut listeners = Vec::new();

        for listener in &gateway.spec.listeners {
            let id = format!("{gw_ns}-{gw_name}-{}", listener.name);
            let protocol = match listener.protocol.as_str() {
                "HTTPS" => ListenerProtocol::Https,
                _ => ListenerProtocol::Http,
            };

            let bind_port = match protocol {
                ListenerProtocol::Https => https_port,
                _ => http_port,
            };

            // Resolve TLS configuration from Gateway listener
            let tls = if protocol == ListenerProtocol::Https {
                self.resolve_listener_tls(listener, &gw_ns).await
            } else {
                None
            };

            listeners.push(ListenerConfig {
                id,
                address: format!("0.0.0.0:{bind_port}"),
                protocol,
                tls,
                default_route: None,
                request_timeout_secs: 60,
                keepalive_timeout_secs: 75,
                max_concurrent_streams: 100,
                keepalive_max_requests: None,
            });
        }

        listeners
    }

    /// Resolve TLS configuration from a Gateway listener's certificateRefs.
    async fn resolve_listener_tls(
        &self,
        listener: &gateway_api::gateways::GatewayListeners,
        gateway_ns: &str,
    ) -> Option<TlsConfig> {
        let tls_config = listener.tls.as_ref()?;
        let cert_refs = tls_config.certificate_refs.as_ref()?;

        if cert_refs.is_empty() {
            return None;
        }

        // Resolve the first certificate as the default
        let first_ref = &cert_refs[0];
        let secret_ns = first_ref.namespace.as_deref().unwrap_or(gateway_ns);
        let hostnames = listener
            .hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default();

        let secret_ref = SecretRef {
            namespace: secret_ns.to_string(),
            name: first_ref.name.clone(),
        };

        let default_cert = match self
            .cert_manager
            .resolve(&secret_ref, hostnames.clone())
            .await
        {
            Ok(cert) => cert,
            Err(e) => {
                warn!(
                    secret = %first_ref.name,
                    namespace = %secret_ns,
                    error = %e,
                    "Failed to resolve TLS certificate, listener will lack TLS"
                );
                return None;
            }
        };

        // Resolve additional certificates as SNI certs
        let mut additional_certs = Vec::new();
        for cert_ref in cert_refs.iter().skip(1) {
            let ns = cert_ref.namespace.as_deref().unwrap_or(gateway_ns);
            let sref = SecretRef {
                namespace: ns.to_string(),
                name: cert_ref.name.clone(),
            };
            match self.cert_manager.resolve(&sref, hostnames.clone()).await {
                Ok(cert) => {
                    additional_certs.push(SniCertificate {
                        hostnames: cert.hostnames.clone(),
                        priority_hostnames: vec![],
                        cert_file: cert.cert_path,
                        key_file: cert.key_path,
                    });
                }
                Err(e) => {
                    warn!(
                        secret = %cert_ref.name,
                        error = %e,
                        "Failed to resolve additional TLS certificate"
                    );
                }
            }
        }

        Some(TlsConfig {
            cert_file: Some(default_cert.cert_path),
            key_file: Some(default_cert.key_path),
            additional_certs,
            ca_file: None,
            min_version: TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: true,
            session_resumption: true,
            acme: None,
        })
    }

    /// Translate an HTTPRoute into Zentinel route, upstream, and filter configs.
    #[allow(clippy::type_complexity)]
    async fn translate_httproute(
        &self,
        route: &HTTPRoute,
        listener_hostnames: &[String],
        client: &Client,
    ) -> Result<
        (
            Vec<RouteConfig>,
            HashMap<String, UpstreamConfig>,
            HashMap<String, FilterConfig>,
        ),
        GatewayError,
    > {
        let route_name = route.name_any();
        let route_ns = route.namespace().unwrap_or_else(|| "default".into());

        let rules = route.spec.rules.as_ref().cloned().unwrap_or_default();
        let mut route_configs = Vec::new();
        let mut upstream_configs = HashMap::new();
        let mut filter_configs = HashMap::new();

        // Compute effective hostnames: intersection of route hostnames and
        // listener hostnames per Gateway API spec.
        let route_hostnames: Vec<String> = route.spec.hostnames.clone().unwrap_or_default();
        let hostnames = intersect_hostnames(&route_hostnames, listener_hostnames);

        // If both route and listener specified hostnames but the intersection
        // is empty, this route doesn't match any listener — skip it entirely.
        if hostnames.is_empty() && !route_hostnames.is_empty() && !listener_hostnames.is_empty() {
            debug!(
                route = %route_name,
                "Skipping route: no hostname intersection with listeners"
            );
            return Ok((route_configs, upstream_configs, filter_configs));
        }

        for (rule_idx, rule) in rules.iter().enumerate() {
            let rule_id = format!("{route_ns}-{route_name}-rule{rule_idx}");

            // Build upstream from backend refs (shared across all match entries)
            let (upstream_id, upstream) = self
                .translate_backends(&rule_id, &rule.backend_refs, &route_ns, client)
                .await?;

            let has_upstream = upstream.is_some();
            if let Some(upstream) = upstream {
                upstream_configs.insert(upstream_id.clone(), upstream);
            }

            // Build header modifications from filters (shared)
            let request_headers = self.extract_request_header_mods(&rule.filters);
            let response_headers = self.extract_response_header_mods(&rule.filters);

            // Extract redirect and rewrite filters (shared)
            let mut route_filter_ids = Vec::new();
            self.extract_redirect_filters(
                &rule.filters,
                &rule_id,
                &mut filter_configs,
                &mut route_filter_ids,
            );
            self.extract_rewrite_filters(
                &rule.filters,
                &rule_id,
                &mut filter_configs,
                &mut route_filter_ids,
            );

            // Each RouteMatch in the matches array is an OR alternative.
            // Generate a separate route for each match entry so the proxy's
            // AND-based matcher handles them correctly.
            let match_sets = self.expand_matches(&rule.matches, &hostnames);

            for (match_idx, conditions) in match_sets.into_iter().enumerate() {
                let match_id = if match_sets_count(&rule.matches) > 1 {
                    format!("{rule_id}-m{match_idx}")
                } else {
                    rule_id.clone()
                };

                // Only reference upstream if one was actually created.
                // Redirect-only routes have no backend refs and no upstream.
                let route_upstream = if has_upstream {
                    Some(upstream_id.clone())
                } else {
                    None
                };

                let route_config = RouteConfig {
                    id: match_id,
                    priority: Priority::Normal,
                    matches: conditions,
                    upstream: route_upstream,
                    service_type: ServiceType::Web,
                    policies: RoutePolicies {
                        request_headers: request_headers.clone(),
                        response_headers: response_headers.clone(),
                        ..RoutePolicies::default()
                    },
                    filters: route_filter_ids.clone(),
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

                route_configs.push(route_config);
            }
        }

        Ok((route_configs, upstream_configs, filter_configs))
    }

    /// Expand HTTPRoute matches into separate condition sets (one per match entry).
    ///
    /// Each `RouteMatch` in the Gateway API spec's `matches` array is an OR
    /// alternative. We generate a separate set of conditions for each, so the
    /// caller can create one proxy route per match entry.
    fn expand_matches(
        &self,
        rule_matches: &Option<Vec<RouteMatch>>,
        hostnames: &[String],
    ) -> Vec<Vec<MatchCondition>> {
        let host_conditions: Vec<MatchCondition> = hostnames
            .iter()
            .map(|h| MatchCondition::Host(h.clone()))
            .collect();

        let route_matches = match rule_matches {
            Some(m) if !m.is_empty() => m,
            _ => {
                // No matches = match everything. Single route with hosts + PathPrefix("/")
                let mut conditions = host_conditions;
                conditions.push(MatchCondition::PathPrefix("/".to_string()));
                return vec![conditions];
            }
        };

        let mut result = Vec::with_capacity(route_matches.len());

        for m in route_matches {
            let mut conditions = host_conditions.clone();

            // Path match
            if let Some(ref path) = m.path {
                let value = path.value.as_deref().unwrap_or("/").to_string();
                match path.r#type {
                    Some(HttpRouteRulesMatchesPathType::Exact) => {
                        conditions.push(MatchCondition::Path(value));
                    }
                    Some(HttpRouteRulesMatchesPathType::RegularExpression) => {
                        conditions.push(MatchCondition::PathRegex(value));
                    }
                    _ => {
                        conditions.push(MatchCondition::PathPrefix(value));
                    }
                }
            }

            // Header matches
            if let Some(ref headers) = m.headers {
                for header in headers {
                    conditions.push(MatchCondition::Header {
                        name: header.name.clone(),
                        value: Some(header.value.clone()),
                    });
                }
            }

            // Method match
            if let Some(ref method) = m.method {
                let method_str = serde_json::to_value(method)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("{method:?}"));
                conditions.push(MatchCondition::Method(vec![method_str]));
            }

            // Query parameter matches
            if let Some(ref params) = m.query_params {
                for param in params {
                    conditions.push(MatchCondition::QueryParam {
                        name: param.name.clone(),
                        value: Some(param.value.clone()),
                    });
                }
            }

            // If this match entry has no path condition but has other
            // conditions, add a catch-all path prefix so the route matches
            // all paths (Gateway API default behavior).
            let has_path = conditions.iter().any(|c| {
                matches!(
                    c,
                    MatchCondition::Path(_)
                        | MatchCondition::PathPrefix(_)
                        | MatchCondition::PathRegex(_)
                )
            });
            if !has_path {
                conditions.push(MatchCondition::PathPrefix("/".to_string()));
            }

            result.push(conditions);
        }

        result
    }

    /// Translate HTTPRoute backend references into a Zentinel upstream.
    async fn translate_backends(
        &self,
        rule_id: &str,
        backend_refs: &Option<Vec<HTTPBackendReference>>,
        route_ns: &str,
        client: &Client,
    ) -> Result<(String, Option<UpstreamConfig>), GatewayError> {
        let upstream_id = format!("{rule_id}-upstream");

        let backend_refs = match backend_refs {
            Some(refs) => refs,
            None => return Ok((upstream_id, None)),
        };

        if backend_refs.is_empty() {
            return Ok((upstream_id, None));
        }

        let mut targets = Vec::new();

        for backend in backend_refs {
            // Only Service (core group) backends are supported.
            // Skip backends with unknown kind/group per Gateway API spec.
            let kind = backend.kind.as_deref().unwrap_or("Service");
            let group = backend.group.as_deref().unwrap_or("");
            if kind != "Service" || (!group.is_empty() && group != "core") {
                warn!(
                    rule_id = rule_id,
                    kind = kind,
                    group = group,
                    "Skipping backend with unsupported kind/group"
                );
                continue;
            }

            let svc_name = &backend.name;
            let svc_ns = backend.namespace.as_deref().unwrap_or(route_ns);
            let svc_port = backend.port.unwrap_or(80);
            let weight = backend.weight.unwrap_or(1);

            // Check cross-namespace reference permission
            if svc_ns != route_ns
                && !self.reference_grants.is_permitted(&ReferenceQuery {
                    source_namespace: route_ns,
                    source_group: "gateway.networking.k8s.io",
                    source_kind: "HTTPRoute",
                    target_namespace: svc_ns,
                    target_group: "",
                    target_kind: "Service",
                    target_name: svc_name,
                })
            {
                warn!(
                    route_ns = route_ns,
                    service = %svc_name,
                    service_ns = %svc_ns,
                    "Cross-namespace backend reference denied"
                );
                continue;
            }

            // Check if service is headless (clusterIP: None).
            // For headless services, we resolve EndpointSlices to get pod IPs
            // since there's no ClusterIP for kube-proxy to route through.
            let svc_api: Api<k8s_openapi::api::core::v1::Service> =
                Api::namespaced(client.clone(), svc_ns);
            let is_headless = svc_api
                .get(svc_name)
                .await
                .ok()
                .and_then(|svc| svc.spec)
                .and_then(|spec| spec.cluster_ip)
                .is_some_and(|ip| ip == "None" || ip.is_empty());

            if is_headless {
                // For headless services, look up EndpointSlices to get pod IPs
                let ep_api: Api<k8s_openapi::api::discovery::v1::EndpointSlice> =
                    Api::namespaced(client.clone(), svc_ns);
                let label_selector = format!("kubernetes.io/service-name={svc_name}");
                let eps = ep_api
                    .list(&ListParams::default().labels(&label_selector))
                    .await
                    .map(|list| list.items)
                    .unwrap_or_default();

                for ep_slice in &eps {
                    // Only use IPv4 endpoints
                    if ep_slice.address_type != "IPv4" {
                        continue;
                    }

                    // Find the target port from the EndpointSlice ports
                    let target_port = ep_slice
                        .ports
                        .as_ref()
                        .and_then(|ports| ports.first())
                        .and_then(|p| p.port)
                        .unwrap_or(svc_port) as u16;

                    for endpoint in &ep_slice.endpoints {
                        // Only use ready endpoints
                        if !endpoint
                            .conditions
                            .as_ref()
                            .and_then(|c| c.ready)
                            .unwrap_or(true)
                        {
                            continue;
                        }
                        for addr in &endpoint.addresses {
                            targets.push(UpstreamTarget {
                                address: format!("{addr}:{target_port}"),
                                weight: weight as u32,
                                max_requests: None,
                                metadata: HashMap::from([
                                    ("k8s-service".to_string(), svc_name.clone()),
                                    ("k8s-namespace".to_string(), svc_ns.to_string()),
                                ]),
                            });
                        }
                    }
                }
            } else {
                // Regular service: use Kubernetes DNS
                // <service>.<namespace>.svc.cluster.local:<port>
                let address = format!("{svc_name}.{svc_ns}.svc.cluster.local:{svc_port}");

                targets.push(UpstreamTarget {
                    address,
                    weight: weight as u32,
                    max_requests: None,
                    metadata: HashMap::from([
                        ("k8s-service".to_string(), svc_name.clone()),
                        ("k8s-namespace".to_string(), svc_ns.to_string()),
                    ]),
                });
            }
        }

        // Remove targets with weight=0 (Gateway API spec: weight 0 = no traffic)
        targets.retain(|t| t.weight > 0);

        // When all backends are invalid (wrong kind, denied cross-namespace, etc.),
        // return None so the route gets no upstream. The proxy will return 500
        // for requests matching this route.
        if targets.is_empty() {
            return Ok((upstream_id, None));
        }

        // Use weighted load balancing when backends have different weights
        let has_varying_weights = targets.windows(2).any(|w| w[0].weight != w[1].weight);
        let load_balancing = if has_varying_weights {
            LoadBalancingAlgorithm::Weighted
        } else {
            LoadBalancingAlgorithm::RoundRobin
        };

        let upstream = UpstreamConfig {
            id: upstream_id.clone(),
            targets,
            load_balancing,
            sticky_session: None,
            health_check: Some(HealthCheck {
                check_type: HealthCheckType::Http {
                    path: "/".to_string(),
                    expected_status: 200,
                    host: None,
                },
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
        };

        Ok((upstream_id, Some(upstream)))
    }

    /// Extract request header modifications from HTTPRoute filters.
    fn extract_request_header_mods(
        &self,
        filters: &Option<Vec<HttpRouteFilter>>,
    ) -> HeaderModifications {
        let mut mods = HeaderModifications::default();

        let filters = match filters {
            Some(f) => f,
            None => return mods,
        };

        for filter in filters {
            if filter.r#type == HTTPFilterType::RequestHeaderModifier {
                if let Some(ref modifier) = filter.request_header_modifier {
                    if let Some(ref adds) = modifier.add {
                        for header in adds {
                            mods.add.insert(header.name.clone(), header.value.clone());
                        }
                    }
                    if let Some(ref removes) = modifier.remove {
                        mods.remove.extend(removes.clone());
                    }
                    if let Some(ref sets) = modifier.set {
                        for header in sets {
                            mods.set.insert(header.name.clone(), header.value.clone());
                        }
                    }
                }
            }
        }

        mods
    }

    /// Extract response header modifications from HTTPRoute filters.
    fn extract_response_header_mods(
        &self,
        filters: &Option<Vec<HttpRouteFilter>>,
    ) -> HeaderModifications {
        let mut mods = HeaderModifications::default();

        let filters = match filters {
            Some(f) => f,
            None => return mods,
        };

        for filter in filters {
            if filter.r#type == HTTPFilterType::ResponseHeaderModifier {
                if let Some(ref modifier) = filter.response_header_modifier {
                    if let Some(ref adds) = modifier.add {
                        for header in adds {
                            mods.add.insert(header.name.clone(), header.value.clone());
                        }
                    }
                    if let Some(ref removes) = modifier.remove {
                        mods.remove.extend(removes.clone());
                    }
                    if let Some(ref sets) = modifier.set {
                        for header in sets {
                            mods.set.insert(header.name.clone(), header.value.clone());
                        }
                    }
                }
            }
        }

        mods
    }

    /// Extract RequestRedirect filters and create Zentinel filter configs.
    fn extract_redirect_filters(
        &self,
        rule_filters: &Option<Vec<HttpRouteFilter>>,
        rule_id: &str,
        filter_configs: &mut HashMap<String, FilterConfig>,
        route_filter_ids: &mut Vec<String>,
    ) {
        let filters = match rule_filters {
            Some(f) => f,
            None => return,
        };

        for (i, filter) in filters.iter().enumerate() {
            if filter.r#type != HTTPFilterType::RequestRedirect {
                continue;
            }

            let Some(ref redirect) = filter.request_redirect else {
                continue;
            };

            let filter_id = format!("{rule_id}-redirect-{i}");

            let scheme = redirect.scheme.as_ref().map(|s| {
                serde_json::to_value(s)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| format!("{s:?}"))
            });

            let status_code = redirect.status_code.map(|c| c as u16).unwrap_or(302);

            let path = redirect.path.as_ref().map(|p| {
                if let Some(ref full) = p.replace_full_path {
                    PathModifier::ReplaceFullPath {
                        value: full.clone(),
                    }
                } else if let Some(ref prefix) = p.replace_prefix_match {
                    PathModifier::ReplacePrefixMatch {
                        value: prefix.clone(),
                    }
                } else {
                    PathModifier::ReplaceFullPath {
                        value: "/".to_string(),
                    }
                }
            });

            let redirect_filter = RedirectFilter {
                hostname: redirect.hostname.clone(),
                status_code,
                scheme,
                port: redirect.port.map(|p| p as u16),
                path,
            };

            filter_configs.insert(
                filter_id.clone(),
                FilterConfig::new(filter_id.clone(), Filter::Redirect(redirect_filter)),
            );
            route_filter_ids.push(filter_id);
        }
    }

    /// Extract URLRewrite filters and create Zentinel filter configs.
    fn extract_rewrite_filters(
        &self,
        rule_filters: &Option<Vec<HttpRouteFilter>>,
        rule_id: &str,
        filter_configs: &mut HashMap<String, FilterConfig>,
        route_filter_ids: &mut Vec<String>,
    ) {
        let filters = match rule_filters {
            Some(f) => f,
            None => return,
        };

        for (i, filter) in filters.iter().enumerate() {
            if filter.r#type != HTTPFilterType::UrlRewrite {
                continue;
            }

            let Some(ref rewrite) = filter.url_rewrite else {
                continue;
            };

            let filter_id = format!("{rule_id}-rewrite-{i}");

            let path = rewrite.path.as_ref().map(|p| {
                if let Some(ref full) = p.replace_full_path {
                    PathModifier::ReplaceFullPath {
                        value: full.clone(),
                    }
                } else if let Some(ref prefix) = p.replace_prefix_match {
                    PathModifier::ReplacePrefixMatch {
                        value: prefix.clone(),
                    }
                } else {
                    PathModifier::ReplaceFullPath {
                        value: "/".to_string(),
                    }
                }
            });

            let rewrite_filter = UrlRewriteFilter {
                hostname: rewrite.hostname.clone(),
                path,
            };

            filter_configs.insert(
                filter_id.clone(),
                FilterConfig::new(filter_id.clone(), Filter::UrlRewrite(rewrite_filter)),
            );
            route_filter_ids.push(filter_id);
        }
    }

    // ========================================================================
    // GRPCRoute Translation
    // ========================================================================

    /// Translate a GRPCRoute into Zentinel route and upstream configs.
    ///
    /// gRPC service/method matches are translated to path-prefix matches
    /// using the gRPC path convention: `/<package.Service>/<Method>`.
    fn translate_grpcroute(
        &self,
        route: &GRPCRoute,
    ) -> Result<(Vec<RouteConfig>, HashMap<String, UpstreamConfig>), GatewayError> {
        let route_name = route.name_any();
        let route_ns = route.namespace().unwrap_or_else(|| "default".into());

        let rules = route.spec.rules.as_ref().cloned().unwrap_or_default();
        let mut route_configs = Vec::new();
        let mut upstream_configs = HashMap::new();

        let hostnames: Vec<String> = route.spec.hostnames.clone().unwrap_or_default();

        for (rule_idx, rule) in rules.iter().enumerate() {
            let rule_id = format!("{route_ns}-{route_name}-grpc-rule{rule_idx}");

            // Build match conditions from gRPC matches
            let matches = self.translate_grpc_matches(&rule.matches, &hostnames);

            // Build upstream from backend refs (same structure as HTTPRoute)
            let backend_refs = rule.backend_refs.as_ref().cloned().unwrap_or_default();
            let (upstream_id, upstream) =
                self.translate_grpc_backends(&rule_id, &backend_refs, &route_ns)?;

            if let Some(upstream) = upstream {
                upstream_configs.insert(upstream_id.clone(), upstream);
            }

            let route_config = RouteConfig {
                id: rule_id,
                priority: Priority::Normal,
                matches,
                upstream: Some(upstream_id),
                service_type: ServiceType::Web, // gRPC runs over HTTP/2
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

            route_configs.push(route_config);
        }

        Ok((route_configs, upstream_configs))
    }

    /// Translate GRPCRoute matches into Zentinel match conditions.
    ///
    /// gRPC uses HTTP/2 POST with path `/<service>/<method>`, so service/method
    /// matches become path prefix/exact matches.
    fn translate_grpc_matches(
        &self,
        rule_matches: &Option<Vec<gateway_api::grpcroutes::GrpcRouteMatch>>,
        hostnames: &[String],
    ) -> Vec<MatchCondition> {
        let mut conditions = Vec::new();

        // Add host matches
        for hostname in hostnames {
            conditions.push(MatchCondition::Host(hostname.clone()));
        }

        // gRPC is always POST
        conditions.push(MatchCondition::Method(vec!["POST".to_string()]));

        let route_matches = match rule_matches {
            Some(m) if !m.is_empty() => m,
            _ => {
                // No matches = match all gRPC traffic
                conditions.push(MatchCondition::PathPrefix("/".to_string()));
                return conditions;
            }
        };

        for m in route_matches {
            if let Some(ref method_match) = m.method {
                let service = method_match.service.as_deref().unwrap_or("");
                let method = method_match.method.as_deref().unwrap_or("");

                let path = match (service.is_empty(), method.is_empty()) {
                    (false, false) => {
                        // Exact: /<service>/<method>
                        conditions.push(MatchCondition::Path(format!("/{service}/{method}")));
                        continue;
                    }
                    (false, true) => {
                        // Service only: prefix /<service>/
                        format!("/{service}/")
                    }
                    (true, false) => {
                        // Method only: harder to match, use path prefix
                        // This is implementation-specific support
                        format!("/{method}")
                    }
                    (true, true) => {
                        // Both empty = match everything
                        "/".to_string()
                    }
                };
                conditions.push(MatchCondition::PathPrefix(path));
            }

            // Header matches
            if let Some(ref headers) = m.headers {
                for header in headers {
                    conditions.push(MatchCondition::Header {
                        name: header.name.clone(),
                        value: Some(header.value.clone()),
                    });
                }
            }
        }

        if conditions
            .iter()
            .all(|c| matches!(c, MatchCondition::Host(_) | MatchCondition::Method(_)))
        {
            conditions.push(MatchCondition::PathPrefix("/".to_string()));
        }

        conditions
    }

    /// Translate GRPCRoute backend refs into a Zentinel upstream.
    fn translate_grpc_backends(
        &self,
        rule_id: &str,
        backend_refs: &[gateway_api::grpcroutes::GRPCBackendReference],
        route_ns: &str,
    ) -> Result<(String, Option<UpstreamConfig>), GatewayError> {
        let upstream_id = format!("{rule_id}-upstream");

        if backend_refs.is_empty() {
            return Ok((upstream_id, None));
        }

        let mut targets = Vec::new();

        for backend in backend_refs {
            let svc_name = &backend.name;
            let svc_ns = backend.namespace.as_deref().unwrap_or(route_ns);
            let svc_port = backend.port.unwrap_or(50051); // default gRPC port
            let weight = backend.weight.unwrap_or(1);

            if svc_ns != route_ns
                && !self.reference_grants.is_permitted(&ReferenceQuery {
                    source_namespace: route_ns,
                    source_group: "gateway.networking.k8s.io",
                    source_kind: "GRPCRoute",
                    target_namespace: svc_ns,
                    target_group: "",
                    target_kind: "Service",
                    target_name: svc_name,
                })
            {
                warn!(
                    route_ns = route_ns,
                    service = %svc_name,
                    service_ns = %svc_ns,
                    "Cross-namespace gRPC backend reference denied"
                );
                continue;
            }

            let address = format!("{svc_name}.{svc_ns}.svc.cluster.local:{svc_port}");

            targets.push(UpstreamTarget {
                address,
                weight: weight as u32,
                max_requests: None,
                metadata: HashMap::from([
                    ("k8s-service".to_string(), svc_name.clone()),
                    ("k8s-namespace".to_string(), svc_ns.to_string()),
                    ("protocol".to_string(), "grpc".to_string()),
                ]),
            });
        }

        if targets.is_empty() {
            return Err(GatewayError::Translation(format!(
                "GRPCRoute rule '{rule_id}' has no valid backend references"
            )));
        }

        let upstream = UpstreamConfig {
            id: upstream_id.clone(),
            targets,
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: Some(HealthCheck {
                check_type: HealthCheckType::Grpc {
                    service: String::new(), // gRPC health check on default service
                },
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig {
                min_version: 2, // gRPC requires HTTP/2
                max_version: 2,
                h2_ping_interval_secs: 30,
                max_h2_streams: 100,
            },
        };

        Ok((upstream_id, Some(upstream)))
    }

    // ========================================================================
    // TLSRoute Translation
    // ========================================================================

    /// Translate a TLSRoute into Zentinel route and upstream configs.
    ///
    /// TLSRoutes are SNI-based passthrough routes — they match on hostnames
    /// and forward the raw TLS connection to backends without termination.
    fn translate_tlsroute(
        &self,
        route: &TLSRoute,
    ) -> Result<(Vec<RouteConfig>, HashMap<String, UpstreamConfig>), GatewayError> {
        let route_name = route.name_any();
        let route_ns = route.namespace().unwrap_or_else(|| "default".into());

        let mut route_configs = Vec::new();
        let mut upstream_configs = HashMap::new();

        for (rule_idx, rule) in route.spec.rules.iter().enumerate() {
            let rule_id = format!("{route_ns}-{route_name}-tls-rule{rule_idx}");

            // TLSRoute matches only on SNI hostnames
            let mut matches = Vec::new();
            for hostname in &route.spec.hostnames {
                matches.push(MatchCondition::Host(hostname.clone()));
            }
            if matches.is_empty() {
                matches.push(MatchCondition::PathPrefix("/".to_string()));
            }

            // Translate backends
            let (upstream_id, upstream) =
                self.translate_tls_backends(&rule_id, &rule.backend_refs, &route_ns)?;

            if let Some(upstream) = upstream {
                upstream_configs.insert(upstream_id.clone(), upstream);
            }

            let route_config = RouteConfig {
                id: rule_id,
                priority: Priority::Normal,
                matches,
                upstream: Some(upstream_id),
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

            route_configs.push(route_config);
        }

        Ok((route_configs, upstream_configs))
    }

    /// Translate TLSRoute backend refs into a Zentinel upstream.
    fn translate_tls_backends(
        &self,
        rule_id: &str,
        backend_refs: &[gateway_api::experimental::common::BackendReference],
        route_ns: &str,
    ) -> Result<(String, Option<UpstreamConfig>), GatewayError> {
        let upstream_id = format!("{rule_id}-upstream");

        if backend_refs.is_empty() {
            return Ok((upstream_id, None));
        }

        let mut targets = Vec::new();

        for backend in backend_refs {
            let svc_name = &backend.name;
            let svc_ns = backend.namespace.as_deref().unwrap_or(route_ns);
            let svc_port = backend.port.unwrap_or(443);
            let weight = backend.weight.unwrap_or(1);

            if svc_ns != route_ns
                && !self.reference_grants.is_permitted(&ReferenceQuery {
                    source_namespace: route_ns,
                    source_group: "gateway.networking.k8s.io",
                    source_kind: "TLSRoute",
                    target_namespace: svc_ns,
                    target_group: "",
                    target_kind: "Service",
                    target_name: svc_name,
                })
            {
                warn!(
                    route_ns = route_ns,
                    service = %svc_name,
                    service_ns = %svc_ns,
                    "Cross-namespace TLS backend reference denied"
                );
                continue;
            }

            let address = format!("{svc_name}.{svc_ns}.svc.cluster.local:{svc_port}");

            targets.push(UpstreamTarget {
                address,
                weight: weight as u32,
                max_requests: None,
                metadata: HashMap::from([
                    ("k8s-service".to_string(), svc_name.clone()),
                    ("k8s-namespace".to_string(), svc_ns.to_string()),
                    ("protocol".to_string(), "tls-passthrough".to_string()),
                ]),
            });
        }

        if targets.is_empty() {
            return Err(GatewayError::Translation(format!(
                "TLSRoute rule '{rule_id}' has no valid backend references"
            )));
        }

        let upstream = UpstreamConfig {
            id: upstream_id.clone(),
            targets,
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: Some(HealthCheck {
                check_type: HealthCheckType::Tcp,
                interval_secs: 10,
                timeout_secs: 5,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None, // Passthrough — no TLS termination at proxy
            http_version: HttpVersionConfig::default(),
        };

        Ok((upstream_id, Some(upstream)))
    }

    /// Check if a route's namespace is allowed by the Gateway's listener
    /// allowedRoutes configuration (Same, All, or Selector).
    async fn is_route_namespace_allowed(
        &self,
        gw: &Gateway,
        route_ns: &str,
        gw_ns: &str,
        client: &Client,
    ) -> bool {
        use gateway_api::gateways::GatewayListenersAllowedRoutesNamespacesFrom;

        for listener in &gw.spec.listeners {
            if let Some(ref allowed) = listener.allowed_routes {
                if let Some(ref namespaces) = allowed.namespaces {
                    if let Some(ref from) = namespaces.from {
                        match from {
                            GatewayListenersAllowedRoutesNamespacesFrom::All => return true,
                            GatewayListenersAllowedRoutesNamespacesFrom::Same => {
                                if gw_ns == route_ns {
                                    return true;
                                }
                            }
                            GatewayListenersAllowedRoutesNamespacesFrom::Selector => {
                                if let Some(ref selector) = namespaces.selector {
                                    if let Some(ref match_labels) = selector.match_labels {
                                        let ns_api: Api<k8s_openapi::api::core::v1::Namespace> =
                                            Api::all(client.clone());
                                        if let Ok(ns) = ns_api.get(route_ns).await {
                                            let ns_labels = ns.metadata.labels.unwrap_or_default();
                                            if match_labels
                                                .iter()
                                                .all(|(k, v)| ns_labels.get(k) == Some(v))
                                            {
                                                return true;
                                            }
                                        }
                                    } else {
                                        return true; // Empty selector matches all
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // No namespaces constraint = default Same
                    if gw_ns == route_ns {
                        return true;
                    }
                }
            } else {
                // No allowedRoutes = Same namespace only (default)
                if gw_ns == route_ns {
                    return true;
                }
            }
        }
        false
    }
}

/// Count the number of match entries in a rule's matches array.
fn match_sets_count(matches: &Option<Vec<RouteMatch>>) -> usize {
    matches.as_ref().map_or(1, |m| m.len().max(1))
}

/// Compute the intersection of route hostnames and listener hostnames.
///
/// Per Gateway API spec:
/// - If listener has no hostname: all route hostnames are effective
/// - If route has no hostnames: all listener hostnames are effective
/// - If both have hostnames: only matching ones are effective
/// - Wildcard matching: `*.example.com` matches `foo.example.com`
fn intersect_hostnames(route_hostnames: &[String], listener_hostnames: &[String]) -> Vec<String> {
    // No listener hostnames = listener accepts everything → use route hostnames as-is
    if listener_hostnames.is_empty() {
        return route_hostnames.to_vec();
    }

    // No route hostnames = route matches everything → use listener hostnames
    if route_hostnames.is_empty() {
        return listener_hostnames.to_vec();
    }

    // Both have hostnames → compute intersection
    let mut result = Vec::new();
    for rh in route_hostnames {
        for lh in listener_hostnames {
            if let Some(effective) = hostname_match(rh, lh) {
                if !result.contains(&effective) {
                    result.push(effective);
                }
            }
        }
    }
    result
}

/// Check if two hostnames match (considering wildcards) and return the more
/// specific one. Returns None if they don't intersect.
fn hostname_match(a: &str, b: &str) -> Option<String> {
    match (a.starts_with("*."), b.starts_with("*.")) {
        // Both exact
        (false, false) => {
            if a.eq_ignore_ascii_case(b) {
                Some(a.to_string())
            } else {
                None
            }
        }
        // a is wildcard, b is exact
        (true, false) => {
            let suffix = &a[1..]; // ".example.com"
            if b.ends_with(suffix) && b.len() > suffix.len() {
                Some(b.to_string()) // exact is more specific
            } else {
                None
            }
        }
        // a is exact, b is wildcard
        (false, true) => {
            let suffix = &b[1..];
            if a.ends_with(suffix) && a.len() > suffix.len() {
                Some(a.to_string())
            } else {
                None
            }
        }
        // Both wildcard
        (true, true) => {
            let a_suffix = &a[1..];
            let b_suffix = &b[1..];
            // The more specific (longer suffix) wildcard wins
            if a_suffix == b_suffix || a_suffix.ends_with(b_suffix) {
                Some(a.to_string())
            } else if b_suffix.ends_with(a_suffix) {
                Some(b.to_string())
            } else {
                None
            }
        }
    }
}
