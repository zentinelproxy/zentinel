//! Namespaces and services, lowered into the configuration the proxy runs.
//!
//! The proxy keeps one set of upstream pools, filters, agents and routes, each
//! keyed by id, and looks a route's upstream and filters up by the id the route
//! names. Namespaces and services were parsed into their own blocks and then
//! left there: their routes were never matched (or only on a listener bound to
//! the namespace), and a route naming a namespace's own upstream got
//! `500 "Upstream pool not found"`, because only global upstreams had pools
//! (#548).
//!
//! [`Config::lower_scopes`] moves every namespace and service resource to the
//! top level under its qualified id (`ns:name`, `ns:svc:name`), and rewrites the
//! references in it to the qualified id they resolve to, following the scope
//! chain (service, then namespace, then exports, then global). Everything that
//! works for global resources -- pools, health checks, filters, rate limiters,
//! agents, error pages, static files -- then works for scoped ones unchanged,
//! and two namespaces may both have a route or upstream called `main`.
//!
//! # Which listener serves which routes
//!
//! A listener belongs to a scope: the global one, a namespace (a listener
//! declared in the namespace's `listeners` block, or a top-level listener with
//! `namespace "ns"`) or a service (the service's `listener` block). A route is
//! served on the listeners of the nearest scope, from its own outwards, that
//! has a listener, and only there:
//!
//! - a namespace or service with no listener of its own is served on its
//!   parent's listeners, ultimately on the global (unbound) listeners;
//! - a namespace or service with a listener is served only on that listener,
//!   never on the global ones, so an internal namespace bound to an internal
//!   port does not leak onto the public one;
//! - a listener serves only routes of its own scope (and of the scopes inside
//!   it that have no listener), never global routes: a namespace-bound listener
//!   was isolated from the global routes before this, and stays so.
//!
//! All the routes served on one listener are matched together, by priority and
//! then specificity, exactly as routes in one `routes` block are.

use std::collections::{HashMap, HashSet};

use zentinel_common::ids::{QualifiedId, Scope};
use zentinel_common::limits::Limits;

use crate::{
    AgentConfig, Config, Filter, FilterConfig, ListenerConfig, NamespaceConfig, RouteConfig,
    UpstreamConfig,
};

/// Where the resources moved by [`Config::lower_scopes`] came from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeIndex {
    /// The scope of every route moved out of a namespace or service, by its
    /// qualified id. A route that is not here is global.
    pub route_scopes: HashMap<String, Scope>,

    /// Namespaces and services that declare a listener of their own,
    /// including one that could not be bound. Their routes are served only on
    /// their own listeners.
    pub listener_scopes: HashSet<Scope>,
}

impl ListenerConfig {
    /// The scope this listener serves: global, a namespace, or a service.
    pub fn scope(&self) -> Scope {
        match (&self.namespace, &self.service) {
            (Some(namespace), Some(service)) => Scope::Service {
                namespace: namespace.clone(),
                service: service.clone(),
            },
            (Some(namespace), None) => Scope::Namespace(namespace.clone()),
            (None, _) => Scope::Global,
        }
    }
}

impl Config {
    /// This configuration with every namespace and service resource moved to
    /// the top level under its qualified id. See the [module docs](self).
    ///
    /// Idempotent: lowering a lowered configuration changes nothing.
    pub fn lower_scopes(&self) -> Config {
        self.lower_scopes_reporting().0
    }

    /// [`Self::lower_scopes`], and the namespace and service settings that are
    /// not applied, as messages for `zentinel lint` / `zentinel test`.
    pub fn lower_scopes_reporting(&self) -> (Config, Vec<String>) {
        let mut lowering = Lowering {
            src: self,
            out: self.clone(),
            problems: Vec::new(),
        };
        lowering.run();
        (lowering.out, lowering.problems)
    }

    /// The scope a route of this (lowered) configuration belongs to.
    pub fn route_scope(&self, route_id: &str) -> Scope {
        self.scope_index
            .route_scopes
            .get(route_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether `scope` has a listener of its own.
    fn scope_has_listener(&self, scope: &Scope) -> bool {
        scope.is_global()
            || self.scope_index.listener_scopes.contains(scope)
            || self.listeners.iter().any(|l| &l.scope() == scope)
    }

    /// The scope whose listeners serve the routes of `scope`: the nearest one,
    /// from `scope` outwards, that has a listener.
    pub fn serving_scope(&self, scope: &Scope) -> Scope {
        scope
            .chain()
            .into_iter()
            .find(|s| self.scope_has_listener(s))
            .unwrap_or_default()
    }

    /// The routes served on a listener of `listener_scope`, in config order.
    pub fn routes_served_on(&self, listener_scope: &Scope) -> Vec<RouteConfig> {
        self.routes
            .iter()
            .filter(|route| &self.serving_scope(&self.route_scope(&route.id)) == listener_scope)
            .cloned()
            .collect()
    }

    /// The `limits` blocks that apply to a request routed in `scope`, each
    /// with the scope it belongs to: the namespace's, then the service's. The
    /// global block is not included.
    pub fn scope_limits(&self, scope: &Scope) -> Vec<(Scope, &Limits)> {
        let Some(ns_id) = scope.namespace() else {
            return Vec::new();
        };
        let Some(ns) = self.namespaces.iter().find(|ns| ns.id == ns_id) else {
            return Vec::new();
        };
        let mut limits = Vec::new();
        if let Some(ns_limits) = &ns.limits {
            limits.push((Scope::Namespace(ns.id.clone()), ns_limits));
        }
        if let Some(svc_id) = scope.service() {
            if let Some(svc) = ns.services.iter().find(|s| s.id == svc_id) {
                if let Some(svc_limits) = &svc.limits {
                    limits.push((scope.clone(), svc_limits));
                }
            }
        }
        limits
    }
}

/// A scope, in words, for messages: `namespace 'api'`, `service 'users' of
/// namespace 'api'`.
fn describe(scope: &Scope) -> String {
    match scope {
        Scope::Global => "the top level".to_string(),
        Scope::Namespace(ns) => format!("namespace '{ns}'"),
        Scope::Service { namespace, service } => {
            format!("service '{service}' of namespace '{namespace}'")
        }
    }
}

/// The kinds of resource a reference can name.
#[derive(Clone, Copy)]
enum Kind {
    Upstream,
    Filter,
    Agent,
}

struct Lowering<'a> {
    /// The configuration as written; references resolve against it.
    src: &'a Config,
    /// The lowered configuration being built.
    out: Config,
    problems: Vec<String>,
}

impl Lowering<'_> {
    fn run(&mut self) {
        // Global resources keep their ids. A reference that does not name a
        // global resource may name an exported one.
        for route in &mut self.out.routes {
            resolve_route_refs(self.src, route, &Scope::Global);
        }
        for filter in self.out.filters.values_mut() {
            resolve_filter_refs(self.src, filter, &Scope::Global);
        }

        for ns in &self.src.namespaces {
            let ns_scope = Scope::Namespace(ns.id.clone());
            self.lower_resources(
                &ns_scope,
                &ns.upstreams,
                &ns.filters,
                &ns.agents,
                &ns.routes,
            );
            for listener in &ns.listeners {
                self.lower_listener(listener, &ns_scope, ns);
            }
            for svc in &ns.services {
                let svc_scope = Scope::Service {
                    namespace: ns.id.clone(),
                    service: svc.id.clone(),
                };
                self.lower_resources(
                    &svc_scope,
                    &svc.upstreams,
                    &svc.filters,
                    &svc.agents,
                    &svc.routes,
                );
                if let Some(listener) = &svc.listener {
                    self.lower_listener(listener, &svc_scope, ns);
                }
            }
        }

        // What moved is no longer in the namespaces. The ids, limits and
        // services stay: the proxy reads a scope's limits from them. Exports
        // were consumed by resolution, and would name resources that are no
        // longer in the namespace.
        for ns in &mut self.out.namespaces {
            ns.listeners.clear();
            ns.upstreams.clear();
            ns.routes.clear();
            ns.agents.clear();
            ns.filters.clear();
            ns.exports = Default::default();
            for svc in &mut ns.services {
                svc.listener = None;
                svc.upstreams.clear();
                svc.routes.clear();
                svc.agents.clear();
                svc.filters.clear();
            }
        }
    }

    fn lower_resources(
        &mut self,
        scope: &Scope,
        upstreams: &HashMap<String, UpstreamConfig>,
        filters: &HashMap<String, FilterConfig>,
        agents: &[AgentConfig],
        routes: &[RouteConfig],
    ) {
        // Sorted, so which of two colliding ids is reported does not depend
        // on hash order.
        let mut upstream_ids: Vec<&String> = upstreams.keys().collect();
        upstream_ids.sort();
        for id in upstream_ids {
            let qid = QualifiedId::new(id, scope.clone()).canonical();
            if self.out.upstreams.contains_key(&qid) {
                self.collision("upstream", id, scope, &qid);
                continue;
            }
            let mut upstream = upstreams[id].clone();
            upstream.id = qid.clone();
            self.out.upstreams.insert(qid, upstream);
        }

        let mut filter_ids: Vec<&String> = filters.keys().collect();
        filter_ids.sort();
        for id in filter_ids {
            let qid = QualifiedId::new(id, scope.clone()).canonical();
            if self.out.filters.contains_key(&qid) {
                self.collision("filter", id, scope, &qid);
                continue;
            }
            let mut filter = filters[id].clone();
            filter.id = qid.clone();
            resolve_filter_refs(self.src, &mut filter, scope);
            self.out.filters.insert(qid, filter);
        }

        for agent in agents {
            let qid = QualifiedId::new(&agent.id, scope.clone()).canonical();
            if self.out.agents.iter().any(|a| a.id == qid) {
                self.collision("agent", &agent.id, scope, &qid);
                continue;
            }
            let mut agent = agent.clone();
            agent.id = qid;
            self.out.agents.push(agent);
        }

        for route in routes {
            let qid = QualifiedId::new(&route.id, scope.clone()).canonical();
            if self.out.routes.iter().any(|r| r.id == qid) {
                self.collision("route", &route.id, scope, &qid);
                continue;
            }
            let mut route = route.clone();
            route.id = qid.clone();
            resolve_route_refs(self.src, &mut route, scope);
            self.out.routes.push(route);
            self.out.scope_index.route_scopes.insert(qid, scope.clone());
        }
    }

    fn collision(&mut self, kind: &str, id: &str, scope: &Scope, qid: &str) {
        self.problems.push(format!(
            "The {kind} '{id}' of {} is being ignored: its qualified id '{qid}' is already \
             the id of a top-level {kind}. Rename one of them.",
            describe(scope)
        ));
    }

    /// Move a namespace's or service's listener to the top level, bound to
    /// that scope, unless it cannot be bound.
    fn lower_listener(&mut self, listener: &ListenerConfig, scope: &Scope, ns: &NamespaceConfig) {
        // Whether or not the listener can be bound, the scope has declared one:
        // its routes are meant for that listener only, and serving them on the
        // global listeners instead could expose them where they were not meant
        // to be.
        self.out.scope_index.listener_scopes.insert(scope.clone());

        let qid = QualifiedId::new(&listener.id, scope.clone()).canonical();
        let mut lowered = listener.clone();
        lowered.id = qid.clone();

        if let Some(named) = &listener.namespace {
            if Some(named.as_str()) != scope.namespace() {
                self.problems.push(format!(
                    "'namespace \"{named}\"' on listener '{}' of {} is being ignored: a \
                     listener declared inside a namespace or service serves that scope.",
                    listener.id,
                    describe(scope)
                ));
            }
        }
        lowered.namespace = scope.namespace().map(str::to_string);
        lowered.service = scope.service().map(str::to_string);

        // `default-route` names a route of the listener's own scope.
        if let Some(default_route) = &listener.default_route {
            let local = match scope {
                Scope::Service { service, .. } => ns
                    .services
                    .iter()
                    .find(|s| &s.id == service)
                    .is_some_and(|s| s.routes.iter().any(|r| &r.id == default_route)),
                _ => ns.routes.iter().any(|r| &r.id == default_route),
            };
            if local {
                lowered.default_route =
                    Some(QualifiedId::new(default_route, scope.clone()).canonical());
            }
        }

        let unbound = |reason: String| {
            format!(
                "Listener '{}' of {} is being ignored: {reason}. The routes of {} are \
                 served only on its own listeners, so they are not served at all until \
                 it can be bound.",
                listener.id,
                describe(scope),
                describe(scope)
            )
        };

        if let Err(message) = crate::validation::check_listen_address(&listener.address) {
            self.problems.push(unbound(message));
            return;
        }
        if let Some(other) = self.out.listeners.iter().find(|l| {
            l.id == qid || crate::validation::addresses_collide(&l.address, &listener.address)
        }) {
            let reason = if other.id == qid {
                format!("its qualified id '{qid}' is already the id of another listener")
            } else {
                format!(
                    "it binds '{}', which listener '{}' also binds",
                    listener.address, other.id
                )
            };
            self.problems.push(unbound(reason));
            return;
        }
        let metrics = &self.src.observability.metrics;
        if metrics.enabled
            && crate::validation::addresses_collide(&metrics.address, &listener.address)
        {
            self.problems.push(unbound(format!(
                "it binds '{}', which the metrics server also binds",
                listener.address
            )));
            return;
        }

        self.out.listeners.push(lowered);
    }
}

/// Rewrite every upstream, filter and agent a route names to the qualified id
/// it resolves to from `scope`. A reference that resolves to nothing is left
/// as written, so it fails as it did before.
fn resolve_route_refs(src: &Config, route: &mut RouteConfig, scope: &Scope) {
    let upstream = |name: &mut String| resolve_into(src, Kind::Upstream, name, scope);
    if let Some(name) = route.upstream.as_mut() {
        upstream(name);
    }
    for name in &mut route.filters {
        resolve_into(src, Kind::Filter, name, scope);
    }
    if let Some(shadow) = route.shadow.as_mut() {
        upstream(&mut shadow.upstream);
    }
    if let Some(fallback) = route.fallback.as_mut() {
        for fb in &mut fallback.upstreams {
            upstream(&mut fb.upstream);
        }
    }
    if let Some(mcp) = route.mcp.as_mut() {
        for mcp_upstream in &mut mcp.upstreams {
            upstream(&mut mcp_upstream.upstream);
        }
    }
    if let Some(inference) = route.inference.as_mut() {
        if let Some(model_routing) = inference.model_routing.as_mut() {
            for mapping in &mut model_routing.mappings {
                upstream(&mut mapping.upstream);
            }
            if let Some(name) = model_routing.default_upstream.as_mut() {
                upstream(name);
            }
        }
        if let Some(guardrails) = inference.guardrails.as_mut() {
            if let Some(pi) = guardrails.prompt_injection.as_mut() {
                resolve_into(src, Kind::Agent, &mut pi.agent, scope);
            }
            if let Some(pii) = guardrails.pii_detection.as_mut() {
                resolve_into(src, Kind::Agent, &mut pii.agent, scope);
            }
        }
    }
}

fn resolve_filter_refs(src: &Config, filter: &mut FilterConfig, scope: &Scope) {
    if let Filter::Agent(agent_filter) = &mut filter.filter {
        resolve_into(src, Kind::Agent, &mut agent_filter.agent, scope);
    }
}

fn resolve_into(src: &Config, kind: Kind, name: &mut String, scope: &Scope) {
    if let Some(qid) = resolve(src, kind, name, scope) {
        *name = qid;
    }
}

/// The qualified id `reference` names from `scope`, or `None`.
///
/// A qualified reference (`ns:name`, `ns:svc:name`) names that resource
/// exactly. An unqualified one is looked up in the scope, its namespace, the
/// exports of every namespace, and the top level, in that order; from the top
/// level, the top level comes first.
fn resolve(src: &Config, kind: Kind, reference: &str, scope: &Scope) -> Option<String> {
    if reference.contains(':') {
        let qid = QualifiedId::parse(reference);
        return defines(src, kind, &qid.scope, &qid.name).then(|| qid.canonical());
    }
    for s in scope.chain() {
        if s.is_global() {
            break;
        }
        if defines(src, kind, &s, reference) {
            return Some(QualifiedId::new(reference, s).canonical());
        }
    }
    if scope.is_global() && defines(src, kind, &Scope::Global, reference) {
        return Some(reference.to_string());
    }
    for ns in &src.namespaces {
        let exported = match kind {
            Kind::Upstream => &ns.exports.upstreams,
            Kind::Filter => &ns.exports.filters,
            Kind::Agent => &ns.exports.agents,
        };
        let ns_scope = Scope::Namespace(ns.id.clone());
        if exported.iter().any(|e| e == reference) && defines(src, kind, &ns_scope, reference) {
            return Some(QualifiedId::new(reference, ns_scope).canonical());
        }
    }
    defines(src, kind, &Scope::Global, reference).then(|| reference.to_string())
}

/// Whether `scope` of the configuration as written defines a `kind` called
/// `name`.
fn defines(src: &Config, kind: Kind, scope: &Scope, name: &str) -> bool {
    let has = |upstreams: &HashMap<String, UpstreamConfig>,
               filters: &HashMap<String, FilterConfig>,
               agents: &[AgentConfig]| match kind {
        Kind::Upstream => upstreams.contains_key(name),
        Kind::Filter => filters.contains_key(name),
        Kind::Agent => agents.iter().any(|a| a.id == name),
    };
    match scope {
        Scope::Global => has(&src.upstreams, &src.filters, &src.agents),
        Scope::Namespace(ns_id) => src
            .namespaces
            .iter()
            .find(|ns| &ns.id == ns_id)
            .is_some_and(|ns| has(&ns.upstreams, &ns.filters, &ns.agents)),
        Scope::Service { namespace, service } => src
            .namespaces
            .iter()
            .find(|ns| &ns.id == namespace)
            .and_then(|ns| ns.services.iter().find(|s| &s.id == service))
            .is_some_and(|svc| has(&svc.upstreams, &svc.filters, &svc.agents)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDL: &str = r#"
        schema-version "1.0"
        system { worker-threads 1 }
        listeners {
            listener "public" { address "127.0.0.1:19480"; }
            listener "admin" { address "127.0.0.1:19481"; namespace "ops"; }
        }
        upstreams {
            upstream "shared" { target "127.0.0.1:3000"; }
        }
        routes {
            route "global" {
                matches { path-prefix "/global"; }
                upstream "shared"
            }
        }
        agents {
            agent "waf" {
                type "waf"
                grpc address="http://127.0.0.1:50051"
                events "request_headers"
            }
        }
        namespace "api" {
            upstreams {
                upstream "backend" { target "127.0.0.1:3001"; }
            }
            agents {
                agent "auth" {
                    type "auth"
                    grpc address="http://127.0.0.1:50052"
                    events "request_headers"
                }
            }
            filters {
                filter "auth" { type "agent"; agent "auth"; }
                filter "waf" { type "agent"; agent "waf"; }
                filter "rl" { type "rate-limit"; max-rps 5; }
            }
            routes {
                route "main" {
                    matches { path-prefix "/api/"; }
                    upstream "backend"
                    filters "auth" "rl"
                }
                route "to-global" {
                    matches { path-prefix "/auth/"; }
                    upstream "shared"
                    filters "waf"
                }
                route "to-infra" {
                    matches { path-prefix "/cache/"; }
                    upstream "redis"
                }
                route "qualified" {
                    matches { path-prefix "/q/"; }
                    upstream "infra:db"
                }
            }
            service "users" {
                upstreams {
                    upstream "backend" { target "127.0.0.1:3002"; }
                }
                routes {
                    route "main" {
                        matches { path-prefix "/users/"; }
                        upstream "backend"
                    }
                    route "parent" {
                        matches { path-prefix "/parent/"; }
                        upstream "shared"
                        filters "rl"
                    }
                }
            }
            service "pay" {
                listener {
                    id "pay-http"
                    address "127.0.0.1:19482"
                }
                routes {
                    route "checkout" {
                        matches { path-prefix "/checkout/"; }
                        upstream "backend"
                    }
                }
            }
        }
        namespace "infra" {
            upstreams {
                upstream "redis" { target "127.0.0.1:6379"; }
                upstream "db" { target "127.0.0.1:5432"; }
            }
            exports { upstreams "redis"; }
        }
        namespace "ops" {
            routes {
                route "metrics" {
                    matches { path "/metrics"; }
                    builtin-handler "metrics"
                }
            }
            service "jobs" {
                routes {
                    route "list" {
                        matches { path "/jobs"; }
                        builtin-handler "status"
                    }
                }
            }
        }
        namespace "web" {
            listeners {
                listener "https" { address "127.0.0.1:19483"; }
            }
            routes {
                route "main" {
                    matches { path-prefix "/"; }
                    upstream "api:backend"
                }
            }
        }
    "#;

    fn lowered() -> Config {
        Config::from_kdl(KDL).expect("config parses").lower_scopes()
    }

    fn route<'a>(config: &'a Config, id: &str) -> &'a RouteConfig {
        config
            .routes
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("route '{id}'"))
    }

    fn ids(routes: Vec<RouteConfig>) -> Vec<String> {
        let mut ids: Vec<String> = routes.into_iter().map(|r| r.id).collect();
        ids.sort();
        ids
    }

    /// #548: every scoped resource is at the top level under its qualified
    /// id, so two scopes can both have a `main` route and a `backend`
    /// upstream.
    #[test]
    fn scoped_resources_move_to_the_top_level_under_qualified_ids() {
        let config = lowered();
        for upstream in ["shared", "api:backend", "api:users:backend", "infra:redis"] {
            let lowered = config.upstreams.get(upstream).expect(upstream);
            assert_eq!(lowered.id, upstream);
        }
        for id in [
            "global",
            "api:main",
            "api:users:main",
            "web:main",
            "ops:jobs:list",
        ] {
            route(&config, id);
        }
        assert!(config.filters.contains_key("api:auth"));
        assert_eq!(config.filters["api:auth"].id, "api:auth");
        assert!(config.agents.iter().any(|a| a.id == "api:auth"));
        assert!(config.agents.iter().any(|a| a.id == "waf"));

        // Nothing is left in the namespaces but what the proxy reads there.
        let api = config.namespaces.iter().find(|n| n.id == "api").unwrap();
        assert!(api.routes.is_empty() && api.upstreams.is_empty());
        assert!(api.services.iter().all(|s| s.routes.is_empty()));
        assert_eq!(api.services.len(), 2);
    }

    /// #548: a route naming its namespace's upstream got 500 "Upstream pool
    /// not found". References now resolve service, namespace, exports,
    /// global, and qualified references directly.
    #[test]
    fn references_resolve_through_the_scope_chain() {
        let config = lowered();
        let upstream = |id: &str| route(&config, id).upstream.clone().unwrap();
        assert_eq!(upstream("api:main"), "api:backend");
        assert_eq!(upstream("api:to-global"), "shared");
        assert_eq!(upstream("api:to-infra"), "infra:redis");
        assert_eq!(upstream("api:qualified"), "infra:db");
        // A service's upstream shadows its namespace's of the same name.
        assert_eq!(upstream("api:users:main"), "api:users:backend");
        // A service without one gets its namespace's.
        assert_eq!(upstream("api:pay:checkout"), "api:backend");
        assert_eq!(upstream("web:main"), "api:backend");
        assert_eq!(upstream("global"), "shared");

        assert_eq!(route(&config, "api:main").filters, ["api:auth", "api:rl"]);
        assert_eq!(route(&config, "api:users:parent").filters, ["api:rl"]);
        // An agent filter names the agent its own scope resolves.
        let agent_of = |id: &str| match &config.filters[id].filter {
            Filter::Agent(f) => f.agent.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(agent_of("api:auth"), "api:auth");
        assert_eq!(agent_of("api:waf"), "waf");
    }

    /// #548: which listeners serve which routes.
    #[test]
    fn routes_are_served_on_the_nearest_scope_with_a_listener() {
        let config = lowered();

        // Global listeners: the global routes, and those of every namespace
        // and service without a listener of its own.
        assert_eq!(
            ids(config.routes_served_on(&Scope::Global)),
            [
                "api:main",
                "api:qualified",
                "api:to-global",
                "api:to-infra",
                "api:users:main",
                "api:users:parent",
                "global",
            ]
        );
        // A namespace bound by a top-level listener serves its own routes and
        // its services' without a listener, and nothing global.
        assert_eq!(
            ids(config.routes_served_on(&Scope::Namespace("ops".into()))),
            ["ops:jobs:list", "ops:metrics"]
        );
        // A service's own listener serves only the service.
        let pay = Scope::Service {
            namespace: "api".into(),
            service: "pay".into(),
        };
        assert_eq!(ids(config.routes_served_on(&pay)), ["api:pay:checkout"]);
        // A listener declared in a namespace serves that namespace.
        assert_eq!(
            ids(config.routes_served_on(&Scope::Namespace("web".into()))),
            ["web:main"]
        );

        // The scoped listeners are top-level listeners now, bound to their
        // scope.
        let listener = |id: &str| {
            config
                .listeners
                .iter()
                .find(|l| l.id == id)
                .unwrap_or_else(|| panic!("listener '{id}'"))
        };
        assert_eq!(listener("api:pay:pay-http").scope(), pay);
        assert_eq!(
            listener("web:https").scope(),
            Scope::Namespace("web".into())
        );
        assert_eq!(listener("public").scope(), Scope::Global);
        assert_eq!(
            config.route_scope("api:users:main").service(),
            Some("users")
        );
        assert_eq!(config.route_scope("global"), Scope::Global);
    }

    #[test]
    fn lowering_is_idempotent() {
        let once = lowered();
        let twice = once.lower_scopes();
        let json = |c: &Config| {
            serde_json::to_value((&c.routes, &c.upstreams, &c.filters, &c.agents, &c.listeners))
                .unwrap()
        };
        assert_eq!(json(&once), json(&twice));
        assert_eq!(once.scope_index, twice.scope_index);
        assert!(once.lower_scopes_reporting().1.is_empty());
    }

    /// The lowered configuration is what `ConfigManager::apply_change`
    /// validates, so it has to pass.
    #[test]
    fn the_lowered_configuration_validates() {
        lowered().validate().expect("lowered config validates");
    }

    /// A namespace's or service's listener that cannot be bound is reported
    /// as ignored, and its routes are not moved onto the global listeners:
    /// they were meant for that listener only.
    #[test]
    fn an_unbindable_scoped_listener_is_reported_and_its_routes_stay_unserved() {
        let config = Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners { listener "public" { address "0.0.0.0:19480"; } }
            namespace "internal" {
                listeners {
                    listener "clash" { address "127.0.0.1:19480"; }
                }
                routes {
                    route "secret" {
                        matches { path-prefix "/"; }
                        builtin-handler "status"
                    }
                }
            }
            "#,
        )
        .unwrap();
        let (lowered, problems) = config.lower_scopes_reporting();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("'clash'"), "{problems:?}");
        assert!(problems[0].contains("is being ignored"), "{problems:?}");
        assert!(problems[0].contains("'public' also binds"), "{problems:?}");
        assert_eq!(lowered.listeners.len(), 1);
        assert!(lowered.routes_served_on(&Scope::Global).is_empty());
        assert!(lowered
            .routes_served_on(&Scope::Namespace("internal".into()))
            .iter()
            .any(|r| r.id == "internal:secret"));
    }

    /// A global route whose id happens to be a namespace route's qualified id
    /// keeps it; the namespace route is reported rather than silently
    /// replacing it.
    #[test]
    fn a_qualified_id_already_taken_is_reported() {
        let config = Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners { listener "public" { address "127.0.0.1:19480"; } }
            routes {
                route "api:main" {
                    matches { path "/top"; }
                    builtin-handler "status"
                }
            }
            namespace "api" {
                routes {
                    route "main" {
                        matches { path "/ns"; }
                        builtin-handler "status"
                    }
                }
            }
            "#,
        )
        .unwrap();
        let (lowered, problems) = config.lower_scopes_reporting();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("route 'main' of namespace 'api' is being ignored"));
        assert_eq!(lowered.routes.len(), 1);
        assert_eq!(lowered.route_scope("api:main"), Scope::Global);
    }

    /// Service limits sit with the service, namespace limits with the
    /// namespace; both survive lowering.
    #[test]
    fn scope_limits_follow_the_chain() {
        let config = Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners { listener "public" { address "127.0.0.1:19480"; } }
            namespace "ns" {
                limits { max-body-size 100; }
                service "svc" {
                    limits { max-body-size 10; }
                }
            }
            "#,
        )
        .unwrap()
        .lower_scopes();
        let svc = Scope::Service {
            namespace: "ns".into(),
            service: "svc".into(),
        };
        let limits = config.scope_limits(&svc);
        assert_eq!(limits.len(), 2);
        assert_eq!(limits[0].0, Scope::Namespace("ns".into()));
        assert_eq!(limits[0].1.max_body_size_bytes, 100);
        assert_eq!(limits[1].0, svc);
        assert_eq!(limits[1].1.max_body_size_bytes, 10);
        assert!(config.scope_limits(&Scope::Global).is_empty());
    }

    /// The shipped example, which has no scoped listener: every namespace and
    /// service route is served on the global listeners, and the lowered
    /// configuration validates.
    #[test]
    fn the_namespaces_example_is_served_on_the_global_listeners() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/examples/namespaces.kdl"
        );
        let (config, problems) = Config::from_file(path).unwrap().lower_scopes_reporting();
        assert!(problems.is_empty(), "{problems:?}");
        let served = ids(config.routes_served_on(&Scope::Global));
        for route in [
            "platform:users-api",
            "platform:user-management:user-crud",
            "storefront:product-api:products",
            "analytics:ingest",
            "fallback",
        ] {
            assert!(served.iter().any(|r| r == route), "{route}: {served:?}");
        }
        assert_eq!(served.len(), config.routes.len());
        config.validate().expect("lowered example validates");
    }
}
