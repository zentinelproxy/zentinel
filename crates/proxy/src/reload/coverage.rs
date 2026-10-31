//! What a reload does with each top-level configuration block (#572).
//!
//! The same bug has shipped three times: state built once at startup and
//! never rebuilt on reload (health checks #516/#540, rate limiters #549,
//! agents #564, route components #572). Each time the reload logged
//! success and the running proxy no longer matched the file.
//!
//! Every field of [`Config`] is listed here with its [`ReloadBehaviour`],
//! through an exhaustive destructure: a new field does not compile until it
//! declares one. A block that a reload does not apply is
//! [`ReloadBehaviour::RestartRequired`], and a reload that changes it logs a
//! warning naming it, so "silently ignored on reload" cannot be written.

use zentinel_config::Config;

/// What a reload does with a top-level configuration block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadBehaviour {
    /// The running proxy follows the new value: rebuilt by the reload
    /// handler, or read from the current configuration where it is used.
    /// The text says how.
    Reconciled(&'static str),
    /// Not applied by a reload. A reload that changes it warns, naming the
    /// block, that a restart is needed.
    RestartRequired(&'static str),
    /// Not a block of the file: derived from the others, or only checked
    /// when the file is loaded.
    NotABlock(&'static str),
}

/// A top-level configuration block: its KDL name, its reload behaviour and
/// its value, compared between the old and new configuration.
pub struct Block {
    /// The block's name as written in KDL.
    pub name: &'static str,
    /// What a reload does with it.
    pub behaviour: ReloadBehaviour,
    /// Its value, for telling whether a reload changed it.
    pub value: Option<serde_json::Value>,
}

fn block<T: serde::Serialize>(name: &'static str, behaviour: ReloadBehaviour, value: &T) -> Block {
    Block {
        name,
        behaviour,
        value: serde_json::to_value(value).ok(),
    }
}

/// Every top-level block of `config`, with its reload behaviour.
pub fn blocks(config: &Config) -> Vec<Block> {
    use ReloadBehaviour::*;
    // Exhaustive on purpose: no `..`. A new field of `Config` must be added
    // here, with its behaviour, before this compiles.
    let Config {
        schema_version,
        server,
        listeners,
        routes,
        upstreams,
        filters,
        agents,
        waf,
        namespaces,
        limits,
        observability,
        rate_limits,
        cache,
        default_upstream: _,
        scope_index: _,
    } = config;
    vec![
        block(
            "schema-version",
            NotABlock("checked when the file is loaded"),
            schema_version,
        ),
        block(
            "system",
            RestartRequired(
                "worker threads and process-level settings are fixed when the process starts",
            ),
            server,
        ),
        block(
            "listeners",
            RestartRequired(
                "listeners (addresses, ports, TLS bindings) are bound at startup; the proxy \
                 keeps serving on the previously bound ones. Certificates are reloaded on \
                 SIGHUP",
            ),
            listeners,
        ),
        block(
            "routes",
            Reconciled(
                "route matchers, rate limiters and each route's error pages, API schema \
                 validator and static file server are rebuilt",
            ),
            routes,
        ),
        block(
            "upstreams",
            Reconciled("pools are rebuilt and health checks reconciled"),
            upstreams,
        ),
        block(
            "filters",
            Reconciled("read from the current configuration per request; rate limiters rebuilt"),
            filters,
        ),
        block(
            "agents",
            Reconciled("AgentManager::reconcile loads, replaces and removes agents"),
            agents,
        ),
        block(
            "waf",
            Reconciled("read from the current configuration per request"),
            waf,
        ),
        block(
            "namespaces",
            Reconciled("lowered into the top-level blocks, which are reconciled"),
            namespaces,
        ),
        block(
            "limits",
            Reconciled("read from the current configuration per request and per connection"),
            limits,
        ),
        block(
            "observability",
            RestartRequired(
                "logging, access/error/audit logs, metrics and tracing are set up at startup",
            ),
            observability,
        ),
        block(
            "rate-limits",
            Reconciled("rate limiters are rebuilt; unchanged ones keep their buckets"),
            rate_limits,
        ),
        block(
            "cache",
            RestartRequired(
                "cache storage (backend, size, disk path) is configured once at startup",
            ),
            cache,
        ),
    ]
}

/// The restart-required blocks a reload from `old` to `new` changes, each
/// with why a restart is needed.
pub fn restart_required_changes(old: &Config, new: &Config) -> Vec<(&'static str, &'static str)> {
    blocks(old)
        .into_iter()
        .zip(blocks(new))
        .filter_map(|(before, after)| match after.behaviour {
            ReloadBehaviour::RestartRequired(why) if before.value != after.value => {
                Some((after.name, why))
            }
            _ => None,
        })
        .collect()
}

/// The warning a reload logs for a changed restart-required block.
pub fn restart_required_message(name: &str, why: &str) -> String {
    format!(
        "'{name}' changed in the new configuration, but it is NOT applied by hot reload \
         ({why}); restart zentinel to apply it"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        Config::from_kdl(&format!(
            r#"
            system {{ worker-threads 1 }}
            listeners {{ listener "l" {{ address "127.0.0.1:8080" }} }}
            upstreams {{ upstream "u" {{ target "127.0.0.1:9000" }} }}
            routes {{ route "r" {{ matches {{ path-prefix "/" }}
                                 upstream "u" }} }}
            {extra}
            "#
        ))
        .expect("parses")
    }

    /// Every top-level block of the KDL schema has a declared behaviour,
    /// and is listed once.
    #[test]
    fn every_block_declares_its_reload_behaviour() {
        let blocks = blocks(&config(""));
        let mut names: Vec<_> = blocks.iter().map(|b| b.name).collect();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "a block is listed twice: {names:?}");
        assert_eq!(
            names,
            [
                "agents",
                "cache",
                "filters",
                "limits",
                "listeners",
                "namespaces",
                "observability",
                "rate-limits",
                "routes",
                "schema-version",
                "system",
                "upstreams",
                "waf",
            ]
        );
    }

    #[test]
    fn a_changed_restart_required_block_is_reported_by_name() {
        let old = config("");
        let new = config(
            r#"observability { logging { level "debug" } }
               cache { max-size 67108864 }"#,
        );
        let changed: Vec<_> = restart_required_changes(&old, &new)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(changed, ["observability", "cache"]);
        let message = restart_required_message("cache", "why");
        assert!(message.contains("'cache'") && message.contains("restart zentinel"));
    }

    #[test]
    fn a_change_to_a_reconciled_block_needs_no_restart() {
        let old = config("");
        let new = Config::from_kdl(
            r#"
            system { worker-threads 1 }
            listeners { listener "l" { address "127.0.0.1:8080" } }
            upstreams { upstream "u" { target "127.0.0.1:9001" } }
            routes { route "r2" { matches { path-prefix "/x" }
                                 upstream "u" } }
            limits { max-body-size-bytes 1024 }
            "#,
        )
        .expect("parses");
        assert_eq!(restart_required_changes(&old, &new), Vec::new());
    }

    #[test]
    fn unchanged_configuration_reports_nothing() {
        assert_eq!(
            restart_required_changes(&config(""), &config("")),
            Vec::new()
        );
    }
}
