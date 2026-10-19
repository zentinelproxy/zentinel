//! Active health check results reach target selection, for every algorithm.
//!
//! Probe results used to stay inside the health checker: nothing read them,
//! so a target failing its health check kept receiving traffic under every
//! load-balancing algorithm. A pool now applies its upstream's
//! `ActiveHealthView` before selecting, through `LoadBalancer::report_health`,
//! which each algorithm already honours.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use pingora_core::upstreams::peer::Peer;
use zentinel_common::errors::ZentinelError;
use zentinel_common::types::LoadBalancingAlgorithm;
use zentinel_config::upstreams::{SameSitePolicy, StickySessionConfig};
use zentinel_config::Config;
use zentinel_proxy::upstream::active_health::ActiveHealthView;
use zentinel_proxy::upstream::{RequestContext, UpstreamPool};

const GOOD: &str = "127.0.0.1:19281";
const BAD: &str = "127.0.0.1:19282";

const ALGORITHMS: &[LoadBalancingAlgorithm] = &[
    LoadBalancingAlgorithm::RoundRobin,
    LoadBalancingAlgorithm::LeastConnections,
    LoadBalancingAlgorithm::Random,
    LoadBalancingAlgorithm::IpHash,
    LoadBalancingAlgorithm::Weighted,
    LoadBalancingAlgorithm::ConsistentHash,
    LoadBalancingAlgorithm::PowerOfTwoChoices,
    LoadBalancingAlgorithm::Adaptive,
    LoadBalancingAlgorithm::LeastTokensQueued,
    LoadBalancingAlgorithm::Maglev,
    LoadBalancingAlgorithm::LocalityAware,
    LoadBalancingAlgorithm::PeakEwma,
    LoadBalancingAlgorithm::DeterministicSubset,
    LoadBalancingAlgorithm::WeightedLeastConnections,
    LoadBalancingAlgorithm::Sticky,
];

fn upstream(algorithm: LoadBalancingAlgorithm) -> zentinel_config::UpstreamConfig {
    let kdl = format!(
        r#"
schema-version "1.0"
system {{ worker-threads 0 }}
listeners {{
    listener "http" {{ address "127.0.0.1:0" }}
}}
upstreams {{
    upstream "backend" {{
        target "{GOOD}"
        target "{BAD}"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
    }}
}}
"#
    );
    let config = Config::from_kdl(&kdl).expect("config parses");
    let mut upstream = config.upstreams["backend"].clone();
    upstream.id = "backend".to_string();
    upstream.load_balancing = algorithm;
    if algorithm == LoadBalancingAlgorithm::Sticky {
        upstream.sticky_session = Some(StickySessionConfig {
            cookie_name: "srv".to_string(),
            cookie_ttl_secs: 60,
            cookie_path: "/".to_string(),
            cookie_secure: false,
            cookie_same_site: SameSitePolicy::default(),
            fallback: LoadBalancingAlgorithm::RoundRobin,
        });
    }
    upstream
}

/// Requests from many clients and keys, so hash-based algorithms are asked
/// about more than one point on their ring.
fn contexts() -> Vec<RequestContext> {
    (1..=40u8)
        .map(|i| RequestContext {
            client_ip: Some(format!("10.0.0.{i}:4000").parse().unwrap()),
            headers: HashMap::new(),
            path: format!("/item/{i}"),
            method: "GET".to_string(),
        })
        .collect()
}

async fn selected(pool: &UpstreamPool) -> Result<BTreeSet<String>, ZentinelError> {
    let mut seen = BTreeSet::new();
    for ctx in contexts() {
        let peer = pool.select_peer(Some(&ctx)).await?;
        seen.insert(peer.address().to_string());
    }
    Ok(seen)
}

// A current-thread runtime on purpose: consistent hash used to build its ring
// with `block_in_place`, which panics there.
#[tokio::test]
async fn unhealthy_targets_are_excluded_by_every_algorithm() {
    let only_bad: BTreeSet<String> = [BAD.to_string()].into();
    let only_good: BTreeSet<String> = [GOOD.to_string()].into();

    for &algorithm in ALGORITHMS {
        let view = Arc::new(ActiveHealthView::new());
        let pool = UpstreamPool::new(upstream(algorithm))
            .await
            .unwrap_or_else(|e| panic!("{algorithm:?}: pool builds: {e}"))
            .with_active_health(view.clone());

        assert!(
            selected(&pool).await.is_ok(),
            "{algorithm:?}: selection works before any probe result"
        );

        view.record([(GOOD.to_string(), true), (BAD.to_string(), false)]);
        assert_eq!(
            selected(&pool).await.unwrap(),
            only_good,
            "{algorithm:?}: a target failing its health check stayed in rotation"
        );

        // A successful request to the healthy target must not re-admit the
        // unhealthy one, and one reported for the unhealthy target (e.g. an
        // in-flight request finishing) must not override the check.
        pool.report_result(BAD, true).await;
        pool.report_result_with_latency(BAD, true, None).await;
        assert_eq!(
            selected(&pool).await.unwrap(),
            only_good,
            "{algorithm:?}: a passive success overrode the active health check"
        );

        // Every target unhealthy: no healthy upstream, which is a 503.
        view.record([(GOOD.to_string(), false)]);
        let err = selected(&pool).await.unwrap_err();
        assert!(
            matches!(err, ZentinelError::NoHealthyUpstream),
            "{algorithm:?}: expected NoHealthyUpstream, got {err:?}"
        );
        assert_eq!(err.to_http_status(), 503);

        // Recovery re-admits a target: with the other one now down, all
        // traffic goes to it (deterministic for every algorithm, unlike
        // asserting that both share it).
        view.record([(BAD.to_string(), true)]);
        assert_eq!(
            selected(&pool).await.unwrap(),
            only_bad,
            "{algorithm:?}: a recovered target was not re-admitted"
        );
    }
}

/// A pool built after the results were recorded -- by a reload or a
/// discovery refresh -- applies them on its first selection instead of
/// treating every target as healthy until the next probe.
#[tokio::test]
async fn a_new_pool_starts_from_known_results() {
    let view = Arc::new(ActiveHealthView::new());
    view.record([(GOOD.to_string(), true), (BAD.to_string(), false)]);

    let pool = UpstreamPool::new(upstream(LoadBalancingAlgorithm::RoundRobin))
        .await
        .expect("pool builds")
        .with_active_health(view.clone());
    assert_eq!(
        selected(&pool).await.unwrap(),
        [GOOD.to_string()].into(),
        "a fresh pool routed to a target already known to be unhealthy"
    );

    // And it publishes what it routes to, for the checker to probe.
    let mut published = view.targets().expect("pool published its targets");
    published.sort();
    assert_eq!(published, vec![GOOD.to_string(), BAD.to_string()]);
}
