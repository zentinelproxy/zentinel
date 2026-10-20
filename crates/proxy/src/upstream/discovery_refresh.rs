//! Periodic re-resolution of upstream service discovery.
//!
//! Pools whose targets come from a discovery source (an upstream's `discovery`
//! block) are resolved once while the proxy starts and then re-resolved on the
//! interval their source declares. This module owns that schedule.
//!
//! # Why one supervisor rather than a task per upstream
//!
//! Pools are replaced wholesale on `SIGHUP`: `Registry::replace` swaps the
//! whole map for one built from the new configuration. A task holding an
//! `Arc<UpstreamPool>` would keep refreshing the pool it captured and write its
//! results back over the pool the reload just installed, so every reload would
//! need to find and abort the old tasks and spawn new ones — with the pools and
//! the tasks tracked separately and able to drift apart.
//!
//! A single supervisor reads the registry on each tick instead. It therefore
//! sees exactly the pools that are installed right now: reloaded pools are
//! picked up automatically, removed ones simply stop appearing, and there is no
//! task lifecycle to keep in step with the pool lifecycle.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use prometheus::{register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec};
use tracing::{debug, info, warn};

use zentinel_common::Registry;

use super::UpstreamPool;

/// How often the supervisor wakes while at least one pool uses discovery.
///
/// Refresh intervals are configured in whole seconds, so a one-second tick
/// resolves every interval exactly. The tick itself does no work beyond
/// comparing deadlines when nothing is due.
const TICK: Duration = Duration::from_secs(1);

/// How often the supervisor wakes while no pool uses discovery.
///
/// The overwhelming majority of configurations have no discovery at all, and
/// the supervisor still has to look because a reload can introduce it. Backing
/// off to half a minute makes the idle case cost effectively nothing while
/// still noticing a reload promptly.
const IDLE_TICK: Duration = Duration::from_secs(30);

/// Upper bound on a single refresh.
///
/// A registry that accepts a connection and then never answers would otherwise
/// hold its slot forever. The refresh is abandoned and retried on the next
/// interval; the pool keeps serving its current targets meanwhile.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);

static DISCOVERY_REFRESHES: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zentinel_upstream_discovery_refreshes_total",
        "Service discovery refreshes that changed an upstream's target set",
        &["upstream"]
    )
    .ok()
});

static DISCOVERY_TARGETS: LazyLock<Option<IntGaugeVec>> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "zentinel_upstream_discovery_targets",
        "Targets currently resolved for an upstream backed by service discovery",
        &["upstream"]
    )
    .ok()
});

/// Start the refresh supervisor.
///
/// Returns immediately; the supervisor runs until the process exits. It is a
/// no-op for pools without a discovery source, so it is safe to start
/// unconditionally.
pub(crate) fn spawn(pools: Registry<UpstreamPool>) {
    tokio::spawn(async move {
        run(pools).await;
    });
}

async fn run(pools: Registry<UpstreamPool>) {
    // When each pool is next due, by pool id. A namespace's upstream is keyed
    // by its qualified id (`ns:name`), so it never shares a schedule with a
    // global upstream of the same name.
    let mut due: HashMap<String, Instant> = HashMap::new();

    loop {
        let now = Instant::now();

        let mut live: Vec<(String, Arc<UpstreamPool>, Duration)> = Vec::new();
        for (id, pool) in pools.snapshot().await {
            if let Some(interval) = pool.discovery_refresh_interval() {
                live.push((id, pool, interval));
            }
        }

        if live.is_empty() {
            due.clear();
            tokio::time::sleep(IDLE_TICK).await;
            continue;
        }

        // Drop schedules for pools that are no longer registered, so the map
        // cannot grow across reloads that rename or remove upstreams.
        let present: std::collections::HashSet<String> =
            live.iter().map(|(id, _, _)| id.clone()).collect();
        due.retain(|key, _| present.contains(key));

        for (id, pool, interval) in live {
            let key = id.clone();

            // First sighting: the pool was resolved when it was built, so the
            // first refresh is one full interval away rather than immediate.
            let deadline = *due.entry(key.clone()).or_insert(now + interval);
            if now < deadline {
                continue;
            }

            // Re-arm before spawning so a refresh that outlives its interval
            // cannot have a second one started underneath it.
            due.insert(key, now + interval);

            let pools = pools.clone();
            tokio::spawn(async move {
                refresh_one(id, pool, pools).await;
            });
        }

        tokio::time::sleep(TICK).await;
    }
}

/// Re-resolve one pool and install the replacement, if the targets changed.
async fn refresh_one(id: String, pool: Arc<UpstreamPool>, pools: Registry<UpstreamPool>) {
    let refreshed = match tokio::time::timeout(REFRESH_TIMEOUT, pool.refreshed()).await {
        Ok(result) => result,
        Err(_) => {
            warn!(
                upstream_id = %id,
                timeout_secs = REFRESH_TIMEOUT.as_secs(),
                "Service discovery refresh timed out; keeping current targets"
            );
            return;
        }
    };

    // `None` means nothing changed, or the source could not be reached and the
    // pool kept its targets. Either way there is nothing to install.
    let Some(new_pool) = refreshed else {
        debug!(upstream_id = %id, "Service discovery refresh: no change");
        return;
    };

    let target_count = new_pool.target_count();
    let new_pool = Arc::new(new_pool);

    let installed = pools.insert(id.clone(), new_pool).await.is_some();

    if !installed {
        // The upstream was removed (or renamed) by a reload while this refresh
        // was in flight. Dropping the result is correct: the pool it was built
        // from is gone.
        debug!(
            upstream_id = %id,
            "Upstream disappeared during discovery refresh; discarding result"
        );
        return;
    }

    if let Some(counter) = DISCOVERY_REFRESHES.as_ref() {
        counter.with_label_values(&[&id]).inc();
    }
    if let Some(gauge) = DISCOVERY_TARGETS.as_ref() {
        gauge.with_label_values(&[&id]).set(target_count as i64);
    }

    info!(
        upstream_id = %id,
        target_count,
        "Installed refreshed upstream pool"
    );
}
