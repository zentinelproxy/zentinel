use murmur3::murmur3_32;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use xxhash_rust::xxh3::Xxh3;

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};
use async_trait::async_trait;
use sentinel_common::errors::{SentinelError, SentinelResult};
use tracing::{debug, info, trace, warn};

/// Hash function types supported by the consistent hash balancer
#[derive(Debug, Clone, Copy)]
pub enum HashFunction {
    Xxh3,
    Murmur3,
    DefaultHasher,
}

/// Configuration for consistent hashing
#[derive(Debug, Clone)]
pub struct ConsistentHashConfig {
    /// Number of virtual nodes per real target
    pub virtual_nodes: usize,
    /// Hash function to use
    pub hash_function: HashFunction,
    /// Enable bounded loads to prevent overload
    pub bounded_loads: bool,
    /// Maximum load factor (1.0 = average load, 1.25 = 25% above average)
    pub max_load_factor: f64,
    /// Key extraction function (e.g., from headers, cookies)
    pub hash_key_extractor: HashKeyExtractor,
}

impl Default for ConsistentHashConfig {
    fn default() -> Self {
        Self {
            virtual_nodes: 150,
            hash_function: HashFunction::Xxh3,
            bounded_loads: true,
            max_load_factor: 1.25,
            hash_key_extractor: HashKeyExtractor::ClientIp,
        }
    }
}

/// Defines how to extract the hash key from a request
#[derive(Clone)]
pub enum HashKeyExtractor {
    ClientIp,
    Header(String),
    Cookie(String),
    Custom(Arc<dyn Fn(&RequestContext) -> Option<String> + Send + Sync>),
}

impl std::fmt::Debug for HashKeyExtractor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientIp => write!(f, "ClientIp"),
            Self::Header(h) => write!(f, "Header({})", h),
            Self::Cookie(c) => write!(f, "Cookie({})", c),
            Self::Custom(_) => write!(f, "Custom"),
        }
    }
}

/// Virtual node in the consistent hash ring
#[derive(Debug, Clone)]
struct VirtualNode {
    /// Hash value of this virtual node
    hash: u64,
    /// Index of the real target this virtual node represents
    target_index: usize,
    /// Virtual node number for this target
    virtual_index: usize,
}

/// Consistent hash load balancer with virtual nodes and bounded loads
pub struct ConsistentHashBalancer {
    /// Configuration
    config: ConsistentHashConfig,
    /// All upstream targets
    targets: Vec<UpstreamTarget>,
    /// Hash ring (sorted by hash value)
    ring: Arc<RwLock<BTreeMap<u64, VirtualNode>>>,
    /// Target health status
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Active connection count per target (for bounded loads)
    connection_counts: Vec<Arc<AtomicU64>>,
    /// Total active connections
    total_connections: Arc<AtomicU64>,
    /// Cache for recent hash lookups (hash -> target_index)
    lookup_cache: Arc<RwLock<HashMap<u64, usize>>>,
    /// Generation counter for detecting ring changes
    generation: Arc<AtomicUsize>,
}

impl ConsistentHashBalancer {
    pub fn new(targets: Vec<UpstreamTarget>, config: ConsistentHashConfig) -> Self {
        trace!(
            target_count = targets.len(),
            virtual_nodes = config.virtual_nodes,
            hash_function = ?config.hash_function,
            bounded_loads = config.bounded_loads,
            max_load_factor = config.max_load_factor,
            hash_key_extractor = ?config.hash_key_extractor,
            "Creating consistent hash balancer"
        );

        let connection_counts = targets
            .iter()
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();

        let balancer = Self {
            config,
            targets: targets.clone(),
            ring: Arc::new(RwLock::new(BTreeMap::new())),
            health_status: Arc::new(RwLock::new(HashMap::new())),
            connection_counts,
            total_connections: Arc::new(AtomicU64::new(0)),
            lookup_cache: Arc::new(RwLock::new(HashMap::with_capacity(1000))),
            generation: Arc::new(AtomicUsize::new(0)),
        };

        // Build initial ring
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(balancer.rebuild_ring());
        });

        debug!(
            target_count = targets.len(),
            "Consistent hash balancer initialized"
        );

        balancer
    }

    /// Rebuild the hash ring based on current targets and health
    async fn rebuild_ring(&self) {
        trace!(
            total_targets = self.targets.len(),
            virtual_nodes_per_target = self.config.virtual_nodes,
            "Starting hash ring rebuild"
        );

        let mut new_ring = BTreeMap::new();
        let health = self.health_status.read().await;

        for (index, target) in self.targets.iter().enumerate() {
            let target_id = format!("{}:{}", target.address, target.port);
            let is_healthy = health.get(&target_id).copied().unwrap_or(true);

            if !is_healthy {
                trace!(
                    target_id = %target_id,
                    target_index = index,
                    "Skipping unhealthy target in ring rebuild"
                );
                continue;
            }

            // Add virtual nodes for this target
            for vnode in 0..self.config.virtual_nodes {
                let vnode_key = format!("{}-vnode-{}", target_id, vnode);
                let hash = self.hash_key(&vnode_key);

                new_ring.insert(
                    hash,
                    VirtualNode {
                        hash,
                        target_index: index,
                        virtual_index: vnode,
                    },
                );
            }

            trace!(
                target_id = %target_id,
                target_index = index,
                vnodes_added = self.config.virtual_nodes,
                "Added virtual nodes for target"
            );
        }

        let healthy_count = new_ring
            .values()
            .map(|n| n.target_index)
            .collect::<std::collections::HashSet<_>>()
            .len();

        if new_ring.is_empty() {
            warn!("No healthy targets available for consistent hash ring");
        } else {
            info!(
                virtual_nodes = new_ring.len(),
                healthy_targets = healthy_count,
                "Rebuilt consistent hash ring"
            );
        }

        *self.ring.write().await = new_ring;

        // Clear cache on ring change
        let cache_size = self.lookup_cache.read().await.len();
        self.lookup_cache.write().await.clear();
        let new_generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;

        trace!(
            cache_entries_cleared = cache_size,
            new_generation = new_generation,
            "Ring rebuild complete, cache cleared"
        );
    }

    /// Hash a key using the configured hash function
    fn hash_key(&self, key: &str) -> u64 {
        match self.config.hash_function {
            HashFunction::Xxh3 => {
                let mut hasher = Xxh3::new();
                hasher.update(key.as_bytes());
                hasher.digest()
            }
            HashFunction::Murmur3 => {
                let mut cursor = Cursor::new(key.as_bytes());
                murmur3_32(&mut cursor, 0).unwrap_or(0) as u64
            }
            HashFunction::DefaultHasher => {
                use std::collections::hash_map::DefaultHasher;
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                hasher.finish()
            }
        }
    }

    /// Find target using consistent hashing with optional bounded loads
    async fn find_target(&self, hash_key: &str) -> Option<usize> {
        let key_hash = self.hash_key(hash_key);

        trace!(
            hash_key = %hash_key,
            key_hash = key_hash,
            bounded_loads = self.config.bounded_loads,
            "Finding target for hash key"
        );

        // Check cache first
        {
            let cache = self.lookup_cache.read().await;
            if let Some(&target_index) = cache.get(&key_hash) {
                // Verify target is still healthy
                let health = self.health_status.read().await;
                let target = &self.targets[target_index];
                let target_id = format!("{}:{}", target.address, target.port);
                if health.get(&target_id).copied().unwrap_or(true) {
                    trace!(
                        hash_key = %hash_key,
                        target_index = target_index,
                        "Cache hit for hash key"
                    );
                    return Some(target_index);
                }
                trace!(
                    hash_key = %hash_key,
                    target_index = target_index,
                    "Cache hit but target unhealthy"
                );
            }
        }

        let ring = self.ring.read().await;

        if ring.is_empty() {
            warn!("Hash ring is empty, no targets available");
            return None;
        }

        // Find the first virtual node with hash >= key_hash
        let candidates = if let Some((&_node_hash, vnode)) = ring.range(key_hash..).next() {
            vec![vnode.clone()]
        } else {
            // Wrap around to the first node
            ring.iter()
                .next()
                .map(|(_, vnode)| vec![vnode.clone()])
                .unwrap_or_default()
        };

        trace!(
            hash_key = %hash_key,
            candidate_count = candidates.len(),
            "Found candidates on hash ring"
        );

        // If bounded loads is disabled, return the first candidate
        if !self.config.bounded_loads {
            let target_index = candidates.first().map(|n| n.target_index);

            // Update cache
            if let Some(idx) = target_index {
                self.lookup_cache.write().await.insert(key_hash, idx);
                trace!(
                    hash_key = %hash_key,
                    target_index = idx,
                    "Selected target (no bounded loads)"
                );
            }

            return target_index;
        }

        // Bounded loads: check if target is overloaded
        let avg_load = self.calculate_average_load().await;
        let max_load = (avg_load * self.config.max_load_factor) as u64;

        trace!(
            avg_load = avg_load,
            max_load = max_load,
            max_load_factor = self.config.max_load_factor,
            "Checking bounded loads"
        );

        // Try candidates in order until we find one that's not overloaded
        for vnode in candidates {
            let current_load = self.connection_counts[vnode.target_index].load(Ordering::Relaxed);

            trace!(
                target_index = vnode.target_index,
                current_load = current_load,
                max_load = max_load,
                "Evaluating candidate load"
            );

            if current_load <= max_load {
                // Update cache
                self.lookup_cache
                    .write()
                    .await
                    .insert(key_hash, vnode.target_index);
                debug!(
                    hash_key = %hash_key,
                    target_index = vnode.target_index,
                    current_load = current_load,
                    "Selected target within load bounds"
                );
                return Some(vnode.target_index);
            }
        }

        trace!(
            hash_key = %hash_key,
            "All candidates overloaded, falling back to least loaded"
        );

        // If all candidates are overloaded, find least loaded target
        self.find_least_loaded_target().await
    }

    /// Calculate average load across all healthy targets
    async fn calculate_average_load(&self) -> f64 {
        let health = self.health_status.read().await;
        let healthy_count = self
            .targets
            .iter()
            .filter(|t| {
                let target_id = format!("{}:{}", t.address, t.port);
                health.get(&target_id).copied().unwrap_or(true)
            })
            .count();

        if healthy_count == 0 {
            return 0.0;
        }

        let total = self.total_connections.load(Ordering::Relaxed);
        total as f64 / healthy_count as f64
    }

    /// Find the least loaded target when all consistent hash candidates are overloaded
    async fn find_least_loaded_target(&self) -> Option<usize> {
        trace!("Finding least loaded target as fallback");

        let health = self.health_status.read().await;

        let mut min_load = u64::MAX;
        let mut best_target = None;

        for (index, target) in self.targets.iter().enumerate() {
            let target_id = format!("{}:{}", target.address, target.port);
            if !health.get(&target_id).copied().unwrap_or(true) {
                trace!(
                    target_index = index,
                    target_id = %target_id,
                    "Skipping unhealthy target"
                );
                continue;
            }

            let load = self.connection_counts[index].load(Ordering::Relaxed);
            trace!(
                target_index = index,
                target_id = %target_id,
                load = load,
                "Evaluating target load"
            );

            if load < min_load {
                min_load = load;
                best_target = Some(index);
            }
        }

        if let Some(idx) = best_target {
            debug!(
                target_index = idx,
                load = min_load,
                "Selected least loaded target"
            );
        } else {
            warn!("No healthy targets found for least loaded selection");
        }

        best_target
    }

    /// Extract hash key from request context
    pub fn extract_hash_key(&self, context: &RequestContext) -> Option<String> {
        let key = match &self.config.hash_key_extractor {
            HashKeyExtractor::ClientIp => context.client_ip.map(|ip| ip.to_string()),
            HashKeyExtractor::Header(name) => context.headers.get(name).cloned(),
            HashKeyExtractor::Cookie(name) => {
                // Parse cookie header and extract specific cookie
                context.headers.get("cookie").and_then(|cookies| {
                    cookies.split(';').find_map(|cookie| {
                        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                        if parts.len() == 2 && parts[0] == name {
                            Some(parts[1].to_string())
                        } else {
                            None
                        }
                    })
                })
            }
            HashKeyExtractor::Custom(extractor) => extractor(context),
        };

        trace!(
            extractor = ?self.config.hash_key_extractor,
            key_found = key.is_some(),
            "Extracted hash key from request"
        );

        key
    }

    /// Track connection acquisition
    pub fn acquire_connection(&self, target_index: usize) {
        let count = self.connection_counts[target_index].fetch_add(1, Ordering::Relaxed) + 1;
        let total = self.total_connections.fetch_add(1, Ordering::Relaxed) + 1;
        trace!(
            target_index = target_index,
            target_connections = count,
            total_connections = total,
            "Acquired connection"
        );
    }

    /// Track connection release
    pub fn release_connection(&self, target_index: usize) {
        let count = self.connection_counts[target_index].fetch_sub(1, Ordering::Relaxed) - 1;
        let total = self.total_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        trace!(
            target_index = target_index,
            target_connections = count,
            total_connections = total,
            "Released connection"
        );
    }
}

#[async_trait]
impl LoadBalancer for ConsistentHashBalancer {
    async fn select(&self, context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        trace!(
            has_context = context.is_some(),
            "Consistent hash select called"
        );

        // Extract hash key from context or use random fallback
        let (hash_key, used_random) = context
            .and_then(|ctx| self.extract_hash_key(ctx))
            .map(|k| (k, false))
            .unwrap_or_else(|| {
                // Generate random key for requests without proper hash key
                use rand::Rng;
                let mut rng = rand::rng();
                let key = format!("random-{}", rng.random::<u64>());
                trace!(random_key = %key, "Generated random hash key (no context key)");
                (key, true)
            });

        let target_index = self.find_target(&hash_key).await.ok_or_else(|| {
            warn!("No healthy upstream targets available");
            SentinelError::NoHealthyUpstream
        })?;

        let target = &self.targets[target_index];

        // Track connection for bounded loads
        if self.config.bounded_loads {
            self.acquire_connection(target_index);
        }

        let current_load = self.connection_counts[target_index].load(Ordering::Relaxed);

        debug!(
            target = %format!("{}:{}", target.address, target.port),
            hash_key = %hash_key,
            target_index = target_index,
            current_load = current_load,
            used_random_key = used_random,
            "Consistent hash selected target"
        );

        Ok(TargetSelection {
            address: format!("{}:{}", target.address, target.port),
            weight: target.weight,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("hash_key".to_string(), hash_key);
                meta.insert("target_index".to_string(), target_index.to_string());
                meta.insert("load".to_string(), current_load.to_string());
                meta.insert("algorithm".to_string(), "consistent_hash".to_string());
                meta
            },
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            address = %address,
            healthy = healthy,
            "Reporting target health"
        );

        let mut health = self.health_status.write().await;
        let previous = health.insert(address.to_string(), healthy);

        // Rebuild ring if health status changed
        if previous != Some(healthy) {
            info!(
                address = %address,
                previous_status = ?previous,
                new_status = healthy,
                "Target health changed, rebuilding ring"
            );
            drop(health); // Release lock before rebuild
            self.rebuild_ring().await;
        }
    }

    async fn healthy_targets(&self) -> Vec<String> {
        let health = self.health_status.read().await;
        let targets: Vec<String> = self
            .targets
            .iter()
            .filter_map(|t| {
                let target_id = format!("{}:{}", t.address, t.port);
                if health.get(&target_id).copied().unwrap_or(true) {
                    Some(target_id)
                } else {
                    None
                }
            })
            .collect();

        trace!(
            total_targets = self.targets.len(),
            healthy_count = targets.len(),
            "Retrieved healthy targets"
        );

        targets
    }

    /// Release connection when request completes
    async fn release(&self, selection: &TargetSelection) {
        if self.config.bounded_loads {
            if let Some(index_str) = selection.metadata.get("target_index") {
                if let Ok(index) = index_str.parse::<usize>() {
                    trace!(
                        target_index = index,
                        address = %selection.address,
                        "Releasing connection for bounded loads"
                    );
                    self.release_connection(index);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_targets(count: usize) -> Vec<UpstreamTarget> {
        (0..count)
            .map(|i| UpstreamTarget {
                address: format!("10.0.0.{}", i + 1),
                port: 8080,
                weight: 100,
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_consistent_distribution() {
        let targets = create_test_targets(5);
        let config = ConsistentHashConfig {
            virtual_nodes: 100,
            bounded_loads: false,
            ..Default::default()
        };

        let balancer = ConsistentHashBalancer::new(targets.clone(), config);

        // Test distribution of 10000 keys
        let mut distribution = vec![0u64; targets.len()];

        for i in 0..10000 {
            let context = RequestContext {
                client_ip: Some(format!("192.168.1.{}:1234", i % 256).parse().unwrap()),
                headers: HashMap::new(),
                path: "/".to_string(),
                method: "GET".to_string(),
            };

            if let Ok(selection) = balancer.select(Some(&context)).await {
                if let Some(index_str) = selection.metadata.get("target_index") {
                    if let Ok(index) = index_str.parse::<usize>() {
                        distribution[index] += 1;
                    }
                }
            }
        }

        // Check that distribution is relatively even (within 50% of average)
        let avg = 10000.0 / targets.len() as f64;
        for count in distribution {
            let ratio = count as f64 / avg;
            assert!(
                ratio > 0.5 && ratio < 1.5,
                "Distribution too skewed: {}",
                ratio
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_bounded_loads() {
        let targets = create_test_targets(3);
        let config = ConsistentHashConfig {
            virtual_nodes: 50,
            bounded_loads: true,
            max_load_factor: 1.2,
            ..Default::default()
        };

        let balancer = ConsistentHashBalancer::new(targets.clone(), config);

        // Simulate high load on first target
        balancer.connection_counts[0].store(100, Ordering::Relaxed);
        balancer.total_connections.store(110, Ordering::Relaxed);

        // New request should avoid overloaded target
        let context = RequestContext {
            client_ip: Some("192.168.1.1:1234".parse().unwrap()),
            headers: HashMap::new(),
            path: "/".to_string(),
            method: "GET".to_string(),
        };

        let selection = balancer.select(Some(&context)).await.unwrap();
        let index = selection
            .metadata
            .get("target_index")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap();

        // Should not select the overloaded target (index 0)
        assert_ne!(index, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ring_rebuild_on_health_change() {
        let targets = create_test_targets(3);
        let config = ConsistentHashConfig::default();

        let balancer = ConsistentHashBalancer::new(targets.clone(), config);

        let initial_generation = balancer.generation.load(Ordering::SeqCst);

        // Mark a target as unhealthy
        balancer.report_health("10.0.0.1:8080", false).await;

        // Generation should have incremented
        let new_generation = balancer.generation.load(Ordering::SeqCst);
        assert_eq!(new_generation, initial_generation + 1);

        // Unhealthy target should not be selected
        let healthy = balancer.healthy_targets().await;
        assert_eq!(healthy.len(), 2);
        assert!(!healthy.contains(&"10.0.0.1:8080".to_string()));
    }
}
