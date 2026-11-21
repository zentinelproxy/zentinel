//! GeoIP filtering for Zentinel proxy
//!
//! This module provides geolocation-based request filtering using MaxMind GeoLite2/GeoIP2
//! and IP2Location databases. Filters can block, allow, or log requests based on country.
//!
//! # Features
//! - Support for MaxMind (.mmdb) and IP2Location (.bin) databases
//! - Block mode (blocklist) and Allow mode (allowlist)
//! - Log-only mode for monitoring without blocking
//! - Per-filter IP→Country caching with configurable TTL
//! - Configurable fail-open/fail-closed on lookup errors
//! - X-GeoIP-Country response header injection

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use zentinel_config::{
    Config, Filter, GeoDatabaseType, GeoFailureMode, GeoFilter, GeoFilterAction,
};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during geo lookup
#[derive(Debug, Clone)]
pub enum GeoLookupError {
    /// IP address could not be parsed
    InvalidIp(String),
    /// Database error during lookup
    DatabaseError(String),
    /// Database file could not be loaded
    LoadError(String),
}

impl std::fmt::Display for GeoLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoLookupError::InvalidIp(ip) => write!(f, "invalid IP address: {}", ip),
            GeoLookupError::DatabaseError(msg) => write!(f, "database error: {}", msg),
            GeoLookupError::LoadError(msg) => write!(f, "failed to load database: {}", msg),
        }
    }
}

impl std::error::Error for GeoLookupError {}

// =============================================================================
// GeoDatabase Trait
// =============================================================================

/// Trait for GeoIP database backends
pub trait GeoDatabase: Send + Sync {
    /// Look up the country code for an IP address
    fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError>;

    /// Get the database type
    fn database_type(&self) -> GeoDatabaseType;
}

// =============================================================================
// MaxMind Database Backend
// =============================================================================

/// MaxMind GeoLite2/GeoIP2 database backend
pub struct MaxMindDatabase {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl MaxMindDatabase {
    /// Open a MaxMind database file
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoLookupError> {
        let path = path.as_ref();
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| {
            GeoLookupError::LoadError(format!("failed to open MaxMind database {:?}: {}", path, e))
        })?;

        debug!(path = ?path, "Opened MaxMind GeoIP database");
        Ok(Self { reader })
    }
}

impl GeoDatabase for MaxMindDatabase {
    fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError> {
        match self.reader.lookup(ip) {
            Ok(result) => {
                if !result.has_data() {
                    trace!(ip = %ip, "IP not found in MaxMind database");
                    return Ok(None);
                }
                match result.decode::<maxminddb::geoip2::Country>() {
                    Ok(Some(record)) => {
                        let country_code = record.country.iso_code.map(|s| s.to_string());
                        trace!(ip = %ip, country = ?country_code, "MaxMind lookup");
                        Ok(country_code)
                    }
                    Ok(None) => {
                        trace!(ip = %ip, "No country data for IP in MaxMind database");
                        Ok(None)
                    }
                    Err(e) => {
                        warn!(ip = %ip, error = %e, "MaxMind decode error");
                        Err(GeoLookupError::DatabaseError(e.to_string()))
                    }
                }
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "MaxMind lookup error");
                Err(GeoLookupError::DatabaseError(e.to_string()))
            }
        }
    }

    fn database_type(&self) -> GeoDatabaseType {
        GeoDatabaseType::MaxMind
    }
}

// =============================================================================
// IP2Location Database Backend
// =============================================================================

/// IP2Location database backend
pub struct Ip2LocationDatabase {
    db: ip2location::DB,
}

impl Ip2LocationDatabase {
    /// Open an IP2Location database file
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoLookupError> {
        let path = path.as_ref();
        let db = ip2location::DB::from_file(path).map_err(|e| {
            GeoLookupError::LoadError(format!(
                "failed to open IP2Location database {:?}: {}",
                path, e
            ))
        })?;

        debug!(path = ?path, "Opened IP2Location GeoIP database");
        Ok(Self { db })
    }
}

impl GeoDatabase for Ip2LocationDatabase {
    fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError> {
        match self.db.ip_lookup(ip) {
            Ok(record) => {
                // Record is an enum - extract country from the LocationDb variant
                let country_code = match record {
                    ip2location::Record::LocationDb(loc) => {
                        loc.country.map(|c| c.short_name.to_string())
                    }
                    ip2location::Record::ProxyDb(proxy) => {
                        proxy.country.map(|c| c.short_name.to_string())
                    }
                };
                trace!(ip = %ip, country = ?country_code, "IP2Location lookup");
                Ok(country_code)
            }
            Err(ip2location::error::Error::RecordNotFound) => {
                trace!(ip = %ip, "IP not found in IP2Location database");
                Ok(None)
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "IP2Location lookup error");
                Err(GeoLookupError::DatabaseError(e.to_string()))
            }
        }
    }

    fn database_type(&self) -> GeoDatabaseType {
        GeoDatabaseType::Ip2Location
    }
}

// =============================================================================
// Cached Country Entry
// =============================================================================

/// Cached country lookup result
struct CachedCountry {
    /// The country code (or None if not found)
    country_code: Option<String>,
    /// When this entry was cached
    cached_at: Instant,
}

// =============================================================================
// GeoFilterResult
// =============================================================================

/// Result of a geo filter check
#[derive(Debug, Clone)]
pub struct GeoFilterResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// The country code (if found)
    pub country_code: Option<String>,
    /// Whether this was a cache hit
    pub cache_hit: bool,
    /// Whether to add the country header
    pub add_header: bool,
    /// HTTP status code to return if blocked
    pub status_code: u16,
    /// Block message to return if blocked
    pub block_message: Option<String>,
}

// =============================================================================
// GeoFilterPool
// =============================================================================

/// A single geo filter instance with its database and cache
pub struct GeoFilterPool {
    /// The underlying GeoIP database (wrapped in RwLock for hot reload)
    database: RwLock<Arc<dyn GeoDatabase>>,
    /// IP → Country cache
    cache: DashMap<IpAddr, CachedCountry>,
    /// Filter configuration
    config: GeoFilter,
    /// Pre-computed set of countries for fast lookup
    countries_set: HashSet<String>,
    /// Cache TTL duration
    cache_ttl: Duration,
    /// Database file path for reload
    database_path: PathBuf,
    /// Database type
    database_type: GeoDatabaseType,
}

impl GeoFilterPool {
    /// Create a new geo filter pool from configuration
    pub fn new(config: GeoFilter) -> Result<Self, GeoLookupError> {
        // The configured type, else the one the extension says. A path that
        // says nothing is refused when the configuration loads; a filter that
        // got here without that check is refused instead of guessed at.
        let db_type = config.resolved_database_type().ok_or_else(|| {
            GeoLookupError::LoadError(format!(
                "cannot tell the database type of {:?} from its extension; \
                 set database-type",
                config.database_path
            ))
        })?;

        let database_path = PathBuf::from(&config.database_path);

        // Open the database
        let database: Arc<dyn GeoDatabase> = match db_type {
            GeoDatabaseType::MaxMind => Arc::new(MaxMindDatabase::open(&config.database_path)?),
            GeoDatabaseType::Ip2Location => {
                Arc::new(Ip2LocationDatabase::open(&config.database_path)?)
            }
        };

        // Build countries set for fast lookup
        let countries_set: HashSet<String> = config.countries.iter().cloned().collect();

        let cache_ttl = Duration::from_secs(config.cache_ttl_secs);

        debug!(
            database_path = %config.database_path,
            database_type = ?db_type,
            action = ?config.action,
            countries_count = countries_set.len(),
            cache_ttl_secs = config.cache_ttl_secs,
            "Created GeoFilterPool"
        );

        Ok(Self {
            database: RwLock::new(database),
            cache: DashMap::new(),
            config,
            countries_set,
            cache_ttl,
            database_path,
            database_type: db_type,
        })
    }

    /// Reload the database from disk
    ///
    /// This atomically swaps the database and clears the cache.
    pub fn reload_database(&self) -> Result<(), GeoLookupError> {
        info!(
            database_path = %self.database_path.display(),
            database_type = ?self.database_type,
            "Reloading geo database"
        );

        // Open the new database
        let new_database: Arc<dyn GeoDatabase> = match self.database_type {
            GeoDatabaseType::MaxMind => Arc::new(MaxMindDatabase::open(&self.database_path)?),
            GeoDatabaseType::Ip2Location => {
                Arc::new(Ip2LocationDatabase::open(&self.database_path)?)
            }
        };

        // Atomically swap the database
        {
            let mut db = self.database.write();
            *db = new_database;
        }

        // Clear the cache since country mappings may have changed
        self.cache.clear();

        info!(
            database_path = %self.database_path.display(),
            "Geo database reloaded successfully"
        );

        Ok(())
    }

    /// Get the database file path
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Check if a client IP should be allowed or blocked
    pub fn check(&self, client_ip: &str) -> GeoFilterResult {
        // Parse the IP address
        let ip: IpAddr = match client_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(client_ip = %client_ip, "Failed to parse client IP for geo filter");
                return self.handle_failure();
            }
        };

        // Check cache first
        let now = Instant::now();
        if let Some(entry) = self.cache.get(&ip) {
            if now.duration_since(entry.cached_at) < self.cache_ttl {
                trace!(ip = %ip, country = ?entry.country_code, "Geo cache hit");
                return self.evaluate(entry.country_code.clone(), true);
            }
            // Entry expired, will be replaced
        }

        // Lookup in database
        let database = self.database.read();
        match database.lookup(ip) {
            Ok(country_code) => {
                // Cache the result
                self.cache.insert(
                    ip,
                    CachedCountry {
                        country_code: country_code.clone(),
                        cached_at: now,
                    },
                );
                self.evaluate(country_code, false)
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "Geo lookup failed");
                self.handle_failure()
            }
        }
    }

    /// Evaluate the filter action based on country code
    fn evaluate(&self, country_code: Option<String>, cache_hit: bool) -> GeoFilterResult {
        let in_list = country_code
            .as_ref()
            .map(|c| self.countries_set.contains(c))
            .unwrap_or(false);

        let allowed = match self.config.action {
            GeoFilterAction::Block => {
                // Block mode: block if country is in the list
                !in_list
            }
            GeoFilterAction::Allow => {
                // Allow mode: allow only if country is in the list. An empty
                // list allows nobody. A KDL configuration refuses one, and so
                // does `Config::validate` for top-level filters; a JSON or
                // TOML filter inside a namespace or service is not checked
                // and can still reach this.
                in_list
            }
            GeoFilterAction::LogOnly => {
                // Log-only mode: always allow
                true
            }
        };

        trace!(
            country = ?country_code,
            in_list = in_list,
            action = ?self.config.action,
            allowed = allowed,
            "Geo filter evaluation"
        );

        GeoFilterResult {
            allowed,
            country_code,
            cache_hit,
            add_header: self.config.add_country_header,
            status_code: self.config.status_code,
            block_message: self.config.block_message.clone(),
        }
    }

    /// Handle lookup failure based on failure mode
    fn handle_failure(&self) -> GeoFilterResult {
        let allowed = match self.config.on_failure {
            GeoFailureMode::Open => true,
            GeoFailureMode::Closed => false,
        };

        GeoFilterResult {
            allowed,
            country_code: None,
            cache_hit: false,
            add_header: false,
            status_code: self.config.status_code,
            block_message: self.config.block_message.clone(),
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let now = Instant::now();
        let total = self.cache.len();
        let valid = self
            .cache
            .iter()
            .filter(|e| now.duration_since(e.cached_at) < self.cache_ttl)
            .count();
        (total, valid)
    }

    /// Clear expired cache entries
    pub fn clear_expired(&self) {
        let now = Instant::now();
        self.cache
            .retain(|_, v| now.duration_since(v.cached_at) < self.cache_ttl);
    }

    /// Create a GeoFilterPool with a pre-built database (for testing).
    #[cfg(test)]
    pub(crate) fn new_with_database(config: GeoFilter, database: Arc<dyn GeoDatabase>) -> Self {
        let countries_set: HashSet<String> = config.countries.iter().cloned().collect();
        let cache_ttl = Duration::from_secs(config.cache_ttl_secs);
        let database_path = PathBuf::from(&config.database_path);
        let database_type = config
            .database_type
            .clone()
            .unwrap_or(GeoDatabaseType::MaxMind);

        Self {
            database: RwLock::new(database),
            cache: DashMap::new(),
            config,
            countries_set,
            cache_ttl,
            database_path,
            database_type,
        }
    }
}

// =============================================================================
// GeoFilterManager
// =============================================================================

/// What [`GeoFilterManager::apply`] did, counted per filter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GeoFilterChanges {
    /// Filters that were not registered and now are.
    pub added: usize,
    /// Filters whose settings changed, now served by a new pool (and an
    /// empty cache).
    pub replaced: usize,
    /// Filters whose settings did not change; their pool and cache are kept.
    pub unchanged: usize,
}

/// The pools of every geo filter of a configuration, built and not yet in use.
///
/// Made by [`GeoFilterManager::prepare`], which opens every database that
/// needs it, and put in use by [`GeoFilterManager::apply`] and
/// [`GeoFilterManager::remove_unlisted`], which cannot fail. Dropping a plan
/// changes nothing.
#[must_use = "a plan does nothing until it is applied"]
pub struct GeoFilterPlan {
    pools: HashMap<String, Arc<GeoFilterPool>>,
}

/// The geo filters of `config`, in the order of their ids.
fn geo_filters(config: &Config) -> Vec<(&String, &GeoFilter)> {
    let mut geo_filters: Vec<(&String, &GeoFilter)> = config
        .filters
        .iter()
        .filter_map(|(id, filter)| match &filter.filter {
            Filter::Geo(geo) => Some((id, geo)),
            _ => None,
        })
        .collect();
    geo_filters.sort_by_key(|(id, _)| *id);
    geo_filters
}

/// A line of the error that lists the filters whose database did not open.
fn load_failure(filter_id: &str, geo_filter: &GeoFilter, error: &GeoLookupError) -> String {
    format!(
        "  - filter '{}', database-path '{}': {}",
        filter_id, geo_filter.database_path, error
    )
}

/// The error for the filters whose database did not open.
fn load_failures(failures: &[String]) -> anyhow::Error {
    anyhow::anyhow!(
        "{} geo filter(s) cannot be used, because their databases did not load:\n{}",
        failures.len(),
        failures.join("\n")
    )
}

/// Manages all geo filter instances
pub struct GeoFilterManager {
    /// Filter ID → GeoFilterPool mapping
    filter_pools: DashMap<String, Arc<GeoFilterPool>>,
}

impl GeoFilterManager {
    /// Create a new empty geo filter manager
    pub fn new() -> Self {
        Self {
            filter_pools: DashMap::new(),
        }
    }

    /// Register every geo filter of `config`, opening its database.
    ///
    /// `config` is the lowered configuration (see `Config::lower_scopes`), so
    /// the geo filters of namespaces and services are among its filters.
    ///
    /// # Errors
    ///
    /// Fails when the database of any geo filter does not open. The error
    /// lists every filter that failed, in the order of their ids, with its
    /// `database-path` and the reason.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let manager = Self::new();
        let plan = manager.prepare(config)?;
        manager.apply(&plan);

        let filter_ids = manager.filter_ids();
        if !filter_ids.is_empty() {
            info!(
                filter_count = filter_ids.len(),
                filter_ids = ?filter_ids,
                "GeoIP filtering initialized"
            );
        }

        Ok(manager)
    }

    /// Open the database of every geo filter of `config`, without keeping
    /// any of them open, for a configuration that is only being checked.
    ///
    /// Opens each database the way [`Self::from_config`] does, one after the
    /// other, so no more than one is held in memory at a time.
    ///
    /// # Errors
    ///
    /// Fails when the database of any geo filter does not open. The error is
    /// the one [`Self::from_config`] gives.
    pub fn check_databases(config: &Config) -> anyhow::Result<()> {
        let mut failures = Vec::new();
        for (filter_id, geo_filter) in geo_filters(config) {
            if let Err(e) = GeoFilterPool::new(geo_filter.clone()) {
                failures.push(load_failure(filter_id, geo_filter, &e));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(load_failures(&failures))
        }
    }

    /// Build the pools of the geo filters of `config`, to bring this manager
    /// up to date with it, without changing the manager.
    ///
    /// A filter whose settings (`database-path` included) are what this
    /// manager's pool for the id was built from keeps that pool, and with it
    /// its database and cache. Every other filter of `config` gets a new pool,
    /// whose database is opened here. [`Self::apply`] then puts the plan in
    /// use.
    ///
    /// Opens databases, which blocks on file reads.
    ///
    /// # Errors
    ///
    /// Fails when the database of any geo filter that needs a new pool does
    /// not open. The error lists every filter that failed, in the order of
    /// their ids, with its `database-path` and the reason. Nothing has been
    /// changed.
    pub fn prepare(&self, config: &Config) -> anyhow::Result<GeoFilterPlan> {
        self.prepare_with(config, GeoFilterPool::new)
    }

    /// [`Self::prepare`], with the function that builds a new pool.
    fn prepare_with(
        &self,
        config: &Config,
        open: impl Fn(GeoFilter) -> Result<GeoFilterPool, GeoLookupError>,
    ) -> anyhow::Result<GeoFilterPlan> {
        let mut pools = HashMap::new();
        let mut failures = Vec::new();
        for (filter_id, geo_filter) in geo_filters(config) {
            let current = self
                .filter_pools
                .get(filter_id)
                .map(|pool| Arc::clone(pool.value()));
            match current {
                Some(pool) if pool.config == *geo_filter => {
                    pools.insert(filter_id.clone(), pool);
                }
                _ => match open(geo_filter.clone()) {
                    Ok(pool) => {
                        pools.insert(filter_id.clone(), Arc::new(pool));
                    }
                    Err(e) => failures.push(load_failure(filter_id, geo_filter, &e)),
                },
            }
        }
        if failures.is_empty() {
            Ok(GeoFilterPlan { pools })
        } else {
            Err(load_failures(&failures))
        }
    }

    /// Put a plan from [`Self::prepare`] in use: register the filters it
    /// adds and replace the ones whose pool it rebuilt.
    ///
    /// Filters the plan does not name stay registered, for the routes that
    /// still name them; [`Self::remove_unlisted`] drops them once those routes
    /// are gone. The plan was made from this manager as it is now, so apply it
    /// before anything else changes the manager.
    ///
    /// A filter is replaced in one step, but the filters of a plan are not
    /// all replaced at one instant: for a moment, a request may meet one
    /// filter as it was and another as it is to be.
    pub fn apply(&self, plan: &GeoFilterPlan) -> GeoFilterChanges {
        let mut changes = GeoFilterChanges::default();
        for (filter_id, pool) in &plan.pools {
            let registered = match self
                .filter_pools
                .insert(filter_id.clone(), Arc::clone(pool))
            {
                None => {
                    changes.added += 1;
                    "Registered geo filter"
                }
                Some(old) if Arc::ptr_eq(&old, pool) => {
                    changes.unchanged += 1;
                    continue;
                }
                Some(_) => {
                    changes.replaced += 1;
                    "Replaced geo filter"
                }
            };
            info!(
                filter_id = %filter_id,
                database_path = %pool.config.database_path,
                action = ?pool.config.action,
                countries_count = pool.config.countries.len(),
                "{registered}"
            );
        }
        changes
    }

    /// Drop the filters a plan from [`Self::prepare`] does not name, and
    /// return how many there were.
    pub fn remove_unlisted(&self, plan: &GeoFilterPlan) -> usize {
        let mut removed = 0;
        self.filter_pools.retain(|filter_id, _| {
            let kept = plan.pools.contains_key(filter_id);
            if !kept {
                removed += 1;
                info!(filter_id = %filter_id, "Removed geo filter");
            }
            kept
        });
        removed
    }

    /// Register a geo filter from configuration
    pub fn register_filter(
        &self,
        filter_id: &str,
        config: GeoFilter,
    ) -> Result<(), GeoLookupError> {
        let pool = GeoFilterPool::new(config)?;
        self.filter_pools
            .insert(filter_id.to_string(), Arc::new(pool));
        debug!(filter_id = %filter_id, "Registered geo filter");
        Ok(())
    }

    /// Check a client IP against a specific filter
    pub fn check(&self, filter_id: &str, client_ip: &str) -> Option<GeoFilterResult> {
        self.filter_pools
            .get(filter_id)
            .map(|pool| pool.check(client_ip))
    }

    /// Get a reference to a filter pool
    pub fn get_pool(&self, filter_id: &str) -> Option<Arc<GeoFilterPool>> {
        self.filter_pools.get(filter_id).map(|r| r.clone())
    }

    /// Check if a filter exists
    pub fn has_filter(&self, filter_id: &str) -> bool {
        self.filter_pools.contains_key(filter_id)
    }

    /// Get all filter IDs
    pub fn filter_ids(&self) -> Vec<String> {
        self.filter_pools.iter().map(|r| r.key().clone()).collect()
    }

    /// Clear expired cache entries in all pools
    pub fn clear_expired_caches(&self) {
        for pool in self.filter_pools.iter() {
            pool.clear_expired();
        }
    }

    /// Reload a filter's database from disk
    pub fn reload_filter(&self, filter_id: &str) -> Result<(), GeoLookupError> {
        if let Some(pool) = self.filter_pools.get(filter_id) {
            pool.reload_database()
        } else {
            Err(GeoLookupError::LoadError(format!(
                "Filter '{}' not found",
                filter_id
            )))
        }
    }

    /// Reload database for all filters using the given path
    pub fn reload_by_path(&self, path: &Path) -> Vec<(String, Result<(), GeoLookupError>)> {
        let mut results = Vec::new();
        for entry in self.filter_pools.iter() {
            if entry.value().database_path() == path {
                let filter_id = entry.key().clone();
                let result = entry.value().reload_database();
                results.push((filter_id, result));
            }
        }
        results
    }

    /// Get all unique database paths being used
    pub fn database_paths(&self) -> Vec<(String, PathBuf)> {
        self.filter_pools
            .iter()
            .map(|e| (e.key().clone(), e.value().database_path().to_path_buf()))
            .collect()
    }
}

impl Default for GeoFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// GeoDatabaseWatcher
// =============================================================================

/// Watches geo database files for changes and triggers reloads
pub struct GeoDatabaseWatcher {
    /// The watcher instance; none while there is no database to watch
    watcher: RwLock<Option<notify::RecommendedWatcher>>,
    /// Mapping from database path to filter IDs using it
    path_to_filters: RwLock<HashMap<PathBuf, Vec<String>>>,
    /// The paths `watcher` is watching
    watched: RwLock<HashSet<PathBuf>>,
    /// Where `watcher` reports the paths that changed; set by
    /// [`Self::start_watching`]
    events: RwLock<Option<mpsc::Sender<PathBuf>>>,
    /// Reference to the geo filter manager
    manager: Arc<GeoFilterManager>,
}

impl GeoDatabaseWatcher {
    /// Create a new database watcher
    pub fn new(manager: Arc<GeoFilterManager>) -> Self {
        Self {
            watcher: RwLock::new(None),
            path_to_filters: RwLock::new(HashMap::new()),
            watched: RwLock::new(HashSet::new()),
            events: RwLock::new(None),
            manager,
        }
    }

    /// Start watching all registered database files
    ///
    /// The receiver gets the path of each database file that changed. It
    /// stays open while there is nothing to watch: a later
    /// [`Self::sync_watches`] can add databases.
    pub fn start_watching(&self) -> Result<mpsc::Receiver<PathBuf>, GeoLookupError> {
        let (tx, rx) = mpsc::channel::<PathBuf>(10);
        *self.events.write() = Some(tx);
        if let Err(e) = self.sync_watches() {
            // Nothing reads the receiver: later calls must not watch either.
            *self.events.write() = None;
            return Err(e);
        }
        Ok(rx)
    }

    /// Make the watched files the database files of the manager's filters as
    /// they are now: watch the ones it has gained and stop watching the ones
    /// it has lost.
    ///
    /// Does nothing before [`Self::start_watching`]. A file that cannot be
    /// watched is logged and tried again by the next call.
    ///
    /// # Errors
    ///
    /// Fails when there are files to watch and the file watcher cannot be
    /// created.
    pub fn sync_watches(&self) -> Result<(), GeoLookupError> {
        let Some(tx) = self.events.read().clone() else {
            return Ok(());
        };

        // Build path → filter ID mapping
        let mut path_map: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for (filter_id, path) in self.manager.database_paths() {
            path_map.entry(path).or_default().push(filter_id);
        }

        // Holding the watcher serialises calls.
        let mut watcher_slot = self.watcher.write();

        if path_map.is_empty() {
            debug!("No geo databases to watch");
            *self.path_to_filters.write() = path_map;
            if watcher_slot.take().is_some() {
                info!("Stopped watching geo database files");
            }
            self.watched.write().clear();
            return Ok(());
        }

        // Store the mapping, so a change to a file watched from here on is
        // known to the filters using it.
        *self.path_to_filters.write() = path_map.clone();

        if watcher_slot.is_none() {
            // Create file watcher
            let watcher =
                notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
                    if let Ok(event) = event {
                        if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                            for path in &event.paths {
                                let _ = tx.blocking_send(path.clone());
                            }
                        }
                    }
                })
                .map_err(|e| {
                    GeoLookupError::LoadError(format!("Failed to create file watcher: {}", e))
                })?;
            *watcher_slot = Some(watcher);
        }
        let Some(watcher) = watcher_slot.as_mut() else {
            return Ok(());
        };

        let mut watched = self.watched.write();

        // Stop watching the files no filter uses any more
        let unused: Vec<PathBuf> = watched
            .iter()
            .filter(|path| !path_map.contains_key(*path))
            .cloned()
            .collect();
        for path in unused {
            if let Err(e) = watcher.unwatch(&path) {
                debug!(path = %path.display(), error = %e, "Failed to stop watching geo database file");
            }
            watched.remove(&path);
            info!(
                path = %path.display(),
                "Stopped watching geo database"
            );
        }

        // Add watches for each database path not watched yet
        for path in path_map.keys() {
            if watched.contains(path) {
                continue;
            }
            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to watch geo database file"
                );
            } else {
                watched.insert(path.clone());
                info!(
                    path = %path.display(),
                    "Watching geo database for changes"
                );
            }
        }

        Ok(())
    }

    /// The database files being watched
    pub fn watched_paths(&self) -> HashSet<PathBuf> {
        self.watched.read().clone()
    }

    /// Handle a file change event
    pub fn handle_change(&self, path: &Path) {
        let path_map = self.path_to_filters.read();
        if let Some(filter_ids) = path_map.get(path) {
            info!(
                path = %path.display(),
                filters = ?filter_ids,
                "Geo database file changed, reloading"
            );

            for filter_id in filter_ids {
                match self.manager.reload_filter(filter_id) {
                    Ok(()) => {
                        info!(
                            filter_id = %filter_id,
                            "Geo filter database reloaded successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            filter_id = %filter_id,
                            error = %e,
                            "Failed to reload geo filter database"
                        );
                    }
                }
            }
        }
    }

    /// Stop watching
    pub fn stop(&self) {
        *self.events.write() = None;
        *self.watcher.write() = None;
        self.watched.write().clear();
        info!("Stopped watching geo database files");
    }
}

// =============================================================================
// Test database
// =============================================================================

/// A MaxMind database file for tests.
#[cfg(test)]
pub(crate) mod test_database {
    use std::path::Path;

    fn string(s: &str) -> Vec<u8> {
        assert!(s.len() < 29);
        let mut out = vec![0x40 | s.len() as u8];
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        assert!(entries.len() < 29);
        let mut out = vec![0xE0 | entries.len() as u8];
        for (key, value) in entries {
            out.extend(string(key));
            out.extend_from_slice(value);
        }
        out
    }

    fn uint16(n: u16) -> Vec<u8> {
        let mut out = vec![0xA2];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    fn uint32(n: u32) -> Vec<u8> {
        let mut out = vec![0xC4];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    /// An extended type: the control byte carries the size, the next byte the
    /// type minus 7.
    fn uint64(n: u64) -> Vec<u8> {
        let mut out = vec![0x08, 0x02];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    fn array(items: &[Vec<u8>]) -> Vec<u8> {
        assert!(items.len() < 29);
        let mut out = vec![items.len() as u8, 0x04];
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    /// Write a database to `path` that says every IPv4 address is in
    /// `country`.
    ///
    /// Its search tree is one node whose two records both point at the one
    /// record of the data section.
    pub(crate) fn write_country_database(path: &Path, country: &str) {
        const NODE_COUNT: u32 = 1;
        // A record past the node count points into the data section, after
        // the 16 bytes that separate the two.
        let record = (NODE_COUNT + 16).to_be_bytes();

        let mut file = Vec::new();
        file.extend_from_slice(&record[1..]);
        file.extend_from_slice(&record[1..]);
        file.extend_from_slice(&[0; 16]);
        file.extend(map(&[("country", map(&[("iso_code", string(country))]))]));
        file.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        file.extend(map(&[
            ("binary_format_major_version", uint16(2)),
            ("binary_format_minor_version", uint16(0)),
            ("build_epoch", uint64(1_700_000_000)),
            ("database_type", string("Test-Country")),
            ("description", map(&[])),
            ("ip_version", uint16(4)),
            ("languages", array(&[string("en")])),
            ("node_count", uint32(NODE_COUNT)),
            ("record_size", uint16(24)),
        ]));
        std::fs::write(path, file).expect("write the test database");
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::{GeoDatabaseType, GeoFailureMode, GeoFilter, GeoFilterAction};

    // =========================================================================
    // Mock GeoDatabase
    // =========================================================================

    /// Mock database that returns pre-configured country codes for IPs.
    struct MockGeoDatabase {
        mapping: HashMap<IpAddr, String>,
        fail_on: HashSet<IpAddr>,
    }

    impl MockGeoDatabase {
        fn new() -> Self {
            Self {
                mapping: HashMap::new(),
                fail_on: HashSet::new(),
            }
        }

        fn with_entries(entries: Vec<(&str, &str)>) -> Self {
            let mut db = Self::new();
            for (ip, country) in entries {
                db.mapping.insert(ip.parse().unwrap(), country.to_string());
            }
            db
        }

        fn with_failure(mut self, ip: &str) -> Self {
            self.fail_on.insert(ip.parse().unwrap());
            self
        }
    }

    impl GeoDatabase for MockGeoDatabase {
        fn lookup(&self, ip: IpAddr) -> Result<Option<String>, GeoLookupError> {
            if self.fail_on.contains(&ip) {
                return Err(GeoLookupError::DatabaseError("mock failure".to_string()));
            }
            Ok(self.mapping.get(&ip).cloned())
        }

        fn database_type(&self) -> GeoDatabaseType {
            GeoDatabaseType::MaxMind
        }
    }

    fn mock_pool(
        action: GeoFilterAction,
        countries: Vec<&str>,
        on_failure: GeoFailureMode,
        db: MockGeoDatabase,
    ) -> GeoFilterPool {
        let config = GeoFilter {
            database_path: "/mock/db.mmdb".to_string(),
            database_type: Some(GeoDatabaseType::MaxMind),
            action,
            countries: countries.into_iter().map(|s| s.to_string()).collect(),
            on_failure,
            status_code: 403,
            block_message: Some("Blocked by geo filter".to_string()),
            cache_ttl_secs: 300,
            add_country_header: true,
        };
        GeoFilterPool::new_with_database(config, Arc::new(db))
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_geo_lookup_error_display() {
        let err = GeoLookupError::InvalidIp("not-an-ip".to_string());
        assert!(err.to_string().contains("invalid IP"));

        let err = GeoLookupError::DatabaseError("db error".to_string());
        assert!(err.to_string().contains("database error"));

        let err = GeoLookupError::LoadError("load error".to_string());
        assert!(err.to_string().contains("failed to load"));
    }

    // =========================================================================
    // Block Mode Tests (blocklist)
    // =========================================================================

    #[test]
    fn block_mode_blocks_listed_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN"), ("5.6.7.8", "US")]);
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN", "RU"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "CN should be blocked");
        assert_eq!(result.country_code, Some("CN".to_string()));
        assert_eq!(result.status_code, 403);
    }

    #[test]
    fn block_mode_allows_unlisted_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN"), ("5.6.7.8", "US")]);
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN", "RU"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("5.6.7.8");
        assert!(result.allowed, "US should be allowed");
        assert_eq!(result.country_code, Some("US".to_string()));
    }

    #[test]
    fn block_mode_allows_unknown_ip() {
        let db = MockGeoDatabase::new(); // Empty database
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("10.0.0.1");
        assert!(result.allowed, "Unknown IP should be allowed in block mode");
        assert_eq!(result.country_code, None);
    }

    // =========================================================================
    // Allow Mode Tests (allowlist)
    // =========================================================================

    #[test]
    fn allow_mode_allows_listed_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US"), ("5.6.7.8", "GB")]);
        let pool = mock_pool(
            GeoFilterAction::Allow,
            vec!["US", "GB", "CA"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(result.allowed, "US should be allowed");

        let result = pool.check("5.6.7.8");
        assert!(result.allowed, "GB should be allowed");
    }

    #[test]
    fn allow_mode_blocks_unlisted_country() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN")]);
        let pool = mock_pool(
            GeoFilterAction::Allow,
            vec!["US", "GB"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "CN should be blocked in allow mode");
    }

    #[test]
    fn allow_mode_blocks_unknown_ip() {
        let db = MockGeoDatabase::new();
        let pool = mock_pool(GeoFilterAction::Allow, vec!["US"], GeoFailureMode::Open, db);

        let result = pool.check("10.0.0.1");
        assert!(!result.allowed, "Unknown IP blocked when allowlist is set");
    }

    #[test]
    fn allow_mode_allows_nobody_when_empty_list() {
        // The configuration refuses this combination; a pool built without
        // it must not read the empty list as "everybody".
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN")]);
        let pool = mock_pool(
            GeoFilterAction::Allow,
            vec![], // Empty countries list
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "Empty allow list should allow nobody");
    }

    // =========================================================================
    // Log-Only Mode Tests
    // =========================================================================

    #[test]
    fn log_only_mode_never_blocks() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "CN")]);
        let pool = mock_pool(
            GeoFilterAction::LogOnly,
            vec!["CN"],
            GeoFailureMode::Open,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(result.allowed, "Log-only mode should never block");
        assert_eq!(result.country_code, Some("CN".to_string()));
    }

    // =========================================================================
    // Failure Mode Tests
    // =========================================================================

    #[test]
    fn fail_open_allows_on_lookup_error() {
        let db = MockGeoDatabase::new().with_failure("1.2.3.4");
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("1.2.3.4");
        assert!(result.allowed, "Fail-open should allow on error");
        assert_eq!(result.country_code, None);
    }

    #[test]
    fn fail_closed_blocks_on_lookup_error() {
        let db = MockGeoDatabase::new().with_failure("1.2.3.4");
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN"],
            GeoFailureMode::Closed,
            db,
        );

        let result = pool.check("1.2.3.4");
        assert!(!result.allowed, "Fail-closed should block on error");
    }

    #[test]
    fn fail_open_allows_on_invalid_ip() {
        let db = MockGeoDatabase::new();
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("not-an-ip");
        assert!(result.allowed, "Fail-open should allow on invalid IP");
    }

    #[test]
    fn fail_closed_blocks_on_invalid_ip() {
        let db = MockGeoDatabase::new();
        let pool = mock_pool(
            GeoFilterAction::Block,
            vec!["CN"],
            GeoFailureMode::Closed,
            db,
        );

        let result = pool.check("not-an-ip");
        assert!(!result.allowed, "Fail-closed should block on invalid IP");
    }

    // =========================================================================
    // Cache Tests
    // =========================================================================

    #[test]
    fn cache_hit_on_repeated_lookup() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let first = pool.check("1.2.3.4");
        assert!(!first.cache_hit, "First lookup should be a cache miss");

        let second = pool.check("1.2.3.4");
        assert!(second.cache_hit, "Second lookup should be a cache hit");
        assert_eq!(second.country_code, Some("US".to_string()));
    }

    #[test]
    fn cache_stats_report_correctly() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US"), ("5.6.7.8", "GB")]);
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        // Initial state
        let (total, valid) = pool.cache_stats();
        assert_eq!(total, 0);
        assert_eq!(valid, 0);

        // After lookups
        pool.check("1.2.3.4");
        pool.check("5.6.7.8");

        let (total, valid) = pool.cache_stats();
        assert_eq!(total, 2);
        assert_eq!(valid, 2);
    }

    #[test]
    fn clear_expired_removes_old_entries() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let config = GeoFilter {
            database_path: "/mock/db.mmdb".to_string(),
            database_type: Some(GeoDatabaseType::MaxMind),
            action: GeoFilterAction::Block,
            countries: vec!["CN".to_string()],
            on_failure: GeoFailureMode::Open,
            status_code: 403,
            block_message: None,
            cache_ttl_secs: 0, // Immediate expiry
            add_country_header: true,
        };
        let pool = GeoFilterPool::new_with_database(config, Arc::new(db));

        pool.check("1.2.3.4");
        let (total, _) = pool.cache_stats();
        assert_eq!(total, 1);

        // With TTL=0, entries are expired immediately
        std::thread::sleep(Duration::from_millis(10));
        pool.clear_expired();

        let (total, _) = pool.cache_stats();
        assert_eq!(total, 0);
    }

    // =========================================================================
    // Country Header Tests
    // =========================================================================

    #[test]
    fn add_header_flag_propagated() {
        let db = MockGeoDatabase::with_entries(vec![("1.2.3.4", "US")]);
        let pool = mock_pool(GeoFilterAction::Block, vec!["CN"], GeoFailureMode::Open, db);

        let result = pool.check("1.2.3.4");
        assert!(result.add_header, "add_country_header should be true");
    }

    // =========================================================================
    // Manager Tests
    // =========================================================================

    #[test]
    fn test_geo_filter_manager_new() {
        let manager = GeoFilterManager::new();
        assert!(manager.filter_ids().is_empty());
        assert!(!manager.has_filter("test"));
    }

    #[test]
    fn test_geo_filter_manager_check_nonexistent_filter() {
        let manager = GeoFilterManager::new();
        let result = manager.check("nonexistent", "1.2.3.4");
        assert!(result.is_none());
    }

    #[test]
    fn test_geo_filter_manager_reload_nonexistent() {
        let manager = GeoFilterManager::new();
        let result = manager.reload_filter("nonexistent");
        assert!(matches!(result, Err(GeoLookupError::LoadError(_))));
    }

    // =========================================================================
    // GeoFilterManager::from_config
    // =========================================================================

    fn config_with(filters: &str) -> Config {
        Config::from_kdl(&format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "http" {{ address "127.0.0.1:19292" protocol "http" }}
            }}
            routes {{
                route "all" {{
                    matches {{ path-prefix "/" }}
                    upstream "backend"
                }}
            }}
            upstreams {{
                upstream "backend" {{ target "127.0.0.1:19293" }}
            }}
            {filters}
            "#
        ))
        .expect("config parses")
    }

    fn geo(id: &str, path: &str) -> String {
        format!(
            r#"filter "{id}" {{
                type "geo"
                database-path "{path}"
                countries "RU" "CN"
            }}"#
        )
    }

    fn failure(config: &Config) -> String {
        match GeoFilterManager::from_config(config) {
            Ok(_) => panic!("a geo filter without a database must not register"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn from_config_fails_for_a_missing_database_and_names_filter_and_path() {
        let config = config_with(&format!(
            "filters {{ {} }}",
            geo("region-block", "/nonexistent/geo/country.mmdb")
        ));

        let message = failure(&config);
        assert!(message.contains("'region-block'"), "{message}");
        assert!(
            message.contains("'/nonexistent/geo/country.mmdb'"),
            "{message}"
        );
    }

    #[test]
    fn from_config_lists_every_failure_in_the_order_of_the_filter_ids() {
        // Written in the reverse of the order they are reported in.
        let config = config_with(&format!(
            "filters {{\n{}\n{}\n{}\n}}",
            geo("zz-last", "/nonexistent/geo/z.mmdb"),
            geo("mm-middle", "/nonexistent/geo/m.mmdb"),
            geo("aa-first", "/nonexistent/geo/a.mmdb"),
        ));

        let message = failure(&config);
        assert!(message.contains("3 geo filter(s)"), "{message}");
        let at = |id: &str| {
            message
                .find(id)
                .unwrap_or_else(|| panic!("{id}: {message}"))
        };
        assert!(at("'aa-first'") < at("'mm-middle'"), "{message}");
        assert!(at("'mm-middle'") < at("'zz-last'"), "{message}");
    }

    #[test]
    fn from_config_registers_nothing_when_there_is_no_geo_filter() {
        let config = config_with(
            r#"filters {
                filter "limit" {
                    type "rate-limit"
                    max-rps 10
                }
            }"#,
        );

        let manager = GeoFilterManager::from_config(&config).expect("no geo filter to open");
        assert!(manager.filter_ids().is_empty());
    }

    #[test]
    fn from_config_opens_the_geo_filters_of_namespaces_and_services() {
        let filters = format!(
            "filters {{ {} }}",
            geo("regional", "/nonexistent/geo/regional.mmdb")
        );
        let config = config_with(&format!(
            "namespace \"ns\" {{\n{filters}\nservice \"svc\" {{\n{filters}\n}}\n}}"
        ))
        .lower_scopes();

        let message = failure(&config);
        assert!(message.contains("2 geo filter(s)"), "{message}");
        assert!(message.contains("ns:regional"), "{message}");
        assert!(message.contains("ns:svc:regional"), "{message}");
    }

    #[test]
    fn a_database_whose_type_cannot_be_told_is_not_guessed_at() {
        let config = GeoFilter {
            database_path: "/nonexistent/geo/country.dat".to_string(),
            database_type: None,
            action: GeoFilterAction::Block,
            countries: vec!["CN".to_string()],
            on_failure: GeoFailureMode::Open,
            status_code: 403,
            block_message: None,
            cache_ttl_secs: 3600,
            add_country_header: true,
        };

        let message = match GeoFilterPool::new(config) {
            Ok(_) => panic!("a database of unknown type must not open"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains("database-type"), "{message}");
    }

    // =========================================================================
    // GeoFilterManager::prepare and apply
    // =========================================================================

    /// A geo filter that blocks `countries` (quoted, space-separated).
    fn geo_blocking(id: &str, path: &str, countries: &str) -> String {
        format!(
            r#"filter "{id}" {{
                type "geo"
                database-path "{path}"
                countries {countries}
            }}"#
        )
    }

    fn filters_config(filters: &[String]) -> Config {
        config_with(&format!("filters {{\n{}\n}}", filters.join("\n")))
    }

    /// Builds the pool of a filter on a database that says `203.0.113.7` is
    /// in RU, unless its path says "missing", and records every path it was
    /// asked to open.
    struct Opener {
        opened: std::cell::RefCell<Vec<String>>,
    }

    impl Opener {
        fn new() -> Self {
            Self {
                opened: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn open(&self, config: GeoFilter) -> Result<GeoFilterPool, GeoLookupError> {
            self.opened.borrow_mut().push(config.database_path.clone());
            if config.database_path.contains("missing") {
                return Err(GeoLookupError::LoadError(format!(
                    "failed to open {}",
                    config.database_path
                )));
            }
            let database = MockGeoDatabase::with_entries(vec![("203.0.113.7", "RU")]);
            Ok(GeoFilterPool::new_with_database(config, Arc::new(database)))
        }

        fn opened(&self) -> Vec<String> {
            self.opened.borrow().clone()
        }
    }

    /// A manager that has registered `config`.
    fn registered(config: &Config) -> GeoFilterManager {
        let manager = GeoFilterManager::new();
        let opener = Opener::new();
        let plan = manager
            .prepare_with(config, |c| opener.open(c))
            .expect("the databases open");
        manager.apply(&plan);
        manager
    }

    /// Where `needle` is in `message`; fails the test when it is not there.
    fn position(message: &str, needle: &str) -> usize {
        message
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} is not in: {message}"))
    }

    fn sorted_ids(manager: &GeoFilterManager) -> Vec<String> {
        let mut ids = manager.filter_ids();
        ids.sort();
        ids
    }

    fn pool(manager: &GeoFilterManager, id: &str) -> Arc<GeoFilterPool> {
        manager
            .get_pool(id)
            .unwrap_or_else(|| panic!("filter {id} is not registered"))
    }

    #[test]
    fn apply_registers_the_filters_of_a_configuration() {
        let manager = GeoFilterManager::new();
        let config = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]);
        let opener = Opener::new();

        let plan = manager
            .prepare_with(&config, |c| opener.open(c))
            .expect("the databases open");
        assert!(
            manager.filter_ids().is_empty(),
            "preparing a plan must not register anything"
        );
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 2,
                replaced: 0,
                unchanged: 0
            }
        );
        assert_eq!(sorted_ids(&manager), ["a", "b"]);
        assert!(!manager.check("a", "203.0.113.7").unwrap().allowed);
    }

    #[test]
    fn unchanged_filters_keep_their_pool_and_cache_and_are_not_opened_again() {
        let config = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]);
        let manager = registered(&config);
        let before = pool(&manager, "a");
        before.check("203.0.113.7");
        assert_eq!(before.cache_stats(), (1, 1));

        // Nothing may be opened: the databases are not there any more.
        let plan = manager
            .prepare_with(&config, |_| {
                Err(GeoLookupError::LoadError("must not be opened".to_string()))
            })
            .expect("nothing changed, so nothing needs opening");
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 0,
                replaced: 0,
                unchanged: 2
            }
        );
        assert_eq!(manager.remove_unlisted(&plan), 0);
        let after = pool(&manager, "a");
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.cache_stats(), (1, 1), "the cache was kept");
    }

    #[test]
    fn a_filter_with_changed_settings_gets_a_new_pool_and_an_empty_cache() {
        let manager = registered(&filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]));
        let old_a = pool(&manager, "a");
        let old_b = pool(&manager, "b");
        assert!(!manager.check("a", "203.0.113.7").unwrap().allowed);

        // `a` now blocks another country; `b` is as it was.
        let changed = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""CN""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]);
        let opener = Opener::new();
        let plan = manager
            .prepare_with(&changed, |c| opener.open(c))
            .expect("the databases open");
        assert_eq!(opener.opened(), ["/geo/a.mmdb"], "only `a` is opened");
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 0,
                replaced: 1,
                unchanged: 1
            }
        );
        let new_a = pool(&manager, "a");
        assert!(!Arc::ptr_eq(&old_a, &new_a));
        assert_eq!(new_a.cache_stats(), (0, 0), "the cache is empty");
        assert!(
            manager.check("a", "203.0.113.7").unwrap().allowed,
            "the new settings apply"
        );
        assert!(Arc::ptr_eq(&old_b, &pool(&manager, "b")));
    }

    #[test]
    fn a_filter_with_a_changed_database_path_gets_a_new_pool() {
        let manager = registered(&filters_config(&[geo_blocking(
            "a",
            "/geo/a.mmdb",
            r#""RU""#,
        )]));
        let old = pool(&manager, "a");

        let moved = filters_config(&[geo_blocking("a", "/geo/moved/a.mmdb", r#""RU""#)]);
        let opener = Opener::new();
        let plan = manager
            .prepare_with(&moved, |c| opener.open(c))
            .expect("the database opens");
        let changes = manager.apply(&plan);

        assert_eq!(changes.replaced, 1);
        let new = pool(&manager, "a");
        assert!(!Arc::ptr_eq(&old, &new));
        assert_eq!(new.database_path(), Path::new("/geo/moved/a.mmdb"));
    }

    #[test]
    fn a_filter_gone_from_the_configuration_is_removed() {
        let manager = registered(&filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]));

        let opener = Opener::new();
        let plan = manager
            .prepare_with(
                &filters_config(&[geo_blocking("a", "/geo/a.mmdb", r#""RU""#)]),
                |c| opener.open(c),
            )
            .expect("nothing needs opening");
        let changes = manager.apply(&plan);

        assert_eq!(
            changes,
            GeoFilterChanges {
                added: 0,
                replaced: 0,
                unchanged: 1
            }
        );
        assert_eq!(
            sorted_ids(&manager),
            ["a", "b"],
            "applying a plan does not drop the filters it does not name"
        );

        assert_eq!(manager.remove_unlisted(&plan), 1);
        assert_eq!(sorted_ids(&manager), ["a"]);
        assert!(manager.check("b", "203.0.113.7").is_none());
    }

    #[test]
    fn a_failure_while_preparing_changes_nothing_and_names_every_failed_filter() {
        let manager = registered(&filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""RU""#),
            geo_blocking("b", "/geo/b.mmdb", r#""CN""#),
        ]));
        let old_a = pool(&manager, "a");
        let old_b = pool(&manager, "b");

        // `a` changes and opens; `b` is gone; `c` and `d` are added, and
        // neither opens.
        let next = filters_config(&[
            geo_blocking("a", "/geo/a.mmdb", r#""CN""#),
            geo_blocking("d", "/geo/missing/d.mmdb", r#""RU""#),
            geo_blocking("c", "/geo/missing/c.mmdb", r#""RU""#),
        ]);
        let opener = Opener::new();
        let message = match manager.prepare_with(&next, |c| opener.open(c)) {
            Ok(_) => panic!("filters whose databases do not open must fail the plan"),
            Err(e) => format!("{e:#}"),
        };

        assert!(message.contains("2 geo filter(s)"), "{message}");
        assert!(message.contains("'/geo/missing/c.mmdb'"), "{message}");
        assert!(message.contains("'/geo/missing/d.mmdb'"), "{message}");
        assert!(
            position(&message, "'c'") < position(&message, "'d'"),
            "the filters are not listed in the order of their ids; {message}"
        );
        assert_eq!(sorted_ids(&manager), ["a", "b"]);
        assert!(Arc::ptr_eq(&old_a, &pool(&manager, "a")));
        assert!(Arc::ptr_eq(&old_b, &pool(&manager, "b")));
        assert!(!manager.check("a", "203.0.113.7").unwrap().allowed);
    }

    #[test]
    fn a_plan_that_is_dropped_changes_nothing() {
        let manager = registered(&filters_config(&[geo_blocking(
            "a",
            "/geo/a.mmdb",
            r#""RU""#,
        )]));
        let old = pool(&manager, "a");

        let opener = Opener::new();
        let plan = manager
            .prepare_with(
                &filters_config(&[geo_blocking("z", "/geo/z.mmdb", r#""RU""#)]),
                |c| opener.open(c),
            )
            .expect("the database opens");
        drop(plan);

        assert_eq!(sorted_ids(&manager), ["a"]);
        assert!(Arc::ptr_eq(&old, &pool(&manager, "a")));
    }

    #[test]
    fn check_databases_names_every_filter_whose_database_does_not_open() {
        let config = filters_config(&[
            geo_blocking("zz-last", "/nonexistent/geo/z.mmdb", r#""RU""#),
            geo_blocking("aa-first", "/nonexistent/geo/a.mmdb", r#""RU""#),
        ]);

        let message = match GeoFilterManager::check_databases(&config) {
            Ok(()) => panic!("databases that do not exist must not pass"),
            Err(e) => format!("{e:#}"),
        };

        assert!(message.contains("2 geo filter(s)"), "{message}");
        assert!(
            position(&message, "'aa-first'") < position(&message, "'zz-last'"),
            "{message}"
        );
        assert!(message.contains("'/nonexistent/geo/z.mmdb'"), "{message}");
    }

    // =========================================================================
    // GeoDatabaseWatcher::sync_watches
    // =========================================================================

    #[test]
    fn the_watched_files_follow_the_filters_of_the_manager() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, b"database").expect("write database");
            path
        };
        let (a, b, c) = (path("a.mmdb"), path("b.mmdb"), path("c.mmdb"));
        let filter =
            |id: &str, path: &Path| geo_blocking(id, &path.display().to_string(), r#""RU""#);
        let opener = Opener::new();

        // Nothing to watch yet, then `a` and `b`.
        let manager = Arc::new(GeoFilterManager::new());
        let watcher = GeoDatabaseWatcher::new(Arc::clone(&manager));
        let _events = watcher.start_watching().expect("start watching");
        assert!(watcher.watched_paths().is_empty());

        let apply = |filters: &[String]| {
            let plan = manager
                .prepare_with(&filters_config(filters), |c| opener.open(c))
                .expect("the databases open");
            manager.apply(&plan);
            manager.remove_unlisted(&plan);
            watcher.sync_watches().expect("sync the watches");
        };
        apply(&[filter("a", &a), filter("b", &b)]);
        assert_eq!(
            watcher.watched_paths(),
            HashSet::from([a.clone(), b.clone()])
        );

        // `b` is replaced by `c`: `c` is watched and `b` is not any more.
        apply(&[filter("a", &a), filter("b", &c)]);
        assert_eq!(
            watcher.watched_paths(),
            HashSet::from([a.clone(), c.clone()])
        );

        // Two filters on one file, and `a` is no longer used.
        apply(&[filter("b", &c), filter("d", &c)]);
        assert_eq!(watcher.watched_paths(), HashSet::from([c.clone()]));

        // Nothing is left to watch.
        apply(&[]);
        assert!(watcher.watched_paths().is_empty());

        // And a filter can come back.
        apply(&[filter("a", &a)]);
        assert_eq!(watcher.watched_paths(), HashSet::from([a]));
    }

    #[test]
    fn sync_watches_does_nothing_before_watching_has_started() {
        let manager = Arc::new(GeoFilterManager::new());
        let watcher = GeoDatabaseWatcher::new(manager);
        watcher.sync_watches().expect("nothing to do");
        assert!(watcher.watched_paths().is_empty());
    }
}
