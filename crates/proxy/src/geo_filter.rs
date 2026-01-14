//! GeoIP filtering for Sentinel proxy
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

use sentinel_config::{GeoDatabaseType, GeoFailureMode, GeoFilter, GeoFilterAction};

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
        // Determine database type (auto-detect from extension if not specified)
        let db_type = config.database_type.clone().unwrap_or_else(|| {
            if config.database_path.ends_with(".mmdb") {
                GeoDatabaseType::MaxMind
            } else {
                GeoDatabaseType::Ip2Location
            }
        });

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
                // Allow mode: allow only if country is in the list
                // If no country found and list is not empty, block
                if self.countries_set.is_empty() {
                    true
                } else {
                    in_list
                }
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
}

// =============================================================================
// GeoFilterManager
// =============================================================================

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
    /// The watcher instance
    watcher: RwLock<Option<notify::RecommendedWatcher>>,
    /// Mapping from database path to filter IDs using it
    path_to_filters: RwLock<HashMap<PathBuf, Vec<String>>>,
    /// Reference to the geo filter manager
    manager: Arc<GeoFilterManager>,
}

impl GeoDatabaseWatcher {
    /// Create a new database watcher
    pub fn new(manager: Arc<GeoFilterManager>) -> Self {
        Self {
            watcher: RwLock::new(None),
            path_to_filters: RwLock::new(HashMap::new()),
            manager,
        }
    }

    /// Start watching all registered database files
    pub fn start_watching(&self) -> Result<mpsc::Receiver<PathBuf>, GeoLookupError> {
        // Build path → filter ID mapping
        let db_paths = self.manager.database_paths();
        let mut path_map: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for (filter_id, path) in db_paths {
            path_map
                .entry(path)
                .or_default()
                .push(filter_id);
        }

        if path_map.is_empty() {
            debug!("No geo databases to watch");
            let (_tx, rx) = mpsc::channel(1);
            return Ok(rx);
        }

        // Store the mapping
        *self.path_to_filters.write() = path_map.clone();

        // Create channel for events
        let (tx, rx) = mpsc::channel::<PathBuf>(10);

        // Create file watcher
        let paths: Vec<PathBuf> = path_map.keys().cloned().collect();
        let watcher = notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
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

        // Store watcher
        *self.watcher.write() = Some(watcher);

        // Add watches for each database path
        if let Some(ref mut watcher) = *self.watcher.write() {
            for path in &paths {
                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to watch geo database file"
                    );
                } else {
                    info!(
                        path = %path.display(),
                        "Watching geo database for changes"
                    );
                }
            }
        }

        Ok(rx)
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
        *self.watcher.write() = None;
        info!("Stopped watching geo database files");
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_lookup_error_display() {
        let err = GeoLookupError::InvalidIp("not-an-ip".to_string());
        assert!(err.to_string().contains("invalid IP"));

        let err = GeoLookupError::DatabaseError("db error".to_string());
        assert!(err.to_string().contains("database error"));

        let err = GeoLookupError::LoadError("load error".to_string());
        assert!(err.to_string().contains("failed to load"));
    }

    #[test]
    fn test_geo_filter_result_default() {
        let result = GeoFilterResult {
            allowed: true,
            country_code: Some("US".to_string()),
            cache_hit: false,
            add_header: true,
            status_code: 403,
            block_message: None,
        };

        assert!(result.allowed);
        assert_eq!(result.country_code, Some("US".to_string()));
        assert!(!result.cache_hit);
        assert!(result.add_header);
    }

    #[test]
    fn test_geo_filter_manager_new() {
        let manager = GeoFilterManager::new();
        assert!(manager.filter_ids().is_empty());
        assert!(!manager.has_filter("test"));
    }

    // Integration tests would require actual database files
    // These are covered in the integration test suite
}
