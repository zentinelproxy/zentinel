//! Configuration builder for merging multiple partial configurations.
//!
//! This module provides `PartialConfig` for representing config from a single file,
//! and `ConfigBuilder` for merging multiple partial configs into a final `Config`.

use anyhow::{anyhow, Result};
use kdl::KdlDocument;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::debug;

use crate::{
    AgentConfig, Config, Limits, ListenerConfig, ObservabilityConfig, RouteConfig, ServerConfig,
    UpstreamConfig, WafConfig,
};

use super::parsers::{
    parse_agent, parse_limits, parse_listener, parse_observability, parse_route, parse_server,
    parse_upstream, parse_waf,
};

/// Partial configuration from a single file.
///
/// Represents the configuration elements found in a single KDL file,
/// before being merged with other partial configs.
#[derive(Debug, Default)]
pub(super) struct PartialConfig {
    pub source_file: PathBuf,
    pub server: Option<ServerConfig>,
    pub listeners: Vec<ListenerConfig>,
    pub routes: Vec<RouteConfig>,
    pub upstreams: HashMap<String, UpstreamConfig>,
    pub agents: Vec<AgentConfig>,
    pub waf: Option<WafConfig>,
    pub limits: Option<Limits>,
    pub observability: Option<ObservabilityConfig>,
    /// Include directives found in this file (relative paths to include)
    pub includes: Vec<PathBuf>,
}

impl PartialConfig {
    /// Parse partial configuration from KDL document.
    pub fn from_kdl(doc: KdlDocument, source: &Path) -> Result<Self> {
        let mut config = Self {
            source_file: source.to_path_buf(),
            ..Default::default()
        };

        for node in doc.nodes() {
            match node.name().value() {
                "include" => {
                    // Parse include directive: include "path/to/file.kdl"
                    if let Some(entry) = node.entries().first() {
                        if let Some(path_str) = entry.value().as_string() {
                            config.includes.push(PathBuf::from(path_str));
                            debug!("Found include directive: {}", path_str);
                        }
                    }
                }
                "server" if config.server.is_none() => {
                    config.server = Some(parse_server(node)?);
                }
                "listener" => {
                    config.listeners.push(parse_listener(node)?);
                }
                "route" => {
                    config.routes.push(parse_route(node)?);
                }
                "upstream" => {
                    let (name, upstream) = parse_upstream(node)?;
                    config.upstreams.insert(name, upstream);
                }
                "agent" => {
                    config.agents.push(parse_agent(node)?);
                }
                "waf" if config.waf.is_none() => {
                    config.waf = Some(parse_waf(node)?);
                }
                "limits" if config.limits.is_none() => {
                    config.limits = Some(parse_limits(node)?);
                }
                "observability" if config.observability.is_none() => {
                    config.observability = Some(parse_observability(node)?);
                }
                "metadata" => {
                    // Skip metadata for now - not part of the main config structure
                }
                _ => {
                    debug!(
                        "Ignoring unknown configuration node: {}",
                        node.name().value()
                    );
                }
            }
        }

        Ok(config)
    }
}

/// Configuration builder for merging multiple partial configs.
///
/// Tracks duplicate IDs and handles singleton configs (server, waf, limits, etc.)
/// with appropriate warnings on override.
pub(super) struct ConfigBuilder {
    server: Option<ServerConfig>,
    listeners: Vec<ListenerConfig>,
    routes: Vec<RouteConfig>,
    upstreams: HashMap<String, UpstreamConfig>,
    filters: HashMap<String, crate::FilterConfig>,
    agents: Vec<AgentConfig>,
    waf: Option<WafConfig>,
    limits: Option<Limits>,
    observability: Option<ObservabilityConfig>,

    // Tracking for duplicates
    listener_ids: HashSet<String>,
    route_ids: HashSet<String>,
    #[allow(dead_code)]
    filter_ids: HashSet<String>,
    agent_ids: HashSet<String>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            server: None,
            listeners: Vec::new(),
            routes: Vec::new(),
            upstreams: HashMap::new(),
            filters: HashMap::new(),
            agents: Vec::new(),
            waf: None,
            limits: None,
            observability: None,
            listener_ids: HashSet::new(),
            route_ids: HashSet::new(),
            filter_ids: HashSet::new(),
            agent_ids: HashSet::new(),
        }
    }

    /// Merge a partial configuration into this builder.
    pub fn merge(&mut self, partial: PartialConfig) -> Result<()> {
        // Merge listeners
        for listener in partial.listeners {
            if !self.listener_ids.insert(listener.id.clone()) {
                return Err(anyhow!(
                    "Duplicate listener '{}' in {:?}",
                    listener.id,
                    partial.source_file
                ));
            }
            self.listeners.push(listener);
        }

        // Merge routes
        for route in partial.routes {
            if !self.route_ids.insert(route.id.clone()) {
                return Err(anyhow!(
                    "Duplicate route '{}' in {:?}",
                    route.id,
                    partial.source_file
                ));
            }
            self.routes.push(route);
        }

        // Merge upstreams (last wins for duplicates)
        for (name, upstream) in partial.upstreams {
            if self.upstreams.contains_key(&name) {
                tracing::warn!(
                    "Overriding upstream '{}' from {:?}",
                    name,
                    partial.source_file
                );
            }
            self.upstreams.insert(name, upstream);
        }

        // Merge agents
        for agent in partial.agents {
            if !self.agent_ids.insert(agent.id.clone()) {
                return Err(anyhow!(
                    "Duplicate agent '{}' in {:?}",
                    agent.id,
                    partial.source_file
                ));
            }
            self.agents.push(agent);
        }

        // Merge singleton configs (last wins with warnings)
        if partial.server.is_some() {
            if self.server.is_some() {
                tracing::warn!("Overriding server config from {:?}", partial.source_file);
            }
            self.server = partial.server;
        }

        if partial.waf.is_some() {
            if self.waf.is_some() {
                tracing::warn!("Overriding WAF config from {:?}", partial.source_file);
            }
            self.waf = partial.waf;
        }

        if partial.limits.is_some() {
            if self.limits.is_some() {
                tracing::warn!("Overriding limits config from {:?}", partial.source_file);
            }
            self.limits = partial.limits;
        }

        if partial.observability.is_some() {
            if self.observability.is_some() {
                tracing::warn!(
                    "Overriding observability config from {:?}",
                    partial.source_file
                );
            }
            self.observability = partial.observability;
        }

        Ok(())
    }

    /// Build the final configuration.
    pub fn build(self) -> Result<Config> {
        Ok(Config {
            server: self
                .server
                .ok_or_else(|| anyhow!("Server configuration is required"))?,
            listeners: self.listeners,
            routes: self.routes,
            upstreams: self.upstreams,
            filters: self.filters,
            agents: self.agents,
            waf: self.waf,
            limits: self.limits.unwrap_or_default(),
            observability: self.observability.unwrap_or_default(),
            default_upstream: None,
        })
    }
}
