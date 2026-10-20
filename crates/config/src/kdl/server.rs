//! Server and listener KDL parsing.

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, trace, warn};

use zentinel_common::types::{TlsVersion, TraceIdFormat};

use crate::server::{
    default_acme_storage, default_graceful_shutdown_timeout, default_keepalive_timeout,
    default_max_concurrent_streams, default_max_connections, default_renewal_days,
    default_request_timeout, default_worker_threads, AcmeChallengeType, AcmeConfig, AcmeKeyType,
    CertFolderReloadMode, DnsProviderConfig, DnsProviderType, ExternalAccountBinding,
    ListenerConfig, ListenerProtocol, PropagationCheckConfig, ServerConfig, SniCertFolder,
    SniCertificate, TlsConfig,
};
use std::time::Duration;

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

/// Parse server configuration block
/// Every key `parse_server_config` reads.
///
/// Kept beside the parser so that adding a setting below without listing it
/// here is a visible omission rather than a silent one. The unknown-key lint
/// reads this list; under-listing it produces false warnings on valid configs.
pub(crate) const RECOGNIZED_SYSTEM_KEYS: &[&str] = &[
    "worker-threads",
    "max-connections",
    "graceful-shutdown-timeout-secs",
    "daemon",
    "pid-file",
    "user",
    "group",
    "working-directory",
    "trace-id-format",
    "auto-reload",
    "route-cache-size",
];

/// Every key the listener parsers read.
///
/// Both `parse_listeners` here and `parse_namespace_listener` in `namespace.rs`
/// build a `ListenerConfig` from exactly this set, so a setting added to one
/// and not the other is a bug this list makes visible.
///
/// Kept beside the parser for the same reason as [`RECOGNIZED_SYSTEM_KEYS`]:
/// the unknown-key lint reads it, and under-listing produces false warnings on
/// valid configs.
pub(crate) const RECOGNIZED_LISTENER_KEYS: &[&str] = &[
    "address",
    "protocol",
    "tls",
    "default-route",
    "namespace",
    "request-timeout-secs",
    "keepalive-timeout-secs",
    "max-concurrent-streams",
    "keepalive-max-requests",
    "trusted-proxies",
];

/// Settings of the `system` block that are parsed and not applied, as messages.
///
/// `max-connections` has never been read by the proxy: Pingora offers no
/// limit on accepted connections (its accept-time `ConnectionFilter` cannot
/// count connections, as it is never told when one closes), and Zentinel has
/// not built one. Rejecting the key would break configs that have been
/// loading, every shipped example among them until #527, so it is logged at
/// load and reported by `zentinel lint` through `validate::unknown_keys`.
pub(crate) fn unapplied_system_settings(node: &kdl::KdlNode, block: &str) -> Vec<String> {
    let mut problems = Vec::new();
    if node
        .children()
        .is_some_and(|c| c.get("max-connections").is_some())
    {
        problems.push(format!(
            "'max-connections' in the '{block}' block is not applied and is being ignored: \
             Zentinel does not limit client connections. Bound load with rate limits, or \
             cap connections in front of the proxy (a load balancer, or the file \
             descriptor limit)."
        ));
    }
    problems
}

/// Parse a listener's `trusted-proxies "10.0.0.0/8" "192.0.2.7" ...`.
///
/// Every argument of every `trusted-proxies` node counts, so a long list can
/// be split over several lines. An entry that is not an address or CIDR
/// network is an error rather than skipped: silently trusting less than the
/// operator wrote breaks client-IP logging, and an entry silently *dropped*
/// from a typo would be just as invisible.
pub(crate) fn parse_trusted_proxies(
    node: &kdl::KdlNode,
    listener_id: &str,
) -> Result<Vec<crate::server::IpCidr>> {
    let mut trusted = Vec::new();
    let Some(children) = node.children() else {
        return Ok(trusted);
    };
    for child in children
        .nodes()
        .iter()
        .filter(|n| n.name().value() == "trusted-proxies")
    {
        for entry in child.entries() {
            let value = entry.value().as_string().ok_or_else(|| {
                anyhow::anyhow!(
                    "Listener '{}': trusted-proxies entries must be strings, e.g. trusted-proxies \"10.0.0.0/8\"",
                    listener_id
                )
            })?;
            let cidr = value.parse().map_err(|e: String| {
                anyhow::anyhow!("Listener '{}': trusted-proxies {}", listener_id, e)
            })?;
            trusted.push(cidr);
        }
    }
    Ok(trusted)
}

pub fn parse_server_config(node: &kdl::KdlNode) -> Result<ServerConfig> {
    trace!("Parsing server configuration block");

    for problem in unapplied_system_settings(node, node.name().value()) {
        warn!("{}", problem);
    }

    let trace_id_format = get_string_entry(node, "trace-id-format")
        .map(|s| TraceIdFormat::from_str_loose(&s))
        .unwrap_or_default();

    let config = ServerConfig {
        worker_threads: get_int_entry(node, "worker-threads")
            .map(|v| v as usize)
            .unwrap_or_else(default_worker_threads),
        max_connections: get_int_entry(node, "max-connections")
            .map(|v| v as usize)
            .unwrap_or_else(default_max_connections),
        graceful_shutdown_timeout_secs: get_int_entry(node, "graceful-shutdown-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or_else(default_graceful_shutdown_timeout),
        daemon: get_bool_entry(node, "daemon").unwrap_or(false),
        pid_file: get_string_entry(node, "pid-file").map(PathBuf::from),
        user: get_string_entry(node, "user"),
        group: get_string_entry(node, "group"),
        working_directory: get_string_entry(node, "working-directory").map(PathBuf::from),
        trace_id_format,
        auto_reload: get_bool_entry(node, "auto-reload").unwrap_or(false),
        route_cache_size: get_int_entry(node, "route-cache-size")
            .map(|v| v as usize)
            .unwrap_or_else(crate::server::default_route_cache_size),
    };

    trace!(
        worker_threads = config.worker_threads,
        max_connections = config.max_connections,
        daemon = config.daemon,
        auto_reload = config.auto_reload,
        "Parsed server configuration"
    );

    Ok(config)
}

/// Parse listeners configuration block
pub fn parse_listeners(node: &kdl::KdlNode) -> Result<Vec<ListenerConfig>> {
    trace!("Parsing listeners configuration block");
    let mut listeners = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "listener" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener requires an ID argument, e.g., listener \"http\" {{ ... }}"
                    )
                })?;

                trace!(listener_id = %id, "Parsing listener");

                let address = get_string_entry(child, "address").ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener '{}' requires an 'address' field, e.g., address \"0.0.0.0:8080\"",
                        id
                    )
                })?;

                let protocol_str =
                    get_string_entry(child, "protocol").unwrap_or_else(|| "http".to_string());
                let protocol = match protocol_str.to_lowercase().as_str() {
                    "http" => ListenerProtocol::Http,
                    "https" => ListenerProtocol::Https,
                    "h2" => ListenerProtocol::Http2,
                    "h3" => ListenerProtocol::Http3,
                    other => {
                        return Err(anyhow::anyhow!(
                            "Invalid protocol '{}' for listener '{}'. Valid protocols: http, https, h2, h3",
                            other,
                            id
                        ));
                    }
                };

                // Parse TLS configuration if present
                let tls = if let Some(children) = child.children() {
                    children
                        .nodes()
                        .iter()
                        .find(|n| n.name().value() == "tls")
                        .map(|tls_node| parse_tls_config(tls_node, &id))
                        .transpose()?
                } else {
                    None
                };

                trace!(
                    listener_id = %id,
                    address = %address,
                    protocol = ?protocol,
                    has_tls = tls.is_some(),
                    "Parsed listener"
                );

                let trusted_proxies = parse_trusted_proxies(child, &id)?;

                listeners.push(ListenerConfig {
                    service: None,
                    id,
                    address,
                    protocol,
                    tls,
                    default_route: get_string_entry(child, "default-route"),
                    namespace: get_string_entry(child, "namespace"),
                    request_timeout_secs: get_int_entry(child, "request-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_request_timeout),
                    keepalive_timeout_secs: get_int_entry(child, "keepalive-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_keepalive_timeout),
                    max_concurrent_streams: get_int_entry(child, "max-concurrent-streams")
                        .map(|v| v as u32)
                        .unwrap_or_else(default_max_concurrent_streams),
                    keepalive_max_requests: get_int_entry(child, "keepalive-max-requests")
                        .map(|v| v as u32),
                    trusted_proxies,
                });
            }
        }
    }

    trace!(
        listener_count = listeners.len(),
        "Finished parsing listeners"
    );
    Ok(listeners)
}

/// Parse TLS configuration block
///
/// Example KDL:
/// ```kdl
/// tls {
///     // Option A: Manual certificates
///     cert-file "/etc/certs/server.crt"
///     key-file "/etc/certs/server.key"
///     ca-file "/etc/certs/ca.crt"  // Optional, for mTLS
///     min-version "1.2"
///     client-auth true
///
///     // SNI certificates
///     sni {
///         hostnames "example.com" "www.example.com"
///         cert-file "/etc/certs/example.crt"
///         key-file "/etc/certs/example.key"
///     }
///
///     // Option B: ACME automatic certificates
///     acme {
///         email "admin@example.com"
///         domains "example.com" "www.example.com"
///         staging false
///         storage "/var/lib/zentinel/acme"
///         renew-before-days 30
///     }
/// }
/// ```
pub fn parse_tls_config(node: &kdl::KdlNode, listener_id: &str) -> Result<TlsConfig> {
    debug!(listener_id = %listener_id, "Parsing TLS configuration");

    reject_unknown_nodes(node, KNOWN_TLS_NODES, "tls", listener_id)?;

    // Parse ACME configuration if present
    let acme = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "acme")
            .map(|acme_node| parse_acme_config(acme_node, listener_id))
            .transpose()?
    } else {
        None
    };

    // cert-file and key-file are required unless ACME is configured
    let cert_file = get_string_entry(node, "cert-file").map(PathBuf::from);
    let key_file = get_string_entry(node, "key-file").map(PathBuf::from);

    // Validate that either manual certs or ACME is configured
    if acme.is_none() && (cert_file.is_none() || key_file.is_none()) {
        return Err(anyhow::anyhow!(
            "TLS configuration for listener '{}' requires either 'cert-file' and 'key-file', or an 'acme' block",
            listener_id
        ));
    }

    // Optional CA file for client verification (mTLS)
    let ca_file = get_string_entry(node, "ca-file").map(PathBuf::from);

    // TLS version configuration
    let min_version = get_string_entry(node, "min-version")
        .map(|s| parse_tls_version(&s))
        .unwrap_or(TlsVersion::Tls12);

    let max_version = get_string_entry(node, "max-version").map(|s| parse_tls_version(&s));

    // Client authentication (mTLS)
    let client_auth = get_bool_entry(node, "client-auth").unwrap_or(false);

    // OCSP and session options
    let ocsp_stapling = get_bool_entry(node, "ocsp-stapling").unwrap_or(true);
    let session_resumption = get_bool_entry(node, "session-resumption").unwrap_or(true);

    // Cipher suites
    let cipher_suites = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "cipher-suite")
            .filter_map(get_first_arg_string)
            .collect()
    } else {
        Vec::new()
    };

    // Parse SNI certificates
    let additional_certs = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "sni")
            .map(|sni_node| parse_sni_certificate(sni_node, listener_id))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    // Certificate folders scanned for cert/key pairs.
    let cert_folders = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "sni-certs")
            .map(|folder_node| parse_sni_cert_folder(folder_node, listener_id))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    let allow_sni_overlaps = get_bool_entry(node, "allow-sni-overlaps").unwrap_or(false);

    debug!(
        listener_id = %listener_id,
        has_cert_file = cert_file.is_some(),
        has_acme = acme.is_some(),
        has_ca = ca_file.is_some(),
        client_auth = client_auth,
        sni_cert_count = additional_certs.len(),
        "Parsed TLS configuration"
    );

    Ok(TlsConfig {
        cert_folders,
        allow_sni_overlaps,
        cert_file,
        key_file,
        additional_certs,
        ca_file,
        min_version,
        max_version,
        cipher_suites,
        client_auth,
        ocsp_stapling,
        session_resumption,
        acme,
    })
}

/// Child nodes recognized inside a listener `tls` block.
const KNOWN_TLS_NODES: &[&str] = &[
    "cert-file",
    "key-file",
    "ca-file",
    "min-version",
    "max-version",
    "client-auth",
    "ocsp-stapling",
    "session-resumption",
    "cipher-suite",
    "sni",
    "sni-certs",
    "allow-sni-overlaps",
    "acme",
];

/// Child nodes recognized inside an `sni` block.
pub(crate) const KNOWN_SNI_NODES: &[&str] = &[
    "hostnames",
    "priority-hostnames",
    "cert-file",
    "key-file",
    "acme",
];

/// Reject child nodes the parser does not understand.
///
/// Unknown nodes in security-relevant blocks previously parsed as nothing,
/// letting a config imply protections that were never active (issue #303).
fn reject_unknown_nodes(
    node: &kdl::KdlNode,
    known: &[&str],
    block: &str,
    listener_id: &str,
) -> Result<()> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    for child in children.nodes() {
        let name = child.name().value();
        if known.contains(&name) {
            continue;
        }
        let hint = match name {
            "additional-certs" | "sni-cert" => {
                "SNI certificates are configured with `sni { ... }` blocks placed directly \
                 inside `tls { }`; the `additional-certs`/`sni-cert` syntax from older \
                 documentation was never supported. "
            }
            "cipher-suites" => {
                "Cipher suites are configured as repeated `cipher-suite \"NAME\"` nodes. "
            }
            "certificates" => {
                "Certificates are configured with `cert-file`/`key-file` plus optional \
                 `sni { ... }` blocks. "
            }
            _ => "",
        };
        return Err(anyhow::anyhow!(
            "Unknown node '{}' in `{}` block of listener '{}'. {}Supported nodes: {}",
            name,
            block,
            listener_id,
            hint,
            known.join(", ")
        ));
    }
    Ok(())
}

/// Parse ACME configuration block
///
/// Example KDL:
/// ```kdl
/// acme {
///     email "admin@example.com"
///     domains "example.com" "www.example.com"
///     staging false
///     storage "/var/lib/zentinel/acme"
///     renew-before-days 30
///     challenge-type "dns-01"  // or "http-01" (default)
///
///     dns-provider {
///         type "hetzner"
///         credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
///         api-timeout-secs 30
///
///         propagation {
///             initial-delay-secs 10
///             check-interval-secs 5
///             timeout-secs 120
///         }
///     }
/// }
/// ```
fn parse_acme_config(node: &kdl::KdlNode, listener_id: &str) -> Result<AcmeConfig> {
    debug!(listener_id = %listener_id, "Parsing ACME configuration");

    // Required: email
    let email = get_string_entry(node, "email").ok_or_else(|| {
        anyhow::anyhow!(
            "ACME configuration for listener '{}' requires 'email'",
            listener_id
        )
    })?;

    // Required: domains (at least one)
    let domains: Vec<String> = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "domains")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    if domains.is_empty() {
        return Err(anyhow::anyhow!(
            "ACME configuration for listener '{}' requires at least one domain in 'domains'",
            listener_id
        ));
    }

    // Optional with defaults
    let server_url = get_string_entry(node, "server-url");
    let staging = get_bool_entry(node, "staging").unwrap_or(false);
    // Parse EAB if present
    let eab = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "eab")
            .map(|eab_node| -> Result<ExternalAccountBinding> {
                let kid = get_string_entry(eab_node, "kid")
                    .ok_or_else(|| anyhow::anyhow!("ACME EAB configuration requires 'kid'"))?;
                let hmac_key = get_string_entry(eab_node, "hmac-key")
                    .ok_or_else(|| anyhow::anyhow!("ACME EAB configuration requires 'hmac-key'"))?;
                Ok(ExternalAccountBinding { kid, hmac_key })
            })
            .transpose()?
    } else {
        None
    };
    let storage = get_string_entry(node, "storage")
        .map(PathBuf::from)
        .unwrap_or_else(default_acme_storage);
    let renew_before_days = get_int_entry(node, "renew-before-days")
        .map(|v| v as u32)
        .unwrap_or_else(default_renewal_days);

    // Parse challenge type
    let challenge_type = get_string_entry(node, "challenge-type")
        .map(|s| parse_challenge_type(&s))
        .unwrap_or_default();

    // Parse key type
    let key_type = if let Some(s) = get_string_entry(node, "key-type") {
        AcmeKeyType::from_str_loose(&s).ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid key-type '{}' for listener '{}'. Valid types: ecdsa-p256, ecdsa-p384",
                s,
                listener_id
            )
        })?
    } else {
        AcmeKeyType::default()
    };

    // Parse DNS provider configuration if present
    let dns_provider = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "dns-provider")
            .map(|dns_node| parse_dns_provider_config(dns_node, listener_id))
            .transpose()?
    } else {
        None
    };

    // Validate: DNS-01 requires dns-provider
    if challenge_type.is_dns01() && dns_provider.is_none() {
        return Err(anyhow::anyhow!(
            "ACME configuration for listener '{}' uses DNS-01 challenge but no 'dns-provider' is configured",
            listener_id
        ));
    }

    // Validate: Wildcard domains require DNS-01
    let has_wildcard = domains.iter().any(|d| d.starts_with("*."));
    if has_wildcard && !challenge_type.is_dns01() {
        return Err(anyhow::anyhow!(
            "ACME configuration for listener '{}' has wildcard domain(s) but uses HTTP-01 challenge. \
             Wildcard domains require 'challenge-type \"dns-01\"'",
            listener_id
        ));
    }

    debug!(
        listener_id = %listener_id,
        email = %email,
        domain_count = domains.len(),
        staging = staging,
        storage = %storage.display(),
        renew_before_days = renew_before_days,
        challenge_type = ?challenge_type,
        has_dns_provider = dns_provider.is_some(),
        "Parsed ACME configuration"
    );

    Ok(AcmeConfig {
        email,
        domains,
        server_url,
        staging,
        eab,
        storage,
        renew_before_days,
        challenge_type,
        key_type,
        dns_provider,
    })
}

/// Parse challenge type string
fn parse_challenge_type(s: &str) -> AcmeChallengeType {
    match s.to_lowercase().as_str() {
        "dns-01" | "dns01" | "dns" => AcmeChallengeType::Dns01,
        _ => AcmeChallengeType::Http01, // Default to HTTP-01
    }
}

/// Parse DNS provider configuration block
///
/// Example KDL:
/// ```kdl
/// dns-provider {
///     type "hetzner"
///     credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
///     credentials-env "HETZNER_DNS_TOKEN"
///     api-timeout-secs 30
///
///     propagation {
///         initial-delay-secs 10
///         check-interval-secs 5
///         timeout-secs 120
///         nameservers "8.8.8.8" "1.1.1.1"
///     }
/// }
/// ```
fn parse_dns_provider_config(node: &kdl::KdlNode, listener_id: &str) -> Result<DnsProviderConfig> {
    debug!(listener_id = %listener_id, "Parsing DNS provider configuration");

    // Required: type
    let provider_type = get_string_entry(node, "type").ok_or_else(|| {
        anyhow::anyhow!(
            "DNS provider configuration for listener '{}' requires 'type'",
            listener_id
        )
    })?;

    let provider = parse_dns_provider_type(&provider_type, node, listener_id)?;

    // Credentials (at least one required)
    let credentials_file = get_string_entry(node, "credentials-file").map(PathBuf::from);
    let credentials_env = get_string_entry(node, "credentials-env");

    if credentials_file.is_none() && credentials_env.is_none() {
        return Err(anyhow::anyhow!(
            "DNS provider configuration for listener '{}' requires either 'credentials-file' or 'credentials-env'",
            listener_id
        ));
    }

    // API timeout
    let api_timeout_secs = get_int_entry(node, "api-timeout-secs")
        .map(|v| v as u64)
        .unwrap_or(30);

    // Propagation configuration
    let propagation = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "propagation")
            .map(parse_propagation_config)
            .unwrap_or_default()
    } else {
        PropagationCheckConfig::default()
    };

    debug!(
        listener_id = %listener_id,
        provider_type = %provider_type,
        has_credentials_file = credentials_file.is_some(),
        has_credentials_env = credentials_env.is_some(),
        api_timeout_secs = api_timeout_secs,
        "Parsed DNS provider configuration"
    );

    Ok(DnsProviderConfig {
        provider,
        credentials_file,
        credentials_env,
        api_timeout_secs,
        propagation,
    })
}

/// Parse DNS provider type
fn parse_dns_provider_type(
    type_str: &str,
    node: &kdl::KdlNode,
    listener_id: &str,
) -> Result<DnsProviderType> {
    match type_str.to_lowercase().as_str() {
        "hetzner" => Ok(DnsProviderType::Hetzner),
        "cloudflare" => Ok(DnsProviderType::Cloudflare),
        "webhook" => {
            let url = get_string_entry(node, "url").ok_or_else(|| {
                anyhow::anyhow!(
                    "DNS provider 'webhook' for listener '{}' requires 'url'",
                    listener_id
                )
            })?;
            let auth_header = get_string_entry(node, "auth-header");
            Ok(DnsProviderType::Webhook { url, auth_header })
        }
        other => Err(anyhow::anyhow!(
            "Unknown DNS provider type '{}' for listener '{}'. Valid types: hetzner, webhook",
            other,
            listener_id
        )),
    }
}

/// Parse propagation check configuration
fn parse_propagation_config(node: &kdl::KdlNode) -> PropagationCheckConfig {
    let initial_delay_secs = get_int_entry(node, "initial-delay-secs")
        .map(|v| v as u64)
        .unwrap_or(10);

    let check_interval_secs = get_int_entry(node, "check-interval-secs")
        .map(|v| v as u64)
        .unwrap_or(5);

    let timeout_secs = get_int_entry(node, "timeout-secs")
        .map(|v| v as u64)
        .unwrap_or(120);

    // Parse nameservers
    let nameservers: Vec<String> = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "nameservers")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    PropagationCheckConfig {
        initial_delay_secs,
        check_interval_secs,
        timeout_secs,
        nameservers,
    }
}

/// Parse an SNI certificate configuration
///
/// Example KDL:
/// ```kdl
/// // With explicit hostnames (no SAN auto-extraction)
/// sni {
///     hostnames "example.com" "www.example.com"
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
///
/// // Without hostnames (auto-extracted from certificate CN/SAN at load time)
/// sni {
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
///
/// // With priority hostnames (auto-extract all SANs, but this cert wins for listed hostnames)
/// sni {
///     priority-hostnames "example.com"
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
/// ```
fn parse_sni_certificate(node: &kdl::KdlNode, listener_id: &str) -> Result<SniCertificate> {
    reject_unknown_nodes(node, KNOWN_SNI_NODES, "sni", listener_id)?;

    let children = node.children();

    // Parse hostnames - explicit override, disables SAN auto-extraction.
    let hostnames: Vec<String> = if let Some(children) = children {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "hostnames")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    // Parse priority-hostnames - tie-breaking with full SAN auto-extraction.
    let priority_hostnames: Vec<String> = if let Some(children) = children {
        children
            .nodes()
            .iter()
            .filter(|n| n.name().value() == "priority-hostnames")
            .flat_map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
            })
            .collect()
    } else {
        Vec::new()
    };

    // Validate mutual exclusion
    if !hostnames.is_empty() && !priority_hostnames.is_empty() {
        return Err(anyhow::anyhow!(
            "SNI certificate for listener '{}' cannot specify both 'hostnames' and 'priority-hostnames'. \
             Use 'hostnames' for an explicit hostname list (no auto-extraction), or \
             'priority-hostnames' for priority tie-breaking with full SAN auto-extraction.",
            listener_id
        ));
    }

    // Parse acme configuration if present
    let acme = if let Some(children) = children {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "acme")
            .map(|n| parse_acme_config(n, listener_id))
            .transpose()?
    } else {
        None
    };

    let cert_file = get_string_entry(node, "cert-file").map(PathBuf::from);
    let key_file = get_string_entry(node, "key-file").map(PathBuf::from);

    // Validate mutual exclusion and completeness
    match (&acme, &cert_file, &key_file) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            return Err(anyhow::anyhow!(
                "SNI certificate for listener '{}' cannot specify both manual files and an 'acme' block",
                listener_id
            ));
        }
        (None, None, _) | (None, _, None) => {
            return Err(anyhow::anyhow!(
                "SNI certificate for listener '{}' requires either both 'cert-file' and 'key-file', or an 'acme' block",
                listener_id
            ));
        }
        _ => {} // Valid: either acme OR (cert_file AND key_file)
    }

    if let Some(ref acme_config) = acme {
        debug!(
            listener_id = %listener_id,
            acme_domains = ?acme_config.domains,
            "Parsed SNI certificate with ACME"
        );
    } else {
        let cert_path = cert_file.as_ref().unwrap().display();
        if !priority_hostnames.is_empty() {
            debug!(
                listener_id = %listener_id,
                priority_hostnames = ?priority_hostnames,
                cert_file = %cert_path,
                "Parsed SNI certificate (SAN auto-extraction with priority tie-breaking)"
            );
        } else if hostnames.is_empty() {
            debug!(
                listener_id = %listener_id,
                cert_file = %cert_path,
                "Parsed SNI certificate (hostnames will be auto-extracted from CN/SAN)"
            );
        } else {
            debug!(
                listener_id = %listener_id,
                hostnames = ?hostnames,
                cert_file = %cert_path,
                "Parsed SNI certificate"
            );
        }
    }

    Ok(SniCertificate {
        hostnames,
        priority_hostnames,
        cert_file,
        key_file,
        acme,
    })
}

/// Parse TLS version string
///
/// Only TLS 1.2 and 1.3 are supported (TLS 1.0/1.1 are deprecated)
/// Parse an `sni-certs { ... }` block.
///
/// ```kdl
/// sni-certs {
///     cert-folder "/etc/zentinel/certs/dynamic/"
///     reload-mode "watch"
///     reload-interval "30s"
/// }
/// ```
fn parse_sni_cert_folder(node: &kdl::KdlNode, listener_id: &str) -> Result<SniCertFolder> {
    let cert_folder = get_string_entry(node, "cert-folder")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "sni-certs block for listener '{}' requires 'cert-folder', for example: \
                 sni-certs {{ cert-folder \"/etc/zentinel/certs/dynamic/\" }}",
                listener_id
            )
        })?;

    let reload_mode = match get_string_entry(node, "reload-mode") {
        None => CertFolderReloadMode::Off,
        Some(mode) => match mode.to_ascii_lowercase().as_str() {
            "off" => CertFolderReloadMode::Off,
            "interval" => CertFolderReloadMode::Interval,
            "watch" => CertFolderReloadMode::Watch,
            other => {
                return Err(anyhow::anyhow!(
                    "sni-certs block for listener '{}' has unknown reload-mode '{}'. \
                     Valid modes are: off, interval, watch",
                    listener_id,
                    other
                ))
            }
        },
    };

    let reload_interval = match get_string_entry(node, "reload-interval") {
        None => Duration::from_secs(30),
        Some(text) => crate::kdl::upstreams::parse_duration_string(&text)
            .map(Duration::from_secs)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "sni-certs block for listener '{}' has an invalid reload-interval '{}'. \
                 Use a duration such as \"30s\", \"5m\" or \"1h\"",
                    listener_id,
                    text
                )
            })?,
    };

    // A timer that never fires is a configuration mistake worth naming rather
    // than silently turning into a busy loop or a no-op.
    if reload_mode != CertFolderReloadMode::Off && reload_interval.is_zero() {
        return Err(anyhow::anyhow!(
            "sni-certs block for listener '{}' has reload-mode '{}' with a zero \
             reload-interval; use a non-zero interval or reload-mode \"off\"",
            listener_id,
            reload_mode
        ));
    }

    // Reject unknown children so a typo does not silently disable reloading.
    if let Some(children) = node.children() {
        const KNOWN: &[&str] = &["cert-folder", "reload-mode", "reload-interval"];
        for child in children.nodes() {
            let name = child.name().value();
            if !KNOWN.contains(&name) {
                return Err(anyhow::anyhow!(
                    "Unknown node '{}' in sni-certs block for listener '{}'. \
                     Valid nodes are: {}",
                    name,
                    listener_id,
                    KNOWN.join(", ")
                ));
            }
        }
    }

    Ok(SniCertFolder {
        cert_folder,
        reload_mode,
        reload_interval,
    })
}

fn parse_tls_version(s: &str) -> TlsVersion {
    match s.to_lowercase().as_str() {
        "1.3" | "tls1.3" | "tlsv1.3" => TlsVersion::Tls13,
        // All other values default to TLS 1.2
        _ => TlsVersion::Tls12,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Vec<ListenerConfig> {
        let doc: kdl::KdlDocument = input.parse().unwrap();
        let node = doc.nodes().first().unwrap();
        parse_listeners(node).unwrap()
    }

    #[test]
    fn parses_listener_namespace_reference() {
        let listeners = parse(
            r#"
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                }
                listener "admin" {
                    address "127.0.0.1:9000"
                    namespace "ops"
                }
            }
            "#,
        );

        let public = listeners.iter().find(|l| l.id == "public").unwrap();
        let admin = listeners.iter().find(|l| l.id == "admin").unwrap();

        assert_eq!(public.namespace, None);
        assert_eq!(admin.namespace, Some("ops".to_string()));
        assert_eq!(admin.address, "127.0.0.1:9000");
    }

    /// Default: nobody is trusted. Entries on several nodes accumulate.
    #[test]
    fn parses_trusted_proxies() {
        let listeners = parse(
            r#"
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                }
                listener "behind-lb" {
                    address "0.0.0.0:8081"
                    trusted-proxies "10.0.0.0/8" "2001:db8::/32"
                    trusted-proxies "192.0.2.7"
                }
            }
            "#,
        );
        let public = listeners.iter().find(|l| l.id == "public").unwrap();
        assert!(public.trusted_proxies.is_empty());
        let lb = listeners.iter().find(|l| l.id == "behind-lb").unwrap();
        let got: Vec<String> = lb.trusted_proxies.iter().map(|c| c.to_string()).collect();
        assert_eq!(got, ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7/32"]);
    }

    /// A typo must not silently shrink (or empty) the trusted set.
    #[test]
    fn rejects_invalid_trusted_proxy() {
        for bad in [r#""10.0.0.0/40""#, r#""lb.internal""#, "10"] {
            let input = format!(
                "listeners {{\n listener \"x\" {{\n  address \"0.0.0.0:8080\"\n  trusted-proxies {bad}\n }}\n}}"
            );
            let doc: kdl::KdlDocument = input.parse().unwrap();
            let err = parse_listeners(doc.nodes().first().unwrap())
                .expect_err(bad)
                .to_string();
            assert!(
                err.contains("Listener 'x'") && err.contains("trusted-proxies"),
                "{err}"
            );
        }
    }

    fn parse_tls(input: &str) -> Result<TlsConfig> {
        let doc: kdl::KdlDocument = input.parse().unwrap();
        let node = doc.nodes().first().unwrap();
        parse_tls_config(node, "test-listener")
    }

    #[test]
    fn tls_block_parses_sni_certificates() {
        let tls = parse_tls(
            r#"
            tls {
                cert-file "/certs/default.crt"
                key-file "/certs/default.key"
                sni {
                    hostnames "example.com"
                    cert-file "/certs/example.crt"
                    key-file "/certs/example.key"
                }
            }
            "#,
        )
        .unwrap();

        assert_eq!(tls.additional_certs.len(), 1);
        assert_eq!(tls.additional_certs[0].hostnames, vec!["example.com"]);
    }

    #[test]
    fn tls_block_rejects_unknown_node_with_documented_legacy_syntax_hint() {
        let err = parse_tls(
            r#"
            tls {
                cert-file "/certs/default.crt"
                key-file "/certs/default.key"
                additional-certs {
                    sni-cert {
                        hostname "example.com"
                    }
                }
            }
            "#,
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Unknown node 'additional-certs'"));
        assert!(message.contains("test-listener"));
        assert!(message.contains("`sni { ... }`"));
    }

    #[test]
    fn tls_block_rejects_plural_cipher_suites_node() {
        let err = parse_tls(
            r#"
            tls {
                cert-file "/certs/default.crt"
                key-file "/certs/default.key"
                cipher-suites {
                    - "TLS_AES_128_GCM_SHA256"
                }
            }
            "#,
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Unknown node 'cipher-suites'"));
        assert!(message.contains("repeated `cipher-suite \"NAME\"` nodes"));
    }

    #[test]
    fn tls_block_rejects_arbitrary_unknown_node() {
        let err = parse_tls(
            r#"
            tls {
                cert-file "/certs/default.crt"
                key-file "/certs/default.key"
                tls13-cipher-suites "TLS_AES_128_GCM_SHA256"
            }
            "#,
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Unknown node 'tls13-cipher-suites'"));
        assert!(message.contains("Supported nodes:"));
    }

    #[test]
    fn sni_block_rejects_unknown_node() {
        let err = parse_tls(
            r#"
            tls {
                cert-file "/certs/default.crt"
                key-file "/certs/default.key"
                sni {
                    hostname "example.com"
                    cert-file "/certs/example.crt"
                    key-file "/certs/example.key"
                }
            }
            "#,
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Unknown node 'hostname'"));
        assert!(message.contains("`sni` block"));
    }
}
