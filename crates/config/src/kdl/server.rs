//! Server and listener KDL parsing.

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, trace};

use zentinel_common::types::{TlsVersion, TraceIdFormat};

use crate::server::{
    default_acme_storage, default_graceful_shutdown_timeout, default_keepalive_timeout,
    default_max_concurrent_streams, default_max_connections, default_renewal_days,
    default_request_timeout, default_worker_threads, AcmeChallengeType, AcmeConfig,
    DnsProviderConfig, DnsProviderType, ListenerConfig, ListenerProtocol, PropagationCheckConfig,
    ServerConfig, SniCertificate, TlsConfig,
};

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

/// Parse server configuration block
pub fn parse_server_config(node: &kdl::KdlNode) -> Result<ServerConfig> {
    trace!("Parsing server configuration block");

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

                listeners.push(ListenerConfig {
                    id,
                    address,
                    protocol,
                    tls,
                    default_route: get_string_entry(child, "default-route"),
                    request_timeout_secs: get_int_entry(child, "request-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_request_timeout),
                    keepalive_timeout_secs: get_int_entry(child, "keepalive-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_keepalive_timeout),
                    max_concurrent_streams: get_int_entry(child, "max-concurrent-streams")
                        .map(|v| v as u32)
                        .unwrap_or_else(default_max_concurrent_streams),
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
    let staging = get_bool_entry(node, "staging").unwrap_or(false);
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
        staging,
        storage,
        renew_before_days,
        challenge_type,
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
/// sni {
///     hostnames "example.com" "www.example.com"
///     cert-file "/etc/certs/example.crt"
///     key-file "/etc/certs/example.key"
/// }
/// ```
fn parse_sni_certificate(node: &kdl::KdlNode, listener_id: &str) -> Result<SniCertificate> {
    // Parse hostnames - can be multiple arguments or a single "hostnames" entry
    let hostnames: Vec<String> = if let Some(children) = node.children() {
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

    if hostnames.is_empty() {
        return Err(anyhow::anyhow!(
            "SNI certificate for listener '{}' requires at least one hostname",
            listener_id
        ));
    }

    let cert_file = get_string_entry(node, "cert-file")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "SNI certificate for listener '{}' requires 'cert-file'",
                listener_id
            )
        })?;

    let key_file = get_string_entry(node, "key-file")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "SNI certificate for listener '{}' requires 'key-file'",
                listener_id
            )
        })?;

    debug!(
        listener_id = %listener_id,
        hostnames = ?hostnames,
        cert_file = %cert_file.display(),
        "Parsed SNI certificate"
    );

    Ok(SniCertificate {
        hostnames,
        cert_file,
        key_file,
    })
}

/// Parse TLS version string
///
/// Only TLS 1.2 and 1.3 are supported (TLS 1.0/1.1 are deprecated)
fn parse_tls_version(s: &str) -> TlsVersion {
    match s.to_lowercase().as_str() {
        "1.3" | "tls1.3" | "tlsv1.3" => TlsVersion::Tls13,
        // All other values default to TLS 1.2
        _ => TlsVersion::Tls12,
    }
}
