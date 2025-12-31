//! Server and listener KDL parsing.

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, trace};

use sentinel_common::types::{TlsVersion, TraceIdFormat};

use crate::server::*;

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
/// }
/// ```
fn parse_tls_config(node: &kdl::KdlNode, listener_id: &str) -> Result<TlsConfig> {
    debug!(listener_id = %listener_id, "Parsing TLS configuration");

    // Get required cert and key files
    let cert_file = get_string_entry(node, "cert-file")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TLS configuration for listener '{}' requires 'cert-file'",
                listener_id
            )
        })?;

    let key_file = get_string_entry(node, "key-file")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TLS configuration for listener '{}' requires 'key-file'",
                listener_id
            )
        })?;

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
        cert_file = %cert_file.display(),
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
    })
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
