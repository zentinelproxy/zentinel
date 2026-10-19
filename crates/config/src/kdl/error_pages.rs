//! Route `error-pages` KDL parsing.
//!
//! ```kdl
//! route "api" {
//!     error-pages {
//!         default-format "json"
//!         template-dir "/etc/zentinel/errors"
//!         pages {
//!             "404" {
//!                 format "json"
//!                 message "Resource not found"
//!             }
//!             "503" {
//!                 format "html"
//!                 template "503.html"
//!                 message "Back in a minute"
//!                 headers {
//!                     Retry-After "30"
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! The block was in the configuration model and the docs for a long time
//! without any KDL parser reading it, so every page anyone wrote was dropped
//! and `zentinel lint` reported the whole block as ignored (#542). Configs
//! carrying such a block have been loading, so nothing in it is a hard error
//! now either: a value that cannot be honoured is left out and reported as a
//! problem, which the parser logs and `zentinel lint` prints through
//! `validate::unknown_keys`.

use std::collections::HashMap;
use std::path::PathBuf;

use super::helpers::{get_first_arg_string, get_string_entry};
use crate::routes::{ErrorFormat, ErrorPage, ErrorPageConfig, ServiceType};

/// Keys an `error-pages` block reads.
///
/// `include-stack-trace` is in the model but deliberately not here: the
/// proxy never produces a stack trace, so the key is reported as ignored
/// rather than accepted and silently doing nothing.
pub(crate) const RECOGNIZED_ERROR_PAGES_KEYS: &[&str] =
    &["default-format", "template-dir", "pages"];

/// Keys a single page (`"404" { ... }` inside `pages`) reads.
pub(crate) const RECOGNIZED_ERROR_PAGE_KEYS: &[&str] =
    &["format", "message", "template", "headers"];

const FORMAT_NAMES: &[&str] = &["html", "json", "text", "xml"];

fn parse_format(value: &str) -> Option<ErrorFormat> {
    match value.to_ascii_lowercase().as_str() {
        "html" => Some(ErrorFormat::Html),
        "json" => Some(ErrorFormat::Json),
        "text" | "plain" => Some(ErrorFormat::Text),
        "xml" => Some(ErrorFormat::Xml),
        _ => None,
    }
}

/// The format a route's errors take when nothing says otherwise.
///
/// Matches `ErrorHandler`'s own fallback. The model's `default_format`
/// defaults to HTML, and the handler prefers it over the service type once a
/// config exists, so leaving it at the model default would turn an `api`
/// route's validation errors into HTML pages just because the route gained a
/// custom 503.
fn service_default_format(service_type: &ServiceType) -> ErrorFormat {
    match service_type {
        ServiceType::Api | ServiceType::Builtin | ServiceType::Inference => ErrorFormat::Json,
        ServiceType::Web | ServiceType::Static => ErrorFormat::Html,
    }
}

/// Whether `name` is a valid HTTP header name (an RFC 9110 token).
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether `value` can be sent as a header value: visible ASCII, spaces and
/// tabs. Anything else makes the response builder fail, and the page with it.
fn is_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

/// Read a route's `error-pages` block, with every part of it that is being
/// ignored.
///
/// Returns `None` for the config when the route has no block. A block whose
/// pages all turn out unusable still yields a config, since its
/// `default-format` applies to errors the proxy generates on the route.
pub(crate) fn resolve_error_pages(
    route: &kdl::KdlNode,
    route_id: &str,
    service_type: &ServiceType,
) -> (Option<ErrorPageConfig>, Vec<String>) {
    let mut problems = Vec::new();
    let Some(block) = route.children().and_then(|c| c.get("error-pages")) else {
        return (None, problems);
    };

    let default_format = match get_string_entry(block, "default-format") {
        None => service_default_format(service_type),
        Some(value) => parse_format(&value).unwrap_or_else(|| {
            problems.push(format!(
                "'default-format \"{}\"' in error-pages on route '{}' is not a format ({}) and \
                 is being ignored; the route's errors use {}.",
                value,
                route_id,
                FORMAT_NAMES.join(", "),
                format_name(service_default_format(service_type)),
            ));
            service_default_format(service_type)
        }),
    };

    let template_dir = get_string_entry(block, "template-dir").map(PathBuf::from);

    let mut config = ErrorPageConfig {
        pages: HashMap::new(),
        default_format,
        include_stack_trace: false,
        template_dir,
    };

    let page_nodes = block
        .children()
        .and_then(|c| c.get("pages"))
        .and_then(|p| p.children())
        .map(|c| c.nodes())
        .unwrap_or_default();

    for page_node in page_nodes {
        let key = page_node.name().value();
        let status = match key.parse::<u16>() {
            Ok(status) if (400..=599).contains(&status) => status,
            _ => {
                problems.push(format!(
                    "Error page '{}' on route '{}' is not an HTTP error status (400-599) and is \
                     being ignored. Name each page by its status code, e.g. \"503\" {{ ... }}.",
                    key, route_id
                ));
                continue;
            }
        };

        let format = match get_string_entry(page_node, "format") {
            None => default_format,
            Some(value) => parse_format(&value).unwrap_or_else(|| {
                problems.push(format!(
                    "'format \"{}\"' on error page {} of route '{}' is not a format ({}) and is \
                     being ignored; the page uses {}.",
                    value,
                    status,
                    route_id,
                    FORMAT_NAMES.join(", "),
                    format_name(default_format),
                ));
                default_format
            }),
        };

        let mut headers = HashMap::new();
        let header_nodes = page_node
            .children()
            .and_then(|c| c.get("headers"))
            .and_then(|h| h.children())
            .map(|c| c.nodes())
            .unwrap_or_default();
        for header in header_nodes {
            let name = header.name().value();
            match get_first_arg_string(header) {
                Some(value) if is_header_name(name) && is_header_value(&value) => {
                    headers.insert(name.to_string(), value);
                }
                _ => problems.push(format!(
                    "Header '{}' on error page {} of route '{}' is not a valid header with a \
                     string value and is being ignored.",
                    name, status, route_id
                )),
            }
        }

        let page = ErrorPage {
            format,
            template: get_string_entry(page_node, "template").map(PathBuf::from),
            message: get_string_entry(page_node, "message"),
            headers,
        };

        // The template is read once, when the proxy builds the route's error
        // handler; a file that is not there then produces the generated page
        // instead. Checked here so the operator hears about it at load time
        // rather than from the first error a client gets.
        if let Some(path) = config.template_path(&page) {
            if crate::validation::HAS_FILESYSTEM && !path.is_file() {
                problems.push(format!(
                    "Template '{}' for error page {} of route '{}' is not a readable file and is \
                     being ignored; the page is generated in its format instead.",
                    path.display(),
                    status,
                    route_id
                ));
            }
        }

        config.pages.insert(status, page);
    }

    (Some(config), problems)
}

fn format_name(format: ErrorFormat) -> &'static str {
    match format {
        ErrorFormat::Html => "html",
        ErrorFormat::Json => "json",
        ErrorFormat::Text => "text",
        ErrorFormat::Xml => "xml",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(kdl: &str) -> kdl::KdlNode {
        let doc: kdl::KdlDocument = kdl.parse().expect("valid KDL");
        doc.nodes()[0].clone()
    }

    #[test]
    fn reads_pages_messages_headers_and_formats() {
        let node = route(
            r#"route "api" {
                error-pages {
                    default-format "text"
                    pages {
                        "404" {
                            format "json"
                            message "Resource not found"
                            headers {
                                Cache-Control "no-store"
                            }
                        }
                        "503" {
                            message "Back soon"
                        }
                    }
                }
            }"#,
        );
        let (config, problems) = resolve_error_pages(&node, "api", &ServiceType::Api);
        assert!(problems.is_empty(), "{problems:?}");
        let config = config.expect("block present");
        assert_eq!(config.default_format, ErrorFormat::Text);
        let not_found = &config.pages[&404];
        assert_eq!(not_found.format, ErrorFormat::Json);
        assert_eq!(not_found.message.as_deref(), Some("Resource not found"));
        assert_eq!(not_found.headers["Cache-Control"], "no-store");
        // A page without a format takes the block's default.
        assert_eq!(config.pages[&503].format, ErrorFormat::Text);
    }

    #[test]
    fn default_format_follows_the_service_type() {
        let block = r#"route "r" { error-pages { pages { "503" { message "x" } } } }"#;
        let (api, _) = resolve_error_pages(&route(block), "r", &ServiceType::Api);
        assert_eq!(api.unwrap().default_format, ErrorFormat::Json);
        let (web, _) = resolve_error_pages(&route(block), "r", &ServiceType::Web);
        assert_eq!(web.unwrap().default_format, ErrorFormat::Html);
    }

    #[test]
    fn no_block_is_no_config() {
        let (config, problems) = resolve_error_pages(
            &route(r#"route "r" { upstream "u" }"#),
            "r",
            &ServiceType::Web,
        );
        assert!(config.is_none());
        assert!(problems.is_empty());
    }

    #[test]
    fn unusable_values_are_reported_not_fatal() {
        let node = route(
            r#"route "r" {
                error-pages {
                    default-format "yaml"
                    pages {
                        "abc" { message "x" }
                        "200" { message "x" }
                        "502" {
                            format "pdf"
                            template "/nonexistent/zentinel/502.html"
                            headers {
                                "Bad Header" "v"
                            }
                        }
                    }
                }
            }"#,
        );
        let (config, problems) = resolve_error_pages(&node, "r", &ServiceType::Web);
        let config = config.unwrap();
        assert_eq!(config.default_format, ErrorFormat::Html);
        assert_eq!(config.pages.len(), 1, "only 502 is a usable status");
        assert_eq!(config.pages[&502].format, ErrorFormat::Html);
        assert!(config.pages[&502].headers.is_empty());
        assert_eq!(problems.len(), 6, "{problems:#?}");
        assert!(problems.iter().all(|p| p.contains("is being ignored")));
    }

    #[test]
    fn relative_templates_resolve_against_the_template_dir() {
        let dir = std::env::temp_dir();
        let name = format!("zentinel-error-page-{}.html", std::process::id());
        std::fs::write(dir.join(&name), "<p>{{message}}</p>").unwrap();
        let node = route(&format!(
            r##"route "r" {{
                error-pages {{
                    template-dir #"{}"#
                    pages {{ "503" {{ template "{}" }} }}
                }}
            }}"##,
            dir.display(),
            name
        ));
        let (config, problems) = resolve_error_pages(&node, "r", &ServiceType::Web);
        std::fs::remove_file(dir.join(&name)).ok();
        assert!(problems.is_empty(), "{problems:?}");
        let config = config.unwrap();
        assert_eq!(
            config.template_path(&config.pages[&503]),
            Some(dir.join(&name))
        );
    }
}
