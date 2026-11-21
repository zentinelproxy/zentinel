//! Shared-cache rules for the response cache (RFC 9111).
//!
//! The response cache answers every client of a route from the same entries,
//! so a response is stored, and reused, only as far as the response itself
//! and the request it answered allow:
//!
//! - A response to a request with `Authorization` is stored only when its
//!   `Cache-Control` has `public`, `s-maxage` or `must-revalidate`
//!   (RFC 9111 section 3.5).
//! - A response with `Vary: *` is not stored. For any other `Vary`, the
//!   response is kept per value of the request headers the field names, and
//!   answers only requests with the same values (RFC 9111 section 4.1).
//! - In addition to those rules, a response with `Set-Cookie` is not stored.
//!   RFC 9111 does not require this; a response that sets a cookie belongs to
//!   the request that got it.
//!
//! The rules look at header maps only, so they are unit-testable without a
//! running proxy. [`record_not_stored`] counts the responses they refuse.

use std::sync::LazyLock;

use http::header::{HeaderMap, HeaderName, AUTHORIZATION, CACHE_CONTROL, SET_COOKIE, VARY};
use pingora_cache::key::HashBinary;
use pingora_cache::VarianceBuilder;
use prometheus::{register_int_counter_vec, IntCounterVec};
use tracing::warn;

/// `Cache-Control` directives that let a shared cache reuse a response to a
/// request with `Authorization` (RFC 9111 section 3.5).
const ALLOWS_AUTHORIZED_REUSE: [&str; 3] = ["public", "s-maxage", "must-revalidate"];

/// `Cache-Control` directives that forbid a shared cache to store a response.
const FORBIDS_STORING: [&str; 3] = ["no-store", "no-cache", "private"];

/// Whether the request had an `Authorization` header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RequestAuthorization {
    /// No `Authorization` header.
    #[default]
    Absent,
    /// An `Authorization` header.
    Present,
}

impl RequestAuthorization {
    /// Whether `request` has an `Authorization` header.
    #[must_use]
    pub fn of(request: &HeaderMap) -> Self {
        if request.contains_key(AUTHORIZATION) {
            Self::Present
        } else {
            Self::Absent
        }
    }

    /// `Present` if either is. Used to combine what the client sent with
    /// what the request holds later, after header changes.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        if self == Self::Present || other == Self::Present {
            Self::Present
        } else {
            Self::Absent
        }
    }
}

/// Why a response is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotStorable {
    /// The request had `Authorization` and the response's `Cache-Control`
    /// has none of `public`, `s-maxage` or `must-revalidate`.
    Authorization,
    /// The response has `Set-Cookie`.
    SetCookie,
    /// The response has `Vary: *`.
    VaryAny,
    /// The response has a `Vary` field that is not a list of header names.
    VaryInvalid,
}

impl NotStorable {
    /// A short, stable name: the `reason` label of the not-stored counter, the
    /// log field and the cache's no-cache reason. A fixed set of four values.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::SetCookie => "set_cookie",
            Self::VaryAny => "vary_any",
            Self::VaryInvalid => "vary_invalid",
        }
    }
}

/// Responses refused under these rules, by route and reason.
static NOT_STORED: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    register_int_counter_vec!(
        "zentinel_cache_not_stored_total",
        "Responses the response cache did not store under the shared-cache rules, by reason",
        &["route", "reason"]
    )
    .map_err(|e| warn!(error = %e, "Failed to register zentinel_cache_not_stored_total"))
    .ok()
});

/// Count a response that was not stored, for `route_id`.
///
/// The `reason` label takes one of four fixed values (see
/// [`NotStorable::as_str`]); the `route` label is a configured route ID.
pub fn record_not_stored(route_id: &str, reason: NotStorable) {
    if let Some(counter) = NOT_STORED.as_ref() {
        counter
            .with_label_values(&[route_id, reason.as_str()])
            .inc();
    }
}

/// Decide from the response headers, and whether its request had
/// `Authorization`, whether the response may be stored in the shared cache.
///
/// This covers only the rules in the module documentation; status codes,
/// the TTL and [`cache_control_forbids_storing`] are decided elsewhere.
///
/// # Errors
///
/// Returns the first rule the response breaks, as a [`NotStorable`].
pub fn check_storable(
    authorization: RequestAuthorization,
    response: &HeaderMap,
) -> Result<(), NotStorable> {
    if authorization == RequestAuthorization::Present
        && !cache_control_has_any(response, &ALLOWS_AUTHORIZED_REUSE)
    {
        return Err(NotStorable::Authorization);
    }
    if response.contains_key(SET_COOKIE) {
        return Err(NotStorable::SetCookie);
    }
    vary_fields(response)?;
    Ok(())
}

/// Whether any `Cache-Control` line of the response has `no-store`,
/// `no-cache` or `private`, read by directive name on every line.
#[must_use]
pub fn cache_control_forbids_storing(response: &HeaderMap) -> bool {
    cache_control_has_any(response, &FORBIDS_STORING)
}

/// The variant of a stored response that `request` selects, from the request
/// header values named by the response's `Vary` field.
///
/// `None` means the response has no `Vary` field, so there is a single
/// variant. A request without a named header selects the same variant as one
/// that sends it empty, and a different one from any request that sends a
/// value.
///
/// A response whose `Vary` is not storable (see [`check_storable`]) has no
/// variants and yields `None`.
#[must_use]
pub fn variance(response: &HeaderMap, request: &HeaderMap) -> Option<HashBinary> {
    let fields = vary_fields(response).ok()?;
    if fields.is_empty() {
        return None;
    }
    let mut builder = VarianceBuilder::new();
    for name in fields {
        // All field lines of the header, as one list.
        let mut value = Vec::new();
        for (i, line) in request.get_all(&name).iter().enumerate() {
            if i > 0 {
                value.extend_from_slice(b", ");
            }
            value.extend_from_slice(line.as_bytes());
        }
        builder.add_owned_name_value(name.as_str().to_owned(), value);
    }
    builder.finalize()
}

/// The header names in the response's `Vary` field lines, lowercased.
fn vary_fields(response: &HeaderMap) -> Result<Vec<HeaderName>, NotStorable> {
    let mut names = Vec::new();
    for line in response.get_all(VARY) {
        let line = line.to_str().map_err(|_| NotStorable::VaryInvalid)?;
        for token in line.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if token == "*" {
                return Err(NotStorable::VaryAny);
            }
            names.push(
                HeaderName::from_bytes(token.as_bytes()).map_err(|_| NotStorable::VaryInvalid)?,
            );
        }
    }
    Ok(names)
}

/// Whether any `Cache-Control` field line has one of the directives `wanted`.
fn cache_control_has_any(headers: &HeaderMap, wanted: &[&str]) -> bool {
    headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(directive_names)
        .any(|name| wanted.iter().any(|w| name.eq_ignore_ascii_case(w)))
}

/// The directive names in one `Cache-Control` field line: the part of each
/// comma-separated member before any `=`. A comma inside a quoted argument
/// (`no-cache="a, b"`) does not end a member.
fn directive_names(line: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(line);
    std::iter::from_fn(move || {
        let current = rest?;
        let mut in_quotes = false;
        let mut escaped = false;
        let mut end = None;
        for (i, c) in current.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' if in_quotes => escaped = true,
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let member = match end {
            Some(i) => {
                rest = Some(&current[i + 1..]);
                &current[..i]
            }
            None => {
                rest = None;
                current
            }
        };
        Some(member.split('=').next().unwrap_or_default().trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(fields: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in fields {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    // ------------------------------------------------------------------
    // Authorization
    // ------------------------------------------------------------------

    #[test]
    fn authorization_without_cache_control_is_not_storable() {
        let result = check_storable(RequestAuthorization::Present, &headers(&[]));
        assert_eq!(result, Err(NotStorable::Authorization));
    }

    #[test]
    fn authorization_with_max_age_alone_is_not_storable() {
        let response = headers(&[("cache-control", "max-age=60")]);
        let result = check_storable(RequestAuthorization::Present, &response);
        assert_eq!(result, Err(NotStorable::Authorization));
    }

    #[test]
    fn authorization_is_storable_when_the_response_allows_it() {
        for value in [
            "public",
            "public, max-age=60",
            "max-age=60, s-maxage=30",
            "s-maxage=30",
            "must-revalidate, max-age=60",
            "Public",
            "MUST-REVALIDATE",
        ] {
            let response = headers(&[("cache-control", value)]);
            assert_eq!(
                check_storable(RequestAuthorization::Present, &response),
                Ok(()),
                "Cache-Control: {value}"
            );
        }
    }

    #[test]
    fn authorization_allowance_is_found_on_any_cache_control_line() {
        let response = headers(&[("cache-control", "max-age=60"), ("cache-control", "public")]);
        assert_eq!(
            check_storable(RequestAuthorization::Present, &response),
            Ok(())
        );
    }

    #[test]
    fn authorization_allowance_is_the_whole_directive_name() {
        for value in [
            "publicly",
            "x-public",
            "s-maxage-ish",
            "extension=public",
            "ext=\"a, public\"",
            "ext=\"a\\\", public\"",
        ] {
            let response = headers(&[("cache-control", value)]);
            assert_eq!(
                check_storable(RequestAuthorization::Present, &response),
                Err(NotStorable::Authorization),
                "Cache-Control: {value}"
            );
        }
    }

    #[test]
    fn without_authorization_cache_control_is_not_consulted() {
        assert_eq!(
            check_storable(RequestAuthorization::Absent, &headers(&[])),
            Ok(())
        );
        let response = headers(&[("cache-control", "max-age=60")]);
        assert_eq!(
            check_storable(RequestAuthorization::Absent, &response),
            Ok(())
        );
    }

    // ------------------------------------------------------------------
    // Set-Cookie
    // ------------------------------------------------------------------

    #[test]
    fn set_cookie_is_not_storable() {
        let response = headers(&[("set-cookie", "sid=1.example; Path=/")]);
        assert_eq!(
            check_storable(RequestAuthorization::Absent, &response),
            Err(NotStorable::SetCookie)
        );
    }

    #[test]
    fn set_cookie_is_not_storable_even_when_public() {
        let response = headers(&[
            ("cache-control", "public, max-age=60"),
            ("set-cookie", "sid=1.example"),
        ]);
        assert_eq!(
            check_storable(RequestAuthorization::Present, &response),
            Err(NotStorable::SetCookie)
        );
    }

    #[test]
    fn cookie_on_the_request_is_not_consulted() {
        let request = headers(&[("cookie", "sid=1.example")]);
        assert_eq!(
            RequestAuthorization::of(&request),
            RequestAuthorization::Absent
        );
    }

    // ------------------------------------------------------------------
    // Request authorization
    // ------------------------------------------------------------------

    #[test]
    fn request_authorization_is_read_from_the_header() {
        let with = headers(&[("authorization", "Bearer token.example")]);
        assert_eq!(
            RequestAuthorization::of(&with),
            RequestAuthorization::Present
        );
        assert_eq!(
            RequestAuthorization::of(&headers(&[])),
            RequestAuthorization::Absent
        );
    }

    #[test]
    fn request_authorization_combines_to_present_if_either_is() {
        use RequestAuthorization::{Absent, Present};
        assert_eq!(Absent.or(Absent), Absent);
        assert_eq!(Present.or(Absent), Present);
        assert_eq!(Absent.or(Present), Present);
        assert_eq!(Present.or(Present), Present);
        assert_eq!(RequestAuthorization::default(), Absent);
    }

    // ------------------------------------------------------------------
    // Cache-Control that forbids storing
    // ------------------------------------------------------------------

    #[test]
    fn cache_control_forbids_storing_on_any_line_by_directive_name() {
        for fields in [
            vec![("cache-control", "no-store")],
            vec![("cache-control", "max-age=60, no-cache")],
            vec![("cache-control", "private=\"a, b\"")],
            vec![
                ("cache-control", "public, max-age=60"),
                ("cache-control", "private"),
            ],
            vec![("cache-control", "PRIVATE")],
        ] {
            assert!(
                cache_control_forbids_storing(&headers(&fields)),
                "{fields:?}"
            );
        }
        for fields in [
            vec![],
            vec![("cache-control", "public, max-age=60")],
            vec![
                ("cache-control", "max-age=60"),
                ("cache-control", "must-revalidate"),
            ],
            vec![("cache-control", "ext=\"no-store\"")],
        ] {
            assert!(
                !cache_control_forbids_storing(&headers(&fields)),
                "{fields:?}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Not-stored counter
    // ------------------------------------------------------------------

    #[test]
    fn not_stored_responses_are_counted_by_route_and_reason() {
        let route = "counter-test-route.example";
        record_not_stored(route, NotStorable::SetCookie);
        record_not_stored(route, NotStorable::SetCookie);
        record_not_stored(route, NotStorable::Authorization);

        let counted = |reason: &str| -> Option<f64> {
            prometheus::gather()
                .iter()
                .filter(|family| family.name() == "zentinel_cache_not_stored_total")
                .flat_map(|family| family.get_metric())
                .find(|metric| {
                    let label = |name: &str| {
                        metric
                            .get_label()
                            .iter()
                            .find(|l| l.name() == name)
                            .map(|l| l.value())
                    };
                    label("route") == Some(route) && label("reason") == Some(reason)
                })
                .map(|metric| metric.get_counter().value())
        };
        assert_eq!(counted("set_cookie"), Some(2.0));
        assert_eq!(counted("authorization"), Some(1.0));
        assert_eq!(counted("vary_any"), None);
    }

    #[test]
    fn not_storable_names_are_the_fixed_label_values() {
        let names = [
            NotStorable::Authorization,
            NotStorable::SetCookie,
            NotStorable::VaryAny,
            NotStorable::VaryInvalid,
        ]
        .map(NotStorable::as_str);
        assert_eq!(
            names,
            ["authorization", "set_cookie", "vary_any", "vary_invalid"]
        );
    }

    // ------------------------------------------------------------------
    // Vary
    // ------------------------------------------------------------------

    #[test]
    fn vary_star_is_not_storable() {
        for fields in [
            vec![("vary", "*")],
            vec![("vary", "Accept, *")],
            vec![("vary", "Accept"), ("vary", "*")],
        ] {
            assert_eq!(
                check_storable(RequestAuthorization::Absent, &headers(&fields)),
                Err(NotStorable::VaryAny),
                "{fields:?}"
            );
        }
    }

    #[test]
    fn vary_that_is_not_a_list_of_names_is_not_storable() {
        let response = headers(&[("vary", "Accept Language")]);
        assert_eq!(
            check_storable(RequestAuthorization::Absent, &response),
            Err(NotStorable::VaryInvalid)
        );

        let mut response = HeaderMap::new();
        response.insert(VARY, HeaderValue::from_bytes(b"caf\xe9").unwrap());
        assert_eq!(
            check_storable(RequestAuthorization::Absent, &response),
            Err(NotStorable::VaryInvalid)
        );
    }

    #[test]
    fn vary_with_names_is_storable() {
        for fields in [
            vec![],
            vec![("vary", "")],
            vec![("vary", "Accept-Encoding")],
            vec![("vary", "Accept, Accept-Language")],
            vec![("vary", "Accept"), ("vary", "Cookie")],
        ] {
            assert_eq!(
                check_storable(RequestAuthorization::Absent, &headers(&fields)),
                Ok(()),
                "{fields:?}"
            );
        }
    }

    #[test]
    fn variance_is_none_without_vary() {
        let request = headers(&[("accept-language", "en")]);
        assert_eq!(variance(&headers(&[]), &request), None);
        assert_eq!(variance(&headers(&[("vary", "")]), &request), None);
    }

    #[test]
    fn variance_is_none_for_a_response_that_is_not_storable() {
        let request = headers(&[("accept-language", "en")]);
        assert_eq!(variance(&headers(&[("vary", "*")]), &request), None);
        assert_eq!(variance(&headers(&[("vary", "a b")]), &request), None);
    }

    #[test]
    fn variance_follows_the_value_of_the_named_header() {
        let response = headers(&[("vary", "Accept-Language")]);
        let en = variance(&response, &headers(&[("accept-language", "en")]));
        let fr = variance(&response, &headers(&[("accept-language", "fr")]));
        let en_again = variance(&response, &headers(&[("Accept-Language", "en")]));
        assert!(en.is_some());
        assert_ne!(en, fr);
        assert_eq!(en, en_again);
    }

    #[test]
    fn variance_ignores_headers_the_response_does_not_name() {
        let response = headers(&[("vary", "Accept-Language")]);
        let a = variance(
            &response,
            &headers(&[("accept-language", "en"), ("user-agent", "a.example")]),
        );
        let b = variance(
            &response,
            &headers(&[("accept-language", "en"), ("user-agent", "b.example")]),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn variance_treats_an_absent_header_like_an_empty_one() {
        let response = headers(&[("vary", "Accept-Language")]);
        let absent = variance(&response, &headers(&[]));
        let empty = variance(&response, &headers(&[("accept-language", "")]));
        let en = variance(&response, &headers(&[("accept-language", "en")]));
        assert!(absent.is_some());
        assert_eq!(absent, empty);
        assert_ne!(absent, en);
    }

    #[test]
    fn variance_does_not_depend_on_name_case_or_order() {
        let request = headers(&[("accept", "text/a"), ("accept-language", "en")]);
        let one = variance(&headers(&[("vary", "Accept, Accept-Language")]), &request);
        let other = variance(&headers(&[("vary", "accept-language,ACCEPT")]), &request);
        let lines = variance(
            &headers(&[("vary", "Accept-Language"), ("vary", "Accept")]),
            &request,
        );
        assert!(one.is_some());
        assert_eq!(one, other);
        assert_eq!(one, lines);
    }

    #[test]
    fn variance_joins_the_field_lines_of_a_request_header() {
        let response = headers(&[("vary", "Accept")]);
        let two_lines = variance(
            &response,
            &headers(&[("accept", "text/a"), ("accept", "text/b")]),
        );
        let one_line = variance(&response, &headers(&[("accept", "text/a, text/b")]));
        let first_only = variance(&response, &headers(&[("accept", "text/a")]));
        assert_eq!(two_lines, one_line);
        assert_ne!(two_lines, first_only);
    }

    #[test]
    fn variance_keeps_each_name_with_its_own_value() {
        let response = headers(&[("vary", "Accept, Accept-Language")]);
        let a = variance(&response, &headers(&[("accept", "x")]));
        let b = variance(&response, &headers(&[("accept-language", "x")]));
        assert_ne!(a, b);
    }

    // ------------------------------------------------------------------
    // Cache-Control directive names
    // ------------------------------------------------------------------

    #[test]
    fn directive_names_split_on_commas_outside_quotes() {
        let names: Vec<&str> = directive_names("max-age=60 , no-cache=\"a, b\", ,Public").collect();
        assert_eq!(names, ["max-age", "no-cache", "", "Public"]);
    }
}
