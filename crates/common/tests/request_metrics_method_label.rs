//! Which `method` label values the request metrics can emit.
//!
//! The method of a request is chosen by the client: HTTP accepts any token as a
//! method, so the set of values a proxy can see is not fixed. The request
//! metrics use it as a label value, so these tests check what reaches the
//! exported series, not only the function that maps a method to a label.
//!
//! # Why the two collectors are separate tests
//!
//! `register_*_vec!` registers into the process-global default registry, so a
//! collector can be created once per process and `prometheus::gather()` sees
//! every test's writes. Each test creates the one collector it needs, and the
//! two collectors use different metric names and different route labels, so
//! neither test can see the other's series.

use std::time::Duration;

use prometheus::proto::MetricFamily;
use zentinel_common::ids::Scope;
use zentinel_common::observability::RequestMetrics;
use zentinel_common::ScopedMetrics;

/// Methods RFC 9110 defines, plus PATCH (RFC 5789).
const STANDARD_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// Methods that are valid tokens but are not in the set above, including one
/// that differs from a standard method only by case.
fn nonstandard_methods() -> Vec<String> {
    let mut methods = vec!["get".to_string(), "Post".to_string(), "PURGE".to_string()];
    methods.extend((0..200).map(|i| format!("EXT{i}")));
    methods
}

/// The `method` label values of every series in `family` for one route.
fn methods_for_route(families: &[MetricFamily], family: &str, route: &str) -> Vec<String> {
    let family = families
        .iter()
        .find(|f| f.name() == family)
        .unwrap_or_else(|| panic!("metric family {family} is not registered"));

    let mut methods: Vec<String> = family
        .metric
        .iter()
        .filter(|m| {
            m.label
                .iter()
                .any(|l| l.name() == "route" && l.value() == route)
        })
        .filter_map(|m| {
            m.label
                .iter()
                .find(|l| l.name() == "method")
                .map(|l| l.value().to_string())
        })
        .collect();
    methods.sort();
    methods
}

/// Assert that `family` has one series per standard method for `route`, plus
/// one for everything else, and no others.
fn assert_bounded_methods(families: &[MetricFamily], family: &str, route: &str) {
    let mut expected: Vec<String> = STANDARD_METHODS.iter().map(|m| m.to_string()).collect();
    expected.push("<other>".to_string());
    expected.sort();

    let actual = methods_for_route(families, family, route);

    // Checked first so a failure reports a count rather than a long list.
    assert_eq!(
        actual.len(),
        expected.len(),
        "{family}: {} series for route {route:?}, expected {} (the standard methods and <other>)",
        actual.len(),
        expected.len()
    );
    assert_eq!(actual, expected, "{family}: unexpected method label values");
}

#[test]
fn request_metrics_count_nonstandard_methods_under_one_label_value() {
    let metrics = RequestMetrics::new().expect("metrics register");
    let route = "method-label";

    for method in STANDARD_METHODS {
        metrics.record_request(route, method, 200, Duration::from_millis(5));
    }
    for method in nonstandard_methods() {
        metrics.record_request(route, &method, 200, Duration::from_millis(5));
    }

    let families = prometheus::gather();

    // One series per standard method, and a single series for everything else.
    for name in [
        "zentinel_requests_total",
        "zentinel_request_duration_seconds",
    ] {
        assert_bounded_methods(&families, name, route);
    }

    // The nonstandard requests were counted, not dropped.
    let requests = families
        .iter()
        .find(|f| f.name() == "zentinel_requests_total")
        .expect("metric family registered");
    let other = requests
        .metric
        .iter()
        .find(|m| {
            m.label
                .iter()
                .any(|l| l.name() == "route" && l.value() == route)
                && m.label
                    .iter()
                    .any(|l| l.name() == "method" && l.value() == "<other>")
        })
        .expect("<other> series exists");
    assert_eq!(
        other.counter.value() as usize,
        nonstandard_methods().len(),
        "every nonstandard request should be counted under <other>"
    );
}

#[test]
fn scoped_metrics_count_nonstandard_methods_under_one_label_value() {
    let metrics = ScopedMetrics::new().expect("scoped metrics register");
    let route = "scoped-method-label";
    let scope = Scope::Global;

    for method in STANDARD_METHODS {
        metrics.record_request(route, method, 200, Duration::from_millis(5), &scope);
    }
    for method in nonstandard_methods() {
        metrics.record_request(route, &method, 200, Duration::from_millis(5), &scope);
    }

    let families = prometheus::gather();

    for name in [
        "zentinel_scoped_requests_total",
        "zentinel_scoped_request_duration_seconds",
    ] {
        assert_bounded_methods(&families, name, route);
    }
}
