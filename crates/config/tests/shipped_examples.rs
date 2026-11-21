//! Every shipped example configuration must load and validate.
//!
//! The examples are what users copy, so an example that `zentinel test`
//! rejects is worse than no example at all. Nine of them had drifted away
//! from the syntax the parser implements before anyone noticed (issue #312),
//! because nothing checked them. This is that check.

use std::path::{Path, PathBuf};

use zentinel_config::Config;

/// Repository root, resolved relative to this crate.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root should exist")
}

/// `config/examples`, the canonical example directory.
fn examples_dir() -> PathBuf {
    repo_root().join("config/examples")
}

/// Every directory that ships example configurations.
///
/// `config/examples` is the canonical one. The repository root also had an
/// `examples/` directory, holding two files that had not parsed for some time
/// (issue #353); this sweep only checked `config/examples`, so nothing
/// noticed. Both are checked now, and a root `examples/` is tolerated rather
/// than required, so re-adding one puts it under the same check rather than
/// outside it.
fn example_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![examples_dir()];
    let root_examples = repo_root().join("examples");
    if root_examples.is_dir() {
        dirs.push(root_examples);
    }
    dirs
}

fn example_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = example_dirs()
        .into_iter()
        .flat_map(|dir| {
            std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{} should be readable: {e}", dir.display()))
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect::<Vec<_>>()
        })
        .filter(|path| path.extension().is_some_and(|ext| ext == "kdl"))
        .collect();
    files.sort();
    files
}

#[test]
fn examples_directory_is_not_empty() {
    // Guards against the sweep below silently passing because it found
    // nothing to check.
    assert!(
        example_files().len() >= 20,
        "expected the shipped examples to still be there, found {}",
        example_files().len()
    );
}

#[test]
fn multi_file_example_loads_and_validates() {
    // Checked through its entry point here, and as a directory below: the
    // files are fragments, so they cannot be checked one by one.
    let entry = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/example-multi-file/zentinel.kdl")
        .canonicalize()
        .expect("multi-file example entry point should exist");

    let config = Config::from_file(&entry)
        .unwrap_or_else(|e| panic!("multi-file example failed to load: {e:#}"));
    config
        .validate()
        .unwrap_or_else(|e| panic!("multi-file example failed to validate: {e}"));

    // The includes must actually contribute: a glob that silently matches
    // nothing would otherwise pass this test with an empty configuration.
    assert!(!config.routes.is_empty(), "includes contributed no routes");
    assert!(
        !config.upstreams.is_empty(),
        "includes contributed no upstreams"
    );
    assert!(
        !config.listeners.is_empty(),
        "includes contributed no listeners"
    );
}

/// #541: the example is also a directory configuration, `zentinel -c
/// config/example-multi-file`. Loaded that way it must read exactly what its
/// entry point reads: each included file once, nothing dropped.
#[test]
fn multi_file_example_loads_as_a_directory() {
    let dir = repo_root().join("config/example-multi-file");

    let from_dir = Config::from_file(&dir)
        .unwrap_or_else(|e| panic!("multi-file example directory failed to load: {e:#}"));
    from_dir
        .validate()
        .unwrap_or_else(|e| panic!("multi-file example directory failed to validate: {e}"));
    let from_entry = Config::from_file(dir.join("zentinel.kdl")).unwrap();

    let ids = |config: &Config| {
        let mut routes: Vec<_> = config.routes.iter().map(|r| r.id.clone()).collect();
        let mut upstreams: Vec<_> = config.upstreams.keys().cloned().collect();
        let mut listeners: Vec<_> = config.listeners.iter().map(|l| l.id.clone()).collect();
        routes.sort();
        upstreams.sort();
        listeners.sort();
        (routes, upstreams, listeners)
    };
    assert_eq!(ids(&from_dir), ids(&from_entry));
    assert!(
        from_dir.listeners.iter().any(|l| l.tls.is_some()),
        "the https listener's TLS settings were dropped"
    );
    assert_eq!(from_dir.limits.max_header_count, 100);
}

/// `test --strict` on the example must have nothing to report, whether given
/// the directory or its entry point, in any of the files.
#[test]
fn multi_file_example_has_no_ignored_settings() {
    let dir = repo_root().join("config/example-multi-file");
    let files = Config::source_files(&dir).expect("example files should be listed");
    assert_eq!(files.len(), 6, "{files:#?}");

    let sources: Vec<_> = files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).unwrap();
            (f, text)
        })
        .collect();
    let mut result = zentinel_config::validate::ValidationResult::new();
    zentinel_config::validate::unknown_keys::check_unknown_keys_in_files(&sources, &mut result);
    assert!(result.warnings.is_empty(), "{:#?}", result.warnings);
}

#[test]
fn every_shipped_example_loads_and_validates() {
    let mut failures = Vec::new();

    for path in example_files() {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        match Config::from_file(&path) {
            Ok(config) => {
                if let Err(e) = config.validate() {
                    failures.push(format!("{name}: validation failed: {e}"));
                }
            }
            Err(e) => failures.push(format!("{name}: failed to load: {e:#}")),
        }
    }

    assert!(
        failures.is_empty(),
        "shipped example configs must load and validate, but {} failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The inference example's model routing, prices and fallback are read, not dropped:
/// its rules were once written in shapes the parser does not take, and the
/// routes loaded with none.
#[test]
fn inference_routing_example_model_rules_and_fallback_are_read() {
    let path = examples_dir().join("inference-routing.kdl");
    let config = Config::from_file(&path).unwrap_or_else(|e| panic!("failed to load: {e:#}"));
    let route = |id: &str| {
        config
            .routes
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("the example should have a route '{id}'"))
    };

    let mappings = |id: &str| {
        route(id)
            .inference
            .as_ref()
            .and_then(|i| i.model_routing.as_ref())
            .map(|m| m.mappings.iter().map(|m| m.upstream.clone()).collect())
            .unwrap_or_else(Vec::<String>::new)
    };
    assert_eq!(
        mappings("anthropic-messages"),
        ["anthropic", "anthropic", "local-llm"]
    );
    assert_eq!(
        mappings("local-inference"),
        ["local-llm", "local-llm", "local-llm"]
    );

    let fallback = route("local-inference")
        .fallback
        .as_ref()
        .expect("the local-inference route should have a fallback");
    // The openai route's prices come from `pricing`, per million tokens.
    let prices = route("openai-chat")
        .inference
        .as_ref()
        .and_then(|i| i.cost_attribution.as_ref())
        .map(|c| c.pricing.len());
    assert_eq!(prices, Some(3));

    assert_eq!(fallback.upstreams.len(), 1);
    assert_eq!(fallback.upstreams[0].upstream, "fallback-llm");
    assert_eq!(fallback.upstreams[0].model_mapping.len(), 2);
}

/// The caching example's cache blocks are read, and a route whose response
/// varies by a request header is not given one: request headers are not part of
/// the cache key.
#[test]
fn http_caching_example_caches_only_routes_that_do_not_vary_by_header() {
    let path = examples_dir().join("http-caching.kdl");
    let config = Config::from_file(&path).unwrap_or_else(|e| panic!("failed to load: {e:#}"));
    let cache_of = |id: &str| {
        config
            .routes
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("the example should have a route '{id}'"))
            .policies
            .cache
            .as_ref()
    };

    let assets = cache_of("static-assets").expect("static-assets should be cached");
    assert!(assets.enabled);
    assert_eq!(assets.default_ttl_secs, 86400);
    assert_eq!(assets.max_size_bytes, 2_097_152);
    assert_eq!(assets.stale_while_revalidate_secs, 3600);
    assert_eq!(assets.stale_if_error_secs, 86400);

    let slow = cache_of("slow-endpoint").expect("slow-endpoint should be cached");
    assert!(slow.enabled);
    assert_eq!(slow.cacheable_methods, ["GET"]);
    assert_eq!(slow.cacheable_status_codes, [200]);

    assert!(cache_of("site-with-exclusions").is_some_and(|c| c.enabled));
    assert!(cache_of("no-cache-auth").is_some_and(|c| !c.enabled));
    for id in [
        "api-cached",
        "dynamic-cached",
        "api-key-cached",
        "custom-cache-key",
    ] {
        assert!(cache_of(id).is_none(), "route '{id}' should not be cached");
    }
}
