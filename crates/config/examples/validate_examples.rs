//! Validate all example KDL configuration files
//!
//! Run with: cargo run -p sentinel-config --example validate_examples

use sentinel_config::Config;

fn main() {
    let examples = [
        // Core examples
        ("config/examples/basic.kdl", true),
        ("config/examples/api-gateway.kdl", true),
        ("config/examples/load-balancer.kdl", true),
        ("config/examples/mixed-services.kdl", true),
        // Feature-specific examples
        ("config/examples/api-schema-validation.kdl", true),
        ("config/examples/inference-routing.kdl", true),
        ("config/examples/ai-guardrails.kdl", true),
        ("config/examples/shadow-traffic.kdl", true),
        ("config/examples/distributed-rate-limit.kdl", true),
        ("config/examples/http-caching.kdl", true),
        ("config/examples/websocket.kdl", true),
        ("config/examples/static-site.kdl", true),
        ("config/examples/tracing.kdl", true),
        ("config/examples/namespaces.kdl", true),
        // Multi-file routes are partial configs, expected to fail full parse
        ("config/example-multi-file/routes/api.kdl", false),
    ];

    let mut errors = Vec::new();
    let mut partial = Vec::new();

    for (path, expect_full_parse) in examples {
        print!("Validating {}... ", path);

        match Config::from_file(path) {
            Ok(_config) => {
                println!("✓ OK");
            }
            Err(e) => {
                if expect_full_parse {
                    println!("✗ Failed");
                    errors.push(format!("{}: {}", path, e));
                } else {
                    // Check if it's at least valid KDL syntax
                    match std::fs::read_to_string(path) {
                        Ok(content) => match content.parse::<kdl::KdlDocument>() {
                            Ok(_) => {
                                println!("⚠ Partial config (valid KDL syntax)");
                                partial.push(path);
                            }
                            Err(kdl_err) => {
                                println!("✗ Invalid KDL syntax");
                                errors.push(format!("{}: {}", path, kdl_err));
                            }
                        },
                        Err(read_err) => {
                            println!("✗ Read error");
                            errors.push(format!("{}: {}", path, read_err));
                        }
                    }
                }
            }
        }
    }

    println!();

    if !partial.is_empty() {
        println!("Partial configs ({}):", partial.len());
        for p in &partial {
            println!("  - {} (valid KDL, partial config)", p);
        }
        println!();
    }

    if !errors.is_empty() {
        eprintln!("Errors ({}):", errors.len());
        for e in &errors {
            eprintln!("  - {}", e);
        }
        std::process::exit(1);
    }

    let full_count = examples.iter().filter(|(_, full)| *full).count();
    println!("✓ {} full configs + {} partial configs validated!", full_count, partial.len());
}
