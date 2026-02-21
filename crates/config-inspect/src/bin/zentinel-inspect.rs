//! CLI for Zentinel configuration inspection.
//!
//! Usage:
//!   zentinel-inspect config.kdl                 # Text summary (default)
//!   zentinel-inspect config.kdl --format mermaid # Mermaid flowchart
//!   zentinel-inspect config.kdl --format json    # JSON graph
//!   zentinel-inspect config.kdl --lint           # Warnings only

use std::process;

use zentinel_config_inspect::{inspect, render};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_usage(&args[0]);
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let config_path = &args[1];
    let format = args
        .iter()
        .position(|a| a == "--format" || a == "-f")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("text");
    let lint_only = args.contains(&"--lint".to_string());

    // Parse the config file
    let kdl_source = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading {}: {}", config_path, e);
            process::exit(1);
        }
    };

    let config = match zentinel_config::Config::from_kdl(&kdl_source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing config: {}", e);
            process::exit(1);
        }
    };

    let topology = inspect(&config);

    if lint_only {
        if topology.warnings.is_empty() {
            println!("No warnings found.");
            process::exit(0);
        }
        for w in &topology.warnings {
            println!("[{}] {}: {}", w.severity, w.code, w.message);
        }
        // Exit with non-zero if there are warnings or errors
        let has_errors = topology
            .warnings
            .iter()
            .any(|w| matches!(w.severity, zentinel_config_inspect::Severity::Error));
        process::exit(if has_errors { 1 } else { 0 });
    }

    match format {
        "mermaid" => print!("{}", render::mermaid::render(&topology)),
        "json" => println!("{}", render::json::render(&topology)),
        "text" => print!("{}", render::text::render(&topology)),
        other => {
            eprintln!("Unknown format: {}", other);
            eprintln!("Valid formats: text, mermaid, json");
            process::exit(1);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("zentinel-inspect — Static config topology analysis for Zentinel proxy\n");
    eprintln!("Usage: {} <config.kdl> [OPTIONS]\n", program);
    eprintln!("Options:");
    eprintln!("  -f, --format <FORMAT>  Output format: text (default), mermaid, json");
    eprintln!("  --lint                 Show only heuristic warnings (no topology)");
    eprintln!("  -h, --help             Show this help message");
}
