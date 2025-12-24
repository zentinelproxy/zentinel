use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're in standalone mode (no ModSecurity)
    if cfg!(feature = "standalone") {
        println!("cargo:warning=Building in standalone mode without ModSecurity");
        // Define a flag so the code knows we're in standalone mode
        println!("cargo:rustc-cfg=modsecurity_unavailable");
        return Ok(());
    }

    // Determine which ModSecurity version to use
    let use_modsec3 = cfg!(feature = "modsecurity3");
    let use_modsec2 = cfg!(feature = "modsecurity2");

    if !use_modsec3 && !use_modsec2 {
        println!("cargo:warning=No ModSecurity version specified, defaulting to v3");
    }

    // Try to find ModSecurity using pkg-config
    let modsec_name = if use_modsec2 {
        "modsecurity"
    } else {
        "modsecurity" // v3 also uses "modsecurity" in pkg-config
    };

    let lib = match pkg_config::probe_library(modsec_name) {
        Ok(lib) => lib,
        Err(e) => {
            // Check if we should try manual configuration
            println!(
                "cargo:warning=pkg-config failed: {}, trying manual configuration",
                e
            );

            // Check common installation paths
            let possible_paths = vec![
                "/usr/local/modsecurity",
                "/usr/local",
                "/opt/modsecurity",
                "/usr",
                "/opt/homebrew",
                "/usr/local/opt/modsecurity",
            ];

            let mut found_path = None;
            for path in &possible_paths {
                let inc_path = format!("{}/include", path);
                let lib_path = format!("{}/lib", path);
                let modsec_header = format!("{}/modsecurity/modsecurity.h", inc_path);

                if std::path::Path::new(&modsec_header).exists() {
                    found_path = Some((inc_path, lib_path));
                    break;
                }
            }

            match found_path {
                Some((inc_path, lib_path)) => {
                    println!("cargo:rustc-link-search=native={}", lib_path);
                    println!("cargo:rustc-link-lib=modsecurity");
                    println!("cargo:include={}", inc_path);

                    // Create a fake pkg-config result for the rest of the build
                    pkg_config::Library {
                        libs: vec!["-lmodsecurity".to_string()],
                        link_paths: vec![PathBuf::from(&lib_path)],
                        frameworks: vec![],
                        framework_paths: vec![],
                        include_paths: vec![PathBuf::from(&inc_path)],
                        version: "0.0.0".to_string(),
                        defines: std::collections::HashMap::new(),
                    }
                }
                None => {
                    // ModSecurity not found - fallback to standalone mode
                    println!("cargo:warning=ModSecurity not found! Building in standalone mode.");
                    println!("cargo:warning=To use ModSecurity, install it and rebuild:");
                    println!("cargo:warning=  macOS: brew install modsecurity");
                    println!("cargo:warning=  Ubuntu/Debian: apt-get install libmodsecurity-dev");
                    println!("cargo:warning=  RHEL/Fedora: dnf install libmodsecurity-devel");
                    println!("cargo:rustc-cfg=modsecurity_unavailable");

                    // Create stub bindings file
                    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
                    std::fs::write(
                        out_path.join("bindings.rs"),
                        "// ModSecurity not available - using stub bindings\n",
                    )?;

                    return Ok(());
                }
            }
        }
    };

    // Generate bindings using bindgen
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_comments(true)
        .generate_inline_functions(true)
        .allowlist_function("modsec_.*")
        .allowlist_function("msc_.*")
        .allowlist_type("ModSecurity.*")
        .allowlist_type("Transaction.*")
        .allowlist_type("RulesSet.*")
        .allowlist_type("ModSecurityIntervention.*")
        .allowlist_var("MODSEC_.*")
        .allowlist_var("MSC_.*")
        .derive_default(true)
        .derive_debug(true)
        .impl_debug(true);

    // Add include paths from pkg-config
    for include in &lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", include.display()));
    }

    // Add version-specific defines
    if use_modsec3 {
        builder = builder.clang_arg("-DMODSECURITY_VERSION_NUM=030000");
    } else if use_modsec2 {
        builder = builder.clang_arg("-DMODSECURITY_VERSION_NUM=020900");
    }

    // Try to generate bindings
    match builder.generate() {
        Ok(bindings) => {
            // Write the bindings to the $OUT_DIR/bindings.rs file
            let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
            bindings
                .write_to_file(out_path.join("bindings.rs"))
                .expect("Couldn't write bindings!");
        }
        Err(e) => {
            println!(
                "cargo:warning=Failed to generate ModSecurity bindings: {}",
                e
            );
            println!("cargo:warning=Falling back to standalone mode");
            println!("cargo:rustc-cfg=modsecurity_unavailable");

            // Create stub bindings file
            let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
            std::fs::write(
                out_path.join("bindings.rs"),
                "// ModSecurity bindings generation failed - using stub\n",
            )?;

            return Ok(());
        }
    }

    // Link additional dependencies that ModSecurity might need
    // These are optional - if they don't exist, linking might still work
    let optional_libs = vec!["pcre", "xml2", "curl", "yajl", "maxminddb"];

    for lib in optional_libs {
        if let Ok(_) = pkg_config::probe_library(lib) {
            println!("cargo:rustc-link-lib={}", lib);
        }
    }

    // On Linux, we might need these
    if cfg!(target_os = "linux") {
        if let Ok(_) = pkg_config::probe_library("lua5.1") {
            println!("cargo:rustc-link-lib=lua5.1");
        }
        println!("cargo:rustc-link-lib=z");
    }

    // Only try to compile the C wrapper if it exists
    let wrapper_path = "src/modsec_wrapper.c";
    if std::path::Path::new(wrapper_path).exists() {
        cc::Build::new()
            .file(wrapper_path)
            .include(&lib.include_paths[0])
            .compile("modsec_wrapper");
    }

    Ok(())
}
