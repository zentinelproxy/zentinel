//! `zentinel bundle install` leaves agents the proxy can actually reach.
//!
//! It used to write a YAML file per agent with a `socket:` block no agent
//! reads and a systemd unit running `<agent> --config <that file>`, and left
//! the proxy's KDL to the user. Agents take `--socket` / `--grpc-address`, so
//! a bundle-installed agent listened on its built-in default while the
//! documented KDL pointed elsewhere.
//!
//! This runs the real binary against a local fake release server
//! (`ZENTINEL_BUNDLE_DOWNLOAD_URL`) into a temp prefix and checks:
//!
//! - the systemd units start each agent with `--socket <path>` /
//!   `--grpc-address 127.0.0.1:<port>`, and no per-agent YAML is written;
//! - the generated `agents.kdl` passes `zentinel test` and names the same
//!   socket and address;
//! - a proxy using that KDL sends traffic to whatever listens where the unit
//!   told the agent to listen;
//! - `bundle install ratelimit` explains that rate limiting is built in.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestHeadersEvent};

/// The embedded lock's waf and zentinelsec versions and gRPC port. After a
/// lock bump the fake server answers 404 and the install step fails, naming
/// the URL it asked for.
const WAF: &str = "0.4.0";
const ZENTINELSEC: &str = "0.4.0";
const ZENTINELSEC_PORT: u16 = 50151;

fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        ("macos", "aarch64") => Some("darwin-aarch64"),
        _ => None, // not published by any agent release
    }
}

/// A shell script standing in for an agent binary: answers `--version` like
/// the real ones and otherwise records the arguments it was started with.
fn fake_agent(binary: &str, version: &str) -> Vec<u8> {
    format!(
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then echo \"{binary} {version}\"; exit 0; fi\n\
         printf '%s\\n' \"$@\" > \"$0.argv\"\n"
    )
    .into_bytes()
}

fn tarball(binary: &str, content: &[u8]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar.append_data(&mut header, binary, content).unwrap();
    tar.into_inner().unwrap().finish().unwrap()
}

/// Serve `files` (path -> body) over HTTP on a free loopback port.
fn serve(files: HashMap<String, Vec<u8>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let files = Arc::new(files);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let files = files.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    line.clear();
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = match files.get(path) {
                    Some(body) => ("200 OK", body.clone()),
                    None => ("404 Not Found", b"not found".to_vec()),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            });
        }
    });
    port
}

fn release_files(platform: &str) -> HashMap<String, Vec<u8>> {
    use sha2::{Digest, Sha256};
    let mut files = HashMap::new();
    for (agent, version) in [("waf", WAF), ("zentinelsec", ZENTINELSEC)] {
        let binary = format!("zentinel-{agent}-agent");
        let archive = tarball(&binary, &fake_agent(&binary, version));
        let path = format!(
            "/zentinelproxy/zentinel-agent-{agent}/releases/download/v{version}/\
             {binary}-{version}-{platform}.tar.gz"
        );
        let sum = format!(
            "{}  {binary}.tar.gz\n",
            hex::encode(Sha256::digest(&archive))
        );
        files.insert(format!("{path}.sha256"), sum.into_bytes());
        files.insert(path, archive);
    }
    files
}

fn zentinel(args: &[&str], home: &Path, release_port: u16) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .args(args)
        .env("HOME", home)
        .env(
            "ZENTINEL_BUNDLE_DOWNLOAD_URL",
            format!("http://127.0.0.1:{release_port}"),
        )
        .env_remove("ZENTINEL_CONFIG")
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The words of a unit's `ExecStart=` line (the generated ones need no
/// unquoting for these paths, which the assertion on `tmp` checks).
fn exec_start(unit: &str) -> Vec<String> {
    let line = unit
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .unwrap_or_else(|| panic!("no ExecStart in\n{unit}"));
    assert!(!line.contains('"'), "unexpected quoting: {line}");
    line.split(' ').map(str::to_string).collect()
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Blocker;

#[async_trait::async_trait]
impl AgentHandlerV2 for Blocker {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("waf", "stand-in", "0.1.0").with_event(EventType::RequestHeaders)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::block(403, Some("BLOCKED-BY-BUNDLE-SOCKET".to_string()))
    }
}

fn get_status(port: u16) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.split_whitespace().nth(1)?.parse().ok()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn bundle_install_wires_agents_the_way_they_are_started() {
    let Some(platform) = platform() else {
        eprintln!("skipping: no agent release is built for this platform");
        return;
    };
    let release_port = serve(release_files(platform));

    // Keep the prefix short: it ends up in a Unix socket path.
    let tmp = tempfile::Builder::new()
        .prefix("zb")
        .tempdir_in("/tmp")
        .unwrap();
    let prefix = tmp.path().join("p");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let prefix_s = prefix.to_str().unwrap();
    assert!(!prefix_s.contains(' '));

    for agent in ["waf", "zentinelsec"] {
        let out = zentinel(
            &[
                "bundle",
                "install",
                agent,
                "--prefix",
                prefix_s,
                "--systemd",
            ],
            &home,
            release_port,
        );
        assert!(out.status.success(), "install {agent}: {}", text(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("verified"), "{}", text(&out));
        assert!(stdout.contains("include \""), "{}", text(&out));
    }

    let config_dir = prefix.join("etc/zentinel/agents");
    let units = prefix.join("lib/systemd/system");
    let socket = prefix.join("run/zentinel/waf.sock");

    // No more YAML nobody reads.
    let leftovers: Vec<_> = std::fs::read_dir(&config_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n != "agents.kdl")
        .collect();
    assert!(leftovers.is_empty(), "unexpected files: {leftovers:?}");

    // The units start the agents on the endpoints the KDL names.
    let waf_unit = std::fs::read_to_string(units.join("zentinel-waf.service")).unwrap();
    let waf_argv = exec_start(&waf_unit);
    assert_eq!(
        waf_argv,
        [
            prefix.join("bin/zentinel-waf-agent").display().to_string(),
            "--socket".to_string(),
            socket.display().to_string(),
        ]
    );
    let sec_unit = std::fs::read_to_string(units.join("zentinel-zentinelsec.service")).unwrap();
    assert_eq!(
        exec_start(&sec_unit)[1..],
        [
            "--grpc-address".to_string(),
            format!("127.0.0.1:{ZENTINELSEC_PORT}")
        ]
    );
    // A non-root install gets user units: no user switch, home visible.
    assert!(!waf_unit.contains("User="), "{waf_unit}");
    assert!(!waf_unit.contains("ProtectHome"), "{waf_unit}");

    let kdl_path = config_dir.join("agents.kdl");
    let kdl = std::fs::read_to_string(&kdl_path).unwrap();
    assert!(
        kdl.contains(&format!("unix-socket \"{}\"", socket.display())),
        "{kdl}"
    );
    assert!(
        kdl.contains(&format!(
            "grpc address=\"http://127.0.0.1:{ZENTINELSEC_PORT}\""
        )),
        "{kdl}"
    );

    // The socket directory exists and is private to the installing user.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    // Starting the agent the way the unit does passes it exactly that.
    let status = Command::new(&waf_argv[0])
        .args(&waf_argv[1..])
        .status()
        .unwrap();
    assert!(status.success());
    let recorded = std::fs::read_to_string(PathBuf::from(format!("{}.argv", waf_argv[0]))).unwrap();
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        ["--socket", socket.to_str().unwrap()]
    );

    // A proxy config using the generated KDL is valid...
    let (listen, backend) = (free_port(), free_port());
    let config = tmp.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"include "{kdl}"
system {{ worker-threads 1 }}
listeners {{ listener "http" {{ address "127.0.0.1:{listen}"; protocol "http"; }} }}
upstreams {{ upstream "backend" {{ target "127.0.0.1:{backend}"; }} }}
filters {{ filter "waf" {{ type "agent"; agent "waf"; failure-mode "closed"; }} }}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "waf"
    }}
}}
observability {{ metrics {{ enabled #false }} }}
"#,
            kdl = kdl_path.display()
        ),
    )
    .unwrap();
    let out = zentinel(
        &["test", "-c", config.to_str().unwrap()],
        &home,
        release_port,
    );
    assert!(out.status.success(), "zentinel test: {}", text(&out));

    // ...and sends traffic to whatever listens where the unit told the
    // agent to listen.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("waf", socket.clone(), Box::new(Blocker));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "stand-in agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }
    let _proxy = Killed(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&config)
            .env_remove("ZENTINEL_CONFIG")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if get_status(listen) == Some(403) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the proxy never consulted the agent on {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn installing_the_retired_ratelimit_agent_explains_why() {
    let tmp = tempfile::tempdir().unwrap();
    let out = zentinel(
        &[
            "bundle",
            "install",
            "ratelimit",
            "--prefix",
            tmp.path().join("p").to_str().unwrap(),
        ],
        tmp.path(),
        1,
    );
    assert!(!out.status.success(), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no longer part of the bundle") && stderr.contains("built into Zentinel"),
        "{}",
        text(&out)
    );
}
