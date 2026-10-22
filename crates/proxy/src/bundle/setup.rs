//! How an installed agent is started, and how the proxy is wired to it.
//!
//! Every agent takes the same command line (agent protocol v2):
//!
//! * `--socket <path>` to listen on a Unix socket, or
//! * `--grpc-address <host:port>` for agents whose release only serves gRPC
//!   (`[transports]` in the lock), plus
//! * whatever file the release cannot start without (`[required_files]`).
//!
//! `bundle install` derives three things from one [`Endpoint`] per agent, so
//! they cannot disagree: the command it prints, the systemd unit it writes with
//! `--systemd`, and the `agents { }` KDL it writes to `agents.kdl` for the
//! proxy. It used to write a YAML file per agent with a `socket:` block that no
//! agent reads, start the agent with `--config` pointing at it, and leave the
//! KDL to the user: agents listened on their built-in default (`/tmp/...`)
//! while the documented KDL pointed at `/var/run/zentinel/...`.

use super::install::InstallPaths;
use super::lock::{AgentInfo, Transport};
use std::path::{Path, PathBuf};

/// File name of the generated KDL, in the install's config directory.
pub const AGENTS_KDL: &str = "agents.kdl";

/// Longest Unix socket path that works everywhere (`sun_path` is 104 bytes on
/// macOS and the BSDs, 108 on Linux, both including the terminating NUL).
pub const MAX_SOCKET_PATH: usize = 103;

/// Where one agent listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix socket.
    Socket(PathBuf),
    /// gRPC on a loopback port.
    Grpc(u16),
}

impl Endpoint {
    /// The endpoint an agent gets under these install paths.
    pub fn for_agent(agent: &AgentInfo, paths: &InstallPaths) -> Self {
        match agent.transport {
            Transport::Uds => {
                Endpoint::Socket(paths.socket_dir.join(format!("{}.sock", agent.name)))
            }
            Transport::Grpc { port } => Endpoint::Grpc(port),
        }
    }

    /// The agent's arguments for this endpoint.
    fn args(&self) -> Vec<String> {
        match self {
            Endpoint::Socket(path) => vec!["--socket".into(), path.display().to_string()],
            Endpoint::Grpc(port) => vec!["--grpc-address".into(), format!("127.0.0.1:{port}")],
        }
    }

    /// The KDL transport node for the proxy's `agent` block.
    fn kdl(&self) -> String {
        match self {
            Endpoint::Socket(path) => {
                format!(
                    "unix-socket \"{}\"",
                    kdl_escape(&path.display().to_string())
                )
            }
            Endpoint::Grpc(port) => format!("grpc address=\"http://127.0.0.1:{port}\""),
        }
    }

    /// A warning if this endpoint cannot work (a socket path too long to bind).
    pub fn problem(&self) -> Option<String> {
        match self {
            Endpoint::Socket(path) if path.as_os_str().len() > MAX_SOCKET_PATH => Some(format!(
                "socket path {} is {} bytes; Unix sockets allow at most {}. \
                 Use a shorter --prefix.",
                path.display(),
                path.as_os_str().len(),
                MAX_SOCKET_PATH
            )),
            _ => None,
        }
    }
}

/// The file an agent needs to start, at its place under the config directory.
pub fn required_file_path(agent: &AgentInfo, paths: &InstallPaths) -> Option<PathBuf> {
    agent
        .required_file
        .as_ref()
        .map(|req| paths.config_dir.join(&req.file))
}

/// The full argument vector the agent is started with, binary first.
pub fn launch_argv(agent: &AgentInfo, paths: &InstallPaths) -> Vec<String> {
    let mut argv = vec![paths.bin_dir.join(&agent.binary_name).display().to_string()];
    argv.extend(Endpoint::for_agent(agent, paths).args());
    if let (Some(req), Some(path)) = (&agent.required_file, required_file_path(agent, paths)) {
        argv.push(req.flag.clone());
        argv.push(path.display().to_string());
    }
    argv
}

/// The launch command as a shell command line.
pub fn launch_command(agent: &AgentInfo, paths: &InstallPaths) -> String {
    launch_argv(agent, paths)
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Name of the systemd unit for an agent.
pub fn systemd_unit_name(agent: &AgentInfo) -> String {
    format!("zentinel-{}.service", agent.name)
}

/// The systemd unit for an agent.
///
/// A system-wide install gets a system unit that runs as `zentinel` (the
/// proxy's user in `deploy/zentinel.service`, so the proxy may connect to the
/// socket) with a preserved runtime directory. Any other install gets a user
/// unit (`systemctl --user`): no `User=`, which a user manager cannot switch
/// to, and no `ProtectHome=`, which would hide a binary in `~/.local/bin`.
/// The previous unit had both, so it could not start from a user install.
pub fn generate_systemd_unit(agent: &AgentInfo, paths: &InstallPaths) -> String {
    let exec = launch_argv(agent, paths)
        .iter()
        .map(|a| systemd_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let condition = required_file_path(agent, paths)
        .map(|p| {
            format!(
                "ConditionPathExists={}\n",
                systemd_quote(&p.display().to_string())
            )
        })
        .unwrap_or_default();
    let name = &agent.name;

    let mut unit = format!(
        "# Generated by `zentinel bundle install`; rerunning it overwrites this file.\n\
         [Unit]\n\
         Description=Zentinel {name} agent\n\
         Documentation=https://zentinelproxy.io/docs/agents/{name}\n\
         # Start before the proxy, which connects to its agents at startup.\n\
         Before=zentinel.service\n\
         {condition}\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         Environment=RUST_LOG=info\n\
         NoNewPrivileges=true\n"
    );

    if paths.system_wide {
        let socket_dir = paths
            .socket_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "zentinel-agents".to_string());
        unit.push_str(&format!(
            "User=zentinel\n\
             Group=zentinel\n\
             UMask=0007\n\
             # The socket directory. Preserved: every agent unit shares it, and\n\
             # without this the first agent to stop would delete the others' sockets.\n\
             RuntimeDirectory={socket_dir}\n\
             RuntimeDirectoryMode=0750\n\
             RuntimeDirectoryPreserve=yes\n\
             ProtectSystem=strict\n\
             ProtectHome=true\n\
             PrivateTmp=true\n\
             RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             SyslogIdentifier=zentinel-{name}\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        ));
    } else {
        unit.push_str(
            "UMask=0077\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
        );
    }
    unit
}

/// The `agents { }` block that wires the proxy to these agents.
///
/// Every agent is listed with the endpoint it is started on. It is a complete
/// top-level KDL node, so it can be pasted into `zentinel.kdl` or pulled in
/// with `include`; agents only see traffic once a route's filters use them.
pub fn generate_agents_kdl(agents: &[AgentInfo], paths: &InstallPaths, bundle: &str) -> String {
    let mut out = format!(
        "// Generated by `zentinel bundle install` (bundle {bundle}); rerunning it\n\
         // overwrites this file. Use it from zentinel.kdl with\n\
         //\n\
         //     include \"{}\"\n\
         //\n\
         // and send a route's traffic through an agent with a filter:\n\
         //\n\
         //     filters {{ filter \"waf\" {{ type \"agent\"; agent \"waf\"; }} }}\n\
         //     routes {{ route \"app\" {{ filters \"waf\"; ... }} }}\n\
         //\n\
         // `events` defaults to request headers only: add \"request_body\" (and the\n\
         // response events) for agents that inspect bodies.\n\
         agents {{\n",
        kdl_escape(&paths.config_dir.join(AGENTS_KDL).display().to_string())
    );
    for (i, agent) in agents.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let endpoint = Endpoint::for_agent(agent, paths);
        out.push_str(&format!(
            "    // {} {}, started as:\n    //   {}\n",
            agent.name,
            agent.version,
            launch_command(agent, paths)
        ));
        if let Some(path) = required_file_path(agent, paths) {
            out.push_str(&format!(
                "    // It does not start until {} exists.\n",
                path.display()
            ));
        }
        out.push_str(&format!(
            "    agent \"{}\" {{\n        {}\n        failure-mode \"open\"\n    }}\n",
            kdl_escape(&agent.name),
            endpoint.kdl()
        ));
    }
    out.push_str("}\n");
    out
}

/// Whether a file is one of the per-agent YAML files earlier versions of
/// `bundle install` wrote. No agent reads them.
pub fn is_legacy_generated_config(content: &str) -> bool {
    content.contains("\nsocket:\n  path: /var/run/zentinel/")
        && content.contains("\nlogging:\n  level: info\n")
}

/// Write a generated file, replacing what is there.
pub fn write_generated(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)
}

fn kdl_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn is_plain(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:=@+,".contains(c))
}

/// Quote an argument for a POSIX shell.
fn shell_quote(s: &str) -> String {
    if is_plain(s) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Quote an argument for a systemd `ExecStart=` line, where `%` and `$` are
/// expanded and whitespace splits words.
fn systemd_quote(s: &str) -> String {
    let escaped = s.replace('%', "%%").replace('$', "$$");
    if is_plain(s) {
        escaped
    } else {
        format!("\"{}\"", escaped.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::lock::{BundleLock, RequiredFile};
    use std::collections::HashMap;

    fn agent(name: &str, transport: Transport, required: Option<(&str, &str)>) -> AgentInfo {
        AgentInfo {
            name: name.to_string(),
            version: "0.4.0".to_string(),
            repository: format!("zentinelproxy/zentinel-agent-{name}"),
            binary_name: format!("zentinel-{name}-agent"),
            precomputed_urls: HashMap::new(),
            platforms: Vec::new(),
            transport,
            required_file: required.map(|(flag, file)| RequiredFile {
                flag: flag.to_string(),
                file: file.to_string(),
            }),
        }
    }

    fn paths(system_wide: bool) -> InstallPaths {
        InstallPaths {
            bin_dir: PathBuf::from("/opt/z/bin"),
            config_dir: PathBuf::from("/opt/z/etc/zentinel/agents"),
            socket_dir: PathBuf::from("/opt/z/run/zentinel"),
            systemd_dir: Some(PathBuf::from("/opt/z/lib/systemd/system")),
            system_wide,
        }
    }

    #[test]
    fn uds_agent_is_started_on_the_socket_the_kdl_names() {
        let waf = agent("waf", Transport::Uds, None);
        let p = paths(false);
        assert_eq!(
            launch_argv(&waf, &p),
            [
                "/opt/z/bin/zentinel-waf-agent",
                "--socket",
                "/opt/z/run/zentinel/waf.sock"
            ]
        );
        let kdl = generate_agents_kdl(std::slice::from_ref(&waf), &p, "26.10_01");
        assert!(
            kdl.contains("unix-socket \"/opt/z/run/zentinel/waf.sock\""),
            "{kdl}"
        );
        let unit = generate_systemd_unit(&waf, &p);
        assert!(
            unit.contains(
                "ExecStart=/opt/z/bin/zentinel-waf-agent --socket /opt/z/run/zentinel/waf.sock\n"
            ),
            "{unit}"
        );
        assert!(!unit.contains("--config"), "{unit}");
    }

    #[test]
    fn grpc_agent_is_started_on_the_port_the_kdl_names() {
        let sec = agent("zentinelsec", Transport::Grpc { port: 50151 }, None);
        let p = paths(true);
        assert_eq!(
            launch_argv(&sec, &p),
            [
                "/opt/z/bin/zentinel-zentinelsec-agent",
                "--grpc-address",
                "127.0.0.1:50151"
            ]
        );
        let kdl = generate_agents_kdl(std::slice::from_ref(&sec), &p, "26.10_01");
        assert!(
            kdl.contains("grpc address=\"http://127.0.0.1:50151\""),
            "{kdl}"
        );
        assert!(!kdl.contains("unix-socket"), "{kdl}");
        let unit = generate_systemd_unit(&sec, &p);
        assert!(
            unit.contains(
                "ExecStart=/opt/z/bin/zentinel-zentinelsec-agent --grpc-address 127.0.0.1:50151\n"
            ),
            "{unit}"
        );
    }

    #[test]
    fn required_file_is_passed_and_gates_the_unit() {
        let lua = agent("lua", Transport::Uds, Some(("--script", "lua.lua")));
        let p = paths(false);
        let argv = launch_argv(&lua, &p);
        assert_eq!(
            &argv[3..],
            ["--script", "/opt/z/etc/zentinel/agents/lua.lua"]
        );
        let unit = generate_systemd_unit(&lua, &p);
        assert!(
            unit.contains("ConditionPathExists=/opt/z/etc/zentinel/agents/lua.lua\n"),
            "{unit}"
        );
        let kdl = generate_agents_kdl(&[lua], &p, "x");
        assert!(kdl.contains("does not start until /opt/z/etc/zentinel/agents/lua.lua exists"));
    }

    #[test]
    fn system_unit_runs_as_the_proxy_user_with_a_preserved_socket_dir() {
        let mut p = paths(true);
        p.socket_dir = PathBuf::from("/run/zentinel-agents");
        let unit = generate_systemd_unit(&agent("waf", Transport::Uds, None), &p);
        for line in [
            "User=zentinel\n",
            "RuntimeDirectory=zentinel-agents\n",
            "RuntimeDirectoryPreserve=yes\n",
            "WantedBy=multi-user.target\n",
            "Before=zentinel.service\n",
        ] {
            assert!(unit.contains(line), "missing {line:?} in\n{unit}");
        }
        // The old unit bound the agent to the proxy and started it after.
        assert!(!unit.contains("BindsTo="));
        assert!(!unit.contains("After=zentinel"));
    }

    /// A user manager cannot switch users, and ProtectHome= hides ~/.local/bin:
    /// the old unit had both and could not start from a user install.
    #[test]
    fn user_unit_has_no_user_switch_and_can_see_home() {
        let unit = generate_systemd_unit(&agent("waf", Transport::Uds, None), &paths(false));
        assert!(!unit.contains("User="), "{unit}");
        assert!(!unit.contains("ProtectHome"), "{unit}");
        assert!(!unit.contains("RuntimeDirectory"), "{unit}");
        assert!(unit.contains("WantedBy=default.target\n"), "{unit}");
    }

    #[test]
    fn arguments_are_quoted_for_shell_systemd_and_kdl() {
        let mut p = paths(false);
        p.bin_dir = PathBuf::from("/opt/my agents/bin");
        p.socket_dir = PathBuf::from("/opt/100%/run");
        let waf = agent("waf", Transport::Uds, None);
        assert_eq!(
            launch_command(&waf, &p),
            "'/opt/my agents/bin/zentinel-waf-agent' --socket '/opt/100%/run/waf.sock'"
        );
        let unit = generate_systemd_unit(&waf, &p);
        assert!(
            unit.contains(
                "ExecStart=\"/opt/my agents/bin/zentinel-waf-agent\" --socket \"/opt/100%%/run/waf.sock\""
            ),
            "{unit}"
        );
        p.socket_dir = PathBuf::from("/opt/a\"b");
        let kdl = generate_agents_kdl(&[waf], &p, "x");
        assert!(kdl.contains(r#"unix-socket "/opt/a\"b/waf.sock""#), "{kdl}");
    }

    #[test]
    fn overlong_socket_path_is_reported() {
        let mut p = paths(false);
        p.socket_dir = PathBuf::from(format!("/{}", "d".repeat(100)));
        let e = Endpoint::for_agent(&agent("waf", Transport::Uds, None), &p);
        assert!(e.problem().is_some());
        let e = Endpoint::for_agent(&agent("waf", Transport::Uds, None), &paths(false));
        assert!(e.problem().is_none());
    }

    /// The KDL written for the whole embedded bundle is read by the proxy's
    /// own config parser, with each agent on the transport and endpoint its
    /// launch command uses.
    #[test]
    fn generated_kdl_for_every_bundled_agent_is_read_by_the_proxy() {
        use zentinel_config::{AgentTransport, Config};

        let lock = BundleLock::embedded().unwrap();
        let agents = lock.agents();
        let p = paths(false);
        let kdl = generate_agents_kdl(&agents, &p, &lock.bundle.version);
        let config = Config::from_kdl(&format!(
            "system {{ worker-threads 1 }}\n\
             listeners {{ listener \"http\" {{ address \"127.0.0.1:18080\"; }} }}\n\
             {kdl}"
        ))
        .unwrap_or_else(|e| panic!("generated KDL rejected: {e:#}\n{kdl}"));
        assert_eq!(config.agents.len(), agents.len());

        for agent in &agents {
            let parsed = config
                .agents
                .iter()
                .find(|a| a.id == agent.name)
                .unwrap_or_else(|| panic!("{} missing from KDL", agent.name));
            let argv = launch_argv(agent, &p);
            match (&agent.transport, &parsed.transport) {
                (Transport::Uds, AgentTransport::UnixSocket { path }) => {
                    assert_eq!(
                        argv[1..3],
                        ["--socket".to_string(), path.display().to_string()]
                    );
                }
                (Transport::Grpc { port }, AgentTransport::Grpc { address, .. }) => {
                    assert_eq!(address, &format!("http://127.0.0.1:{port}"));
                    assert_eq!(
                        argv[1..3],
                        ["--grpc-address".to_string(), format!("127.0.0.1:{port}")]
                    );
                }
                (want, got) => panic!("{}: {want:?} written as {got:?}", agent.name),
            }
        }
    }

    #[test]
    fn legacy_generated_yaml_is_recognised() {
        let old = "# WAF Agent Configuration\n\nsocket:\n  path: /var/run/zentinel/waf.sock\n  mode: 0660\n\nlogging:\n  level: info\n  format: json\n";
        assert!(is_legacy_generated_config(old));
        assert!(!is_legacy_generated_config("settings:\n  enabled: true\n"));
    }
}
