//! Bundle status checking
//!
//! Compares installed agent versions against the lock file.

use crate::bundle::install::{get_installed_version, InstallPaths};
use crate::bundle::lock::{AgentInfo, BundleLock};
use std::fmt;

/// Status of an individual agent
#[derive(Debug, Clone)]
pub struct AgentStatus {
    /// Agent name
    pub name: String,

    /// Expected version from lock file
    pub expected_version: String,

    /// Currently installed version (if any)
    pub installed_version: Option<String>,

    /// Status indicator
    pub status: Status,
}

/// Agent installation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Installed and up to date
    UpToDate,

    /// Installed but different version
    Outdated,

    /// Not installed
    NotInstalled,

    /// Built into the proxy (echo agent)
    BuiltIn,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::UpToDate => write!(f, "up to date"),
            Status::Outdated => write!(f, "outdated"),
            Status::NotInstalled => write!(f, "not installed"),
            Status::BuiltIn => write!(f, "built-in"),
        }
    }
}

/// Overall bundle status
#[derive(Debug)]
pub struct BundleStatus {
    /// Bundle version from lock file
    pub bundle_version: String,

    /// Status of each agent
    pub agents: Vec<AgentStatus>,

    /// Installation paths being checked
    pub paths: InstallPaths,
}

impl BundleStatus {
    /// Check the status of all bundled agents
    pub fn check(lock: &BundleLock, paths: &InstallPaths) -> Self {
        let mut agents = Vec::new();

        for agent_info in lock.agents() {
            let status = check_agent_status(&agent_info, paths);
            agents.push(status);
        }

        // Sort by name for consistent output
        agents.sort_by(|a, b| a.name.cmp(&b.name));

        Self {
            bundle_version: lock.bundle.version.clone(),
            agents,
            paths: paths.clone(),
        }
    }

    /// Check if all agents are installed and up to date
    pub fn is_complete(&self) -> bool {
        self.agents
            .iter()
            .all(|a| a.status == Status::UpToDate || a.status == Status::BuiltIn)
    }

    /// Get agents that need to be installed or updated
    pub fn pending_agents(&self) -> Vec<&AgentStatus> {
        self.agents
            .iter()
            .filter(|a| a.status == Status::NotInstalled || a.status == Status::Outdated)
            .collect()
    }

    /// Get count of each status type
    pub fn summary(&self) -> StatusSummary {
        let mut summary = StatusSummary::default();
        for agent in &self.agents {
            match agent.status {
                Status::UpToDate => summary.up_to_date += 1,
                Status::Outdated => summary.outdated += 1,
                Status::NotInstalled => summary.not_installed += 1,
                Status::BuiltIn => summary.built_in += 1,
            }
        }
        summary.total = self.agents.len();
        summary
    }

    /// Format status for display
    pub fn display(&self) -> String {
        use std::fmt::Write;

        let mut output = String::new();

        writeln!(output, "Zentinel Bundle Status").unwrap();
        writeln!(output, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━").unwrap();
        writeln!(output, "Bundle version: {}", self.bundle_version).unwrap();
        writeln!(output, "Install path:   {}", self.paths.bin_dir.display()).unwrap();
        writeln!(output).unwrap();

        // Header
        writeln!(
            output,
            "{:<15} {:<12} {:<12} Status",
            "Agent", "Installed", "Expected"
        )
        .unwrap();
        writeln!(output, "{}", "─".repeat(55)).unwrap();

        // Agent rows
        for agent in &self.agents {
            let installed = agent.installed_version.as_deref().unwrap_or("-");
            let status_icon = match agent.status {
                Status::UpToDate => "✓",
                Status::Outdated => "↑",
                Status::NotInstalled => "✗",
                Status::BuiltIn => "•",
            };

            writeln!(
                output,
                "{:<15} {:<12} {:<12} {} {}",
                agent.name, installed, agent.expected_version, status_icon, agent.status
            )
            .unwrap();
        }

        // Summary
        let summary = self.summary();
        writeln!(output).unwrap();
        writeln!(
            output,
            "Total: {} | Up to date: {} | Outdated: {} | Not installed: {}",
            summary.total,
            summary.up_to_date + summary.built_in,
            summary.outdated,
            summary.not_installed
        )
        .unwrap();

        output
    }
}

/// Summary counts
#[derive(Debug, Default)]
pub struct StatusSummary {
    pub total: usize,
    pub up_to_date: usize,
    pub outdated: usize,
    pub not_installed: usize,
    pub built_in: usize,
}

/// Check the status of a single agent
fn check_agent_status(agent: &AgentInfo, paths: &InstallPaths) -> AgentStatus {
    let installed_version = get_installed_version(&paths.bin_dir, &agent.binary_name);

    let status = match &installed_version {
        Some(v) if v == &agent.version => Status::UpToDate,
        Some(_) => Status::Outdated,
        None => Status::NotInstalled,
    };

    AgentStatus {
        name: agent.name.clone(),
        expected_version: agent.version.clone(),
        installed_version,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_display() {
        assert_eq!(format!("{}", Status::UpToDate), "up to date");
        assert_eq!(format!("{}", Status::Outdated), "outdated");
        assert_eq!(format!("{}", Status::NotInstalled), "not installed");
        assert_eq!(format!("{}", Status::BuiltIn), "built-in");
    }

    #[test]
    fn test_status_equality() {
        assert_eq!(Status::UpToDate, Status::UpToDate);
        assert_ne!(Status::UpToDate, Status::Outdated);
    }

    #[test]
    fn test_bundle_status_summary() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![
                AgentStatus {
                    name: "waf".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.2.0".to_string()),
                    status: Status::UpToDate,
                },
                AgentStatus {
                    name: "ratelimit".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: None,
                    status: Status::NotInstalled,
                },
            ],
            paths: InstallPaths::user(),
        };

        let summary = status.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.up_to_date, 1);
        assert_eq!(summary.not_installed, 1);
        assert_eq!(summary.outdated, 0);
        assert_eq!(summary.built_in, 0);
    }

    #[test]
    fn test_bundle_status_summary_all_types() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![
                AgentStatus {
                    name: "waf".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.2.0".to_string()),
                    status: Status::UpToDate,
                },
                AgentStatus {
                    name: "ratelimit".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.1.0".to_string()),
                    status: Status::Outdated,
                },
                AgentStatus {
                    name: "denylist".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: None,
                    status: Status::NotInstalled,
                },
                AgentStatus {
                    name: "echo".to_string(),
                    expected_version: "built-in".to_string(),
                    installed_version: Some("built-in".to_string()),
                    status: Status::BuiltIn,
                },
            ],
            paths: InstallPaths::user(),
        };

        let summary = status.summary();
        assert_eq!(summary.total, 4);
        assert_eq!(summary.up_to_date, 1);
        assert_eq!(summary.outdated, 1);
        assert_eq!(summary.not_installed, 1);
        assert_eq!(summary.built_in, 1);
    }

    #[test]
    fn test_is_complete_true() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![
                AgentStatus {
                    name: "waf".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.2.0".to_string()),
                    status: Status::UpToDate,
                },
                AgentStatus {
                    name: "echo".to_string(),
                    expected_version: "built-in".to_string(),
                    installed_version: Some("built-in".to_string()),
                    status: Status::BuiltIn,
                },
            ],
            paths: InstallPaths::user(),
        };

        assert!(status.is_complete());
    }

    #[test]
    fn test_is_complete_false_not_installed() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![AgentStatus {
                name: "waf".to_string(),
                expected_version: "0.2.0".to_string(),
                installed_version: None,
                status: Status::NotInstalled,
            }],
            paths: InstallPaths::user(),
        };

        assert!(!status.is_complete());
    }

    #[test]
    fn test_is_complete_false_outdated() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![AgentStatus {
                name: "waf".to_string(),
                expected_version: "0.2.0".to_string(),
                installed_version: Some("0.1.0".to_string()),
                status: Status::Outdated,
            }],
            paths: InstallPaths::user(),
        };

        assert!(!status.is_complete());
    }

    #[test]
    fn test_pending_agents() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![
                AgentStatus {
                    name: "waf".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.2.0".to_string()),
                    status: Status::UpToDate,
                },
                AgentStatus {
                    name: "ratelimit".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.1.0".to_string()),
                    status: Status::Outdated,
                },
                AgentStatus {
                    name: "denylist".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: None,
                    status: Status::NotInstalled,
                },
            ],
            paths: InstallPaths::user(),
        };

        let pending = status.pending_agents();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|a| a.name == "ratelimit"));
        assert!(pending.iter().any(|a| a.name == "denylist"));
        assert!(!pending.iter().any(|a| a.name == "waf"));
    }

    #[test]
    fn test_pending_agents_empty() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![AgentStatus {
                name: "waf".to_string(),
                expected_version: "0.2.0".to_string(),
                installed_version: Some("0.2.0".to_string()),
                status: Status::UpToDate,
            }],
            paths: InstallPaths::user(),
        };

        assert!(status.pending_agents().is_empty());
    }

    #[test]
    fn test_display_output_contains_header() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![],
            paths: InstallPaths::user(),
        };

        let output = status.display();
        assert!(output.contains("Zentinel Bundle Status"));
        assert!(output.contains("Bundle version: 26.01_1"));
    }

    #[test]
    fn test_display_output_contains_agents() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![
                AgentStatus {
                    name: "waf".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.2.0".to_string()),
                    status: Status::UpToDate,
                },
                AgentStatus {
                    name: "ratelimit".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: None,
                    status: Status::NotInstalled,
                },
            ],
            paths: InstallPaths::user(),
        };

        let output = status.display();
        assert!(output.contains("waf"));
        assert!(output.contains("ratelimit"));
        assert!(output.contains("0.2.0"));
        assert!(output.contains("✓")); // up to date icon
        assert!(output.contains("✗")); // not installed icon
    }

    #[test]
    fn test_display_output_contains_summary() {
        let status = BundleStatus {
            bundle_version: "26.01_1".to_string(),
            agents: vec![
                AgentStatus {
                    name: "waf".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: Some("0.2.0".to_string()),
                    status: Status::UpToDate,
                },
                AgentStatus {
                    name: "ratelimit".to_string(),
                    expected_version: "0.2.0".to_string(),
                    installed_version: None,
                    status: Status::NotInstalled,
                },
            ],
            paths: InstallPaths::user(),
        };

        let output = status.display();
        assert!(output.contains("Total: 2"));
        assert!(output.contains("Up to date: 1"));
        assert!(output.contains("Not installed: 1"));
    }

    #[test]
    fn test_agent_status_fields() {
        let status = AgentStatus {
            name: "test".to_string(),
            expected_version: "1.0.0".to_string(),
            installed_version: Some("0.9.0".to_string()),
            status: Status::Outdated,
        };

        assert_eq!(status.name, "test");
        assert_eq!(status.expected_version, "1.0.0");
        assert_eq!(status.installed_version, Some("0.9.0".to_string()));
        assert_eq!(status.status, Status::Outdated);
    }

    #[test]
    fn test_status_summary_default() {
        let summary = StatusSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.up_to_date, 0);
        assert_eq!(summary.outdated, 0);
        assert_eq!(summary.not_installed, 0);
        assert_eq!(summary.built_in, 0);
    }
}
