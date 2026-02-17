//! DNS-01 challenge support for ACME
//!
//! This module provides DNS-01 challenge handling for wildcard certificates
//! and domains where HTTP-01 is not feasible.
//!
//! # Architecture
//!
//! - [`DnsProvider`] - Trait for DNS provider implementations
//! - [`Dns01ChallengeManager`] - Orchestrates DNS-01 challenge flow
//! - [`PropagationChecker`] - Verifies DNS propagation before validation
//! - [`CredentialLoader`] - Secure loading of provider credentials
//!
//! # Providers
//!
//! - [`HetznerProvider`] - Hetzner DNS API
//! - [`WebhookProvider`] - Generic webhook for custom DNS providers
//!
//! # Example
//!
//! ```kdl
//! acme {
//!     email "admin@example.com"
//!     domains "example.com" "*.example.com"
//!     challenge-type "dns-01"
//!
//!     dns-provider {
//!         type "hetzner"
//!         credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
//!         api-timeout-secs 30
//!
//!         propagation {
//!             initial-delay-secs 10
//!             check-interval-secs 5
//!             timeout-secs 120
//!         }
//!     }
//! }
//! ```

pub mod challenge;
mod credentials;
mod propagation;
mod provider;
mod providers;

pub use challenge::{create_challenge_info, Dns01ChallengeInfo, Dns01ChallengeManager};
pub use credentials::CredentialLoader;
pub use propagation::{PropagationChecker, PropagationConfig};
pub use provider::{DnsProvider, DnsProviderError, DnsResult};
pub use providers::{create_provider, HetznerProvider, WebhookProvider};
