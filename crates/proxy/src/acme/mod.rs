//! ACME automatic certificate management
//!
//! Provides zero-config TLS via Let's Encrypt and compatible CAs.
//!
//! # Features
//!
//! - Automatic certificate issuance and renewal
//! - HTTP-01 challenge handling
//! - DNS-01 challenge support for wildcard certificates
//! - Modular DNS provider system (Hetzner, webhook)
//! - Persistent storage for certificates and account credentials
//! - Background renewal scheduler
//!
//! # Architecture
//!
//! The ACME module consists of five main components:
//!
//! - [`AcmeClient`] - Wrapper around `instant-acme` for ACME protocol operations
//! - [`CertificateStorage`] - Persistent storage for certificates and account keys
//! - [`ChallengeManager`] - Manages pending HTTP-01 challenges for serving
//! - [`dns`] - DNS-01 challenge support with pluggable providers
//! - [`RenewalScheduler`] - Background task for checking and renewing certificates
//!
//! # Example (HTTP-01)
//!
//! ```kdl
//! listener "https" {
//!     address "0.0.0.0:443"
//!     protocol "https"
//!
//!     tls {
//!         acme {
//!             email "admin@example.com"
//!             domains "example.com" "www.example.com"
//!             staging false
//!             storage "/var/lib/zentinel/acme"
//!             renew-before-days 30
//!         }
//!     }
//! }
//! ```
//!
//! # Example (DNS-01 for Wildcards)
//!
//! ```kdl
//! listener "https" {
//!     address "0.0.0.0:443"
//!     protocol "https"
//!
//!     tls {
//!         acme {
//!             email "admin@example.com"
//!             domains "example.com" "*.example.com"
//!             challenge-type "dns-01"
//!
//!             dns-provider {
//!                 type "hetzner"
//!                 credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
//!                 api-timeout-secs 30
//!
//!                 propagation {
//!                     initial-delay-secs 10
//!                     check-interval-secs 5
//!                     timeout-secs 120
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # Challenge Flow (HTTP-01)
//!
//! When a certificate needs to be obtained or renewed:
//!
//! 1. [`AcmeClient`] creates a new order with the ACME server
//! 2. For each domain, the ACME server provides a challenge token
//! 3. [`ChallengeManager`] registers the token and key authorization
//! 4. The ACME server validates by requesting `/.well-known/acme-challenge/<token>`
//! 5. Zentinel's request filter intercepts and returns the key authorization
//! 6. Once validated, [`AcmeClient`] finalizes the order and receives the certificate
//! 7. [`CertificateStorage`] persists the certificate and triggers TLS reload
//!
//! # Challenge Flow (DNS-01)
//!
//! For wildcard certificates or when HTTP-01 is not feasible:
//!
//! 1. [`AcmeClient`] creates a new order with DNS-01 challenges
//! 2. For each domain, [`dns::Dns01ChallengeManager`] creates TXT records via the DNS provider
//! 3. [`dns::PropagationChecker`] waits for DNS propagation
//! 4. The ACME server validates by querying `_acme-challenge.{domain}` TXT records
//! 5. Once validated, [`AcmeClient`] finalizes the order and receives the certificate
//! 6. DNS records are cleaned up, certificate is persisted

mod challenge;
pub mod challenge_server;
mod client;
pub mod dns;
mod error;
mod scheduler;
mod storage;

pub use challenge::ChallengeManager;
pub use client::AcmeClient;
pub use error::AcmeError;
pub use scheduler::RenewalScheduler;
pub use storage::CertificateStorage;
