//! Kubernetes Gateway API controller for Zentinel proxy.
//!
//! This crate implements a Kubernetes controller that watches Gateway API
//! resources (GatewayClass, Gateway, HTTPRoute, ReferenceGrant) and translates
//! them into Zentinel proxy configuration.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │             Kubernetes API Server                 │
//! │  GatewayClass  Gateway  HTTPRoute  ReferenceGrant │
//! └──────────┬───────────────────────────────────────┘
//!            │ watch/reconcile
//! ┌──────────▼───────────────────────────────────────┐
//! │           zentinel-gateway controller             │
//! │  ┌─────────────┐  ┌───────────┐  ┌────────────┐ │
//! │  │ GatewayClass│  │  Gateway  │  │  HTTPRoute  │ │
//! │  │ Reconciler  │  │ Reconciler│  │  Reconciler │ │
//! │  └─────────────┘  └───────────┘  └────────────┘ │
//! │           │                                      │
//! │  ┌────────▼──────────────────────────────────┐   │
//! │  │         Config Translator                  │   │
//! │  │  Gateway API → zentinel_config::Config     │   │
//! │  └────────┬──────────────────────────────────┘   │
//! └───────────┼──────────────────────────────────────┘
//!             │ ArcSwap
//! ┌───────────▼──────────────────────────────────────┐
//! │           Zentinel Proxy (data plane)             │
//! └──────────────────────────────────────────────────┘
//! ```

pub mod controller;
pub mod error;
pub mod reconcilers;
pub mod tls;
pub mod translator;

pub use controller::GatewayController;
pub use error::GatewayError;
pub use tls::SecretCertificateManager;
