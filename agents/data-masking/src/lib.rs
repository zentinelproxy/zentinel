//! Data Masking Agent for Zentinel
//!
//! This agent provides PII protection capabilities:
//! - Reversible tokenization (request-scoped)
//! - Format-preserving encryption (FF1)
//! - Pattern-based detection and masking
//! - Support for JSON, XML, and form-urlencoded content

pub mod buffer;
pub mod config;
pub mod errors;
pub mod handler;
pub mod masking;
pub mod parsers;
pub mod store;

pub use config::DataMaskingConfig;
pub use errors::{MaskingError, MaskingResult};
pub use handler::DataMaskingAgent;
