//! Configuration validation
//!
//! This module provides comprehensive validation for Zentinel configurations,
//! including network connectivity, certificate validation, and best practices linting.

pub mod agents;
pub mod certs;
pub mod lint;
pub mod network;

use std::fmt;

/// Validation error category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Schema/syntax error
    Schema,
    /// Network connectivity issue
    Network,
    /// Certificate issue
    Certificate,
    /// Agent connectivity issue
    Agent,
    /// Configuration logic error
    Logic,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Schema => write!(f, "Schema"),
            ErrorCategory::Network => write!(f, "Network"),
            ErrorCategory::Certificate => write!(f, "Certificate"),
            ErrorCategory::Agent => write!(f, "Agent"),
            ErrorCategory::Logic => write!(f, "Logic"),
        }
    }
}

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub category: ErrorCategory,
    pub message: String,
}

impl ValidationError {
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.message)
    }
}

/// Validation warning
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub message: String,
}

impl ValidationWarning {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Validation result containing errors and warnings
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    /// Create a new empty validation result
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }

    /// Merge another validation result into this one
    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }

    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Check if there are any warnings
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// Validation options
#[derive(Debug, Clone, Default)]
pub struct ValidationOpts {
    pub skip_network: bool,
    pub skip_agents: bool,
    pub skip_certs: bool,
}
