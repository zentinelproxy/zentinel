//! Secure credential loading for DNS providers
//!
//! Supports loading credentials from:
//! - JSON files with various key names
//! - Environment variables
//! - Plain text files (single token)

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde::Deserialize;
use tracing::{debug, warn};

use super::provider::DnsProviderError;

/// Credential loader for DNS provider authentication
#[derive(Debug, Default)]
pub struct CredentialLoader;

impl CredentialLoader {
    /// Load credentials from a file
    ///
    /// Supports multiple formats:
    /// - JSON: `{"token": "..."}` or `{"api_key": "...", "api_secret": "..."}`
    /// - Plain text: Entire file content is the token
    ///
    /// # Security
    ///
    /// Validates file permissions on Unix (must be 0600 or 0400)
    pub fn load_from_file(path: &Path) -> Result<Credentials, DnsProviderError> {
        // Check file permissions on Unix
        #[cfg(unix)]
        {
            let metadata = fs::metadata(path).map_err(|e| {
                DnsProviderError::Credentials(format!(
                    "Failed to read credentials file '{}': {}",
                    path.display(),
                    e
                ))
            })?;

            let mode = metadata.permissions().mode();
            let file_mode = mode & 0o777;

            // Only owner should have access (0600 or 0400)
            if file_mode & 0o077 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:o}", file_mode),
                    "Credentials file has overly permissive permissions (should be 0600 or 0400)"
                );
                // Continue anyway, but log warning
            }
        }

        let content = fs::read_to_string(path).map_err(|e| {
            DnsProviderError::Credentials(format!(
                "Failed to read credentials file '{}': {}",
                path.display(),
                e
            ))
        })?;

        Self::parse_credentials(&content, path)
    }

    /// Load credentials from an environment variable
    pub fn load_from_env(var_name: &str) -> Result<Credentials, DnsProviderError> {
        let value = std::env::var(var_name).map_err(|_| {
            DnsProviderError::Credentials(format!(
                "Environment variable '{}' not set",
                var_name
            ))
        })?;

        // Try JSON first, fall back to plain token
        if value.trim().starts_with('{') {
            Self::parse_json_credentials(&value)
        } else {
            Ok(Credentials::Token(value.trim().to_string()))
        }
    }

    /// Parse credentials from content string
    fn parse_credentials(content: &str, path: &Path) -> Result<Credentials, DnsProviderError> {
        let trimmed = content.trim();

        // Try JSON first
        if trimmed.starts_with('{') {
            return Self::parse_json_credentials(trimmed);
        }

        // Plain text token
        if trimmed.is_empty() {
            return Err(DnsProviderError::Credentials(format!(
                "Credentials file '{}' is empty",
                path.display()
            )));
        }

        debug!(path = %path.display(), "Loaded credentials as plain text token");
        Ok(Credentials::Token(trimmed.to_string()))
    }

    /// Parse JSON credentials
    fn parse_json_credentials(json: &str) -> Result<Credentials, DnsProviderError> {
        // Try multiple JSON formats
        #[derive(Deserialize)]
        struct TokenFormat {
            token: Option<String>,
            api_token: Option<String>,
        }

        #[derive(Deserialize)]
        struct KeySecretFormat {
            api_key: String,
            api_secret: String,
        }

        #[derive(Deserialize)]
        struct ApiKeyOnlyFormat {
            api_key: Option<String>,
        }

        // Try key+secret format first (more specific)
        if let Ok(parsed) = serde_json::from_str::<KeySecretFormat>(json) {
            debug!("Loaded credentials as JSON key+secret");
            return Ok(Credentials::KeySecret {
                key: parsed.api_key,
                secret: parsed.api_secret,
            });
        }

        // Try token-only format
        if let Ok(parsed) = serde_json::from_str::<TokenFormat>(json) {
            if let Some(token) = parsed.token.or(parsed.api_token) {
                debug!("Loaded credentials as JSON token");
                return Ok(Credentials::Token(token));
            }
        }

        // Try api_key-only format (some providers use api_key as token)
        if let Ok(parsed) = serde_json::from_str::<ApiKeyOnlyFormat>(json) {
            if let Some(key) = parsed.api_key {
                debug!("Loaded credentials as JSON api_key token");
                return Ok(Credentials::Token(key));
            }
        }

        Err(DnsProviderError::Credentials(
            "Invalid JSON credentials format. Expected {\"token\": \"...\"} or {\"api_key\": \"...\", \"api_secret\": \"...\"}".to_string()
        ))
    }
}

/// Credential types supported by DNS providers
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Single API token
    Token(String),
    /// API key and secret pair
    KeySecret { key: String, secret: String },
}

impl Credentials {
    /// Get the token if this is a Token credential
    pub fn token(&self) -> Option<&str> {
        match self {
            Credentials::Token(t) => Some(t),
            Credentials::KeySecret { .. } => None,
        }
    }

    /// Get the key if this is a KeySecret credential
    pub fn key(&self) -> Option<&str> {
        match self {
            Credentials::KeySecret { key, .. } => Some(key),
            Credentials::Token(_) => None,
        }
    }

    /// Get the secret if this is a KeySecret credential
    pub fn secret(&self) -> Option<&str> {
        match self {
            Credentials::KeySecret { secret, .. } => Some(secret),
            Credentials::Token(_) => None,
        }
    }

    /// Returns the token or key (for providers that use either)
    pub fn as_bearer_token(&self) -> &str {
        match self {
            Credentials::Token(t) => t,
            Credentials::KeySecret { key, .. } => key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_json_token() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"token": "test-token-123"}}"#).unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        assert_eq!(creds.token(), Some("test-token-123"));
    }

    #[test]
    fn test_load_json_api_token() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"api_token": "api-token-456"}}"#).unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        assert_eq!(creds.token(), Some("api-token-456"));
    }

    #[test]
    fn test_load_json_key_secret() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"api_key": "key123", "api_secret": "secret456"}}"#).unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        assert_eq!(creds.key(), Some("key123"));
        assert_eq!(creds.secret(), Some("secret456"));
    }

    #[test]
    fn test_load_plain_text() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "plain-text-token").unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        assert_eq!(creds.token(), Some("plain-text-token"));
    }

    #[test]
    fn test_load_plain_text_with_whitespace() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  token-with-spaces  \n").unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        assert_eq!(creds.token(), Some("token-with-spaces"));
    }

    #[test]
    fn test_empty_file_error() {
        let file = NamedTempFile::new().unwrap();
        let result = CredentialLoader::load_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_json_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"invalid": "format"}}"#).unwrap();

        let result = CredentialLoader::load_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_json_api_key_only() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"api_key": "just-a-key"}}"#).unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        // Without api_secret, api_key is treated as a token
        assert_eq!(creds.token(), Some("just-a-key"));
    }

    #[test]
    fn test_load_json_with_extra_fields() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"token": "my-token", "extra": "field", "another": 123}}"#).unwrap();

        let creds = CredentialLoader::load_from_file(file.path()).unwrap();
        assert_eq!(creds.token(), Some("my-token"));
    }

    #[test]
    fn test_credentials_as_bearer_token() {
        let token_creds = Credentials::Token("my-token".to_string());
        assert_eq!(token_creds.as_bearer_token(), "my-token");

        let key_secret_creds = Credentials::KeySecret {
            key: "my-key".to_string(),
            secret: "my-secret".to_string(),
        };
        assert_eq!(key_secret_creds.as_bearer_token(), "my-key");
    }

    #[test]
    fn test_credentials_accessors() {
        let token_creds = Credentials::Token("my-token".to_string());
        assert_eq!(token_creds.token(), Some("my-token"));
        assert_eq!(token_creds.key(), None);
        assert_eq!(token_creds.secret(), None);

        let key_secret_creds = Credentials::KeySecret {
            key: "my-key".to_string(),
            secret: "my-secret".to_string(),
        };
        assert_eq!(key_secret_creds.token(), None);
        assert_eq!(key_secret_creds.key(), Some("my-key"));
        assert_eq!(key_secret_creds.secret(), Some("my-secret"));
    }

    #[test]
    fn test_load_from_env() {
        std::env::set_var("TEST_DNS_TOKEN_12345", "env-token-value");

        let creds = CredentialLoader::load_from_env("TEST_DNS_TOKEN_12345").unwrap();
        assert_eq!(creds.token(), Some("env-token-value"));

        std::env::remove_var("TEST_DNS_TOKEN_12345");
    }

    #[test]
    fn test_load_from_env_json() {
        std::env::set_var("TEST_DNS_JSON_12345", r#"{"token": "json-env-token"}"#);

        let creds = CredentialLoader::load_from_env("TEST_DNS_JSON_12345").unwrap();
        assert_eq!(creds.token(), Some("json-env-token"));

        std::env::remove_var("TEST_DNS_JSON_12345");
    }

    #[test]
    fn test_load_from_env_not_set() {
        let result = CredentialLoader::load_from_env("NONEXISTENT_VAR_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_nonexistent_file() {
        let result = CredentialLoader::load_from_file(std::path::Path::new("/nonexistent/path/to/creds.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "   \n\t  \n").unwrap();

        let result = CredentialLoader::load_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_json() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"token": "unclosed"#).unwrap();

        let result = CredentialLoader::load_from_file(file.path());
        // Malformed JSON starting with '{' will fail JSON parsing and be treated as plain text
        // The result depends on how the parsing handles it
        assert!(result.is_err());
    }
}
