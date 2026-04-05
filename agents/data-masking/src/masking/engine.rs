//! Core masking engine.

use crate::config::{DataMaskingConfig, Direction, HashAlgorithm, MaskingAction};
use crate::errors::{MaskingError, MaskingResult};
use crate::masking::{CompiledPatterns, FpeCipher};
use crate::parsers::get_parser;
use crate::store::TokenStore;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Direction of masking operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskDirection {
    /// Tokenize/encrypt (request direction).
    Mask,
    /// Detokenize/decrypt (response direction).
    Unmask,
}

/// Core masking engine.
pub struct MaskingEngine {
    config: DataMaskingConfig,
    store: Arc<dyn TokenStore>,
    fpe_cipher: Option<FpeCipher>,
    patterns: CompiledPatterns,
}

impl MaskingEngine {
    /// Create a new masking engine.
    pub fn new(config: DataMaskingConfig, store: Arc<dyn TokenStore>) -> MaskingResult<Self> {
        // Initialize FPE cipher if configured
        let fpe_cipher = if config.fpe.key.is_some() || std::env::var(&config.fpe.key_env).is_ok() {
            Some(FpeCipher::from_config(&config.fpe)?)
        } else {
            None
        };

        // Compile patterns
        let patterns = CompiledPatterns::from_config(&config.patterns)?;

        Ok(Self {
            config,
            store,
            fpe_cipher,
            patterns,
        })
    }

    /// Get reference to the token store.
    pub fn store(&self) -> &Arc<dyn TokenStore> {
        &self.store
    }

    /// Mask request body (tokenize/encrypt sensitive fields).
    pub async fn mask_request_body(
        &self,
        correlation_id: &str,
        body: &[u8],
        content_type: &str,
    ) -> MaskingResult<Vec<u8>> {
        self.process_body(
            correlation_id,
            body,
            content_type,
            Direction::Request,
            MaskDirection::Mask,
        )
        .await
    }

    /// Unmask response body (detokenize/decrypt).
    pub async fn unmask_response_body(
        &self,
        correlation_id: &str,
        body: &[u8],
        content_type: &str,
    ) -> MaskingResult<Vec<u8>> {
        self.process_body(
            correlation_id,
            body,
            content_type,
            Direction::Response,
            MaskDirection::Unmask,
        )
        .await
    }

    /// Process body content.
    async fn process_body(
        &self,
        correlation_id: &str,
        body: &[u8],
        content_type: &str,
        direction: Direction,
        mask_direction: MaskDirection,
    ) -> MaskingResult<Vec<u8>> {
        // Get appropriate parser
        let parser = get_parser(content_type)?;
        let mut accessor = parser.parse(body)?;

        // Apply configured field rules
        for rule in &self.config.fields {
            let applies = match direction {
                Direction::Request => rule.direction.applies_to_request(),
                Direction::Response => rule.direction.applies_to_response(),
                Direction::Both => true,
            };

            if !applies {
                continue;
            }

            // Find matching paths
            let paths = accessor.find_paths(&rule.path);
            for path in paths {
                if let Some(value) = accessor.get(&path) {
                    let processed = self
                        .apply_action(correlation_id, &value, &rule.action, mask_direction)
                        .await?;
                    accessor.set(&path, processed)?;
                }
            }
        }

        // Apply pattern detection (only on mask direction)
        if mask_direction == MaskDirection::Mask {
            for (path, value) in accessor.all_values() {
                if let Some(action) = self.patterns.detect(&value) {
                    let processed = self
                        .apply_action(correlation_id, &value, action, mask_direction)
                        .await?;
                    accessor.set(&path, processed)?;
                }
            }
        }

        // Serialize back
        parser.serialize(accessor.as_ref())
    }

    /// Apply a masking action to a value.
    pub async fn apply_action(
        &self,
        correlation_id: &str,
        value: &str,
        action: &MaskingAction,
        direction: MaskDirection,
    ) -> MaskingResult<String> {
        match (action, direction) {
            // Tokenization
            (MaskingAction::Tokenize { format }, MaskDirection::Mask) => self
                .store
                .tokenize(correlation_id, value, format)
                .await
                .map_err(MaskingError::Store),
            (MaskingAction::Tokenize { .. }, MaskDirection::Unmask) => self
                .store
                .detokenize(correlation_id, value)
                .await
                .map_err(MaskingError::Store)?
                .ok_or_else(|| MaskingError::TokenNotFound(value.to_string())),

            // Format-preserving encryption
            (MaskingAction::Fpe { alphabet }, MaskDirection::Mask) => {
                let cipher = self
                    .fpe_cipher
                    .as_ref()
                    .ok_or(MaskingError::FpeNotConfigured)?;
                cipher.encrypt(value, alphabet, correlation_id)
            }
            (MaskingAction::Fpe { alphabet }, MaskDirection::Unmask) => {
                let cipher = self
                    .fpe_cipher
                    .as_ref()
                    .ok_or(MaskingError::FpeNotConfigured)?;
                cipher.decrypt(value, alphabet, correlation_id)
            }

            // Character masking (irreversible)
            (
                MaskingAction::Mask {
                    char: mask_char,
                    preserve_start,
                    preserve_end,
                },
                MaskDirection::Mask,
            ) => Ok(apply_char_mask(
                value,
                *mask_char,
                *preserve_start,
                *preserve_end,
            )),
            (MaskingAction::Mask { .. }, MaskDirection::Unmask) => {
                // Cannot reverse, return as-is
                Ok(value.to_string())
            }

            // Redaction (irreversible)
            (MaskingAction::Redact { replacement }, MaskDirection::Mask) => Ok(replacement.clone()),
            (MaskingAction::Redact { .. }, MaskDirection::Unmask) => Ok(value.to_string()),

            // Hashing (irreversible)
            (
                MaskingAction::Hash {
                    algorithm,
                    truncate,
                },
                MaskDirection::Mask,
            ) => Ok(compute_hash(value, algorithm, *truncate)),
            (MaskingAction::Hash { .. }, MaskDirection::Unmask) => Ok(value.to_string()),
        }
    }

    /// Apply header masking action.
    pub async fn apply_header_action(
        &self,
        correlation_id: &str,
        value: &str,
        action: &MaskingAction,
    ) -> MaskingResult<String> {
        self.apply_action(correlation_id, value, action, MaskDirection::Mask)
            .await
    }
}

/// Apply character masking while preserving start and end characters.
fn apply_char_mask(
    value: &str,
    mask_char: char,
    preserve_start: usize,
    preserve_end: usize,
) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();

    if preserve_start + preserve_end >= len {
        return value.to_string();
    }

    let mut result = String::with_capacity(len);

    for (i, c) in chars.iter().enumerate() {
        if i < preserve_start || i >= len - preserve_end {
            result.push(*c);
        } else {
            result.push(mask_char);
        }
    }

    result
}

/// Compute hash of value.
fn compute_hash(value: &str, algorithm: &HashAlgorithm, truncate: usize) -> String {
    let hash = match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            let digest = hasher.finalize();
            digest.iter().fold(String::with_capacity(64), |mut acc, byte| {
                use std::fmt::Write;
                write!(acc, "{byte:02x}").expect("write to String cannot fail");
                acc
            })
        }
    };

    if truncate > 0 && truncate < hash.len() {
        hash[..truncate].to_string()
    } else {
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_char_mask() {
        assert_eq!(
            apply_char_mask("4111111111111111", '*', 4, 4),
            "4111********1111"
        );
        assert_eq!(apply_char_mask("123-45-6789", '*', 0, 4), "*******6789");
        assert_eq!(
            apply_char_mask("test@example.com", '*', 2, 0),
            "te**************"
        );
    }

    #[test]
    fn test_char_mask_short_value() {
        // If preserve counts exceed length, return unchanged
        assert_eq!(apply_char_mask("abc", '*', 2, 2), "abc");
    }

    #[test]
    fn test_hash() {
        let hash = compute_hash("test", &HashAlgorithm::Sha256, 0);
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars

        let truncated = compute_hash("test", &HashAlgorithm::Sha256, 8);
        assert_eq!(truncated.len(), 8);
    }
}
