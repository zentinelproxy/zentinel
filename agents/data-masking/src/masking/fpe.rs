//! Format-preserving encryption using AES-based cipher.
//!
//! This implements a simplified format-preserving encryption scheme.
//! For production use with regulatory requirements, consider using
//! a certified FF1 implementation.

use crate::config::{FpeAlphabet, FpeConfig};
use crate::errors::MaskingError;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

/// Format-preserving encryption cipher.
pub struct FpeCipher {
    key: [u8; 32],
}

impl FpeCipher {
    /// Create a new FPE cipher from configuration.
    pub fn from_config(config: &FpeConfig) -> Result<Self, MaskingError> {
        // Try to get key from config or environment
        let key_hex = config
            .key
            .clone()
            .or_else(|| std::env::var(&config.key_env).ok())
            .ok_or(MaskingError::FpeNotConfigured)?;

        let key_bytes = hex_decode(&key_hex)
            .map_err(|_| MaskingError::FpeError("invalid key hex".to_string()))?;

        if key_bytes.len() != 32 {
            return Err(MaskingError::FpeError(
                "key must be 32 bytes (64 hex chars)".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        Ok(Self { key })
    }

    /// Create cipher with raw key bytes.
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Encrypt a value while preserving its format.
    pub fn encrypt(
        &self,
        plaintext: &str,
        alphabet: &FpeAlphabet,
        tweak: &str,
    ) -> Result<String, MaskingError> {
        self.transform(plaintext, alphabet, tweak, true)
    }

    /// Decrypt a value.
    pub fn decrypt(
        &self,
        ciphertext: &str,
        alphabet: &FpeAlphabet,
        tweak: &str,
    ) -> Result<String, MaskingError> {
        self.transform(ciphertext, alphabet, tweak, false)
    }

    /// Transform using Feistel network with AES rounds.
    fn transform(
        &self,
        input: &str,
        alphabet: &FpeAlphabet,
        tweak: &str,
        encrypt: bool,
    ) -> Result<String, MaskingError> {
        let chars: Vec<char> = alphabet.chars().chars().collect();
        let radix = chars.len();

        // Convert input to indices
        let mut indices: Vec<usize> = input
            .chars()
            .filter_map(|c| chars.iter().position(|&ch| ch == c))
            .collect();

        if indices.len() != input.chars().filter(|c| chars.contains(c)).count() {
            // Some characters not in alphabet - preserve them
            return self.transform_with_preservation(input, alphabet, tweak, encrypt);
        }

        if indices.is_empty() {
            return Ok(input.to_string());
        }

        // Use balanced Feistel network
        let n = indices.len();
        let half = n / 2;
        let rounds = 10;

        let round_range: Box<dyn Iterator<Item = usize>> = if encrypt {
            Box::new(0..rounds)
        } else {
            Box::new((0..rounds).rev())
        };

        for round in round_range {
            let (left, right) = indices.split_at_mut(half);

            // Generate round key
            let round_key = self.generate_round_key(tweak, round, right, radix);

            // Apply Feistel function
            for (i, l) in left.iter_mut().enumerate() {
                let f = round_key[i % round_key.len()] as usize;
                if encrypt {
                    *l = (*l + f) % radix;
                } else {
                    *l = (*l + radix - (f % radix)) % radix;
                }
            }

            // Swap halves (except last round for encryption, first for decryption)
            if (encrypt && round < rounds - 1) || (!encrypt && round > 0) {
                let temp: Vec<usize> = left.to_vec();
                left.copy_from_slice(&right[..half.min(right.len())]);
                right[..temp.len()].copy_from_slice(&temp);
            }
        }

        // Convert indices back to characters
        let result: String = indices.iter().map(|&i| chars[i]).collect();
        Ok(result)
    }

    /// Transform while preserving characters not in alphabet.
    fn transform_with_preservation(
        &self,
        input: &str,
        alphabet: &FpeAlphabet,
        tweak: &str,
        encrypt: bool,
    ) -> Result<String, MaskingError> {
        let chars: Vec<char> = alphabet.chars().chars().collect();

        // Extract only alphabet characters
        let alphabet_chars: String = input.chars().filter(|c| chars.contains(c)).collect();

        if alphabet_chars.is_empty() {
            return Ok(input.to_string());
        }

        // Transform the alphabet characters
        let transformed = self.transform(&alphabet_chars, alphabet, tweak, encrypt)?;
        let mut transformed_iter = transformed.chars();

        // Reconstruct with preserved characters
        let result: String = input
            .chars()
            .map(|c| {
                if chars.contains(&c) {
                    transformed_iter.next().unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();

        Ok(result)
    }

    /// Generate a round key using AES and SHA-256.
    fn generate_round_key(
        &self,
        tweak: &str,
        round: usize,
        data: &[usize],
        radix: usize,
    ) -> Vec<u8> {
        // Build input for key derivation
        let mut hasher = Sha256::new();
        hasher.update(self.key);
        hasher.update(tweak.as_bytes());
        hasher.update((round as u64).to_le_bytes());

        // Include current state
        for &d in data {
            hasher.update((d as u64).to_le_bytes());
        }
        hasher.update((radix as u64).to_le_bytes());

        let hash = hasher.finalize();

        // Use AES to expand
        let cipher = Aes256::new_from_slice(&self.key).expect("valid key length");
        let mut block = aes::Block::default();
        block.copy_from_slice(&hash[..16]);
        cipher.encrypt_block(&mut block);

        block.to_vec()
    }
}

/// Decode hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn test_fpe_roundtrip_digits() {
        let cipher = FpeCipher::new(&test_key());
        let plaintext = "4111111111111111";

        let encrypted = cipher
            .encrypt(plaintext, &FpeAlphabet::Digits, "tweak")
            .unwrap();

        // Encrypted should be same length and all digits
        assert_eq!(encrypted.len(), plaintext.len());
        assert!(encrypted.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(encrypted, plaintext);

        let decrypted = cipher
            .decrypt(&encrypted, &FpeAlphabet::Digits, "tweak")
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_fpe_preserves_format() {
        let cipher = FpeCipher::new(&test_key());
        let plaintext = "123456789"; // SSN without dashes (just digits)

        let encrypted = cipher
            .encrypt(plaintext, &FpeAlphabet::Ssn, "tweak")
            .unwrap();

        // Should preserve length and be all digits
        assert_eq!(encrypted.len(), plaintext.len());
        assert!(encrypted.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(encrypted, plaintext);

        let decrypted = cipher
            .decrypt(&encrypted, &FpeAlphabet::Ssn, "tweak")
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_fpe_different_tweaks() {
        let cipher = FpeCipher::new(&test_key());
        let plaintext = "1234567890";

        let encrypted1 = cipher
            .encrypt(plaintext, &FpeAlphabet::Digits, "tweak1")
            .unwrap();
        let encrypted2 = cipher
            .encrypt(plaintext, &FpeAlphabet::Digits, "tweak2")
            .unwrap();

        // Different tweaks should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_fpe_alphanumeric() {
        let cipher = FpeCipher::new(&test_key());
        let plaintext = "ABC123xyz";

        let encrypted = cipher
            .encrypt(plaintext, &FpeAlphabet::Alphanumeric, "tweak")
            .unwrap();

        assert_eq!(encrypted.len(), plaintext.len());
        assert!(encrypted.chars().all(|c| c.is_ascii_alphanumeric()));

        let decrypted = cipher
            .decrypt(&encrypted, &FpeAlphabet::Alphanumeric, "tweak")
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
