//! TinyFlake: Operator-friendly Trace ID Generation
//!
//! TinyFlake is Sentinel's default trace ID format, designed for operators who need to
//! copy, paste, and correlate request IDs across logs, dashboards, and support tickets.
//!
//! # Format
//!
//! ```text
//! k7BxR3nVp2Ym
//! └──┘└───────┘
//!  3ch   8ch
//!  time  random
//! ```
//!
//! - **11 characters total** (vs 36 for UUID)
//! - **Base58 encoded** (excludes confusing chars: `0`, `O`, `I`, `l`)
//! - **Time-prefixed** for chronological sorting in logs
//! - **No dashes** for easy double-click selection in terminals
//!
//! # Comparison with Snowflake
//!
//! TinyFlake is inspired by Twitter's Snowflake but differs in key ways:
//!
//! | Feature | Snowflake | TinyFlake |
//! |---------|-----------|-----------|
//! | Length | 19 digits | 11 chars |
//! | Encoding | Decimal | Base58 |
//! | Coordination | Requires worker IDs | None (random) |
//! | Time resolution | Milliseconds | Seconds |
//! | Uniqueness | Guaranteed | Statistical |
//!
//! # Collision Probability
//!
//! The 8-character random component provides 58^8 ≈ 128 trillion combinations.
//! Using the birthday paradox formula:
//!
//! - At **1,000 req/sec**: 50% collision chance after ~11 million requests (~3 hours)
//! - At **10,000 req/sec**: 50% collision chance after ~11 million requests (~18 minutes)
//! - At **100,000 req/sec**: 50% collision chance after ~11 million requests (~2 minutes)
//!
//! However, collisions only matter within the same second (due to time prefix).
//! Within a single second at 100k req/sec, collision probability is ~0.004%.
//!
//! For guaranteed uniqueness, use UUID format instead.
//!
//! # Configuration
//!
//! In `sentinel.kdl`:
//!
//! ```kdl
//! server {
//!     trace-id-format "tinyflake"  // default, or "uuid"
//! }
//! ```
//!
//! # Examples
//!
//! ```
//! use sentinel_proxy::trace_id::{generate_tinyflake, generate_uuid, generate_for_format, TraceIdFormat};
//!
//! // Generate TinyFlake (default)
//! let id = generate_tinyflake();
//! assert_eq!(id.len(), 11);
//!
//! // Generate UUID
//! let uuid = generate_uuid();
//! assert_eq!(uuid.len(), 36);
//!
//! // Generate based on format config
//! let id = generate_for_format(TraceIdFormat::TinyFlake);
//! ```
//!
//! # Header Propagation
//!
//! TinyFlake respects incoming trace headers in this order:
//! 1. `X-Trace-Id`
//! 2. `X-Correlation-Id`
//! 3. `X-Request-Id`
//!
//! If an incoming request has any of these headers, that value is used instead of
//! generating a new ID. This allows distributed tracing across services.

use std::time::{SystemTime, UNIX_EPOCH};

// Re-export TraceIdFormat from sentinel_common for convenience
pub use sentinel_common::TraceIdFormat;

/// Generate a trace ID using the specified format
#[inline]
pub fn generate_for_format(format: TraceIdFormat) -> String {
    match format {
        TraceIdFormat::TinyFlake => generate_tinyflake(),
        TraceIdFormat::Uuid => generate_uuid(),
    }
}

// ============================================================================
// TinyFlake Generation
// ============================================================================

/// Base58 alphabet (Bitcoin-style)
///
/// Excludes visually ambiguous characters:
/// - `0` (zero) and `O` (capital o)
/// - `I` (capital i) and `l` (lowercase L)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// TinyFlake ID length
pub const TINYFLAKE_LENGTH: usize = 11;

/// Time component length (3 Base58 chars = 58^3 = 195,112 values ≈ 54 hours)
const TIME_COMPONENT_LENGTH: usize = 3;

/// Random component length (8 Base58 chars = 58^8 ≈ 128 trillion values)
const RANDOM_COMPONENT_LENGTH: usize = 8;

/// Time component modulo (58^3)
const TIME_MODULO: u64 = 195_112;

/// Generate a TinyFlake trace ID
///
/// Format: 11 characters, Base58 encoded
/// - 3 chars: timestamp component (cycles every ~54 hours)
/// - 8 chars: random component
///
/// # Example
///
/// ```
/// use sentinel_proxy::trace_id::generate_tinyflake;
///
/// let id = generate_tinyflake();
/// assert_eq!(id.len(), 11);
/// println!("Generated TinyFlake: {}", id);
/// ```
pub fn generate_tinyflake() -> String {
    let mut id = String::with_capacity(TINYFLAKE_LENGTH);

    // Time component: seconds since epoch mod TIME_MODULO
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_component = (now % TIME_MODULO) as usize;
    encode_base58(time_component, TIME_COMPONENT_LENGTH, &mut id);

    // Random component: 6 random bytes encoded as 8 Base58 chars
    let random_bytes: [u8; 6] = rand::random();
    let random_value = u64::from_le_bytes([
        random_bytes[0],
        random_bytes[1],
        random_bytes[2],
        random_bytes[3],
        random_bytes[4],
        random_bytes[5],
        0,
        0,
    ]) as usize;
    encode_base58(random_value, RANDOM_COMPONENT_LENGTH, &mut id);

    id
}

/// Encode a number as Base58 with fixed width
///
/// The output is zero-padded (using '1', the first Base58 char) to ensure
/// consistent length.
fn encode_base58(mut value: usize, width: usize, output: &mut String) {
    let mut chars = Vec::with_capacity(width);

    for _ in 0..width {
        chars.push(BASE58_ALPHABET[value % 58] as char);
        value /= 58;
    }

    // Reverse to get most significant digit first
    for c in chars.into_iter().rev() {
        output.push(c);
    }
}

// ============================================================================
// UUID Generation
// ============================================================================

/// Generate a UUID v4 trace ID
///
/// Format: 36 characters with dashes (standard UUID format)
///
/// # Example
///
/// ```
/// use sentinel_proxy::trace_id::generate_uuid;
///
/// let id = generate_uuid();
/// assert_eq!(id.len(), 36);
/// assert!(id.contains('-'));
/// ```
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_tinyflake_format() {
        let id = generate_tinyflake();

        // Should be exactly 11 characters
        assert_eq!(
            id.len(),
            TINYFLAKE_LENGTH,
            "TinyFlake should be {} chars, got: {} ({})",
            TINYFLAKE_LENGTH,
            id.len(),
            id
        );

        // Should only contain Base58 characters
        for c in id.chars() {
            assert!(
                BASE58_ALPHABET.contains(&(c as u8)),
                "Invalid char '{}' in TinyFlake: {}",
                c,
                id
            );
        }

        // Should not contain confusing characters
        assert!(!id.contains('0'), "TinyFlake should not contain '0'");
        assert!(!id.contains('O'), "TinyFlake should not contain 'O'");
        assert!(!id.contains('I'), "TinyFlake should not contain 'I'");
        assert!(!id.contains('l'), "TinyFlake should not contain 'l'");
    }

    #[test]
    fn test_tinyflake_uniqueness() {
        // Generate 10,000 IDs and verify no duplicates
        let mut ids = HashSet::new();
        for _ in 0..10_000 {
            let id = generate_tinyflake();
            assert!(
                ids.insert(id.clone()),
                "Duplicate TinyFlake generated: {}",
                id
            );
        }
    }

    #[test]
    fn test_tinyflake_time_ordering() {
        // IDs generated in the same second should have same time prefix
        let id1 = generate_tinyflake();
        let id2 = generate_tinyflake();

        assert_eq!(
            &id1[..TIME_COMPONENT_LENGTH],
            &id2[..TIME_COMPONENT_LENGTH],
            "Time prefix should match within same second: {} vs {}",
            id1,
            id2
        );
    }

    #[test]
    fn test_uuid_format() {
        let id = generate_uuid();

        // Should be exactly 36 characters
        assert_eq!(id.len(), 36, "UUID should be 36 chars, got: {}", id.len());

        // Should contain 4 dashes
        assert_eq!(
            id.matches('-').count(),
            4,
            "UUID should have 4 dashes: {}",
            id
        );

        // Should be parseable as UUID
        assert!(
            uuid::Uuid::parse_str(&id).is_ok(),
            "Should be valid UUID: {}",
            id
        );
    }

    #[test]
    fn test_trace_id_format_generate() {
        let tinyflake = generate_for_format(TraceIdFormat::TinyFlake);
        assert_eq!(tinyflake.len(), TINYFLAKE_LENGTH);

        let uuid = generate_for_format(TraceIdFormat::Uuid);
        assert_eq!(uuid.len(), 36);
    }

    #[test]
    fn test_trace_id_format_from_str() {
        assert_eq!(TraceIdFormat::from_str_loose("tinyflake"), TraceIdFormat::TinyFlake);
        assert_eq!(TraceIdFormat::from_str_loose("TINYFLAKE"), TraceIdFormat::TinyFlake);
        assert_eq!(TraceIdFormat::from_str_loose("uuid"), TraceIdFormat::Uuid);
        assert_eq!(TraceIdFormat::from_str_loose("UUID"), TraceIdFormat::Uuid);
        assert_eq!(TraceIdFormat::from_str_loose("uuid4"), TraceIdFormat::Uuid);
        assert_eq!(TraceIdFormat::from_str_loose("uuidv4"), TraceIdFormat::Uuid);
        assert_eq!(TraceIdFormat::from_str_loose("unknown"), TraceIdFormat::TinyFlake); // Default
    }

    #[test]
    fn test_trace_id_format_display() {
        assert_eq!(TraceIdFormat::TinyFlake.to_string(), "tinyflake");
        assert_eq!(TraceIdFormat::Uuid.to_string(), "uuid");
    }

    #[test]
    fn test_encode_base58() {
        let mut output = String::new();

        // 0 encodes to all '1's (first char in Base58 alphabet)
        encode_base58(0, 3, &mut output);
        assert_eq!(output, "111");

        // 57 (last index) encodes to 'z' (last char in Base58 alphabet)
        output.clear();
        encode_base58(57, 3, &mut output);
        assert_eq!(output, "11z");

        // 58 wraps to next position
        output.clear();
        encode_base58(58, 3, &mut output);
        assert_eq!(output, "121");
    }

    #[test]
    fn test_base58_alphabet_is_correct() {
        // Verify no confusing characters
        let alphabet_str = std::str::from_utf8(BASE58_ALPHABET).unwrap();
        assert!(!alphabet_str.contains('0'));
        assert!(!alphabet_str.contains('O'));
        assert!(!alphabet_str.contains('I'));
        assert!(!alphabet_str.contains('l'));

        // Verify length
        assert_eq!(BASE58_ALPHABET.len(), 58);

        // Verify all unique
        let unique: HashSet<u8> = BASE58_ALPHABET.iter().copied().collect();
        assert_eq!(unique.len(), 58);
    }
}
