//! Request body decompression with ratio limits
//!
//! This module provides safe decompression of request bodies for WAF/agent inspection.
//! It implements ratio limiting to prevent "zip bomb" attacks where a small compressed
//! payload expands to an enormous size.
//!
//! # Security Features
//!
//! - **Ratio limiting**: Stops decompression if output/input ratio exceeds threshold
//! - **Size limiting**: Stops decompression if output exceeds max bytes
//! - **Incremental checking**: Ratio checked during decompression, not just at end
//!
//! # Supported Encodings
//!
//! - gzip (Content-Encoding: gzip)
//! - deflate (Content-Encoding: deflate)
//! - brotli (Content-Encoding: br)
//!
//! # Example
//!
//! ```ignore
//! use zentinel_proxy::decompression::{decompress_body, DecompressionConfig};
//!
//! let config = DecompressionConfig {
//!     max_ratio: 100.0,
//!     max_output_bytes: 10 * 1024 * 1024, // 10MB
//! };
//!
//! let result = decompress_body(&compressed_data, "gzip", &config)?;
//! ```

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use thiserror::Error;
use tracing::{debug, trace, warn};

/// Decompression errors
#[derive(Debug, Error)]
pub enum DecompressionError {
    /// Decompression ratio exceeded the configured limit
    #[error("Decompression ratio {ratio:.1} exceeds limit {limit:.1} (zip bomb protection)")]
    RatioExceeded { ratio: f64, limit: f64 },

    /// Decompressed size exceeded the configured limit
    #[error("Decompressed size {size} exceeds limit {limit} bytes")]
    SizeExceeded { size: usize, limit: usize },

    /// Unsupported content encoding
    #[error("Unsupported content encoding: {0}")]
    UnsupportedEncoding(String),

    /// IO error during decompression
    #[error("Decompression IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid compressed data
    #[error("Invalid compressed data: {0}")]
    InvalidData(String),
}

/// Decompression configuration
#[derive(Debug, Clone)]
pub struct DecompressionConfig {
    /// Maximum allowed ratio of decompressed/compressed size
    /// Default: 100.0 (decompressed can be 100x larger than compressed)
    pub max_ratio: f64,

    /// Maximum decompressed output size in bytes
    /// Default: 10MB
    pub max_output_bytes: usize,
}

impl Default for DecompressionConfig {
    fn default() -> Self {
        Self {
            max_ratio: 100.0,
            max_output_bytes: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Decompression result with metadata
#[derive(Debug)]
pub struct DecompressionResult {
    /// Decompressed data
    pub data: Vec<u8>,
    /// Original compressed size
    pub compressed_size: usize,
    /// Final decompressed size
    pub decompressed_size: usize,
    /// Actual ratio achieved
    pub ratio: f64,
    /// Content encoding that was decompressed
    pub encoding: String,
}

/// Statistics for decompression operations
#[derive(Debug, Default)]
pub struct DecompressionStats {
    /// Total decompression attempts
    pub total_attempts: AtomicU64,
    /// Successful decompressions
    pub successful: AtomicU64,
    /// Ratio limit violations
    pub ratio_exceeded: AtomicU64,
    /// Size limit violations
    pub size_exceeded: AtomicU64,
    /// Unsupported encodings
    pub unsupported: AtomicU64,
    /// IO/format errors
    pub errors: AtomicU64,
    /// Total bytes decompressed
    pub bytes_decompressed: AtomicU64,
}

impl DecompressionStats {
    pub fn record_success(&self, bytes: usize) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.successful.fetch_add(1, Ordering::Relaxed);
        self.bytes_decompressed
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_ratio_exceeded(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.ratio_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_size_exceeded(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.size_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_unsupported(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.unsupported.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Parse Content-Encoding header to determine encoding type
///
/// Request body inspection does not use this: it reads every
/// `Content-Encoding` header with [`content_codings`] and
/// [`BodyCoding::classify`].
pub fn parse_content_encoding(header_value: &str) -> Option<&str> {
    // Handle multiple encodings (e.g., "gzip, chunked")
    // We only decompress the first compression encoding
    for encoding in header_value.split(',') {
        let encoding = encoding.trim().to_lowercase();
        match encoding.as_str() {
            "gzip" | "x-gzip" => return Some("gzip"),
            "deflate" => return Some("deflate"),
            "br" | "brotli" => return Some("br"),
            "identity" | "chunked" => continue, // Not compression
            _ => continue,
        }
    }
    None
}

/// Check if the content encoding is supported for decompression
///
/// Request body inspection does not use this: it reads every
/// `Content-Encoding` header with [`content_codings`] and
/// [`BodyCoding::classify`].
pub fn is_supported_encoding(encoding: &str) -> bool {
    matches!(
        encoding.to_lowercase().as_str(),
        "gzip" | "x-gzip" | "deflate" | "br" | "brotli"
    )
}

/// The content codings a request declares, from the values of all its
/// `Content-Encoding` headers (RFC 9110 section 8.4).
///
/// Each value is a comma-separated list; the codings of all the headers
/// follow one another in the order they were sent. Names are compared
/// without regard to ASCII case, so they come back lowercase, without the
/// spaces and tabs around them. Empty list elements and `identity`, which
/// stands for no coding, are left out.
pub fn content_codings<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|value| {
            String::from_utf8_lossy(value)
                .split(',')
                .map(|coding| coding.trim_matches([' ', '\t']).to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|coding| !coding.is_empty() && coding != "identity")
        .collect()
}

/// The name [`decompress_body`] is given for a coding it can decode.
fn decodable_coding(coding: &str) -> Option<&'static str> {
    match coding {
        "gzip" | "x-gzip" => Some("gzip"),
        "deflate" => Some("deflate"),
        "br" | "brotli" => Some("br"),
        _ => None,
    }
}

/// How many characters of a request's declared codings are kept for logs.
const DECLARED_CODINGS_LOG_LIMIT: usize = 64;

/// A content-coded request body that is not decoded for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndecodedBody {
    /// The `encoding` of the metric: `gzip`, `deflate` or `br` for a body
    /// in one of those alone, `other` for any other coding or for several.
    pub label: &'static str,
    /// The codings the request declared, lowercase, for logs.
    pub declared: String,
}

/// How a request body's `Content-Encoding` headers are handled for the
/// agents that inspect the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyCoding {
    /// No content coding, or only `identity`: inspected as sent.
    Identity,
    /// One coding that is supported, with decoding on: decoded, within the
    /// configured limits, for inspection. The name is `gzip`, `deflate` or
    /// `br`.
    Decode(&'static str),
    /// Not decoded: decoding is off, or the coding is not supported, or
    /// there are several of them. The body cannot be inspected as sent.
    NotDecoded(UndecodedBody),
}

impl BodyCoding {
    /// Classify a request by the values of all its `Content-Encoding`
    /// headers. `decode` is whether a body in a supported coding can be
    /// decoded: the route's `body-inspection { decompress }`, and a mode
    /// that sends the agents the body whole, not in chunks as it arrives.
    /// `hybrid` mode holds a body whole only up to its threshold, so a body
    /// that goes past it is not decoded after all
    /// (`RequestContext::body_goes_in_pieces`).
    pub fn classify<'a>(values: impl IntoIterator<Item = &'a [u8]>, decode: bool) -> Self {
        let codings = content_codings(values);
        let mut declared = codings.join(", ");
        if let Some((end, _)) = declared.char_indices().nth(DECLARED_CODINGS_LOG_LIMIT) {
            declared.truncate(end);
        }
        match codings.as_slice() {
            [] => BodyCoding::Identity,
            [coding] => match (decodable_coding(coding), decode) {
                (Some(name), true) => BodyCoding::Decode(name),
                (Some(name), false) => BodyCoding::NotDecoded(UndecodedBody {
                    label: name,
                    declared,
                }),
                (None, _) => BodyCoding::NotDecoded(UndecodedBody {
                    label: "other",
                    declared,
                }),
            },
            _ => BodyCoding::NotDecoded(UndecodedBody {
                label: "other",
                declared,
            }),
        }
    }
}

/// Decompress body data with ratio and size limits
///
/// Returns the decompressed data or an error if limits are exceeded.
///
/// # Arguments
///
/// * `data` - Compressed data bytes
/// * `encoding` - Content-Encoding value (gzip, deflate, br)
/// * `config` - Decompression limits configuration
///
/// # Returns
///
/// * `Ok(DecompressionResult)` - Successfully decompressed with metadata
/// * `Err(DecompressionError)` - Limit exceeded or decompression failed
pub fn decompress_body(
    data: &[u8],
    encoding: &str,
    config: &DecompressionConfig,
) -> Result<DecompressionResult, DecompressionError> {
    let compressed_size = data.len();

    if compressed_size == 0 {
        return Ok(DecompressionResult {
            data: Vec::new(),
            compressed_size: 0,
            decompressed_size: 0,
            ratio: 1.0,
            encoding: encoding.to_string(),
        });
    }

    trace!(
        encoding = encoding,
        compressed_size = compressed_size,
        max_ratio = config.max_ratio,
        max_output = config.max_output_bytes,
        "Starting body decompression"
    );

    let encoding_lower = encoding.to_lowercase();
    let decompressed = match encoding_lower.as_str() {
        "gzip" | "x-gzip" => decompress_gzip(data, config)?,
        "deflate" => decompress_deflate(data, config)?,
        "br" | "brotli" => decompress_brotli(data, config)?,
        _ => {
            return Err(DecompressionError::UnsupportedEncoding(
                encoding.to_string(),
            ))
        }
    };

    let decompressed_size = decompressed.len();
    let ratio = if compressed_size > 0 {
        decompressed_size as f64 / compressed_size as f64
    } else {
        1.0
    };

    debug!(
        encoding = encoding,
        compressed_size = compressed_size,
        decompressed_size = decompressed_size,
        ratio = format!("{:.2}", ratio),
        "Body decompression complete"
    );

    Ok(DecompressionResult {
        data: decompressed,
        compressed_size,
        decompressed_size,
        ratio,
        encoding: encoding.to_string(),
    })
}

/// Decompress gzip data with incremental ratio checking
fn decompress_gzip(
    data: &[u8],
    config: &DecompressionConfig,
) -> Result<Vec<u8>, DecompressionError> {
    let mut decoder = GzDecoder::new(data);
    decompress_with_limits(&mut decoder, data.len(), config)
}

/// Whether `data` starts with a zlib header (RFC 1950): the deflate method
/// in the low half of the first byte, and a two-byte header that is a
/// multiple of 31.
fn has_zlib_header(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] => cmf & 0x0f == 8 && (u16::from(*cmf) * 256 + u16::from(*flg)) % 31 == 0,
        _ => false,
    }
}

/// Decompress deflate data with incremental ratio checking
///
/// The `deflate` coding is the zlib format (RFC 9110 section 8.4.1.2), but
/// a raw deflate stream (RFC 1951) is sent for it as well; the zlib header
/// tells them apart.
fn decompress_deflate(
    data: &[u8],
    config: &DecompressionConfig,
) -> Result<Vec<u8>, DecompressionError> {
    if has_zlib_header(data) {
        let mut decoder = ZlibDecoder::new(data);
        decompress_with_limits(&mut decoder, data.len(), config)
    } else {
        let mut decoder = DeflateDecoder::new(data);
        decompress_with_limits(&mut decoder, data.len(), config)
    }
}

/// Decompress brotli data with incremental ratio checking
fn decompress_brotli(
    data: &[u8],
    config: &DecompressionConfig,
) -> Result<Vec<u8>, DecompressionError> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    decompress_with_limits(&mut decoder, data.len(), config)
}

/// Common decompression logic with ratio and size limits
///
/// Reads from the decoder in chunks, checking limits after each chunk.
fn decompress_with_limits<R: Read>(
    decoder: &mut R,
    compressed_size: usize,
    config: &DecompressionConfig,
) -> Result<Vec<u8>, DecompressionError> {
    // Pre-allocate with reasonable estimate (assume 5x ratio initially)
    let initial_capacity =
        std::cmp::min(compressed_size.saturating_mul(5), config.max_output_bytes);
    let mut output = Vec::with_capacity(initial_capacity);

    // Read in chunks to check ratio incrementally
    let chunk_size = 64 * 1024; // 64KB chunks
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let bytes_read = match decoder.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                return Err(DecompressionError::InvalidData(e.to_string()));
            }
            Err(e) => return Err(DecompressionError::IoError(e)),
        };

        // Check size limit before appending
        let new_size = output.len() + bytes_read;
        if new_size > config.max_output_bytes {
            warn!(
                current_size = output.len(),
                would_be = new_size,
                limit = config.max_output_bytes,
                "Decompression size limit exceeded"
            );
            return Err(DecompressionError::SizeExceeded {
                size: new_size,
                limit: config.max_output_bytes,
            });
        }

        // Check ratio limit
        if compressed_size > 0 {
            let current_ratio = new_size as f64 / compressed_size as f64;
            if current_ratio > config.max_ratio {
                warn!(
                    compressed_size = compressed_size,
                    decompressed_size = new_size,
                    ratio = format!("{:.2}", current_ratio),
                    limit = config.max_ratio,
                    "Decompression ratio limit exceeded (zip bomb protection)"
                );
                return Err(DecompressionError::RatioExceeded {
                    ratio: current_ratio,
                    limit: config.max_ratio,
                });
            }
        }

        output.extend_from_slice(&buffer[..bytes_read]);
    }

    Ok(output)
}

/// Wrapper for decompressing body with statistics tracking
pub fn decompress_body_with_stats(
    data: &[u8],
    encoding: &str,
    config: &DecompressionConfig,
    stats: &DecompressionStats,
) -> Result<DecompressionResult, DecompressionError> {
    match decompress_body(data, encoding, config) {
        Ok(result) => {
            stats.record_success(result.decompressed_size);
            Ok(result)
        }
        Err(DecompressionError::RatioExceeded { .. }) => {
            stats.record_ratio_exceeded();
            Err(DecompressionError::RatioExceeded {
                ratio: 0.0,
                limit: config.max_ratio,
            })
        }
        Err(DecompressionError::SizeExceeded { size, limit }) => {
            stats.record_size_exceeded();
            Err(DecompressionError::SizeExceeded { size, limit })
        }
        Err(DecompressionError::UnsupportedEncoding(e)) => {
            stats.record_unsupported();
            Err(DecompressionError::UnsupportedEncoding(e))
        }
        Err(e) => {
            stats.record_error();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    fn compress_gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn compress_deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn compress_brotli(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut output, 4096, 4, 22);
            encoder.write_all(data).unwrap();
        }
        output
    }

    #[test]
    fn test_parse_content_encoding() {
        assert_eq!(parse_content_encoding("gzip"), Some("gzip"));
        assert_eq!(parse_content_encoding("GZIP"), Some("gzip"));
        assert_eq!(parse_content_encoding("x-gzip"), Some("gzip"));
        assert_eq!(parse_content_encoding("deflate"), Some("deflate"));
        assert_eq!(parse_content_encoding("br"), Some("br"));
        assert_eq!(parse_content_encoding("brotli"), Some("br"));
        assert_eq!(parse_content_encoding("identity"), None);
        assert_eq!(parse_content_encoding("chunked"), None);
        assert_eq!(parse_content_encoding("gzip, chunked"), Some("gzip"));
    }

    fn codings(values: &[&str]) -> Vec<String> {
        content_codings(values.iter().map(|v| v.as_bytes()))
    }

    #[test]
    fn content_codings_reads_a_comma_separated_list() {
        assert_eq!(codings(&["gzip"]), ["gzip"]);
        assert_eq!(codings(&["gzip, br"]), ["gzip", "br"]);
        assert_eq!(codings(&["gzip,br"]), ["gzip", "br"]);
    }

    #[test]
    fn content_codings_ignores_case_and_surrounding_whitespace() {
        assert_eq!(codings(&["GZip"]), ["gzip"]);
        assert_eq!(codings(&[" gzip "]), ["gzip"]);
        assert_eq!(codings(&["\tgzip\t,\tBR "]), ["gzip", "br"]);
    }

    #[test]
    fn content_codings_follows_every_header_in_order() {
        assert_eq!(codings(&["gzip", "br"]), ["gzip", "br"]);
        assert_eq!(codings(&["deflate, gzip", "br"]), ["deflate", "gzip", "br"]);
    }

    #[test]
    fn content_codings_leaves_out_identity_and_empty_elements() {
        assert!(codings(&["identity"]).is_empty());
        assert!(codings(&["Identity, IDENTITY"]).is_empty());
        assert_eq!(codings(&["identity, gzip"]), ["gzip"]);
        assert!(codings(&[""]).is_empty());
        assert!(codings(&[" "]).is_empty());
        assert!(codings(&[","]).is_empty());
        assert_eq!(codings(&["gzip,,br,"]), ["gzip", "br"]);
        assert!(codings(&[]).is_empty());
    }

    #[test]
    fn content_codings_keeps_a_value_that_is_not_text() {
        // Not a name that is decoded, so it must not read as no coding.
        assert_eq!(content_codings([&b"gz\xffip"[..]]).len(), 1);
    }

    fn classify(values: &[&str], decompress: bool) -> BodyCoding {
        BodyCoding::classify(values.iter().map(|v| v.as_bytes()), decompress)
    }

    fn not_decoded(label: &'static str, declared: &str) -> BodyCoding {
        BodyCoding::NotDecoded(UndecodedBody {
            label,
            declared: declared.to_string(),
        })
    }

    #[test]
    fn classify_a_body_without_a_coding_as_it_is() {
        assert_eq!(classify(&[], true), BodyCoding::Identity);
        assert_eq!(classify(&["identity"], true), BodyCoding::Identity);
        assert_eq!(classify(&[""], false), BodyCoding::Identity);
    }

    #[test]
    fn classify_one_supported_coding_as_decoded_when_enabled() {
        assert_eq!(classify(&["gzip"], true), BodyCoding::Decode("gzip"));
        assert_eq!(classify(&["x-gzip"], true), BodyCoding::Decode("gzip"));
        assert_eq!(classify(&["GZIP "], true), BodyCoding::Decode("gzip"));
        assert_eq!(classify(&["deflate"], true), BodyCoding::Decode("deflate"));
        assert_eq!(classify(&["br"], true), BodyCoding::Decode("br"));
        assert_eq!(classify(&["brotli"], true), BodyCoding::Decode("br"));
        assert_eq!(
            classify(&["identity, gzip"], true),
            BodyCoding::Decode("gzip")
        );
        assert_eq!(
            classify(&["gzip", "identity"], true),
            BodyCoding::Decode("gzip")
        );
    }

    #[test]
    fn classify_a_supported_coding_as_not_decoded_when_disabled() {
        assert_eq!(classify(&["gzip"], false), not_decoded("gzip", "gzip"));
        assert_eq!(classify(&["BR"], false), not_decoded("br", "br"));
    }

    #[test]
    fn classify_an_unsupported_coding_as_not_decoded() {
        assert_eq!(classify(&["zstd"], true), not_decoded("other", "zstd"));
        assert_eq!(classify(&["ZSTD "], true), not_decoded("other", "zstd"));
        assert_eq!(
            classify(&["compress"], true),
            not_decoded("other", "compress")
        );
        assert_eq!(classify(&["zstd"], false), not_decoded("other", "zstd"));
    }

    #[test]
    fn classify_several_codings_as_not_decoded() {
        assert_eq!(
            classify(&["gzip, br"], true),
            not_decoded("other", "gzip, br")
        );
        assert_eq!(
            classify(&["gzip", "br"], true),
            not_decoded("other", "gzip, br")
        );
        assert_eq!(
            classify(&["gzip, gzip"], true),
            not_decoded("other", "gzip, gzip")
        );
    }

    #[test]
    fn classify_keeps_the_declared_codings_for_logs_short() {
        let long = vec!["x"; 200].join(", ");
        let BodyCoding::NotDecoded(undecoded) = classify(&[long.as_str()], true) else {
            panic!("several codings are not decoded");
        };
        assert_eq!(
            undecoded.declared.chars().count(),
            DECLARED_CODINGS_LOG_LIMIT
        );
        assert_eq!(undecoded.label, "other");
    }

    #[test]
    fn test_decompress_gzip() {
        let original = b"Hello, World! This is a test of gzip decompression.";
        let compressed = compress_gzip(original);
        let config = DecompressionConfig::default();

        let result = decompress_body(&compressed, "gzip", &config).unwrap();

        assert_eq!(result.data, original);
        assert_eq!(result.compressed_size, compressed.len());
        assert_eq!(result.decompressed_size, original.len());
        assert!(result.ratio > 0.0);
    }

    /// `deflate` as RFC 9110 defines the coding: the zlib format.
    fn compress_zlib(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_decompress_deflate_in_the_zlib_format() {
        let original = b"Hello, World! This is a test of zlib-wrapped deflate.";
        let compressed = compress_zlib(original);
        let config = DecompressionConfig::default();

        let result = decompress_body(&compressed, "deflate", &config).unwrap();

        assert_eq!(result.data, original);
    }

    #[test]
    fn test_decompress_deflate() {
        let original = b"Hello, World! This is a test of deflate decompression.";
        let compressed = compress_deflate(original);
        let config = DecompressionConfig::default();

        let result = decompress_body(&compressed, "deflate", &config).unwrap();

        assert_eq!(result.data, original);
    }

    #[test]
    fn test_decompress_brotli() {
        let original = b"Hello, World! This is a test of brotli decompression.";
        let compressed = compress_brotli(original);
        let config = DecompressionConfig::default();

        let result = decompress_body(&compressed, "br", &config).unwrap();

        assert_eq!(result.data, original);
    }

    #[test]
    fn test_ratio_limit_exceeded() {
        // Create data that compresses very well (repeated pattern)
        let original = vec![b'A'; 100_000]; // 100KB of 'A's
        let compressed = compress_gzip(&original);

        // Set a very low ratio limit
        let config = DecompressionConfig {
            max_ratio: 2.0, // Only allow 2x expansion
            max_output_bytes: 10 * 1024 * 1024,
        };

        let result = decompress_body(&compressed, "gzip", &config);
        assert!(matches!(
            result,
            Err(DecompressionError::RatioExceeded { .. })
        ));
    }

    #[test]
    fn test_size_limit_exceeded() {
        let original = vec![b'X'; 100_000]; // 100KB
        let compressed = compress_gzip(&original);

        let config = DecompressionConfig {
            max_ratio: 1000.0,
            max_output_bytes: 50_000, // Only allow 50KB output
        };

        let result = decompress_body(&compressed, "gzip", &config);
        assert!(matches!(
            result,
            Err(DecompressionError::SizeExceeded { .. })
        ));
    }

    #[test]
    fn test_unsupported_encoding() {
        let data = b"some data";
        let config = DecompressionConfig::default();

        let result = decompress_body(data, "unknown", &config);
        assert!(matches!(
            result,
            Err(DecompressionError::UnsupportedEncoding(_))
        ));
    }

    #[test]
    fn test_empty_data() {
        let config = DecompressionConfig::default();

        let result = decompress_body(&[], "gzip", &config).unwrap();
        assert!(result.data.is_empty());
        assert_eq!(result.ratio, 1.0);
    }

    #[test]
    fn test_stats_tracking() {
        let stats = DecompressionStats::default();
        let original = b"test data";
        let compressed = compress_gzip(original);
        let config = DecompressionConfig::default();

        let _result = decompress_body_with_stats(&compressed, "gzip", &config, &stats).unwrap();

        assert_eq!(stats.total_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(stats.successful.load(Ordering::Relaxed), 1);
        assert!(stats.bytes_decompressed.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_large_compression_ratio_allowed() {
        // Highly compressible data (all zeros)
        let original = vec![0u8; 1_000_000]; // 1MB of zeros
        let compressed = compress_gzip(&original);

        // Allow high ratio
        let config = DecompressionConfig {
            max_ratio: 10000.0,
            max_output_bytes: 10 * 1024 * 1024,
        };

        let result = decompress_body(&compressed, "gzip", &config).unwrap();
        assert_eq!(result.data.len(), 1_000_000);

        // The ratio should be very high
        assert!(result.ratio > 100.0);
    }

    #[test]
    fn test_is_supported_encoding() {
        assert!(is_supported_encoding("gzip"));
        assert!(is_supported_encoding("GZIP"));
        assert!(is_supported_encoding("x-gzip"));
        assert!(is_supported_encoding("deflate"));
        assert!(is_supported_encoding("br"));
        assert!(is_supported_encoding("brotli"));
        assert!(!is_supported_encoding("identity"));
        assert!(!is_supported_encoding("chunked"));
        assert!(!is_supported_encoding("unknown"));
    }
}
