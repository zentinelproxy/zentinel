//! Agent download functionality
//!
//! Downloads agent binaries from their GitHub releases.

use crate::bundle::lock::AgentInfo;
use flate2::read::GzDecoder;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tar::Archive;
use thiserror::Error;

/// Errors that can occur during download
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Failed to create temporary file: {0}")]
    TempFile(#[from] io::Error),

    #[error("Download failed with status {status}: {url}")]
    DownloadFailed { url: String, status: u16 },

    #[error("Checksum verification failed for {agent}")]
    ChecksumMismatch { agent: String },

    #[error("Failed to extract archive: {0}")]
    Extract(String),

    #[error("Binary not found in archive: {0}")]
    BinaryNotFound(String),
}

/// Result of a download operation
pub struct DownloadResult {
    /// Path to the downloaded and extracted binary
    pub binary_path: PathBuf,

    /// Size of the downloaded archive in bytes
    pub archive_size: u64,

    /// Whether checksum was verified
    pub checksum_verified: bool,
}

/// Detect the current operating system
pub fn detect_os() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "macos")]
    {
        "darwin"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "unknown"
    }
}

/// Detect the current architecture
pub fn detect_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unknown"
    }
}

/// Download an agent binary to a temporary directory
///
/// Returns the path to the extracted binary.
pub async fn download_agent(
    agent: &AgentInfo,
    temp_dir: &Path,
    verify_checksum: bool,
) -> Result<DownloadResult, FetchError> {
    let os = detect_os();
    let arch = detect_arch();

    let url = agent.download_url(os, arch);
    let checksum_url = agent.checksum_url(os, arch);

    tracing::info!(
        agent = %agent.name,
        version = %agent.version,
        url = %url,
        "Downloading agent"
    );

    let client = reqwest::Client::builder()
        .user_agent("zentinel-bundle")
        .build()?;

    // Download the archive
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(FetchError::DownloadFailed {
            url,
            status: response.status().as_u16(),
        });
    }

    let archive_bytes = response.bytes().await?;
    let archive_size = archive_bytes.len() as u64;

    // Verify checksum if requested
    let checksum_verified = if verify_checksum {
        match verify_sha256(&client, &checksum_url, &archive_bytes).await {
            Ok(true) => {
                tracing::debug!(agent = %agent.name, "Checksum verified");
                true
            }
            Ok(false) => {
                return Err(FetchError::ChecksumMismatch {
                    agent: agent.name.clone(),
                });
            }
            Err(e) => {
                tracing::warn!(
                    agent = %agent.name,
                    error = %e,
                    "Checksum verification skipped (file not available)"
                );
                false
            }
        }
    } else {
        false
    };

    // Extract the archive
    let binary_path = extract_archive(&archive_bytes, &agent.binary_name, temp_dir)?;

    Ok(DownloadResult {
        binary_path,
        archive_size,
        checksum_verified,
    })
}

/// Verify SHA256 checksum of downloaded data
async fn verify_sha256(
    client: &reqwest::Client,
    checksum_url: &str,
    data: &[u8],
) -> Result<bool, FetchError> {
    use sha2::{Digest, Sha256};

    // Download checksum file
    let response = client.get(checksum_url).send().await?;

    if !response.status().is_success() {
        return Err(FetchError::DownloadFailed {
            url: checksum_url.to_string(),
            status: response.status().as_u16(),
        });
    }

    let checksum_content = response.text().await?;

    // Parse expected checksum (format: "sha256hash  filename")
    let expected = checksum_content
        .split_whitespace()
        .next()
        .ok_or_else(|| FetchError::Extract("Invalid checksum file format".to_string()))?
        .to_lowercase();

    // Calculate actual checksum
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual = hex::encode(hasher.finalize());

    Ok(expected == actual)
}

/// Extract a tarball and find the binary
fn extract_archive(
    archive_bytes: &[u8],
    binary_name: &str,
    dest_dir: &Path,
) -> Result<PathBuf, FetchError> {
    let decoder = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(decoder);

    // Create destination directory
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| FetchError::Extract(format!("Failed to create directory: {}", e)))?;

    // Extract all files
    archive
        .unpack(dest_dir)
        .map_err(|e| FetchError::Extract(format!("Failed to extract: {}", e)))?;

    // Find the binary (might be at top level or in a subdirectory)
    let binary_path = find_binary(dest_dir, binary_name)?;

    // Make it executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&binary_path)
            .map_err(|e| FetchError::Extract(e.to_string()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&binary_path, perms)
            .map_err(|e| FetchError::Extract(e.to_string()))?;
    }

    Ok(binary_path)
}

/// Find the binary in the extracted directory
fn find_binary(dir: &Path, binary_name: &str) -> Result<PathBuf, FetchError> {
    // Check top level
    let direct_path = dir.join(binary_name);
    if direct_path.exists() {
        return Ok(direct_path);
    }

    // Check bin subdirectory
    let bin_path = dir.join("bin").join(binary_name);
    if bin_path.exists() {
        return Ok(bin_path);
    }

    // Search recursively
    for entry in walkdir(dir).flatten() {
        if entry.file_name().to_string_lossy() == binary_name {
            return Ok(entry.path().to_path_buf());
        }
    }

    Err(FetchError::BinaryNotFound(binary_name.to_string()))
}

/// Simple recursive directory walker
fn walkdir(dir: &Path) -> impl Iterator<Item = io::Result<std::fs::DirEntry>> + '_ {
    WalkDir::new(dir)
}

struct WalkDir {
    stack: Vec<PathBuf>,
    current: Option<std::fs::ReadDir>,
}

impl WalkDir {
    fn new(dir: &Path) -> Self {
        Self {
            stack: vec![dir.to_path_buf()],
            current: None,
        }
    }
}

impl Iterator for WalkDir {
    type Item = io::Result<std::fs::DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to get next entry from current ReadDir
            if let Some(ref mut read_dir) = self.current {
                if let Some(entry) = read_dir.next() {
                    match entry {
                        Ok(e) => {
                            if e.path().is_dir() {
                                self.stack.push(e.path());
                            }
                            return Some(Ok(e));
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }
                // Current ReadDir exhausted
                self.current = None;
            }

            // Pop next directory from stack
            let dir = self.stack.pop()?;
            match std::fs::read_dir(&dir) {
                Ok(read_dir) => self.current = Some(read_dir),
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_detect_platform() {
        let os = detect_os();
        let arch = detect_arch();

        // Should detect something
        assert!(!os.is_empty());
        assert!(!arch.is_empty());

        // On common platforms
        #[cfg(target_os = "linux")]
        assert_eq!(os, "linux");

        #[cfg(target_os = "macos")]
        assert_eq!(os, "darwin");

        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "amd64");

        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "arm64");
    }

    #[test]
    fn test_detect_os_is_known() {
        let os = detect_os();
        assert!(
            ["linux", "darwin", "windows", "unknown"].contains(&os),
            "Unexpected OS: {}",
            os
        );
    }

    #[test]
    fn test_detect_arch_is_known() {
        let arch = detect_arch();
        assert!(
            ["amd64", "arm64", "unknown"].contains(&arch),
            "Unexpected arch: {}",
            arch
        );
    }

    #[test]
    fn test_find_binary_direct() {
        let temp = tempfile::tempdir().unwrap();
        let binary_name = "test-binary";

        // Create binary at top level
        std::fs::write(temp.path().join(binary_name), "binary content").unwrap();

        let result = find_binary(temp.path(), binary_name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().file_name().unwrap(), binary_name);
    }

    #[test]
    fn test_find_binary_in_bin_dir() {
        let temp = tempfile::tempdir().unwrap();
        let binary_name = "test-binary";

        // Create binary in bin/ subdirectory
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        std::fs::write(bin_dir.join(binary_name), "binary content").unwrap();

        let result = find_binary(temp.path(), binary_name);
        assert!(result.is_ok());
        assert!(result.unwrap().to_string_lossy().contains("bin"));
    }

    #[test]
    fn test_find_binary_nested() {
        let temp = tempfile::tempdir().unwrap();
        let binary_name = "zentinel-waf-agent";

        // Create deeply nested structure (like some release artifacts)
        let nested = temp.path().join("zentinel-waf-agent-0.2.0").join("bin");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join(binary_name), "binary content").unwrap();

        let result = find_binary(temp.path(), binary_name);
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_binary_not_found() {
        let temp = tempfile::tempdir().unwrap();

        let result = find_binary(temp.path(), "nonexistent-binary");
        assert!(matches!(result, Err(FetchError::BinaryNotFound(_))));
    }

    #[test]
    fn test_extract_archive_valid_tarball() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        let temp = tempfile::tempdir().unwrap();
        let binary_name = "test-binary";

        // Create a valid tar.gz archive in memory
        let mut archive_data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive_data, Compression::default());
            let mut builder = Builder::new(encoder);

            // Add a file to the archive
            let binary_content = b"#!/bin/sh\necho hello";
            let mut header = tar::Header::new_gnu();
            header.set_size(binary_content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();

            builder
                .append_data(&mut header, binary_name, &binary_content[..])
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }

        let result = extract_archive(&archive_data, binary_name, temp.path());
        assert!(result.is_ok());

        let binary_path = result.unwrap();
        assert!(binary_path.exists());
    }

    #[test]
    fn test_extract_archive_invalid_gzip() {
        let temp = tempfile::tempdir().unwrap();
        let invalid_data = b"this is not a gzip file";

        let result = extract_archive(invalid_data, "binary", temp.path());
        assert!(matches!(result, Err(FetchError::Extract(_))));
    }

    #[test]
    fn test_download_result_fields() {
        let result = DownloadResult {
            binary_path: PathBuf::from("/tmp/test"),
            archive_size: 1024,
            checksum_verified: true,
        };

        assert_eq!(result.archive_size, 1024);
        assert!(result.checksum_verified);
    }

    #[test]
    fn test_fetch_error_display() {
        let err = FetchError::ChecksumMismatch {
            agent: "waf".to_string(),
        };
        assert!(err.to_string().contains("waf"));

        let err = FetchError::BinaryNotFound("test".to_string());
        assert!(err.to_string().contains("test"));

        let err = FetchError::DownloadFailed {
            url: "https://example.com".to_string(),
            status: 404,
        };
        assert!(err.to_string().contains("404"));
    }
}
