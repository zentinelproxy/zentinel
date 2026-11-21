//! Agent download functionality
//!
//! Downloads agent binaries from their GitHub releases.

use crate::bundle::lock::AgentInfo;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
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

    #[error(
        "Cannot verify {agent}: the checksum at {url} is unavailable ({reason}); \
         pass --skip-verify to install without verifying the archive"
    )]
    ChecksumUnavailable {
        agent: String,
        url: String,
        reason: String,
    },

    #[error("Failed to extract archive: {0}")]
    Extract(String),

    #[error("Binary not found in archive: {0}")]
    BinaryNotFound(String),

    #[error("{agent} {version} is not published for {platform} (available: {available})")]
    UnsupportedPlatform {
        agent: String,
        version: String,
        platform: String,
        available: String,
    },
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
///
/// With `verify_checksum`, the archive is only extracted once it matches the
/// SHA-256 digest published next to it. A checksum that cannot be fetched or
/// read stops the download just as a mismatch does; without `verify_checksum`
/// the checksum is not requested and the result reports it as unverified.
///
/// # Errors
///
/// Returns `FetchError::ChecksumUnavailable` when the checksum file cannot be
/// downloaded or does not start with a SHA-256 digest, and
/// `FetchError::ChecksumMismatch` when the digest differs from the archive's.
pub async fn download_agent(
    agent: &AgentInfo,
    temp_dir: &Path,
    verify_checksum: bool,
) -> Result<DownloadResult, FetchError> {
    let os = detect_os();
    let arch = detect_arch();

    // Refuse up front rather than report a bare 404 for a platform the
    // release was never built for.
    if !agent.supports(os, arch) {
        return Err(FetchError::UnsupportedPlatform {
            agent: agent.name.clone(),
            version: agent.version.clone(),
            platform: AgentInfo::platform_key(os, arch),
            available: agent.platforms.join(", "),
        });
    }

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

    // Verify checksum if requested. A checksum that cannot be obtained is an
    // error, not a reason to install the archive unchecked.
    let checksum_verified = if verify_checksum {
        let expected = fetch_expected_checksum(&client, &checksum_url)
            .await
            .map_err(|reason| FetchError::ChecksumUnavailable {
                agent: agent.name.clone(),
                url: checksum_url.clone(),
                reason,
            })?;
        let actual = hex::encode(Sha256::digest(&archive_bytes));
        if expected != actual {
            return Err(FetchError::ChecksumMismatch {
                agent: agent.name.clone(),
            });
        }
        tracing::debug!(agent = %agent.name, "Checksum verified");
        true
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

/// Fetch the published SHA-256 digest of an archive.
///
/// The file is `sha256sum` output (`<hex digest>  <file name>`); only the
/// digest is used. Returns the lowercase digest, or the reason it could not
/// be obtained: the request failed, the server did not answer with a success
/// status, or the content does not start with a SHA-256 digest.
async fn fetch_expected_checksum(
    client: &reqwest::Client,
    checksum_url: &str,
) -> Result<String, String> {
    let response = client
        .get(checksum_url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP status {}", status.as_u16()));
    }

    let content = response
        .text()
        .await
        .map_err(|e| format!("could not read the response: {e}"))?;

    parse_sha256_digest(&content)
}

/// The digest at the start of a `sha256sum`-style line, in lowercase.
fn parse_sha256_digest(content: &str) -> Result<String, String> {
    let digest = content
        .split_whitespace()
        .next()
        .ok_or_else(|| "the checksum file is empty".to_string())?;

    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "the checksum file does not start with a 64-digit hexadecimal SHA-256 digest"
                .to_string(),
        );
    }

    Ok(digest.to_ascii_lowercase())
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
    use crate::bundle::lock::Transport;
    use std::collections::HashMap;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    const TEST_BINARY: &str = "test-agent";

    fn test_archive() -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let content = b"#!/bin/sh\n";
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, TEST_BINARY, &content[..])
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// An agent whose release for this platform is served at `base`.
    ///
    /// The URL is set through `precomputed_urls`, so the tests do not depend
    /// on process-wide environment variables.
    fn test_agent(base: &str) -> AgentInfo {
        let mut precomputed_urls = HashMap::new();
        precomputed_urls.insert(
            AgentInfo::platform_key(detect_os(), detect_arch()),
            format!("{base}/agent.tar.gz"),
        );
        AgentInfo {
            name: "waf".to_string(),
            version: "1.0.0".to_string(),
            repository: "example/agent-waf".to_string(),
            binary_name: TEST_BINARY.to_string(),
            precomputed_urls,
            platforms: Vec::new(),
            transport: Transport::Uds,
            required_file: None,
        }
    }

    /// Serve `archive` at `/agent.tar.gz`. `/agent.tar.gz.sha256` answers
    /// with `checksum`, or is not served at all (404) when that is `None`.
    async fn serve_release(
        archive: &[u8],
        checksum: Option<ResponseTemplate>,
    ) -> (MockServer, AgentInfo) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive.to_vec()))
            .mount(&server)
            .await;
        if let Some(response) = checksum {
            Mock::given(method("GET"))
                .and(path("/agent.tar.gz.sha256"))
                .respond_with(response)
                .mount(&server)
                .await;
        }
        let agent = test_agent(&server.uri());
        (server, agent)
    }

    /// Run `download_agent` and return its error, asserting that nothing was
    /// extracted.
    async fn download_error(
        archive: &[u8],
        checksum: Option<ResponseTemplate>,
    ) -> (FetchError, String) {
        let (server, agent) = serve_release(archive, checksum).await;
        let temp = tempfile::tempdir().unwrap();

        let result = download_agent(&agent, temp.path(), true).await;

        let err = match result {
            Ok(done) => panic!(
                "download_agent succeeded without a verified checksum (checksum_verified: {})",
                done.checksum_verified
            ),
            Err(err) => err,
        };
        assert!(
            !temp.path().join(TEST_BINARY).exists(),
            "the archive must not be extracted when verification fails"
        );
        (err, format!("{}/agent.tar.gz.sha256", server.uri()))
    }

    fn assert_names_agent_url_and_skip_option(err: &FetchError, checksum_url: &str) {
        let message = err.to_string();
        assert!(message.contains("waf"), "{message}");
        assert!(message.contains(checksum_url), "{message}");
        assert!(message.contains("--skip-verify"), "{message}");
    }

    #[tokio::test]
    async fn download_agent_rejects_a_missing_checksum_file() {
        let (err, checksum_url) = download_error(&test_archive(), None).await;

        assert_names_agent_url_and_skip_option(&err, &checksum_url);
        assert!(err.to_string().contains("404"), "{err}");
    }

    #[tokio::test]
    async fn download_agent_rejects_a_checksum_request_that_fails() {
        let (err, checksum_url) =
            download_error(&test_archive(), Some(ResponseTemplate::new(500))).await;

        assert_names_agent_url_and_skip_option(&err, &checksum_url);
        assert!(err.to_string().contains("500"), "{err}");
    }

    #[tokio::test]
    async fn download_agent_rejects_an_empty_checksum_file() {
        let (err, checksum_url) = download_error(
            &test_archive(),
            Some(ResponseTemplate::new(200).set_body_string("")),
        )
        .await;

        assert_names_agent_url_and_skip_option(&err, &checksum_url);
    }

    #[tokio::test]
    async fn download_agent_rejects_a_checksum_file_without_a_digest() {
        let archive = test_archive();
        let truncated = sha256_hex(&archive)[..63].to_string();
        for body in [
            "<html>not found</html>",
            "not-a-digest  agent.tar.gz\n",
            &truncated,
        ] {
            let (err, checksum_url) = download_error(
                &archive,
                Some(ResponseTemplate::new(200).set_body_string(body)),
            )
            .await;

            assert_names_agent_url_and_skip_option(&err, &checksum_url);
        }
    }

    #[tokio::test]
    async fn download_agent_rejects_a_checksum_that_does_not_match() {
        let archive = test_archive();
        let other = sha256_hex(b"some other archive");
        let (err, _) = download_error(
            &archive,
            Some(ResponseTemplate::new(200).set_body_string(format!("{other}  agent.tar.gz\n"))),
        )
        .await;

        assert!(
            matches!(err, FetchError::ChecksumMismatch { ref agent } if agent == "waf"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn download_agent_installs_when_the_checksum_matches() {
        let archive = test_archive();
        // sha256sum output, with the digest in upper case.
        let body = format!("{}  agent.tar.gz\n", sha256_hex(&archive).to_uppercase());
        let (_server, agent) = serve_release(
            &archive,
            Some(ResponseTemplate::new(200).set_body_string(body)),
        )
        .await;
        let temp = tempfile::tempdir().unwrap();

        let done = download_agent(&agent, temp.path(), true).await.unwrap();

        assert!(done.checksum_verified);
        assert_eq!(done.archive_size, archive.len() as u64);
        assert!(done.binary_path.exists());
    }

    #[tokio::test]
    async fn download_agent_without_verification_does_not_need_a_checksum_file() {
        let archive = test_archive();
        let (server, agent) = serve_release(&archive, None).await;
        // The checksum file must not even be requested.
        Mock::given(path("/agent.tar.gz.sha256"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let temp = tempfile::tempdir().unwrap();

        let done = download_agent(&agent, temp.path(), false).await.unwrap();

        assert!(!done.checksum_verified);
        assert!(done.binary_path.exists());
    }

    #[test]
    fn parse_sha256_digest_takes_the_first_field_in_lowercase() {
        let digest = "0123456789ABCDEFabcdef0123456789ABCDEFabcdef0123456789ABCDEFabcd";

        assert_eq!(
            parse_sha256_digest(&format!("{digest}  agent.tar.gz\n")).unwrap(),
            digest.to_ascii_lowercase()
        );
        assert_eq!(
            parse_sha256_digest(&format!("{digest} *agent.tar.gz")).unwrap(),
            digest.to_ascii_lowercase()
        );
        assert_eq!(
            parse_sha256_digest(digest).unwrap(),
            digest.to_ascii_lowercase()
        );
    }

    #[test]
    fn parse_sha256_digest_rejects_anything_else() {
        let digest = sha256_hex(b"archive");

        for content in [
            String::new(),
            "  \n".to_string(),
            digest[..63].to_string(),
            format!("{digest}0"),
            format!("sha256:{digest}"),
            format!("{}g", &digest[..63]),
            "404 page not found".to_string(),
        ] {
            assert!(
                parse_sha256_digest(&content).is_err(),
                "accepted {content:?}"
            );
        }
    }
}
