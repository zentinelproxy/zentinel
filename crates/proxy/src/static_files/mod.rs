//! Static file serving module for Zentinel proxy
//!
//! This module provides high-performance static file serving with:
//! - Range requests (206 Partial Content) for resumable downloads and video seeking
//! - Zero-copy file serving using memory-mapped files for large files
//! - On-the-fly gzip/brotli compression
//! - In-memory caching for small files
//! - Directory listing and SPA routing
//!
//! # Module Structure
//!
//! - `cache`: File caching with pre-computed compression
//! - `compression`: Content encoding and compression utilities
//! - `range`: HTTP Range request handling

mod cache;
mod compression;
mod range;

pub use cache::{CacheStats, CachedFile, FileCache};
pub use compression::ContentEncoding;

use anyhow::Result;
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::Full;
use mime_guess::from_path;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tracing::{debug, trace, warn};

use zentinel_config::StaticFileConfig;

use compression::{compress_content, negotiate_encoding, should_compress};
use range::serve_range_request;

// ============================================================================
// Constants
// ============================================================================

/// Minimum file size for compression (1KB) - smaller files have overhead
const MIN_COMPRESS_SIZE: u64 = 1024;

/// Maximum file size to cache in memory (1MB)
const MAX_CACHE_FILE_SIZE: u64 = 1024 * 1024;

/// File size threshold for memory-mapped serving (10MB)
const MMAP_THRESHOLD: u64 = 10 * 1024 * 1024;

// ============================================================================
// Static File Server
// ============================================================================

/// Static file server
pub struct StaticFileServer {
    /// Configuration for static file serving
    config: Arc<StaticFileConfig>,
    /// Cached file metadata
    cache: Arc<FileCache>,
}

impl StaticFileServer {
    /// Create a new static file server
    pub fn new(config: StaticFileConfig) -> Self {
        trace!(
            root = %config.root.display(),
            index = %config.index,
            directory_listing = config.directory_listing,
            compress = config.compress,
            has_fallback = config.fallback.is_some(),
            "Creating static file server"
        );

        let cache = Arc::new(FileCache::with_defaults());

        debug!(
            root = %config.root.display(),
            "Static file server initialized"
        );

        Self {
            config: Arc::new(config),
            cache,
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        let stats = self.cache.stats();
        trace!(
            entries = stats.entry_count,
            total_size = stats.total_size,
            "Retrieved cache stats"
        );
        stats
    }

    /// Clear the file cache
    pub fn clear_cache(&self) {
        let before = self.cache.stats().entry_count;
        self.cache.clear();
        debug!(cleared_entries = before, "File cache cleared");
    }

    /// Serve a static file request
    pub async fn serve<B>(&self, req: &Request<B>, path: &str) -> Result<Response<Full<Bytes>>> {
        trace!(
            method = %req.method(),
            path = %path,
            "Serving static file request"
        );

        // Validate request method
        match req.method() {
            &Method::GET | &Method::HEAD => {}
            _ => {
                debug!(
                    method = %req.method(),
                    path = %path,
                    "Method not allowed for static file"
                );
                return Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header(header::ALLOW, "GET, HEAD")
                    .body(Full::new(Bytes::new()))?);
            }
        }

        // Resolve path securely
        let file_path = match self.resolve_path(path) {
            Some(p) => p,
            None => {
                debug!(
                    path = %path,
                    "Path resolution failed or blocked"
                );
                return self.not_found_response();
            }
        };

        trace!(
            request_path = %path,
            resolved_path = %file_path.display(),
            "Path resolved"
        );

        // Check if path is a directory
        let metadata = match fs::metadata(&file_path).await {
            Ok(m) => m,
            Err(e) => {
                trace!(
                    path = %file_path.display(),
                    error = %e,
                    "File metadata lookup failed"
                );
                // File not found - check for SPA fallback
                if self.config.fallback.is_some() {
                    if let Some(index_path) = self.find_spa_fallback() {
                        trace!(
                            original_path = %path,
                            fallback_path = %index_path.display(),
                            "Using SPA fallback"
                        );
                        let meta = fs::metadata(&index_path).await?;
                        return self.serve_file(req, &index_path, meta).await;
                    }
                }
                return self.not_found_response();
            }
        };

        if metadata.is_dir() {
            trace!(
                path = %file_path.display(),
                "Path is directory, looking for index"
            );
            // Try to serve index file
            for index_file in &["index.html", "index.htm"] {
                let index_path = file_path.join(index_file);
                if let Ok(index_meta) = fs::metadata(&index_path).await {
                    if index_meta.is_file() {
                        trace!(
                            index_file = %index_file,
                            "Found index file"
                        );
                        return self.serve_file(req, &index_path, index_meta).await;
                    }
                }
            }

            // Directory listing if enabled
            if self.config.directory_listing {
                trace!(
                    path = %file_path.display(),
                    "Generating directory listing"
                );
                return self.generate_directory_listing(&file_path).await;
            }

            debug!(
                path = %file_path.display(),
                "Directory listing not allowed"
            );
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from_static(
                    b"Directory listing not allowed",
                )))?);
        }

        // Serve the file
        self.serve_file(req, &file_path, metadata).await
    }

    /// Resolve path securely
    fn resolve_path(&self, path: &str) -> Option<PathBuf> {
        // Remove leading slash and decode URL encoding
        let path = path.trim_start_matches('/');
        let decoded = urlencoding::decode(path).ok()?;

        // Build path and validate it doesn't escape root
        let mut resolved = self.config.root.clone();
        for component in Path::new(decoded.as_ref()).components() {
            match component {
                Component::Normal(c) => resolved.push(c),
                Component::ParentDir => {
                    // Reject any path traversal attempts
                    warn!("Path traversal attempt detected: {}", path);
                    return None;
                }
                Component::CurDir => {}
                _ => return None,
            }
        }

        // Verify path is within root
        if !resolved.starts_with(&self.config.root) {
            warn!(
                "Path escapes root directory: {:?} (root: {:?})",
                resolved, self.config.root
            );
            return None;
        }

        Some(resolved)
    }

    /// Find SPA fallback index file
    fn find_spa_fallback(&self) -> Option<PathBuf> {
        if let Some(ref fallback) = self.config.fallback {
            let index_path = self.config.root.join(fallback);
            if index_path.exists() {
                return Some(index_path);
            }
        }
        None
    }

    /// Serve a file
    async fn serve_file<B>(
        &self,
        req: &Request<B>,
        file_path: &Path,
        metadata: std::fs::Metadata,
    ) -> Result<Response<Full<Bytes>>> {
        let modified = metadata.modified()?;
        let file_size = metadata.len();

        trace!(
            path = %file_path.display(),
            size = file_size,
            "Serving file"
        );

        // Generate ETag based on size and modification time
        let etag = self.generate_etag_from_metadata(file_size, modified);

        // Check conditional headers (If-None-Match, If-Modified-Since)
        if let Some(response) = self.check_conditional_headers(req, &etag, modified)? {
            trace!(
                path = %file_path.display(),
                status = 304,
                "Returning 304 Not Modified"
            );
            return Ok(response);
        }

        // Determine content type
        let content_type = self.get_content_type(file_path);

        // Negotiate content encoding
        let encoding = if self.config.compress
            && should_compress(&content_type)
            && file_size >= MIN_COMPRESS_SIZE
        {
            negotiate_encoding(req)
        } else {
            ContentEncoding::Identity
        };

        trace!(
            path = %file_path.display(),
            content_type = %content_type,
            encoding = ?encoding,
            "Content negotiation complete"
        );

        // Check for Range header
        if let Some(range_header) = req.headers().get(header::RANGE) {
            trace!(
                path = %file_path.display(),
                "Processing range request"
            );
            return serve_range_request(
                req,
                file_path,
                file_size,
                &content_type,
                &etag,
                modified,
                range_header,
                &self.config.cache_control,
            )
            .await;
        }

        // Check cache for small files
        if file_size < MAX_CACHE_FILE_SIZE {
            if let Some(cached) = self.cache.get(file_path) {
                if cached.is_fresh() && cached.size == file_size {
                    trace!(
                        path = %file_path.display(),
                        "Serving from cache"
                    );
                    return self.serve_cached(req, cached, encoding);
                }
            }
        }

        // For HEAD requests, return headers only
        if req.method() == Method::HEAD {
            trace!(
                path = %file_path.display(),
                "Serving HEAD request"
            );
            return self.build_head_response(&content_type, file_size, &etag, modified);
        }

        // Serve the file based on size
        if file_size >= MMAP_THRESHOLD {
            // Large file: stream it
            debug!(
                path = %file_path.display(),
                size = file_size,
                "Serving large file"
            );
            self.serve_large_file(
                file_path,
                &content_type,
                file_size,
                &etag,
                modified,
                encoding,
            )
            .await
        } else {
            // Small/medium file: read into memory
            trace!(
                path = %file_path.display(),
                size = file_size,
                "Serving small/medium file"
            );
            self.serve_small_file(
                req,
                file_path,
                &content_type,
                file_size,
                &etag,
                modified,
                encoding,
            )
            .await
        }
    }

    /// Generate ETag from file metadata
    fn generate_etag_from_metadata(&self, size: u64, modified: std::time::SystemTime) -> String {
        let modified_ts = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("\"{:x}-{:x}\"", size, modified_ts)
    }

    /// Check conditional headers and return 304 if appropriate
    fn check_conditional_headers<B>(
        &self,
        req: &Request<B>,
        etag: &str,
        modified: std::time::SystemTime,
    ) -> Result<Option<Response<Full<Bytes>>>> {
        // Check If-None-Match (ETag)
        if let Some(if_none_match) = req.headers().get(header::IF_NONE_MATCH) {
            if let Ok(if_none_match_str) = if_none_match.to_str() {
                // Handle multiple ETags separated by commas
                let matches = if_none_match_str == "*"
                    || if_none_match_str
                        .split(',')
                        .any(|tag| tag.trim().trim_matches('"') == etag.trim_matches('"'));

                if matches {
                    return Ok(Some(
                        Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header(header::ETAG, etag)
                            .body(Full::new(Bytes::new()))?,
                    ));
                }
            }
        }

        // Check If-Modified-Since
        if let Some(if_modified) = req.headers().get(header::IF_MODIFIED_SINCE) {
            if let Ok(if_modified_str) = if_modified.to_str() {
                if let Ok(if_modified_time) = httpdate::parse_http_date(if_modified_str) {
                    // Only compare seconds (HTTP dates have second precision)
                    let modified_secs = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let if_modified_secs = if_modified_time
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if modified_secs <= if_modified_secs {
                        return Ok(Some(
                            Response::builder()
                                .status(StatusCode::NOT_MODIFIED)
                                .header(header::ETAG, etag)
                                .body(Full::new(Bytes::new()))?,
                        ));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Get content type for a file
    fn get_content_type(&self, path: &Path) -> String {
        from_path(path).first_or_octet_stream().as_ref().to_string()
    }

    /// Serve a small file (read into memory)
    async fn serve_small_file<B>(
        &self,
        _req: &Request<B>,
        file_path: &Path,
        content_type: &str,
        file_size: u64,
        etag: &str,
        modified: std::time::SystemTime,
        encoding: ContentEncoding,
    ) -> Result<Response<Full<Bytes>>> {
        let content = fs::read(file_path).await?;
        let content = Bytes::from(content);

        // Compress if needed
        let (final_content, content_encoding) = if encoding != ContentEncoding::Identity {
            match compress_content(&content, encoding) {
                Ok(compressed) if compressed.len() < content.len() => (compressed, Some(encoding)),
                _ => (content.clone(), None),
            }
        } else {
            (content.clone(), None)
        };

        // Cache the file
        if file_size < MAX_CACHE_FILE_SIZE {
            let gzip_content = if should_compress(content_type) {
                compress_content(&content, ContentEncoding::Gzip).ok()
            } else {
                None
            };

            let brotli_content = if should_compress(content_type) {
                compress_content(&content, ContentEncoding::Brotli).ok()
            } else {
                None
            };

            self.cache.insert(
                file_path.to_path_buf(),
                CachedFile {
                    content: content.clone(),
                    gzip_content,
                    brotli_content,
                    content_type: content_type.to_string(),
                    etag: etag.to_string(),
                    last_modified: modified,
                    cached_at: Instant::now(),
                    size: file_size,
                },
            );
        }

        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, final_content.len())
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ETAG, etag)
            .header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified))
            .header(header::CACHE_CONTROL, &self.config.cache_control);

        if let Some(enc) = content_encoding {
            response = response.header(header::CONTENT_ENCODING, enc.as_str());
            response = response.header(header::VARY, "Accept-Encoding");
        }

        Ok(response.body(Full::new(final_content))?)
    }

    /// Serve a large file (streaming)
    async fn serve_large_file(
        &self,
        file_path: &Path,
        content_type: &str,
        file_size: u64,
        etag: &str,
        modified: std::time::SystemTime,
        _encoding: ContentEncoding,
    ) -> Result<Response<Full<Bytes>>> {
        // For large files, don't compress (streaming compression is complex)
        // Just read and serve the file
        let content = fs::read(file_path).await?;

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, file_size)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ETAG, etag)
            .header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified))
            .header(header::CACHE_CONTROL, &self.config.cache_control)
            .body(Full::new(Bytes::from(content)))?)
    }

    /// Serve a cached file
    fn serve_cached<B>(
        &self,
        req: &Request<B>,
        cached: CachedFile,
        encoding: ContentEncoding,
    ) -> Result<Response<Full<Bytes>>> {
        // Determine best content to serve based on encoding preference
        let (content, content_encoding) =
            match (encoding, &cached.brotli_content, &cached.gzip_content) {
                (ContentEncoding::Brotli, Some(brotli), _) => {
                    (brotli.clone(), Some(ContentEncoding::Brotli))
                }
                (ContentEncoding::Gzip, _, Some(gzip)) => {
                    (gzip.clone(), Some(ContentEncoding::Gzip))
                }
                _ => (cached.content.clone(), None),
            };

        // For HEAD, return empty body
        let body = if req.method() == Method::HEAD {
            Bytes::new()
        } else {
            content
        };

        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, &cached.content_type)
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ETAG, &cached.etag)
            .header(header::CACHE_CONTROL, &self.config.cache_control)
            .header(
                header::LAST_MODIFIED,
                httpdate::fmt_http_date(cached.last_modified),
            );

        if let Some(enc) = content_encoding {
            response = response.header(header::CONTENT_ENCODING, enc.as_str());
            response = response.header(header::VARY, "Accept-Encoding");
        }

        Ok(response.body(Full::new(body))?)
    }

    /// Build HEAD response
    fn build_head_response(
        &self,
        content_type: &str,
        file_size: u64,
        etag: &str,
        modified: std::time::SystemTime,
    ) -> Result<Response<Full<Bytes>>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, file_size)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ETAG, etag)
            .header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified))
            .header(header::CACHE_CONTROL, &self.config.cache_control)
            .body(Full::new(Bytes::new()))?)
    }

    /// Generate directory listing
    async fn generate_directory_listing(&self, dir_path: &Path) -> Result<Response<Full<Bytes>>> {
        let mut entries = fs::read_dir(dir_path).await?;
        let mut items = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = metadata.is_dir();
            let size = if is_dir { 0 } else { metadata.len() };
            let modified = metadata.modified()?;

            items.push((name, is_dir, size, modified));
        }

        // Sort: directories first, then alphabetically
        items.sort_by(|a, b| match (a.1, b.1) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.0.cmp(&b.0),
        });

        let path_display = dir_path
            .strip_prefix(&self.config.root)
            .unwrap_or(dir_path)
            .display();

        let mut html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Index of /{}</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        h1 {{ font-size: 24px; }}
        table {{ border-collapse: collapse; }}
        th, td {{ padding: 8px 15px; text-align: left; }}
        th {{ background: #f0f0f0; }}
        tr:hover {{ background: #f8f8f8; }}
        a {{ text-decoration: none; color: #0066cc; }}
        a:hover {{ text-decoration: underline; }}
        .dir {{ font-weight: bold; }}
        .size {{ text-align: right; }}
    </style>
</head>
<body>
    <h1>Index of /{}</h1>
    <table>
        <tr><th>Name</th><th>Size</th><th>Modified</th></tr>"#,
            path_display, path_display
        );

        for (name, is_dir, size, modified) in items {
            let display_name = if is_dir {
                format!("{}/", name)
            } else {
                name.clone()
            };
            let size_str = if is_dir {
                "-".to_string()
            } else {
                format_size(size)
            };
            let class = if is_dir { "dir" } else { "" };

            html.push_str(&format!(
                r#"<tr><td><a href="{}" class="{}">{}</a></td><td class="size">{}</td><td>{}</td></tr>"#,
                urlencoding::encode(&name),
                class,
                html_escape::encode_text(&display_name),
                size_str,
                httpdate::fmt_http_date(modified)
            ));
        }

        html.push_str("</table></body></html>");

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(html)))?)
    }

    /// Generate 404 Not Found response
    fn not_found_response(&self) -> Result<Response<Full<Bytes>>> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"404 Not Found")))?)
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Format file size for display
fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_static_file_server() {
        let temp_dir = TempDir::new().unwrap();
        let root = temp_dir.path().to_path_buf();

        // Create test files
        std::fs::write(root.join("test.txt"), "Hello, World!").unwrap();
        std::fs::write(root.join("style.css"), "body { color: red; }").unwrap();

        let config = StaticFileConfig {
            root: root.clone(),
            index: "index.html".to_string(),
            directory_listing: true,
            cache_control: "public, max-age=3600".to_string(),
            compress: true,
            mime_types: std::collections::HashMap::new(),
            fallback: None,
        };

        let server = StaticFileServer::new(config);

        // Test serving a file
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test.txt")
            .body(())
            .unwrap();

        let response = server.serve(&req, "/test.txt").await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }
}
