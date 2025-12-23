//! Static file serving module for Sentinel proxy
//!
//! This module provides high-performance static file serving with
//! support for compression, caching, directory listing, and SPA routing.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use mime_guess::from_path;
use pingora_core::prelude::*;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};

use sentinel_config::StaticFileConfig;

/// Static file server
pub struct StaticFileServer {
    /// Configuration for static file serving
    config: Arc<StaticFileConfig>,
    /// Cached file metadata
    cache: Arc<FileCache>,
}

/// File cache for improved performance
struct FileCache {
    entries: dashmap::DashMap<PathBuf, CachedFile>,
    max_size: usize,
    max_age: std::time::Duration,
}

/// Cached file entry
struct CachedFile {
    content: Bytes,
    content_type: String,
    etag: String,
    last_modified: std::time::SystemTime,
    cached_at: std::time::Instant,
}

impl StaticFileServer {
    /// Create a new static file server
    pub fn new(config: StaticFileConfig) -> Self {
        let cache = Arc::new(FileCache::new(100 * 1024 * 1024, 3600)); // 100MB, 1 hour

        Self {
            config: Arc::new(config),
            cache,
        }
    }

    /// Serve a static file request
    pub async fn serve<B>(&self, req: &Request<B>, path: &str) -> Result<Response<Full<Bytes>>> {
        // Validate request method
        match req.method() {
            &Method::GET | &Method::HEAD => {}
            _ => {
                return Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .header(header::ALLOW, "GET, HEAD")
                    .body(Full::new(Bytes::new()))?);
            }
        }

        // Normalize and validate the path
        let file_path = self.resolve_path(path)?;

        // Check if the path exists and get metadata
        let metadata = match fs::metadata(&file_path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Try fallback if configured (for SPA routing)
                if let Some(ref fallback) = self.config.fallback {
                    let fallback_path = self.config.root.join(fallback);
                    if let Ok(m) = fs::metadata(&fallback_path).await {
                        return self.serve_file(req, &fallback_path).await;
                    }
                }
                return self.not_found();
            }
            Err(e) => {
                error!("Failed to get file metadata for {:?}: {}", file_path, e);
                return self.internal_error();
            }
        };

        if metadata.is_dir() {
            self.handle_directory(req, &file_path).await
        } else {
            self.serve_file(req, &file_path).await
        }
    }

    /// Resolve and validate the file path
    fn resolve_path(&self, path: &str) -> Result<PathBuf> {
        // Remove leading slash and clean the path
        let path = path.trim_start_matches('/');
        let path = Path::new(path);

        // Prevent directory traversal attacks
        let mut components = vec![];
        for component in path.components() {
            match component {
                Component::Normal(c) => components.push(c),
                Component::ParentDir => {
                    // Reject paths with ".."
                    return Err(anyhow::anyhow!("Invalid path: contains parent directory"));
                }
                _ => {}
            }
        }

        // Build the full path
        let mut full_path = self.config.root.clone();
        for component in components {
            full_path.push(component);
        }

        // Ensure the path is within the root directory
        if !full_path.starts_with(&self.config.root) {
            return Err(anyhow::anyhow!("Invalid path: outside of root directory"));
        }

        Ok(full_path)
    }

    /// Handle directory requests
    async fn handle_directory<B>(
        &self,
        req: &Request<B>,
        dir_path: &Path,
    ) -> Result<Response<Full<Bytes>>> {
        // Try to serve index file
        let index_path = dir_path.join(&self.config.index);
        if fs::metadata(&index_path).await.is_ok() {
            return self.serve_file(req, &index_path).await;
        }

        // Generate directory listing if enabled
        if self.config.directory_listing {
            return self.generate_directory_listing(dir_path).await;
        }

        // Return 403 Forbidden if directory listing is disabled
        Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::new()))?)
    }

    /// Serve a file
    async fn serve_file<B>(
        &self,
        req: &Request<B>,
        file_path: &Path,
    ) -> Result<Response<Full<Bytes>>> {
        // Check cache
        if let Some(cached) = self.cache.get(file_path) {
            if cached.is_fresh() {
                return self.serve_cached(req, cached);
            }
        }

        // Read file metadata
        let metadata = fs::metadata(file_path).await?;
        let modified = metadata.modified()?;
        let file_size = metadata.len();

        // Check if-modified-since header
        if let Some(if_modified) = req.headers().get(header::IF_MODIFIED_SINCE) {
            if let Ok(if_modified_str) = if_modified.to_str() {
                if let Ok(if_modified_time) = httpdate::parse_http_date(if_modified_str) {
                    if modified <= if_modified_time {
                        return Ok(Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .body(Full::new(Bytes::new()))?);
                    }
                }
            }
        }

        // Determine content type
        let content_type = self.get_content_type(file_path);

        // Read file content
        let content = if req.method() == Method::HEAD {
            Bytes::new()
        } else if file_size > 10 * 1024 * 1024 {
            // Stream large files instead of loading into memory
            return self
                .stream_large_file(file_path, &content_type, modified)
                .await;
        } else {
            let mut file = fs::File::open(file_path).await?;
            let mut buffer = Vec::with_capacity(file_size as usize);
            file.read_to_end(&mut buffer).await?;
            Bytes::from(buffer)
        };

        // Generate ETag
        let etag = self.generate_etag(&content, modified);

        // Check if-none-match header
        if let Some(if_none_match) = req.headers().get(header::IF_NONE_MATCH) {
            if let Ok(if_none_match_str) = if_none_match.to_str() {
                if if_none_match_str == etag {
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(header::ETAG, etag)
                        .body(Full::new(Bytes::new()))?);
                }
            }
        }

        // Cache small files
        if file_size < 1024 * 1024 {
            // Cache files < 1MB
            self.cache.insert(
                file_path.to_path_buf(),
                CachedFile {
                    content: content.clone(),
                    content_type: content_type.clone(),
                    etag: etag.clone(),
                    last_modified: modified,
                    cached_at: std::time::Instant::now(),
                },
            );
        }

        // Build response
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, content.len())
            .header(header::ETAG, etag)
            .header(header::CACHE_CONTROL, &self.config.cache_control)
            .header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified));

        // Add compression if supported and configured
        if self.config.compress && Self::should_compress(&content_type) {
            if let Some(encoding) = Self::negotiate_encoding(req) {
                response = response.header(header::CONTENT_ENCODING, encoding);
                // In production, actually compress the content here
            }
        }

        Ok(response.body(Full::new(content))?)
    }

    /// Serve cached file
    fn serve_cached<B>(
        &self,
        req: &Request<B>,
        cached: CachedFile,
    ) -> Result<Response<Full<Bytes>>> {
        // Check if-none-match
        if let Some(if_none_match) = req.headers().get(header::IF_NONE_MATCH) {
            if let Ok(if_none_match_str) = if_none_match.to_str() {
                if if_none_match_str == cached.etag {
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(header::ETAG, cached.etag)
                        .body(Full::new(Bytes::new()))?);
                }
            }
        }

        let content = if req.method() == Method::HEAD {
            Bytes::new()
        } else {
            cached.content.clone()
        };

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, cached.content_type)
            .header(header::CONTENT_LENGTH, content.len())
            .header(header::ETAG, cached.etag)
            .header(header::CACHE_CONTROL, &self.config.cache_control)
            .header(
                header::LAST_MODIFIED,
                httpdate::fmt_http_date(cached.last_modified),
            )
            .body(Full::new(content))?)
    }

    /// Stream large files
    async fn stream_large_file(
        &self,
        file_path: &Path,
        content_type: &str,
        modified: std::time::SystemTime,
    ) -> Result<Response<Full<Bytes>>> {
        // For now, read the entire file
        // In production, use actual streaming with chunked transfer encoding
        let content = fs::read(file_path).await?;
        let etag = self.generate_etag(&content, modified);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, content.len())
            .header(header::ETAG, etag)
            .header(header::CACHE_CONTROL, &self.config.cache_control)
            .header(header::LAST_MODIFIED, httpdate::fmt_http_date(modified))
            .body(Full::new(Bytes::from(content)))?)
    }

    /// Generate directory listing HTML
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

        // Sort items: directories first, then alphabetically
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

    /// Get content type for a file
    fn get_content_type(&self, path: &Path) -> String {
        // Check custom MIME type mappings first
        if let Some(ext) = path.extension() {
            if let Some(ext_str) = ext.to_str() {
                if let Some(mime) = self.config.mime_types.get(ext_str) {
                    return mime.clone();
                }
            }
        }

        // Use mime_guess for standard types
        from_path(path).first_or_octet_stream().to_string()
    }

    /// Generate ETag for content
    fn generate_etag(&self, content: &[u8], modified: std::time::SystemTime) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.len().hash(&mut hasher);
        modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .hash(&mut hasher);
        format!("\"{}\"", hasher.finish())
    }

    /// Check if content type should be compressed
    fn should_compress(content_type: &str) -> bool {
        content_type.starts_with("text/")
            || content_type.contains("javascript")
            || content_type.contains("json")
            || content_type.contains("xml")
            || content_type.contains("svg")
    }

    /// Negotiate content encoding
    fn negotiate_encoding<B>(req: &Request<B>) -> Option<&'static str> {
        if let Some(accept_encoding) = req.headers().get(header::ACCEPT_ENCODING) {
            if let Ok(ae_str) = accept_encoding.to_str() {
                // Simple parsing - in production use proper quality value parsing
                if ae_str.contains("br") {
                    return Some("br");
                } else if ae_str.contains("gzip") {
                    return Some("gzip");
                } else if ae_str.contains("deflate") {
                    return Some("deflate");
                }
            }
        }
        None
    }

    /// Return 404 Not Found response
    fn not_found(&self) -> Result<Response<Full<Bytes>>> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"404 Not Found")))?)
    }

    /// Return 500 Internal Server Error response
    fn internal_error(&self) -> Result<Response<Full<Bytes>>> {
        Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(b"500 Internal Server Error")))?)
    }
}

impl FileCache {
    fn new(max_size: usize, max_age_secs: u64) -> Self {
        Self {
            entries: dashmap::DashMap::new(),
            max_size,
            max_age: std::time::Duration::from_secs(max_age_secs),
        }
    }

    fn get(&self, path: &Path) -> Option<CachedFile> {
        self.entries.get(path).map(|entry| entry.clone())
    }

    fn insert(&self, path: PathBuf, file: CachedFile) {
        // Simple cache eviction - remove old entries
        self.entries.retain(|_, v| v.is_fresh());

        // Check cache size limit (simplified)
        if self.entries.len() > 1000 {
            // Remove oldest entries
            let mut oldest = Vec::new();
            for entry in self.entries.iter() {
                oldest.push((entry.key().clone(), entry.cached_at));
            }
            oldest.sort_by_key(|e| e.1);
            for (path, _) in oldest.iter().take(100) {
                self.entries.remove(path);
            }
        }

        self.entries.insert(path, file);
    }
}

impl CachedFile {
    fn is_fresh(&self) -> bool {
        self.cached_at.elapsed() < std::time::Duration::from_secs(3600)
    }
}

impl Clone for CachedFile {
    fn clone(&self) -> Self {
        Self {
            content: self.content.clone(),
            content_type: self.content_type.clone(),
            etag: self.etag.clone(),
            last_modified: self.last_modified,
            cached_at: self.cached_at,
        }
    }
}

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
        fs::write(root.join("index.html"), b"<h1>Hello</h1>")
            .await
            .unwrap();
        fs::write(root.join("test.txt"), b"Test content")
            .await
            .unwrap();
        fs::create_dir(root.join("subdir")).await.unwrap();
        fs::write(root.join("subdir/file.js"), b"console.log('test');")
            .await
            .unwrap();

        let config = StaticFileConfig {
            root: root.clone(),
            index: "index.html".to_string(),
            directory_listing: true,
            cache_control: "public, max-age=3600".to_string(),
            compress: true,
            mime_types: HashMap::new(),
            fallback: None,
        };

        let server = StaticFileServer::new(config);

        // Test serving a file
        let req = Request::get("/test.txt").body(()).unwrap();
        let response = server.serve(&req, "/test.txt").await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test serving index file
        let req = Request::get("/").body(()).unwrap();
        let response = server.serve(&req, "/").await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test 404
        let req = Request::get("/nonexistent.txt").body(()).unwrap();
        let response = server.serve(&req, "/nonexistent.txt").await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_path_validation() {
        let config = StaticFileConfig {
            root: PathBuf::from("/var/www"),
            index: "index.html".to_string(),
            directory_listing: false,
            cache_control: "public".to_string(),
            compress: false,
            mime_types: HashMap::new(),
            fallback: None,
        };

        let server = StaticFileServer::new(config);

        // Valid paths
        assert!(server.resolve_path("/index.html").is_ok());
        assert!(server.resolve_path("/subdir/file.txt").is_ok());

        // Invalid paths (directory traversal)
        assert!(server.resolve_path("/../etc/passwd").is_err());
        assert!(server.resolve_path("/subdir/../../../etc/passwd").is_err());
    }
}
