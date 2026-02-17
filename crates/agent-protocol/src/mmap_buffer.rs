//! Memory-mapped buffers for efficient large body handling.
//!
//! This module provides `LargeBodyBuffer`, a smart buffer that automatically
//! switches between in-memory storage (for small bodies) and memory-mapped
//! files (for large bodies) to minimize heap memory usage.
//!
//! # Feature Flag
//!
//! This module requires the `mmap-buffers` feature flag:
//!
//! ```toml
//! [dependencies]
//! zentinel-agent-protocol = { version = "0.3", features = ["mmap-buffers"] }
//! ```
//!
//! # Performance
//!
//! - **Small bodies** (< threshold): Zero-copy in-memory buffer
//! - **Large bodies** (>= threshold): Memory-mapped temp file with OS-level caching
//!
//! Memory-mapped files provide:
//! - Lazy loading: Data is loaded on-demand as pages are accessed
//! - OS caching: The kernel manages memory pressure efficiently
//! - Zero-copy potential: Can pass directly to I/O without copying
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_protocol::mmap_buffer::{LargeBodyBuffer, LargeBodyBufferConfig};
//!
//! // Configure with 1MB threshold
//! let config = LargeBodyBufferConfig {
//!     mmap_threshold: 1024 * 1024, // 1MB
//!     ..Default::default()
//! };
//!
//! let mut buffer = LargeBodyBuffer::with_config(config);
//!
//! // Write data (small chunks go to memory, spills to mmap above threshold)
//! buffer.write_chunk(b"request body data...")?;
//!
//! // Read back - seamless regardless of storage type
//! let data = buffer.as_slice()?;
//! ```

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use memmap2::Mmap;
use tempfile::NamedTempFile;

/// Configuration for large body buffer behavior.
#[derive(Debug, Clone)]
pub struct LargeBodyBufferConfig {
    /// Threshold in bytes above which to use memory-mapped files.
    ///
    /// Bodies smaller than this are kept in memory. Bodies larger than this
    /// are written to a temp file and memory-mapped.
    ///
    /// Default: 1MB (1,048,576 bytes)
    pub mmap_threshold: usize,

    /// Maximum body size allowed.
    ///
    /// Writes that would exceed this size return an error.
    ///
    /// Default: 100MB (104,857,600 bytes)
    pub max_body_size: usize,

    /// Custom temp directory for mmap files.
    ///
    /// If None, uses the system default temp directory.
    ///
    /// Default: None (system temp)
    pub temp_dir: Option<PathBuf>,
}

impl Default for LargeBodyBufferConfig {
    fn default() -> Self {
        Self {
            mmap_threshold: 1024 * 1024,      // 1MB
            max_body_size: 100 * 1024 * 1024, // 100MB
            temp_dir: None,
        }
    }
}

/// Storage backend for the buffer.
enum BufferStorage {
    /// In-memory Vec for small bodies
    Memory(Vec<u8>),
    /// Memory-mapped temp file for large bodies
    Mmap {
        file: NamedTempFile,
        len: usize,
        /// We use Mmap (read-only) for the stored mapping. When we need to write,
        /// we drop this and write directly to the file, then re-map.
        mmap: Option<Mmap>,
    },
}

/// A buffer that automatically uses memory-mapped files for large bodies.
///
/// This provides efficient handling of request/response bodies that may be
/// very large (file uploads, large API responses) without consuming heap
/// memory proportional to body size.
///
/// # Storage Strategy
///
/// - Bodies below `mmap_threshold`: Stored in a `Vec<u8>` in heap memory
/// - Bodies above `mmap_threshold`: Written to a temp file and memory-mapped
///
/// The transition is automatic and transparent to the caller.
///
/// # Thread Safety
///
/// `LargeBodyBuffer` is NOT thread-safe. It should be used from a single task.
/// For concurrent access, wrap in `Arc<Mutex<_>>` or use per-task buffers.
pub struct LargeBodyBuffer {
    config: LargeBodyBufferConfig,
    storage: BufferStorage,
    total_written: usize,
}

impl LargeBodyBuffer {
    /// Create a new buffer with default configuration.
    pub fn new() -> Self {
        Self::with_config(LargeBodyBufferConfig::default())
    }

    /// Create a new buffer with custom configuration.
    pub fn with_config(config: LargeBodyBufferConfig) -> Self {
        Self {
            config,
            storage: BufferStorage::Memory(Vec::new()),
            total_written: 0,
        }
    }

    /// Get the current buffer configuration.
    pub fn config(&self) -> &LargeBodyBufferConfig {
        &self.config
    }

    /// Get the total number of bytes written to the buffer.
    pub fn len(&self) -> usize {
        self.total_written
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.total_written == 0
    }

    /// Check if the buffer is using memory-mapped storage.
    pub fn is_mmap(&self) -> bool {
        matches!(self.storage, BufferStorage::Mmap { .. })
    }

    /// Write a chunk of data to the buffer.
    ///
    /// If this write would exceed `max_body_size`, an error is returned.
    /// If this write pushes the buffer over `mmap_threshold`, the buffer
    /// automatically transitions to memory-mapped storage.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The write would exceed `max_body_size`
    /// - Failed to create temp file (for mmap transition)
    /// - Failed to write to storage
    pub fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let new_size = self.total_written + data.len();

        // Check size limit
        if new_size > self.config.max_body_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Body size {} exceeds maximum {}",
                    new_size, self.config.max_body_size
                ),
            ));
        }

        // Check if we need to transition to mmap
        if new_size >= self.config.mmap_threshold {
            self.ensure_mmap()?;
        }

        // Write to storage
        match &mut self.storage {
            BufferStorage::Memory(vec) => {
                vec.extend_from_slice(data);
            }
            BufferStorage::Mmap { file, len, mmap } => {
                // Unmap if mapped (to allow file to grow)
                *mmap = None;

                // Seek to end and write
                file.as_file_mut().seek(SeekFrom::End(0))?;
                file.as_file_mut().write_all(data)?;
                *len = new_size;
            }
        }

        self.total_written = new_size;
        Ok(())
    }

    /// Get the buffer contents as a slice.
    ///
    /// For mmap storage, this creates or returns the memory mapping.
    ///
    /// # Errors
    ///
    /// Returns an error if the memory mapping fails.
    pub fn as_slice(&mut self) -> io::Result<&[u8]> {
        match &mut self.storage {
            BufferStorage::Memory(vec) => Ok(vec.as_slice()),
            BufferStorage::Mmap { file, len, mmap } => {
                // Create mmap if not already mapped
                if mmap.is_none() {
                    file.as_file_mut().sync_all()?;
                    // SAFETY: We control all writes to this file and ensure
                    // it's not modified while mapped
                    let mapped = unsafe { Mmap::map(file.as_file())? };
                    *mmap = Some(mapped);
                }
                Ok(&mmap.as_ref().unwrap()[..*len])
            }
        }
    }

    /// Get mutable access to buffer contents.
    ///
    /// For mmap storage, this reads the file into memory for modification.
    /// Note: After calling this on mmap storage, the buffer transitions to
    /// in-memory storage.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn as_mut_slice(&mut self) -> io::Result<&mut [u8]> {
        // If in mmap mode, convert to memory first
        self.convert_mmap_to_memory()?;

        if let BufferStorage::Memory(ref mut vec) = self.storage {
            Ok(vec.as_mut_slice())
        } else {
            unreachable!("convert_mmap_to_memory should have converted to Memory")
        }
    }

    /// Convert mmap storage to memory storage if needed.
    fn convert_mmap_to_memory(&mut self) -> io::Result<()> {
        if let BufferStorage::Mmap { file, len, mmap } = &mut self.storage {
            // Drop any existing mapping
            *mmap = None;
            file.as_file_mut().sync_all()?;

            let data_len = *len;

            // Read file into memory
            let mut vec = Vec::with_capacity(data_len);
            file.as_file_mut().seek(SeekFrom::Start(0))?;
            file.as_file_mut().read_to_end(&mut vec)?;

            // Store in a temporary
            let new_storage = BufferStorage::Memory(vec);
            self.storage = new_storage;
        }
        Ok(())
    }

    /// Clear the buffer, releasing all memory and temp files.
    pub fn clear(&mut self) {
        self.storage = BufferStorage::Memory(Vec::new());
        self.total_written = 0;
    }

    /// Take ownership of the buffer contents as a Vec<u8>.
    ///
    /// For mmap storage, this reads the entire file into memory.
    /// Use with caution for large bodies.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from mmap storage fails.
    pub fn into_vec(mut self) -> io::Result<Vec<u8>> {
        match &mut self.storage {
            BufferStorage::Memory(vec) => Ok(std::mem::take(vec)),
            BufferStorage::Mmap { file, len, mmap } => {
                // Drop any existing mmap
                *mmap = None;

                // Read the file contents
                let mut vec = Vec::with_capacity(*len);
                file.as_file_mut().seek(SeekFrom::Start(0))?;
                file.as_file_mut().read_to_end(&mut vec)?;
                Ok(vec)
            }
        }
    }

    /// Transition from memory storage to mmap storage.
    fn ensure_mmap(&mut self) -> io::Result<()> {
        if matches!(self.storage, BufferStorage::Mmap { .. }) {
            return Ok(());
        }

        // Create temp file
        let temp_file = match &self.config.temp_dir {
            Some(dir) => NamedTempFile::new_in(dir)?,
            None => NamedTempFile::new()?,
        };

        // Copy existing data to temp file
        if let BufferStorage::Memory(vec) = &self.storage {
            temp_file.as_file().write_all(vec)?;
        }

        self.storage = BufferStorage::Mmap {
            file: temp_file,
            len: self.total_written,
            mmap: None,
        };

        Ok(())
    }
}

impl Default for LargeBodyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LargeBodyBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LargeBodyBuffer")
            .field("len", &self.total_written)
            .field("is_mmap", &self.is_mmap())
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = LargeBodyBufferConfig::default();
        assert_eq!(config.mmap_threshold, 1024 * 1024);
        assert_eq!(config.max_body_size, 100 * 1024 * 1024);
        assert!(config.temp_dir.is_none());
    }

    #[test]
    fn test_new_buffer() {
        let buffer = LargeBodyBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert!(!buffer.is_mmap());
    }

    #[test]
    fn test_small_body_stays_in_memory() {
        let mut buffer = LargeBodyBuffer::with_config(LargeBodyBufferConfig {
            mmap_threshold: 1024,
            max_body_size: 10 * 1024,
            temp_dir: None,
        });

        buffer.write_chunk(b"hello world").unwrap();
        assert!(!buffer.is_mmap());
        assert_eq!(buffer.len(), 11);

        let data = buffer.as_slice().unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn test_large_body_uses_mmap() {
        let mut buffer = LargeBodyBuffer::with_config(LargeBodyBufferConfig {
            mmap_threshold: 100,
            max_body_size: 10 * 1024,
            temp_dir: None,
        });

        // Write data that exceeds threshold
        let data = vec![0u8; 200];
        buffer.write_chunk(&data).unwrap();

        assert!(buffer.is_mmap());
        assert_eq!(buffer.len(), 200);

        let slice = buffer.as_slice().unwrap();
        assert_eq!(slice.len(), 200);
    }

    #[test]
    fn test_transition_to_mmap_preserves_data() {
        let mut buffer = LargeBodyBuffer::with_config(LargeBodyBufferConfig {
            mmap_threshold: 50,
            max_body_size: 1024,
            temp_dir: None,
        });

        // Write small chunk first
        buffer.write_chunk(b"initial data ").unwrap();
        assert!(!buffer.is_mmap());

        // Write more to trigger transition
        let padding = vec![b'x'; 50];
        buffer.write_chunk(&padding).unwrap();
        assert!(buffer.is_mmap());

        // Verify all data preserved
        let slice = buffer.as_slice().unwrap();
        assert!(slice.starts_with(b"initial data "));
        assert_eq!(slice.len(), 13 + 50);
    }

    #[test]
    fn test_max_body_size_enforced() {
        let mut buffer = LargeBodyBuffer::with_config(LargeBodyBufferConfig {
            mmap_threshold: 1024,
            max_body_size: 100,
            temp_dir: None,
        });

        let data = vec![0u8; 101];
        let result = buffer.write_chunk(&data);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_into_vec_memory() {
        let mut buffer = LargeBodyBuffer::new();
        buffer.write_chunk(b"test data").unwrap();

        let vec = buffer.into_vec().unwrap();
        assert_eq!(vec, b"test data");
    }

    #[test]
    fn test_into_vec_mmap() {
        let mut buffer = LargeBodyBuffer::with_config(LargeBodyBufferConfig {
            mmap_threshold: 10,
            max_body_size: 1024,
            temp_dir: None,
        });

        let data = b"this is some larger data that exceeds threshold";
        buffer.write_chunk(data).unwrap();
        assert!(buffer.is_mmap());

        let vec = buffer.into_vec().unwrap();
        assert_eq!(vec, data);
    }

    #[test]
    fn test_clear() {
        let mut buffer = LargeBodyBuffer::new();
        buffer.write_chunk(b"some data").unwrap();
        assert!(!buffer.is_empty());

        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert!(!buffer.is_mmap());
    }

    #[test]
    fn test_multiple_chunks() {
        let mut buffer = LargeBodyBuffer::new();

        buffer.write_chunk(b"chunk1 ").unwrap();
        buffer.write_chunk(b"chunk2 ").unwrap();
        buffer.write_chunk(b"chunk3").unwrap();

        let data = buffer.as_slice().unwrap();
        assert_eq!(data, b"chunk1 chunk2 chunk3");
    }

    #[test]
    fn test_empty_chunk() {
        let mut buffer = LargeBodyBuffer::new();

        buffer.write_chunk(b"").unwrap();
        assert!(buffer.is_empty());

        buffer.write_chunk(b"data").unwrap();
        buffer.write_chunk(b"").unwrap();
        assert_eq!(buffer.len(), 4);
    }
}
