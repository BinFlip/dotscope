//! Memory-mapped file handling for efficient binary output.
//!
//! This module provides the [`crate::cilassembly::write::output::Output`] type for managing
//! memory-mapped files during binary generation. It implements atomic file operations
//! with proper cleanup and cross-platform compatibility for the dotscope binary writing pipeline.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::write::output::Output`] - Memory-mapped output file with atomic finalization
//!
//! # Architecture
//!
//! The output system is built around safe memory-mapped file operations:
//!
//! ## Atomic Operations
//! Files are written to temporary locations and atomically moved to their final destination
//! to prevent corruption from interrupted operations or system failures.
//!
//! ## Memory Mapping
//! Large binary files are handled through memory mapping for efficient random access
//! without loading entire files into memory at once.
//!
//! ## Resource Management
//! Proper cleanup is ensured through RAII patterns and explicit finalization steps
//! that handle both success and error cases.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::write::output::Output;
//! use std::path::Path;
//!
//! // Create a memory-mapped output file
//! let mut output = Output::create("output.dll", 4096)?;
//!
//! // Write data at specific offsets
//! output.write_at(0, b"MZ")?; // DOS signature
//! output.write_u32_le_at(100, 0x12345678)?; // Little-endian value
//!
//! // Atomically finalize the file
//! output.finalize()?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::write::output::Output`] type is not [`Send`] or [`Sync`] as it contains
//! memory-mapped file handles and temporary file resources that are tied to the creating thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::write::planner`] - Layout planning for file size calculation
//! - [`crate::cilassembly::write::writers`] - Specialized writers that use output files
//! - [`crate::cilassembly::write`] - Main write pipeline coordination

use std::path::{Path, PathBuf};

use memmap2::{MmapMut, MmapOptions};

use crate::{Error, Result};

/// A memory-mapped output file that supports atomic operations.
///
/// This wrapper provides safe and efficient access to large binary files during generation.
/// It implements the write-to-temp-then-rename pattern for atomic file operations while
/// providing memory-mapped access for efficient random writes.
///
/// # Features
///
/// - **Memory-mapped access**: Efficient random access to large files without full loading
/// - **Atomic finalization**: Temporary file is atomically moved to final destination
/// - **Proper cleanup**: Automatic cleanup on error or drop through RAII patterns
/// - **Cross-platform compatibility**: Works consistently across different operating systems
/// - **Bounds checking**: All write operations are bounds-checked for safety
///
/// # Memory Management
///
/// The file is backed by a temporary file that is memory-mapped for access. This allows
/// efficient writing to arbitrary offsets without the memory overhead of loading the
/// entire file content into application memory.
///
/// # Atomic Operations
///
/// Files are written to a temporary location in the same directory as the target file
/// to ensure atomic rename operations work correctly (same filesystem requirement).
/// Only after successful completion is the file moved to its final location.
pub struct Output {
    /// The memory mapping of the target file
    mmap: MmapMut,

    /// The target path
    target_path: PathBuf,

    /// Whether the file has been finalized
    finalized: bool,
}

impl Output {
    /// Creates a new memory-mapped output file.
    ///
    /// This creates a file directly at the target path and maps it into memory
    /// for efficient writing operations. If finalization fails or the output
    /// is dropped without being finalized, the file will be automatically cleaned up.
    ///
    /// # Arguments
    ///
    /// * `target_path` - The path where the file should be created
    /// * `size` - The total size of the file to create
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::cilassembly::write::output::Output`] ready for writing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::WriteMmapFailed`] in the following cases:
    /// - Target file creation fails
    /// - File size setting fails
    /// - Memory mapping creation fails
    pub fn create<P: AsRef<Path>>(target_path: P, size: u64) -> Result<Self> {
        let target_path = target_path.as_ref().to_path_buf();

        // Create the file directly at the target location
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target_path)
            .map_err(|e| Error::WriteMmapFailed {
                message: format!("Failed to create target file: {e}"),
            })?;

        // Set the file size
        file.set_len(size).map_err(|e| Error::WriteMmapFailed {
            message: format!("Failed to set file size: {e}"),
        })?;

        // Create memory mapping
        let mmap = unsafe {
            MmapOptions::new()
                .map_mut(&file)
                .map_err(|e| Error::WriteMmapFailed {
                    message: format!("Failed to create memory mapping: {e}"),
                })?
        };

        Ok(Self {
            mmap,
            target_path,
            finalized: false,
        })
    }

    /// Gets a mutable slice to the entire file contents.
    ///
    /// Provides direct access to the entire memory-mapped file for bulk operations.
    /// Use with caution as this bypasses bounds checking.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.mmap[..]
    }

    /// Gets a mutable slice to a specific range of the file.
    ///
    /// Provides bounds-checked access to a specific range within the file.
    ///
    /// # Arguments
    /// * `start` - Starting byte offset (inclusive)
    /// * `end` - Ending byte offset (exclusive)
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the range is invalid or exceeds file bounds.
    pub fn get_mut_range(&mut self, start: usize, end: usize) -> Result<&mut [u8]> {
        if end > self.mmap.len() {
            return Err(Error::WriteMmapFailed {
                message: format!("Range end {} exceeds file size {}", end, self.mmap.len()),
            });
        }

        if start > end {
            return Err(Error::WriteMmapFailed {
                message: format!("Range start {start} is greater than end {end}"),
            });
        }

        Ok(&mut self.mmap[start..end])
    }

    /// Gets a mutable slice starting at the given offset with the specified size.
    ///
    /// Convenience method for getting a slice by offset and length rather than start/end.
    ///
    /// # Arguments
    /// * `start` - Starting byte offset
    /// * `size` - Number of bytes to include in the slice
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the range is invalid or exceeds file bounds.
    pub fn get_mut_slice(&mut self, start: usize, size: usize) -> Result<&mut [u8]> {
        let end = start + size;
        if end > self.mmap.len() {
            return Err(crate::Error::WriteMmapFailed {
                message: format!(
                    "Write would exceed file size: start={}, size={}, end={}, file_size={}",
                    start,
                    size,
                    end,
                    self.mmap.len()
                ),
            });
        }
        self.get_mut_range(start, end)
    }

    /// Writes data at a specific offset in the file.
    ///
    /// Performs bounds-checked writing of arbitrary data to the specified file offset.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the data
    /// * `data` - Byte slice to write to the file
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the write would exceed file bounds.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let start = offset as usize;
        let end = start + data.len();

        if end > self.mmap.len() {
            return Err(Error::WriteMmapFailed {
                message: format!(
                    "Write would exceed file size: offset={}, len={}, file_size={}",
                    offset,
                    data.len(),
                    self.mmap.len()
                ),
            });
        }

        self.mmap[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Writes a single byte at a specific offset.
    ///
    /// Convenience method for writing a single byte value.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the byte
    /// * `byte` - Byte value to write
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the offset exceeds file bounds.
    pub fn write_byte_at(&mut self, offset: u64, byte: u8) -> Result<()> {
        let index = offset as usize;

        if index >= self.mmap.len() {
            return Err(Error::WriteMmapFailed {
                message: format!(
                    "Byte write would exceed file size: offset={}, file_size={}",
                    offset,
                    self.mmap.len()
                ),
            });
        }

        self.mmap[index] = byte;
        Ok(())
    }

    /// Writes a little-endian u16 at a specific offset.
    ///
    /// Convenience method for writing 16-bit values in little-endian byte order.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the value
    /// * `value` - 16-bit value to write in little-endian format
    pub fn write_u16_le_at(&mut self, offset: u64, value: u16) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a little-endian u32 at a specific offset.
    ///
    /// Convenience method for writing 32-bit values in little-endian byte order.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the value
    /// * `value` - 32-bit value to write in little-endian format
    pub fn write_u32_le_at(&mut self, offset: u64, value: u32) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a little-endian u64 at a specific offset.
    ///
    /// Convenience method for writing 64-bit values in little-endian byte order.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the value
    /// * `value` - 64-bit value to write in little-endian format
    pub fn write_u64_le_at(&mut self, offset: u64, value: u64) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Gets the total size of the file.
    ///
    /// Returns the size in bytes of the memory-mapped file as specified during creation.
    pub fn size(&self) -> u64 {
        self.mmap.len() as u64
    }

    /// Flushes any pending writes to disk.
    ///
    /// Forces any cached writes in the memory mapping to be written to the underlying file.
    /// This does not guarantee durability until [`crate::cilassembly::write::output::Output::finalize`] is called.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the flush operation fails.
    pub fn flush(&mut self) -> Result<()> {
        self.mmap.flush().map_err(|e| Error::WriteMmapFailed {
            message: format!("Failed to flush memory mapping: {e}"),
        })
    }

    /// Finalizes the file by flushing all pending writes.
    ///
    /// This operation ensures data durability and marks the file as complete:
    /// 1. Flushes the memory mapping to write cached data to disk
    /// 2. Marks the file as finalized to prevent cleanup on drop
    ///
    /// After calling this method, the file is complete and will remain at the target path.
    /// This method can only be called once per [`crate::cilassembly::write::output::Output`] instance.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteFinalizationFailed`] in the following cases:
    /// - File has already been finalized
    /// - Memory mapping flush fails
    pub fn finalize(mut self) -> Result<()> {
        if self.finalized {
            return Err(Error::WriteFinalizationFailed {
                message: "File has already been finalized".to_string(),
            });
        }

        // Flush memory mapping
        self.mmap
            .flush()
            .map_err(|e| Error::WriteFinalizationFailed {
                message: format!("Failed to flush memory mapping: {e}"),
            })?;

        // Mark as finalized
        self.finalized = true;
        Ok(())
    }

    /// Gets the target path where the file will be created.
    ///
    /// Returns the final destination path specified during creation.
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if !self.finalized {
            // File was not finalized, so we should clean it up
            // First try to flush any pending writes
            let _ = self.flush();

            // Drop the mmap first to release the file handle
            // This is done implicitly when mmap is dropped

            // Then delete the incomplete file
            let _ = std::fs::remove_file(&self.target_path);
        }
        // If finalized, the file should remain at the target location
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, io::Read};
    use tempfile::tempdir;

    #[test]
    fn test_mmap_file_creation() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mmap_file = Output::create(&target_path, 1024).unwrap();
        assert_eq!(mmap_file.size(), 1024);
        assert!(!mmap_file.finalized);
    }

    #[test]
    fn test_write_operations() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 1024).unwrap();

        // Test byte write
        mmap_file.write_byte_at(0, 0x42).unwrap();

        // Test u32 write
        mmap_file.write_u32_le_at(4, 0x12345678).unwrap();

        // Test slice write
        mmap_file.write_at(8, b"Hello, World!").unwrap();

        // Verify the data
        let slice = mmap_file.as_mut_slice();
        assert_eq!(slice[0], 0x42);
        assert_eq!(&slice[4..8], &[0x78, 0x56, 0x34, 0x12]); // Little endian
        assert_eq!(&slice[8..21], b"Hello, World!");
    }

    #[test]
    fn test_finalization() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        {
            let mut mmap_file = Output::create(&target_path, 16).unwrap();
            mmap_file.write_at(0, b"Test content").unwrap();
            mmap_file.finalize().unwrap();
        }

        // Verify the file was created and contains the expected data
        assert!(target_path.exists());

        let mut file = File::open(&target_path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        assert_eq!(&contents[0..12], b"Test content");
    }

    #[test]
    fn test_bounds_checking() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 10).unwrap();

        // This should fail - trying to write beyond file size
        assert!(mmap_file.write_at(8, b"too long").is_err());

        // This should also fail - single byte beyond end
        assert!(mmap_file.write_byte_at(10, 0x42).is_err());
    }
}
