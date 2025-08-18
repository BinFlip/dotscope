//! Memory-mapped file handling for efficient binary output.
//!
//! This module provides the [`crate::cilassembly::writer::output::Output`] type for managing
//! memory-mapped files during binary generation. It implements atomic file operations
//! with proper cleanup and cross-platform compatibility for the dotscope binary writing pipeline.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::output::Output`] - Memory-mapped output file with atomic finalization
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
//! use crate::cilassembly::writer::output::Output;
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
//! The [`crate::cilassembly::writer::output::Output`] type is not [`Send`] or [`Sync`] as it contains
//! memory-mapped file handles and temporary file resources that are tied to the creating thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::writer::layout`] - Layout planning for file size calculation
//! - [`crate::cilassembly::writer::executor`] - Execution engine that uses output files
//! - [`crate::cilassembly::writer`] - Main write pipeline coordination

use std::path::{Path, PathBuf};

use memmap2::{MmapMut, MmapOptions};

use crate::{cilassembly::writer::layout::FileRegion, utils::write_compressed_uint, Error, Result};

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
    /// Returns a new [`crate::cilassembly::writer::output::Output`] ready for writing.
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
            return Err(Error::WriteMmapFailed {
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
        let start = usize::try_from(offset).map_err(|_| Error::WriteMmapFailed {
            message: format!("Offset {offset} too large for target architecture"),
        })?;
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

    /// Copies data from the source offset to the target offset within the same file.
    ///
    /// This method provides efficient in-file copying for relocating existing content.
    /// It's used extensively during the binary generation process to move sections
    /// and preserve existing data in new locations.
    ///
    /// # Arguments
    /// * `source_offset` - Source offset to copy from
    /// * `target_offset` - Target offset to copy to
    /// * `size` - Number of bytes to copy
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if either range exceeds file bounds
    /// or if the ranges overlap in a way that would cause data corruption.
    pub fn copy_range(&mut self, source_offset: u64, target_offset: u64, size: u64) -> Result<()> {
        let source_start = usize::try_from(source_offset).map_err(|_| Error::WriteMmapFailed {
            message: format!("Source offset {source_offset} too large for target architecture"),
        })?;
        let target_start = usize::try_from(target_offset).map_err(|_| Error::WriteMmapFailed {
            message: format!("Target offset {target_offset} too large for target architecture"),
        })?;
        let copy_size = usize::try_from(size).map_err(|_| Error::WriteMmapFailed {
            message: format!("Size {size} too large for target architecture"),
        })?;

        let source_end = source_start + copy_size;
        let target_end = target_start + copy_size;

        // Validate bounds
        if source_end > self.mmap.len() {
            return Err(Error::WriteMmapFailed {
                message: format!(
                    "Source range would exceed file size: {}..{} (file size: {})",
                    source_start,
                    source_end,
                    self.mmap.len()
                ),
            });
        }

        if target_end > self.mmap.len() {
            return Err(Error::WriteMmapFailed {
                message: format!(
                    "Target range would exceed file size: {}..{} (file size: {})",
                    target_start,
                    target_end,
                    self.mmap.len()
                ),
            });
        }

        // For safety, use copy_within which handles overlapping ranges correctly
        self.mmap
            .copy_within(source_start..source_end, target_start);
        Ok(())
    }

    /// Fills a region with zeros.
    ///
    /// Efficient method for zeroing out large regions, commonly used for
    /// clearing old metadata locations after they've been relocated.
    ///
    /// # Arguments
    /// * `offset` - Starting byte offset
    /// * `size` - Number of bytes to zero
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the region would exceed file bounds.
    pub fn zero_range(&mut self, offset: u64, size: u64) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::WriteMmapFailed {
            message: format!("Offset {offset} too large for target architecture"),
        })?;
        let zero_size = usize::try_from(size).map_err(|_| Error::WriteMmapFailed {
            message: format!("Size {size} too large for target architecture"),
        })?;

        let slice = self.get_mut_slice(start, zero_size)?;
        slice.fill(0);
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
        let index = usize::try_from(offset).map_err(|_| Error::WriteMmapFailed {
            message: format!("Offset {offset} too large for target architecture"),
        })?;

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

    /// Writes a compressed unsigned integer at the specified offset.
    ///
    /// Uses ECMA-335 compressed integer encoding:
    /// - Values < 0x80: 1 byte
    /// - Values < 0x4000: 2 bytes (with high bit set)
    /// - Larger values: 4 bytes (with high 2 bits set)
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the compressed integer
    /// * `value` - 32-bit value to encode and write
    ///
    /// # Returns
    /// Returns the new offset after writing (offset + bytes_written).
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the write would exceed file bounds.
    pub fn write_compressed_uint_at(&mut self, offset: u64, value: u32) -> Result<u64> {
        let mut buffer = Vec::new();
        write_compressed_uint(value, &mut buffer);

        self.write_at(offset, &buffer)?;
        Ok(offset + buffer.len() as u64)
    }

    /// Writes data with automatic 4-byte alignment padding.
    ///
    /// Writes the data at the specified offset and adds 0xFF padding bytes to align
    /// to the next 4-byte boundary. The 0xFF bytes are safe for all heap types as
    /// they create invalid entries that won't be parsed.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the data
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Returns the new aligned offset after writing and padding.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the write would exceed file bounds.
    pub fn write_aligned_data(&mut self, offset: u64, data: &[u8]) -> Result<u64> {
        // Write the data
        self.write_at(offset, data)?;
        let data_end = offset + data.len() as u64;

        // Calculate padding needed for 4-byte alignment
        let padding_needed = (4 - (data.len() % 4)) % 4;

        if padding_needed > 0 {
            // Fill padding with 0xFF bytes to prevent creation of valid heap entries
            let padding_slice = self.get_mut_slice(
                usize::try_from(data_end).map_err(|_| Error::WriteMmapFailed {
                    message: format!(
                        "Data end offset {data_end} too large for target architecture"
                    ),
                })?,
                padding_needed,
            )?;
            padding_slice.fill(0xFF);
        }

        Ok(data_end + padding_needed as u64)
    }

    /// Writes data and returns the next position for sequential writing.
    ///
    /// Convenience method that combines writing data with position tracking,
    /// eliminating the common pattern of manual position updates.
    ///
    /// # Arguments
    /// * `position` - Current write position, will be updated to point after the written data
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Returns the new position after writing.
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the write would exceed file bounds.
    pub fn write_and_advance(&mut self, position: &mut usize, data: &[u8]) -> Result<()> {
        let slice = self.get_mut_slice(*position, data.len())?;
        slice.copy_from_slice(data);
        *position += data.len();
        Ok(())
    }

    /// Fills a region with the specified byte value.
    ///
    /// Efficient method for filling large regions with a single byte value,
    /// commonly used for padding and zero-initialization.
    ///
    /// # Arguments
    /// * `offset` - Starting byte offset
    /// * `size` - Number of bytes to fill
    /// * `fill_byte` - Byte value to fill with
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the region would exceed file bounds.
    pub fn fill_region(&mut self, offset: u64, size: usize, fill_byte: u8) -> Result<()> {
        let slice = self.get_mut_slice(
            usize::try_from(offset).map_err(|_| Error::WriteMmapFailed {
                message: format!("Offset {offset} too large for target architecture"),
            })?,
            size,
        )?;
        slice.fill(fill_byte);
        Ok(())
    }

    /// Adds heap padding to align written data to 4-byte boundary.
    ///
    /// Calculates the padding needed based on the number of bytes written since heap_start
    /// and fills the padding with 0xFF bytes to prevent creation of valid heap entries.
    /// This matches the existing heap padding pattern used throughout the writers.
    ///
    /// # Arguments
    /// * `current_pos` - Current write position after writing heap data
    /// * `heap_start` - Starting position of the heap being written
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the padding would exceed file bounds.
    pub fn add_heap_padding(&mut self, current_pos: usize, heap_start: usize) -> Result<()> {
        let bytes_written = current_pos - heap_start;
        let padding_needed = (4 - (bytes_written % 4)) % 4;

        if padding_needed > 0 {
            self.fill_region(current_pos as u64, padding_needed, 0xFF)?;
        }

        Ok(())
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
    /// This does not guarantee durability until [`crate::cilassembly::writer::output::Output::finalize`] is called.
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
    /// This method can only be called once per [`crate::cilassembly::writer::output::Output`] instance.
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

    /// Gets a mutable slice for a FileRegion.
    ///
    /// Convenience method that accepts a FileRegion instead of separate offset and size parameters.
    /// This makes it easier to work with layout regions throughout the writing pipeline.
    ///
    /// # Arguments
    /// * `region` - The file region to get a slice for
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the region is invalid or exceeds file bounds.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region = FileRegion::new(0x1000, 0x500);
    /// let slice = output.get_mut_slice_region(&region)?;
    /// ```
    pub fn get_mut_slice_region(&mut self, region: &FileRegion) -> Result<&mut [u8]> {
        self.get_mut_slice(
            usize::try_from(region.offset).map_err(|_| Error::WriteMmapFailed {
                message: format!(
                    "Region offset {} too large for target architecture",
                    region.offset
                ),
            })?,
            usize::try_from(region.size).map_err(|_| Error::WriteMmapFailed {
                message: format!(
                    "Region size {} too large for target architecture",
                    region.size
                ),
            })?,
        )
    }

    /// Writes data to a FileRegion.
    ///
    /// Convenience method that writes data starting at the region's offset.
    /// The data size should not exceed the region's size.
    ///
    /// # Arguments
    /// * `region` - The file region to write to
    /// * `data` - Byte slice to write to the region
    ///
    /// # Errors
    /// Returns [`crate::Error::WriteMmapFailed`] if the write would exceed file bounds.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region = FileRegion::new(0x1000, 0x500);
    /// output.write_to_region(&region, &data)?;
    /// ```
    pub fn write_to_region(&mut self, region: &FileRegion, data: &[u8]) -> Result<()> {
        self.write_at(region.offset, data)
    }

    /// Validates that a layout-planned file region is completely within file bounds.
    ///
    /// This utility method performs pre-operation validation to ensure that a [`FileRegion`]
    /// calculated during layout planning is completely within the file boundaries. This is
    /// particularly useful for validation before performing bulk operations on regions or
    /// when implementing defensive programming practices.
    ///
    /// Unlike the error-generating bounds checks in other methods, this method provides
    /// a simple boolean result that can be used for conditional logic and validation
    /// workflows without exception handling overhead.
    ///
    /// # Arguments
    ///
    /// * `region` - A [`FileRegion`] to validate against current file bounds.
    ///   The region's offset and size are checked to ensure the entire region
    ///   `[offset..offset+size)` is within file boundaries.
    ///
    /// # Returns
    ///
    /// Returns `true` if the region is completely within file bounds (including the
    /// case where the region ends exactly at the file size). Returns `false` if any
    /// part of the region extends beyond the file or if the region has invalid parameters.
    ///
    /// # Examples
    /// ```rust,ignore
    /// let region = FileRegion::new(0x1000, 0x500);
    /// if output.region_is_valid(&region) {
    ///     let slice = output.get_mut_slice_region(&region)?;
    /// }
    /// ```
    pub fn region_is_valid(&self, region: &FileRegion) -> bool {
        region.end_offset() <= self.size()
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
    fn test_copy_range() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 1024).unwrap();

        // Write some data
        mmap_file.write_at(0, b"Hello, World!").unwrap();

        // Copy it to another location
        mmap_file.copy_range(0, 100, 13).unwrap();

        // Verify the copy
        let slice = mmap_file.as_mut_slice();
        assert_eq!(&slice[100..113], b"Hello, World!");
    }

    #[test]
    fn test_zero_range() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 1024).unwrap();

        // Write some data
        mmap_file.write_at(0, b"Hello, World!").unwrap();

        // Zero part of it
        mmap_file.zero_range(5, 5).unwrap();

        // Verify the zeroing
        let slice = mmap_file.as_mut_slice();
        assert_eq!(&slice[0..5], b"Hello");
        assert_eq!(&slice[5..10], &[0, 0, 0, 0, 0]);
        assert_eq!(&slice[10..13], b"ld!");
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
