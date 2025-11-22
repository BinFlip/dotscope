//! Physical file backend for memory-mapped I/O.
//!
//! This module provides the [`crate::file::physical::Physical`] backend that implements the
//! [`crate::file::Backend`] trait for accessing files from disk using memory-mapped I/O.
//! This approach provides efficient access to large files without loading the entire content
//! into memory upfront, while still allowing fast random access to any part of the file.
//!
//! # Architecture
//!
//! The physical backend uses memory-mapped I/O to map files directly into the process's
//! virtual address space. This architecture provides several key benefits:
//!
//! - **Efficient memory usage** - Only requested portions are loaded into physical memory
//! - **Operating system optimization** - Leverages OS-level caching and paging
//! - **Shared memory** - Multiple processes can efficiently access the same file
//! - **Lazy loading** - Pages are loaded on-demand as they are accessed
//!
//! # Key Components
//!
//! ## Core Type
//! - [`crate::file::physical::Physical`] - Main backend struct implementing [`crate::file::Backend`]
//!
//! ## Backend Methods
//! - [`crate::file::physical::Physical::new`] - Creates backend from file path with memory mapping
//! - [`crate::file::Backend::data_slice`] - Retrieves byte slices with bounds checking
//! - [`crate::file::Backend::data`] - Returns the complete memory-mapped file data
//! - [`crate::file::Backend::len`] - Returns total file size
//!
//! # Usage Examples
//!
//! ## Basic File Access
//!
//! ```rust,ignore
//! use dotscope::file::{Physical, Backend};
//! use std::path::Path;
//!
//! let physical = Physical::new(Path::new("assembly.dll"))?;
//! println!("File size: {} bytes", physical.len());
//!
//! // Read the first 4 bytes (e.g., PE signature)
//! let header = physical.data_slice(0, 4)?;
//! assert_eq!(header, b"MZ\x90\x00");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Random Access Pattern
//!
//! ```rust,ignore
//! use dotscope::file::{Physical, Backend};
//! use std::path::Path;
//!
//! let physical = Physical::new(Path::new("MyAssembly.dll"))?;
//!
//! // Check DOS header
//! let dos_header = physical.data_slice(0, 2)?;
//! assert_eq!(dos_header, b"MZ");
//!
//! // Access PE header offset (at offset 60)
//! let pe_offset_bytes = physical.data_slice(60, 4)?;
//! let pe_offset = u32::from_le_bytes([
//!     pe_offset_bytes[0], pe_offset_bytes[1],
//!     pe_offset_bytes[2], pe_offset_bytes[3]
//! ]);
//!
//! // Jump to PE header location
//! let pe_signature = physical.data_slice(pe_offset as usize, 4)?;
//! assert_eq!(pe_signature, b"PE\x00\x00");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Error Handling
//!
//! ```rust,ignore
//! use dotscope::file::Physical;
//! use std::path::Path;
//!
//! // Handle file that doesn't exist
//! match Physical::new(Path::new("nonexistent.dll")) {
//!     Ok(physical) => println!("File opened successfully"),
//!     Err(e) => println!("Failed to open file: {}", e),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::file`] - Provides the [`crate::file::Backend`] trait implementation
//! - [`crate::file::File`] - Uses physical backend for file-based parsing operations
//! - [`crate::metadata::cilobject`] - Can parse CIL objects from memory-mapped files
//!
//! The physical backend is ideal for production scenarios where files are accessed
//! from disk and memory efficiency is important, complementing the memory backend
//! for scenarios where data is already loaded into memory.

use super::Backend;
use crate::{
    Error::{Error, FileError},
    Result,
};

use memmap2::Mmap;
use std::{fs, path::Path};

/// A file backend that uses memory-mapped I/O for efficient access to files on disk.
///
/// [`crate::file::physical::Physical`] provides a way to access large files by mapping them
/// directly into the process's virtual address space. This eliminates the need to read
/// the entire file into memory upfront and allows the operating system to manage
/// memory efficiently through demand paging.
///
/// The backend is particularly well-suited for reading .NET assemblies, which can be
/// large and are typically accessed in a non-sequential pattern when parsing metadata.
/// All access operations include bounds checking to ensure memory safety.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::{Physical, Backend};
/// use std::path::Path;
///
/// // Open a .NET assembly file
/// let physical = Physical::new(Path::new("MyAssembly.dll"))?;
///
/// // Check if it's a valid PE file
/// let dos_header = physical.data_slice(0, 2)?;
/// assert_eq!(dos_header, b"MZ");
///
/// // Get the full file size
/// println!("Assembly size: {} bytes", physical.len());
///
/// // Access the entire file data
/// let full_data = physical.data();
/// println!("First byte: 0x{:02X}", full_data[0]);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug)]
pub struct Physical {
    /// Memory-mapped file data
    data: Mmap,
}

impl Physical {
    /// Create a new physical file backend by memory-mapping the specified file.
    ///
    /// This method opens the file at the given path and creates a memory mapping
    /// for it. The file is mapped as read-only and shared, allowing multiple
    /// processes to efficiently access the same file.
    ///
    /// # Arguments
    /// * `path` - Path to the PE file on disk. Accepts `&Path`, `&str`, `String`, or `PathBuf`.
    ///
    /// # Errors
    /// Returns [`crate::Error::FileError`] if the file cannot be opened or
    /// [`crate::Error::Error`] if memory mapping fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::file::Physical;
    /// use std::path::Path;
    ///
    /// // Open a .NET assembly
    /// let physical = Physical::new(Path::new("System.dll"))?;
    /// assert!(physical.len() > 0);
    ///
    /// // Open a file that doesn't exist (will return an error)
    /// let result = Physical::new(Path::new("nonexistent.dll"));
    /// assert!(result.is_err());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(path: impl AsRef<Path>) -> Result<Physical> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) => return Err(FileError(error)),
        };

        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(error) => return Err(Error(error.to_string())),
        };

        Ok(Physical { data: mmap })
    }

    /// Creates a new physical file backend from an opened std::fs::File.
    ///
    /// This method takes an already-opened file handle and creates a memory mapping
    /// for it. This is useful when you need to open the file with specific permissions
    /// or flags before creating the backend.
    ///
    /// # Arguments
    /// * `file` - An opened file handle
    ///
    /// # Errors
    /// Returns [`crate::Error::Error`] if memory mapping fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::file::Physical;
    /// use std::fs::File;
    ///
    /// let std_file = File::open("System.dll")?;
    /// let physical = Physical::from_std_file(std_file)?;
    /// assert!(physical.len() > 0);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_std_file(file: fs::File) -> Result<Physical> {
        // Note: We take ownership of `file` even though we only borrow it for Mmap::map().
        // This is intentional - the file handle must remain alive for the duration of the mmap,
        // and Mmap internally keeps the file alive. Taking by value matches std library conventions.
        let mmap = unsafe { Mmap::map(&file) }.map_err(|error| Error(error.to_string()))?;

        Ok(Physical { data: mmap })
    }
}

impl Backend for Physical {
    fn data_slice(&self, offset: usize, len: usize) -> Result<&[u8]> {
        let Some(offset_end) = offset.checked_add(len) else {
            return Err(out_of_bounds_error!());
        };

        if offset_end > self.data.len() {
            return Err(out_of_bounds_error!());
        }

        Ok(&self.data[offset..offset_end])
    }

    fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn into_data(self: Box<Self>) -> Vec<u8> {
        self.data.as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn physical() {
        let physical = Physical::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll"),
        )
        .unwrap();

        assert_eq!(physical.len(), 2255024);
        assert_eq!(physical.data()[0], 0x4D);
        assert_eq!(physical.data()[1], 0x5A);
        assert_eq!(
            physical.data_slice(12, 5).unwrap(),
            &[0xFF, 0xFF, 0x00, 0x00, 0xB8]
        );

        if physical
            .data_slice(u32::MAX as usize, u32::MAX as usize)
            .is_ok()
        {
            panic!("This should not work!")
        }

        if physical.data_slice(0, 4 * 1024 * 1024).is_ok() {
            panic!("This should not work!")
        }
    }

    #[test]
    fn test_physical_invalid_file_path() {
        let result = Physical::new(PathBuf::from("/nonexistent/path/to/file.dll"));
        assert!(result.is_err());
        match result.unwrap_err() {
            FileError(io_error) => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("Expected FileError"),
        }
    }

    #[test]
    fn test_physical_empty_file() {
        // Create a temporary empty file to test with
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("empty_test_file.bin");
        std::fs::write(&temp_path, b"").unwrap();

        let physical = Physical::new(&temp_path).unwrap();
        assert_eq!(physical.len(), 0);
        assert_eq!(physical.data().len(), 0);

        // Test edge cases with empty file
        assert!(physical.data_slice(0, 1).is_err());
        assert!(physical.data_slice(1, 0).is_err());
        let empty_slice: &[u8] = &[];
        assert_eq!(physical.data_slice(0, 0).unwrap(), empty_slice);

        // Cleanup
        std::fs::remove_file(&temp_path).unwrap();
    }

    #[test]
    fn test_physical_large_offset_overflow() {
        let physical = Physical::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll"),
        )
        .unwrap();

        // Test offset + len overflow
        let result = physical.data_slice(usize::MAX, 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));

        // Test offset exactly at length
        let len = physical.len();
        let result = physical.data_slice(len, 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));

        // Test offset + len exceeds length by 1
        let result = physical.data_slice(len - 1, 2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));
    }

    #[test]
    fn test_physical_boundary_conditions() {
        let physical = Physical::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll"),
        )
        .unwrap();

        let len = physical.len();

        // Test reading exactly at the boundary (should work)
        let result = physical.data_slice(len - 1, 1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        // Test reading the entire file
        let result = physical.data_slice(0, len);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), len);

        // Test zero-length read at end
        let result = physical.data_slice(len, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_physical_into_data() {
        // Test with real file
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let physical = Physical::new(&path).unwrap();

        let expected_len = physical.len();
        let expected_first = physical.data()[0];
        let expected_last = physical.data()[expected_len - 1];

        // Convert to Box<dyn Backend>
        let backend: Box<dyn Backend> = Box::new(physical);

        // Call into_data() - should copy the mmap'd data
        let recovered_data = backend.into_data();

        // Verify data is copied correctly
        assert_eq!(recovered_data.len(), expected_len);
        assert_eq!(recovered_data[0], expected_first);
        assert_eq!(recovered_data[expected_len - 1], expected_last);

        // Verify MZ signature
        assert_eq!(&recovered_data[0..2], b"MZ");
    }

    #[test]
    fn test_physical_into_data_small_file() {
        // Create a small temporary file
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_physical_into_data.bin");

        let test_data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        std::fs::write(&temp_path, &test_data).unwrap();

        let physical = Physical::new(&temp_path).unwrap();
        let backend: Box<dyn Backend> = Box::new(physical);
        let recovered_data = backend.into_data();

        assert_eq!(recovered_data, test_data);

        // Cleanup
        std::fs::remove_file(&temp_path).unwrap();
    }
}
