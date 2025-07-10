//! In-memory file backend for parsing from byte buffers.
//!
//! This module provides the [`Memory`] backend that implements the [`crate::file::Backend`]
//! trait for parsing .NET assemblies directly from memory buffers. This approach is ideal
//! when working with embedded data, network streams, or scenarios where file data is
//! already loaded into memory, offering fast random access to any part of the file.
//!
//! # Architecture
//!
//! The memory backend uses a simple design centered around a single [`Vec<u8>`] that stores
//! the entire file contents. This provides several advantages:
//!
//! - **Direct Access**: No file system calls needed after initialization
//! - **Fast Random Access**: Constant-time access to any byte range
//! - **Thread Safety**: Can be safely shared across threads when wrapped appropriately
//! - **Simplicity**: Minimal overhead compared to file-based backends
//!
//! # Key Components
//!
//! ## Core Types
//! - [`Memory`] - Main backend struct implementing [`crate::file::Backend`]
//!
//! ## Core Methods
//! - [`Memory::new`] - Creates backend from a byte vector
//! - [`crate::file::Backend::data_slice`] - Retrieves byte slices with bounds checking
//! - [`crate::file::Backend::data`] - Returns the complete file data
//! - [`crate::file::Backend::len`] - Returns total file size
//!
//! # Usage Examples
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use dotscope::file::{File, memory::Memory};
//!
//! // Create from a byte vector
//! let data = vec![/* PE file bytes */];
//! let backend = Memory::new(data);
//! let file = File::new(Box::new(backend))?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Loading from File System
//!
//! ```rust,ignore
//! use dotscope::file::{File, memory::Memory};
//! use std::fs;
//!
//! // Load entire file into memory first
//! let file_data = fs::read("assembly.dll")?;
//! let backend = Memory::new(file_data);
//! let file = File::new(Box::new(backend))?;
//!
//! // Fast access to any part of the file
//! println!("File size: {} bytes", file.len());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Processing Network Data
//!
//! ```rust,ignore
//! use dotscope::file::{File, memory::Memory};
//!
//! // Hypothetical function that downloads assembly
//! fn download_assembly() -> Vec<u8> { vec![] }
//!
//! let downloaded_data = download_assembly();
//! let backend = Memory::new(downloaded_data);
//! let file = File::new(Box::new(backend))?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`Memory`] backend is thread-safe for concurrent read operations. Once created,
//! the stored data is immutable, making it safe to share across threads. Multiple threads
//! can safely call [`crate::file::Backend::data_slice`] and other accessor methods
//! concurrently without additional synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::file`] - Provides the [`crate::file::Backend`] trait implementation
//! - [`crate::file::File`] - Uses memory backend for file parsing operations
//! - [`crate::metadata::cilobject`] - Can parse CIL objects from memory-backed files
//!
//! The memory backend is one of several backend options, alongside file-based backends,
//! providing flexibility in how assembly data is accessed and processed.

use super::Backend;
use crate::Result;

/// In-memory file backend for parsing .NET assemblies from byte buffers.
///
/// This backend implementation stores the entire file contents in memory, providing
/// fast random access to any part of the file. It's ideal for scenarios where the
/// file data is already available in memory or when working with smaller files
/// where memory usage isn't a concern.
///
/// The backend takes ownership of the provided byte vector and uses it directly
/// as the backing store, avoiding any unnecessary copying of data. All access
/// operations are bounds-checked to ensure memory safety.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::{File, memory::Memory};
/// use std::fs;
///
/// // Load file into memory first
/// let file_data = fs::read("assembly.dll")?;
/// let backend = Memory::new(file_data);
/// let file = File::new(Box::new(backend))?;
///
/// // Now you can parse the assembly from memory
/// println!("File size: {} bytes", file.len());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Thread Safety
///
/// [`Memory`] is [`std::marker::Send`] and [`std::marker::Sync`] as the stored data is immutable
/// after creation. Multiple threads can safely access the data concurrently through the
/// [`crate::file::Backend`] trait methods.
#[derive(Debug)]
pub struct Memory {
    /// The in-memory data buffer
    data: Vec<u8>,
}

impl Memory {
    /// Creates a new memory backend from a byte vector.
    ///
    /// Takes ownership of the provided byte vector and uses it as the backing store
    /// for the file backend. The data is moved into the backend, so no copying occurs.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte vector containing the file data to parse
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::file::memory::Memory;
    ///
    /// // From a vector of bytes
    /// let file_bytes = vec![0x4D, 0x5A, /* ... rest of PE file ... */];
    /// let backend = Memory::new(file_bytes);
    ///
    /// // The original vector is consumed and cannot be used anymore
    /// // println!("{:?}", file_bytes); // This would be a compile error
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn new(data: Vec<u8>) -> Memory {
        Memory { data }
    }
}

impl Backend for Memory {
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
        self.data.as_slice()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory() {
        let mut data = vec![0xCC_u8; 1048];
        data[10] = 0xBB;
        data[11] = 0xBB;
        data[12] = 0xBB;
        data[13] = 0xBB;
        data[14] = 0xBB;

        let memory = Memory::new(data);

        assert_eq!(memory.len(), 1048);
        assert_eq!(memory.data()[0], 0xCC);
        assert_eq!(memory.data()[42], 0xCC);
        assert_eq!(
            memory.data_slice(10, 5).unwrap(),
            &[0xBB, 0xBB, 0xBB, 0xBB, 0xBB]
        );

        if memory
            .data_slice(u32::MAX as usize, u32::MAX as usize)
            .is_ok()
        {
            panic!("This should not work!")
        }

        if memory.data_slice(0, 2048).is_ok() {
            panic!("This should not work!")
        }
    }

    #[test]
    fn test_memory_empty_buffer() {
        let memory = Memory::new(vec![]);

        assert_eq!(memory.len(), 0);
        assert_eq!(memory.data().len(), 0);

        // Test edge cases with empty buffer
        assert!(memory.data_slice(0, 1).is_err());
        assert!(memory.data_slice(1, 0).is_err());
        let empty_slice: &[u8] = &[];
        assert_eq!(memory.data_slice(0, 0).unwrap(), empty_slice);
    }

    #[test]
    fn test_memory_single_byte() {
        let memory = Memory::new(vec![0x42]);

        assert_eq!(memory.len(), 1);
        assert_eq!(memory.data()[0], 0x42);

        // Test boundary conditions
        assert_eq!(memory.data_slice(0, 1).unwrap(), &[0x42]);
        assert!(memory.data_slice(0, 2).is_err());
        assert!(memory.data_slice(1, 1).is_err());
        let empty_slice: &[u8] = &[];
        assert_eq!(memory.data_slice(1, 0).unwrap(), empty_slice);
    }

    #[test]
    fn test_memory_offset_overflow() {
        let memory = Memory::new(vec![0x00; 100]);

        // Test offset + len overflow
        let result = memory.data_slice(usize::MAX, 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));

        // Test offset exactly at length
        let result = memory.data_slice(100, 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));

        // Test offset + len exceeds length by 1
        let result = memory.data_slice(99, 2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::Error::OutOfBounds { .. }
        ));
    }

    #[test]
    fn test_memory_large_buffer() {
        let size = 10_000;
        let mut data = vec![0x00; size];
        data[size - 1] = 0xFF;

        let memory = Memory::new(data);
        assert_eq!(memory.len(), size);

        // Test reading at the end
        assert_eq!(memory.data_slice(size - 1, 1).unwrap(), &[0xFF]);

        // Test reading entire buffer
        let full_data = memory.data_slice(0, size).unwrap();
        assert_eq!(full_data.len(), size);
        assert_eq!(full_data[size - 1], 0xFF);
    }
}
