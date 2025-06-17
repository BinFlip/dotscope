//! Low-level byte order and safe reading utilities for CIL and PE parsing.
//!
//! This module provides comprehensive, endian-aware binary data reading functionality for parsing
//! .NET PE files and CIL metadata structures. It implements safe, bounds-checked operations for
//! reading primitive types from byte buffers with both little-endian and big-endian support,
//! ensuring data integrity and preventing buffer overruns during binary analysis.
//!
//! # Architecture
//!
//! The module is built around the [`crate::file::io::CilIO`] trait which provides a unified
//! interface for reading binary data in a type-safe manner. The architecture includes:
//!
//! - Generic trait-based reading for all primitive types
//! - Automatic bounds checking to prevent buffer overruns
//! - Support for both fixed-size and dynamic-size field reading
//! - Consistent error handling through the [`crate::Result`] type
//! - Zero-copy operations that work directly on byte slices
//!
//! # Key Components
//!
//! ## Core Trait
//! - [`crate::file::io::CilIO`] - Trait defining endian-aware reading capabilities for primitive types
//!
//! ## Little-Endian Reading Functions
//! - [`crate::file::io::read_le`] - Read values from buffer start in little-endian format
//! - [`crate::file::io::read_le_at`] - Read values at specific offset with auto-advance in little-endian
//! - [`crate::file::io::read_le_at_dyn`] - Dynamic size reading (2 or 4 bytes) in little-endian
//!
//! ## Big-Endian Reading Functions
//! - [`crate::file::io::read_be`] - Read values from buffer start in big-endian format
//! - [`crate::file::io::read_be_at`] - Read values at specific offset with auto-advance in big-endian
//! - [`crate::file::io::read_be_at_dyn`] - Dynamic size reading (2 or 4 bytes) in big-endian
//!
//! ## Supported Types
//! The [`crate::file::io::CilIO`] trait is implemented for:
//! - **Unsigned integers**: `u8`, `u16`, `u32`, `u64`
//! - **Signed integers**: `i8`, `i16`, `i32`, `i64`
//! - **Floating point**: `f32`, `f64`
//!
//! # Usage Examples
//!
//! ## Basic Value Reading
//!
//! ```rust,ignore
//! use dotscope::file::io::{read_le, read_be};
//!
//! // Little-endian reading (most common for PE files)
//! let data = [0x01, 0x00, 0x00, 0x00]; // u32 value: 1
//! let value: u32 = read_le(&data)?;
//! assert_eq!(value, 1);
//!
//! // Big-endian reading (less common)
//! let data = [0x00, 0x00, 0x00, 0x01]; // u32 value: 1
//! let value: u32 = read_be(&data)?;
//! assert_eq!(value, 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Sequential Reading with Offset Tracking
//!
//! ```rust,ignore
//! use dotscope::file::io::read_le_at;
//!
//! let data = [0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00];
//! let mut offset = 0;
//!
//! // Read multiple values sequentially
//! let first: u16 = read_le_at(&data, &mut offset)?;  // offset: 0 -> 2
//! let second: u16 = read_le_at(&data, &mut offset)?; // offset: 2 -> 4  
//! let third: u32 = read_le_at(&data, &mut offset)?;  // offset: 4 -> 8
//!
//! assert_eq!(first, 1);
//! assert_eq!(second, 2);
//! assert_eq!(third, 3);
//! assert_eq!(offset, 8);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Dynamic Size Reading
//!
//! ```rust,ignore
//! use dotscope::file::io::read_le_at_dyn;
//!
//! let data = [0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
//! let mut offset = 0;
//!
//! // Read as u16 (promoted to u32)
//! let small = read_le_at_dyn(&data, &mut offset, false)?;
//! assert_eq!(small, 1);
//!
//! // Read as u32
//! let large = read_le_at_dyn(&data, &mut offset, true)?;
//! assert_eq!(large, 2);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! All reading functions return [`crate::Result<T>`] and will return [`crate::Error::OutOfBounds`]
//! if there are insufficient bytes in the buffer to complete the read operation. This ensures
//! memory safety and prevents buffer overruns during parsing.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::file::parser`] - Uses I/O functions for parsing PE file structures
//! - [`crate::metadata`] - Reads metadata tables and structures from binary data
//! - [`crate::file::physical`] - Provides low-level file access for reading operations
//!
//! The module is designed to be the foundational layer for all binary data access throughout
//! the dotscope library, ensuring consistent and safe parsing behavior across all components.

use crate::{Error::OutOfBounds, Result};

/// Trait for implementing type-specific safe binary data reading operations.
///
/// This trait provides a unified interface for reading primitive types from byte slices
/// in a safe and endian-aware manner. It abstracts over the conversion from byte arrays
/// to typed values, supporting both little-endian and big-endian formats commonly
/// encountered in binary file parsing.
///
/// The trait is implemented for all primitive integer and floating-point types used
/// in PE file and .NET metadata parsing, ensuring type safety and consistent behavior
/// across all binary reading operations.
///
/// # Implementation Details
///
/// Each implementation defines a `Bytes` associated type that represents the fixed-size
/// byte array required for that particular type (e.g., `[u8; 4]` for `u32`). The trait
/// methods then convert these byte arrays to the target type using the appropriate
/// endianness conversion.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::CilIO;
///
/// // The trait is used internally by the reading functions
/// let bytes = [0x01, 0x00, 0x00, 0x00];
/// let value = u32::from_le_bytes(bytes);
/// assert_eq!(value, 1);
///
/// // Big-endian conversion
/// let bytes = [0x00, 0x00, 0x00, 0x01];
/// let value = u32::from_be_bytes(bytes);
/// assert_eq!(value, 1);
/// ```
pub trait CilIO: Sized {
    /// Associated type representing the byte array type for this numeric type.
    ///
    /// This type must be convertible from a byte slice and is used for reading
    /// binary data in both little-endian and big-endian formats.
    type Bytes: Sized + for<'a> TryFrom<&'a [u8]>;

    /// Read T from a byte buffer in little-endian
    fn from_le_bytes(bytes: Self::Bytes) -> Self;
    /// Read T from a byte buffer in big-endian
    fn from_be_bytes(bytes: Self::Bytes) -> Self;

    //fn to_le_bytes(bytes: Self::Bytes) -> Self;
    //fn to_be_bytes(bytes: Self::Bytes) -> Self;
}

// Implement CilIO support for u64
impl CilIO for u64 {
    type Bytes = [u8; 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u64::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u64::from_be_bytes(bytes)
    }
}

// Implement CilIO support for i64
impl CilIO for i64 {
    type Bytes = [u8; 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i64::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i64::from_be_bytes(bytes)
    }
}

// Implement CilIO support for u32
impl CilIO for u32 {
    type Bytes = [u8; 4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u32::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u32::from_be_bytes(bytes)
    }
}

// Implement CilIO support for i32
impl CilIO for i32 {
    type Bytes = [u8; 4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i32::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i32::from_be_bytes(bytes)
    }
}

// Implement CilIO support from u16
impl CilIO for u16 {
    type Bytes = [u8; 2];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u16::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u16::from_be_bytes(bytes)
    }
}

// Implement CilIO support from i16
impl CilIO for i16 {
    type Bytes = [u8; 2];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i16::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i16::from_be_bytes(bytes)
    }
}

// Implement CilIO support from u8
impl CilIO for u8 {
    type Bytes = [u8; 1];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        u8::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        u8::from_be_bytes(bytes)
    }
}

// Implement CilIO support from i8
impl CilIO for i8 {
    type Bytes = [u8; 1];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        i8::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        i8::from_be_bytes(bytes)
    }
}

// Implement CilIO support from f32
impl CilIO for f32 {
    type Bytes = [u8; 4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        f32::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        f32::from_be_bytes(bytes)
    }
}

// Implement CilIO support from f64
impl CilIO for f64 {
    type Bytes = [u8; 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        f64::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        f64::from_be_bytes(bytes)
    }
}

// Implement CilIO support from usize
impl CilIO for usize {
    type Bytes = [u8; std::mem::size_of::<usize>()];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        usize::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        usize::from_be_bytes(bytes)
    }
}

// Implement CilIO support from isize
impl CilIO for isize {
    type Bytes = [u8; std::mem::size_of::<isize>()];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        isize::from_le_bytes(bytes)
    }

    fn from_be_bytes(bytes: Self::Bytes) -> Self {
        isize::from_be_bytes(bytes)
    }
}

/// Safely reads a value of type `T` in little-endian byte order from a data buffer.
///
/// This function reads from the beginning of the buffer and supports all types that implement
/// the [`crate::file::io::CilIO`] trait (u8, i8, u16, i16, u32, i32, u64, i64, f32, f64).
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::read_le;
///
/// let data = [0x01, 0x00, 0x00, 0x00]; // Little-endian u32: 1
/// let value: u32 = read_le(&data)?;
/// assert_eq!(value, 1);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_le<T: CilIO>(data: &[u8]) -> Result<T> {
    let mut offset = 0_usize;
    read_le_at(data, &mut offset)
}

/// Safely reads a value of type `T` in little-endian byte order from a data buffer at a specific offset.
///
/// This function reads from the specified offset and automatically advances the offset by the
/// number of bytes read. Supports all types that implement the [`crate::file::io::CilIO`] trait.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::read_le_at;
///
/// let data = [0x01, 0x00, 0x02, 0x00]; // Two u16 values: 1, 2
/// let mut offset = 0;
///
/// let first: u16 = read_le_at(&data, &mut offset)?;
/// assert_eq!(first, 1);
/// assert_eq!(offset, 2);
///
/// let second: u16 = read_le_at(&data, &mut offset)?;
/// assert_eq!(second, 2);
/// assert_eq!(offset, 4);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_le_at<T: CilIO>(data: &[u8], offset: &mut usize) -> Result<T> {
    let type_len = std::mem::size_of::<T>();
    if (type_len + *offset) > data.len() {
        return Err(OutOfBounds);
    }

    let Ok(read) = data[*offset..*offset + type_len].try_into() else {
        return Err(OutOfBounds);
    };

    *offset += type_len;

    Ok(T::from_le_bytes(read))
}

/// Dynamically reads either a 2-byte or 4-byte value in little-endian byte order.
///
/// This function reads either a u16 or u32 value based on the `is_large` parameter,
/// automatically promoting u16 values to u32 for consistent return type handling.
/// This is commonly used in PE metadata parsing where field sizes vary based on context.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
/// * `is_large` - If `true`, reads 4 bytes as u32; if `false`, reads 2 bytes as u16 and promotes to u32
///
/// # Returns
///
/// Returns the decoded value as u32, or [`crate::Error::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::read_le_at_dyn;
///
/// let data = [0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
/// let mut offset = 0;
///
/// // Read 2 bytes (promoted to u32)
/// let small_val = read_le_at_dyn(&data, &mut offset, false)?;
/// assert_eq!(small_val, 1);
/// assert_eq!(offset, 2);
///
/// // Read 4 bytes
/// let large_val = read_le_at_dyn(&data, &mut offset, true)?;
/// assert_eq!(large_val, 2);
/// assert_eq!(offset, 6);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_le_at_dyn(data: &[u8], offset: &mut usize, is_large: bool) -> Result<u32> {
    let res = if is_large {
        read_le_at::<u32>(data, offset)?
    } else {
        u32::from(read_le_at::<u16>(data, offset)?)
    };

    Ok(res)
}

/// Safely reads a value of type `T` in big-endian byte order from a data buffer.
///
/// This function reads from the beginning of the buffer and supports all types that implement
/// the [`crate::file::io::CilIO`] trait. Note that PE/CIL files typically use little-endian,
/// so this function is mainly for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::read_be;
///
/// let data = [0x00, 0x00, 0x00, 0x01]; // Big-endian u32: 1
/// let value: u32 = read_be(&data)?;
/// assert_eq!(value, 1);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_be<T: CilIO>(data: &[u8]) -> Result<T> {
    let mut offset = 0_usize;
    read_be_at(data, &mut offset)
}

/// Safely reads a value of type `T` in big-endian byte order from a data buffer at a specific offset.
///
/// This function reads from the specified offset and automatically advances the offset by the
/// number of bytes read. Note that PE/CIL files typically use little-endian, so this function
/// is mainly for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
///
/// # Returns
///
/// Returns the decoded value or [`crate::Error::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::read_be_at;
///
/// let data = [0x00, 0x01, 0x00, 0x02]; // Two big-endian u16 values: 1, 2
/// let mut offset = 0;
///
/// let first: u16 = read_be_at(&data, &mut offset)?;
/// assert_eq!(first, 1);
/// assert_eq!(offset, 2);
///
/// let second: u16 = read_be_at(&data, &mut offset)?;
/// assert_eq!(second, 2);
/// assert_eq!(offset, 4);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_be_at<T: CilIO>(data: &[u8], offset: &mut usize) -> Result<T> {
    let type_len = std::mem::size_of::<T>();
    if (type_len + *offset) > data.len() {
        return Err(OutOfBounds);
    }

    let Ok(read) = data[*offset..*offset + type_len].try_into() else {
        return Err(OutOfBounds);
    };

    *offset += type_len;

    Ok(T::from_be_bytes(read))
}

/// Dynamically reads either a 2-byte or 4-byte value in big-endian byte order.
///
/// This function reads either a u16 or u32 value based on the `is_large` parameter,
/// automatically promoting u16 values to u32 for consistent return type handling.
/// Note that PE/CIL files typically use little-endian, so this function is mainly
/// for completeness and special cases.
///
/// # Arguments
///
/// * `data` - The byte buffer to read from
/// * `offset` - Mutable reference to the offset position (will be advanced after reading)
/// * `is_large` - If `true`, reads 4 bytes as u32; if `false`, reads 2 bytes as u16 and promotes to u32
///
/// # Returns
///
/// Returns the decoded value as u32, or [`crate::Error::OutOfBounds`] if there are insufficient bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::file::io::read_be_at_dyn;
///
/// let data = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
/// let mut offset = 0;
///
/// // Read 2 bytes (promoted to u32)
/// let small_val = read_be_at_dyn(&data, &mut offset, false)?;
/// assert_eq!(small_val, 1);
/// assert_eq!(offset, 2);
///
/// // Read 4 bytes
/// let large_val = read_be_at_dyn(&data, &mut offset, true)?;
/// assert_eq!(large_val, 2);
/// assert_eq!(offset, 6);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn read_be_at_dyn(data: &[u8], offset: &mut usize, is_large: bool) -> Result<u32> {
    let res = if is_large {
        read_be_at::<u32>(data, offset)?
    } else {
        u32::from(read_be_at::<u16>(data, offset)?)
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BUFFER: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    #[test]
    fn read_le_u8() {
        let result = read_le::<u8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x01);
    }

    #[test]
    fn read_le_i8() {
        let result = read_le::<i8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x01);
    }

    #[test]
    fn read_le_u16() {
        let result = read_le::<u16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0201);
    }

    #[test]
    fn read_le_i16() {
        let result = read_le::<i16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0201);
    }

    #[test]
    fn read_le_u32() {
        let result = read_le::<u32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0403_0201);
    }

    #[test]
    fn read_le_i32() {
        let result = read_le::<i32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0403_0201);
    }

    #[test]
    fn read_le_u64() {
        let result = read_le::<u64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0807060504030201);
    }

    #[test]
    fn read_le_i64() {
        let result = read_le::<i64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x0807060504030201);
    }

    #[test]
    fn read_be_u8() {
        let result = read_be::<u8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x1);
    }

    #[test]
    fn read_be_i8() {
        let result = read_be::<i8>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x1);
    }

    #[test]
    fn read_be_u16() {
        let result = read_be::<u16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x102);
    }

    #[test]
    fn read_be_i16() {
        let result = read_be::<i16>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x102);
    }

    #[test]
    fn read_be_u32() {
        let result = read_be::<u32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x1020304);
    }

    #[test]
    fn read_be_i32() {
        let result = read_be::<i32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x1020304);
    }

    #[test]
    fn read_be_u64() {
        let result = read_be::<u64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x102030405060708);
    }

    #[test]
    fn read_be_i64() {
        let result = read_be::<i64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 0x102030405060708);
    }

    #[test]
    fn read_be_f32() {
        let result = read_be::<f32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 2.3879393e-38);
    }

    #[test]
    fn read_be_f64() {
        let result = read_be::<f64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 8.20788039913184e-304);
    }

    #[test]
    fn read_le_f32() {
        let result = read_le::<f32>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 1.5399896e-36);
    }

    #[test]
    fn read_le_f64() {
        let result = read_le::<f64>(&TEST_BUFFER).unwrap();
        assert_eq!(result, 5.447603722011605e-270);
    }

    #[test]
    fn read_be_from() {
        let mut offset = 2_usize;
        let result = read_be_at::<u16>(&TEST_BUFFER, &mut offset).unwrap();
        assert_eq!(result, 0x304);
    }

    #[test]
    fn read_le_from() {
        let mut offset = 2_usize;
        let result = read_le_at::<u16>(&TEST_BUFFER, &mut offset).unwrap();
        assert_eq!(result, 0x403);
    }

    #[test]
    fn read_le_dyn() {
        let mut offset = 0;

        let res_1 = read_le_at_dyn(&TEST_BUFFER, &mut offset, true).unwrap();
        assert_eq!(res_1, 0x4030201);

        offset = 0;
        let res_2 = read_le_at_dyn(&TEST_BUFFER, &mut offset, false).unwrap();
        assert_eq!(res_2, 0x201);
    }

    #[test]
    fn read_be_dyn() {
        let mut offset = 0;

        let res_1 = read_be_at_dyn(&TEST_BUFFER, &mut offset, true).unwrap();
        assert_eq!(res_1, 0x1020304);

        offset = 0;
        let res_2 = read_be_at_dyn(&TEST_BUFFER, &mut offset, false).unwrap();
        assert_eq!(res_2, 0x102);
    }

    #[test]
    fn errors() {
        let buffer = [0xFF, 0xFF, 0xFF, 0xFF];

        let result = read_le::<u64>(&buffer);
        assert!(matches!(result, Err(OutOfBounds)));

        let result = read_le::<f64>(&buffer);
        assert!(matches!(result, Err(OutOfBounds)));
    }

    #[test]
    fn read_le_usize() {
        let size_bytes = std::mem::size_of::<usize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - little endian representation of 0x12345678 (or truncated for smaller usize)
        buffer[0] = 0x78;
        buffer[1] = 0x56;
        if size_bytes >= 4 {
            buffer[2] = 0x34;
            buffer[3] = 0x12;
        }

        let result = read_le::<usize>(&buffer).unwrap();
        if size_bytes == 8 {
            assert_eq!(result, 0x12345678);
        } else {
            assert_eq!(result, 0x5678);
        }
    }

    #[test]
    fn read_be_usize() {
        let size_bytes = std::mem::size_of::<usize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - big endian representation
        if size_bytes >= 4 {
            buffer[size_bytes - 4] = 0x12;
            buffer[size_bytes - 3] = 0x34;
        }
        buffer[size_bytes - 2] = 0x56;
        buffer[size_bytes - 1] = 0x78;

        let result = read_be::<usize>(&buffer).unwrap();
        if size_bytes == 8 {
            assert_eq!(result, 0x12345678);
        } else {
            assert_eq!(result, 0x5678);
        }
    }

    #[test]
    fn read_le_isize() {
        let size_bytes = std::mem::size_of::<isize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - little endian representation of -1
        for item in buffer.iter_mut().take(size_bytes) {
            *item = 0xFF;
        }

        let result = read_le::<isize>(&buffer).unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn read_be_isize() {
        let size_bytes = std::mem::size_of::<isize>();
        let mut buffer = vec![0u8; size_bytes];

        // Create test data - big endian representation of -1
        for item in buffer.iter_mut().take(size_bytes) {
            *item = 0xFF;
        }

        let result = read_be::<isize>(&buffer).unwrap();
        assert_eq!(result, -1);
    }
}
