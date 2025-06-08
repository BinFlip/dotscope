//! Low-level byte order and safe reading utilities for CIL and PE parsing.
//!
//! This module provides the [`CilIO`] trait for safe, endian-aware reading of primitive types
//! from byte slices. It is used throughout the file and metadata modules to ensure correct
//! parsing of binary data structures.

use crate::{Error::OutOfBounds, Result};

/// Trait for implementing type specific safe reader / writers
///
/// This trait abstracts over reading primitive types from byte slices in a safe and endian-aware way.
/// It is implemented for all common integer types used in PE and metadata parsing.
///
/// # Examples
///
/// ```text
/// // Internal usage in crate:
/// let bytes = [0x01, 0x00, 0x00, 0x00];
/// let value = u32::from_le_bytes(bytes);
/// assert_eq!(value, 1);
/// ```
pub trait CilIO: Sized {
    #[allow(missing_docs)]
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

/// Generic method to safely read T in little-endian from a data stream. Currently T can be u8, u16, u32 and u64
///
/// ## Arguments
/// * 'data' - The data buffer / stream to read from
pub fn read_le<T: CilIO>(data: &[u8]) -> Result<T> {
    let mut offset = 0_usize;
    read_le_at(data, &mut offset)
}

/// Generic method to safely read T from an offset and in little-endian from a data stream.
/// Currently T can be u8, u16, u32 and u64
///
/// ## Arguments
/// * 'data'    - The data buffer / stream to read from
/// * 'offset'  - An offset to read from, will be advanced by the amount of bytes read
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

/// Safely read 4 or 2 bytes from an offset and in little-endian from a data stream.
///
/// ## Arguments
/// * 'data'        - The data buffer / stream to read from
/// * 'offset'      - An offset to read from, will be advanced by the amount of bytes read
/// * `is_large`    - Indicates if 2 or 4 bytes should be read
pub fn read_le_at_dyn(data: &[u8], offset: &mut usize, is_large: bool) -> Result<u32> {
    let res = if is_large {
        read_le_at::<u32>(data, offset)?
    } else {
        u32::from(read_le_at::<u16>(data, offset)?)
    };

    Ok(res)
}

/// Generic method to safely read T in big-endian from a data stream. Currently T can be u8, u16, u32 and u64
///
/// ## Arguments
/// * 'data' - The data buffer / stream to read from
pub fn read_be<T: CilIO>(data: &[u8]) -> Result<T> {
    let mut offset = 0_usize;
    read_be_at(data, &mut offset)
}

/// Generic method to safely read T from an offset and in big-endian from a data stream.
/// Currently T can be u8, u16, u32 and u64
///
/// ## Arguments
/// * 'data'    - The data buffer / stream to read from
/// * 'offset'  - An offset to read from, will be advanced by the amount of bytes read
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

/// Safely read 4 or 2 bytes from an offset and in big-endian from a data stream.
///
/// ## Arguments
/// * 'data'        - The data buffer / stream to read from
/// * 'offset'      - An offset to read from, will be advanced by the amount of bytes read
/// * `is_large`    - Indicates if 2 or 4 bytes should be read
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
}
