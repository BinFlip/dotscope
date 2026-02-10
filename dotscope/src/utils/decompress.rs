//! Decompression utilities for obfuscator-embedded payloads.
//!
//! This module provides native decompression implementations used to intercept
//! decompression calls during emulation. Obfuscators commonly embed LZMA or Deflate
//! compressed payloads that are decompressed at runtime.
//!
//! # ConfuserEx LZMA Format
//!
//! ConfuserEx uses a custom LZMA format:
//! - 5 bytes: LZMA decoder properties
//! - 4 bytes: Uncompressed size (little-endian i32)
//! - Rest: Compressed data stream
//!
//! # Deflate Format
//!
//! Standard Deflate streams as used by `System.IO.Compression.DeflateStream`.

use std::io::{Cursor, Read};

use flate2::read::{DeflateDecoder, GzDecoder};

/// Result type for decompression operations.
pub type DecompressResult<T> = std::result::Result<T, DecompressError>;

/// Error type for decompression operations.
#[derive(Debug)]
pub enum DecompressError {
    /// Invalid LZMA header or properties.
    InvalidLzmaHeader,
    /// LZMA decompression failed.
    LzmaError(String),
    /// Deflate decompression failed.
    DeflateError(String),
    /// Input buffer too small.
    BufferTooSmall,
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLzmaHeader => write!(f, "Invalid LZMA header"),
            Self::LzmaError(msg) => write!(f, "LZMA decompression error: {msg}"),
            Self::DeflateError(msg) => write!(f, "Deflate decompression error: {msg}"),
            Self::BufferTooSmall => write!(f, "Input buffer too small"),
        }
    }
}

impl std::error::Error for DecompressError {}

/// Checks if the given data appears to be ConfuserEx LZMA format.
///
/// ConfuserEx LZMA format:
/// - 5 bytes: LZMA properties (first byte typically 0x5D for default settings)
/// - 4 bytes: Uncompressed size (little-endian i32, may be negative for unknown)
/// - Rest: Compressed LZMA stream
///
/// # Arguments
///
/// * `data` - The potentially compressed data.
///
/// # Returns
///
/// `true` if the data appears to be ConfuserEx LZMA format.
#[must_use]
pub fn is_confuserex_lzma(data: &[u8]) -> bool {
    if data.len() < 13 {
        // Need at least 9 bytes header + some compressed data
        return false;
    }

    // LZMA properties byte: encodes lc, lp, pb parameters
    // Valid range: 0-224 (9 * 5 * 5 - 1)
    // ConfuserEx typically uses default settings: lc=3, lp=0, pb=2 -> 0x5D
    let props_byte = data[0];
    if props_byte > 224 {
        return false;
    }

    // For better heuristics, check if props byte matches common LZMA settings
    // 0x5D is the most common (lc=3, lp=0, pb=2)
    // But we allow any valid props for flexibility

    // Check dictionary size (bytes 1-4 of LZMA properties)
    // ConfuserEx typically uses 1MB dictionary (0x00100000)
    let dict_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);

    // Dictionary size must be reasonable: 1KB to 16MB
    // Too small or too large suggests this isn't LZMA
    if !(1024..=16 * 1024 * 1024).contains(&dict_size) {
        return false;
    }

    // Bytes 5-8: Uncompressed size (little-endian i32)
    // For ConfuserEx, this is typically a small positive number (the decrypted constants)
    let uncompressed_size = i32::from_le_bytes([data[5], data[6], data[7], data[8]]);

    // Uncompressed size should be positive and reasonable (< 10MB)
    // Negative or very large sizes indicate this isn't LZMA data
    if uncompressed_size <= 0 || uncompressed_size > 10 * 1024 * 1024 {
        return false;
    }

    // Additional check: compressed data should be smaller than uncompressed
    // (otherwise why compress it?)
    let compressed_data_len = data.len() - 9; // minus header
    if compressed_data_len as i32 > uncompressed_size {
        // Compressed larger than uncompressed - suspicious
        return false;
    }

    true
}

/// Decompresses ConfuserEx LZMA data.
///
/// # Arguments
///
/// * `data` - The LZMA compressed data in ConfuserEx format.
///
/// # Returns
///
/// The decompressed data, or an error if decompression fails.
///
/// # Format
///
/// ```text
/// [0..5]  : LZMA properties (5 bytes)
/// [5..9]  : Uncompressed size (4 bytes, little-endian i32)
/// [9..]   : LZMA compressed stream
/// ```
pub fn decompress_confuserex_lzma(data: &[u8]) -> DecompressResult<Vec<u8>> {
    if data.len() < 9 {
        return Err(DecompressError::BufferTooSmall);
    }

    // Parse header
    let props = &data[0..5];
    let uncompressed_size = i32::from_le_bytes([data[5], data[6], data[7], data[8]]);
    let compressed = &data[9..];

    // Build LZMA stream header for lzma-rs
    // lzma-rs expects: 5 bytes props + 8 bytes uncompressed size (little-endian u64) + compressed data
    let mut lzma_stream = Vec::with_capacity(13 + compressed.len());
    lzma_stream.extend_from_slice(props);

    // Convert i32 to u64 for lzma-rs format
    let size_u64 = if uncompressed_size < 0 {
        u64::MAX // Unknown size
    } else {
        uncompressed_size as u64
    };
    lzma_stream.extend_from_slice(&size_u64.to_le_bytes());
    lzma_stream.extend_from_slice(compressed);

    // Decompress using lzma-rs
    let mut cursor = Cursor::new(&lzma_stream);
    let mut decompressed = Vec::new();

    lzma_rs::lzma_decompress(&mut cursor, &mut decompressed)
        .map_err(|e| DecompressError::LzmaError(e.to_string()))?;

    Ok(decompressed)
}

/// Decompresses Deflate data using flate2.
///
/// # Arguments
///
/// * `data` - The Deflate compressed data.
///
/// # Returns
///
/// The decompressed data, or an error if decompression fails.
pub fn decompress_deflate(data: &[u8]) -> DecompressResult<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed = Vec::new();

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| DecompressError::DeflateError(e.to_string()))?;

    Ok(decompressed)
}

/// Decompresses GZip data using flate2.
///
/// # Arguments
///
/// * `data` - The GZip compressed data.
///
/// # Returns
///
/// The decompressed data, or an error if decompression fails.
pub fn decompress_gzip(data: &[u8]) -> DecompressResult<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| DecompressError::DeflateError(e.to_string()))?;

    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::DeflateEncoder, write::GzEncoder, Compression};

    use super::*;

    #[test]
    fn test_is_confuserex_lzma_valid() {
        // Valid LZMA header with default ConfuserEx settings
        // props=0x5D, dict=1MB (0x00100000), size=100 bytes
        // Needs at least 13 bytes (9 header + 4 compressed data)
        let valid_header = [
            0x5D, // props byte (lc=3, lp=0, pb=2)
            0x00, 0x00, 0x10, 0x00, // dictionary size: 1MB little-endian
            0x64, 0x00, 0x00, 0x00, // uncompressed size: 100 bytes
            0x00, 0x00, 0x00, 0x00, // start of compressed data (minimum 4 bytes)
        ];
        assert!(is_confuserex_lzma(&valid_header));
    }

    #[test]
    fn test_is_confuserex_lzma_invalid_props() {
        // Invalid props byte (> 224)
        let invalid_props = [
            0xFF, // invalid props byte
            0x00, 0x00, 0x10, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_confuserex_lzma(&invalid_props));
    }

    #[test]
    fn test_is_confuserex_lzma_too_small() {
        // Buffer too small (less than 13 bytes)
        let too_small = [0x5D, 0x00, 0x00, 0x10, 0x00, 0x64, 0x00, 0x00, 0x00];
        assert!(!is_confuserex_lzma(&too_small));
    }

    #[test]
    fn test_decompress_deflate() {
        let original = b"Hello, World! This is a test of deflate compression.";

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_deflate(&compressed).unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn test_decompress_gzip() {
        let original = b"Hello, World! This is a test of gzip compression.";

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(&decompressed, original);
    }
}
