//! Decompression utilities for obfuscator-embedded payloads.
//!
//! This module provides native decompression implementations used to intercept
//! decompression calls during emulation. Obfuscators commonly embed LZMA or Deflate
//! compressed payloads that are decompressed at runtime.
//!
//! # ConfuserEx LZMA Format
//!
//! Two header layouts appear in the wild, sharing the same 5 property bytes and
//! differing only in the width of the uncompressed-size field that follows:
//!
//! - 5 bytes properties + 8 bytes size (little-endian u64) — the standard
//!   `.lzma` (alone) header, written by builds that drive the LZMA SDK's stream
//!   API directly
//! - 5 bytes properties + 4 bytes size (little-endian u32) — stock ConfuserEx's
//!   `Lzma.Decompress`
//!
//! Nothing in the assembly records which is in use, so both are attempted and
//! each is held to the length its own header declares.
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

/// Upper bound on a declared decompressed size, in bytes.
///
/// This is a guard against corrupt or hostile length fields driving a large
/// allocation, **not** a property of the format — LZMA itself allows any
/// `u64`. The bound only has to sit far above anything a real assembly
/// produces: a constants blob holds an assembly's literals, which run to
/// kilobytes for typical programs and single-digit megabytes for pathological
/// ones, so 512 MB leaves several orders of magnitude of headroom while still
/// rejecting a field that is plainly nonsense.
const MAX_DECOMPRESSED_SIZE: u64 = 512 * 1024 * 1024;

/// Header layouts used by ConfuserEx and its forks.
///
/// Both start with the same 5 property bytes and differ only in the width of
/// the uncompressed-size field that follows.
const LZMA_HEADER_LAYOUTS: [usize; 2] = [
    13, // 5 props + 8-byte size — the standard `.lzma` (alone) header
    9,  // 5 props + 4-byte size — stock ConfuserEx's `Lzma.Decompress`
];

/// Validates the 5 LZMA property bytes shared by every supported layout.
///
/// Checks the properties byte encodes a legal `lc`/`lp`/`pb` triple and that
/// the dictionary size is one a real encoder would choose.
fn valid_lzma_props(data: &[u8]) -> bool {
    // Properties byte encodes (pb * 5 + lp) * 9 + lc; the largest legal value
    // is 9 * 5 * 5 - 1 = 224.
    let Some(&props_byte) = data.first() else {
        return false;
    };
    if props_byte > 224 {
        return false;
    }

    // Dictionary size: the SDK's presets span 64 KB to 64 MB depending on the
    // fork's compression level, so accept a generous band around that.
    let Some(dict_bytes) = data.get(1..5).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
        return false;
    };
    let dict_size = u32::from_le_bytes(dict_bytes);
    (1024u32..=1024u32.saturating_mul(1024).saturating_mul(1024)).contains(&dict_size)
}

/// Reads the declared uncompressed size for a given header length.
///
/// Returns `None` when the buffer is too short, or the size is zero or beyond
/// [`MAX_DECOMPRESSED_SIZE`]. An all-ones field means "unknown" and maps to
/// `Some(None)` — plausible, but with no length to verify against.
fn declared_size(data: &[u8], header_len: usize) -> Option<Option<u64>> {
    let size = match header_len {
        13 => u64::from_le_bytes(data.get(5..13)?.try_into().ok()?),
        _ => u64::from(u32::from_le_bytes(data.get(5..9)?.try_into().ok()?)),
    };
    // `-1` in either width signals an unknown length
    if size == u64::MAX || size == u64::from(u32::MAX) {
        return Some(None);
    }
    if size == 0 || size > MAX_DECOMPRESSED_SIZE {
        return None;
    }
    Some(Some(size))
}

/// Checks if the given data appears to be ConfuserEx LZMA format.
///
/// Two header layouts are recognised, both sharing the same 5 property bytes
/// and differing in the width of the uncompressed-size field:
///
/// - 5 bytes properties + 8 bytes size — the standard `.lzma` (alone) header,
///   used by forks that call the LZMA SDK's stream API directly.
/// - 5 bytes properties + 4 bytes size — stock ConfuserEx's `Lzma.Decompress`.
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
        // Need at least the largest header plus some compressed data
        return false;
    }

    if !valid_lzma_props(data) {
        return false;
    }

    // Accept if either header layout yields a plausible declared size.
    //
    // Deliberately *not* checked: that the compressed payload is smaller than
    // the decompressed output. LZMA expands small high-entropy inputs, and the
    // constants blob is XOR-encrypted before compression — so a 44-byte blob
    // routinely compresses to more than 44 bytes. Requiring shrinkage rejected
    // exactly the assemblies this hook exists to handle.
    LZMA_HEADER_LAYOUTS
        .iter()
        .any(|&len| declared_size(data, len).is_some())
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
/// Two layouts are attempted, sharing the same 5 property bytes and differing
/// in the width of the uncompressed-size field:
///
/// ```text
/// [0..5]  : LZMA properties (5 bytes)
/// [5..13] : Uncompressed size (8 bytes, little-endian u64)   -- standard `.lzma`
/// [13..]  : LZMA compressed stream
///
/// [0..5]  : LZMA properties (5 bytes)
/// [5..9]  : Uncompressed size (4 bytes, little-endian u32)   -- stock ConfuserEx
/// [9..]   : LZMA compressed stream
/// ```
///
/// The layout is not recorded anywhere in the assembly, so both are tried and
/// the first that decodes to the length its own header declares wins. Guessing
/// wrong shifts the payload by four bytes and corrupts the range coder, so a
/// successful decode is itself the discriminator.
pub fn decompress_confuserex_lzma(data: &[u8]) -> DecompressResult<Vec<u8>> {
    if data.len() < 9 {
        return Err(DecompressError::BufferTooSmall);
    }
    if !valid_lzma_props(data) {
        return Err(DecompressError::InvalidLzmaHeader);
    }

    let props = data.get(0..5).ok_or(DecompressError::BufferTooSmall)?;
    let mut last_err: Option<DecompressError> = None;

    for &header_len in &LZMA_HEADER_LAYOUTS {
        let Some(size) = declared_size(data, header_len) else {
            continue;
        };
        let Some(compressed) = data.get(header_len..) else {
            continue;
        };
        if compressed.is_empty() {
            continue;
        }

        // lzma-rs expects the alone format: 5 props + 8-byte size + payload.
        let mut lzma_stream = Vec::with_capacity(compressed.len().saturating_add(13));
        lzma_stream.extend_from_slice(props);
        lzma_stream.extend_from_slice(&size.unwrap_or(u64::MAX).to_le_bytes());
        lzma_stream.extend_from_slice(compressed);

        let mut cursor = Cursor::new(&lzma_stream);
        let mut decompressed = Vec::new();
        match lzma_rs::lzma_decompress(&mut cursor, &mut decompressed) {
            Ok(()) => {
                // A wrong layout can still decode into garbage of the wrong
                // length; hold the result to its declared size when known.
                if size.is_none_or(|expected| decompressed.len() as u64 == expected) {
                    return Ok(decompressed);
                }
                last_err = Some(DecompressError::InvalidLzmaHeader);
            }
            Err(e) => last_err = Some(DecompressError::LzmaError(e.to_string())),
        }
    }

    Err(last_err.unwrap_or(DecompressError::InvalidLzmaHeader))
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

    use flate2::{
        write::{DeflateEncoder, GzEncoder},
        Compression,
    };

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

    /// A real ConfuserEx constants blob, taken from an assembly produced by a
    /// fork that writes the standard 13-byte `.lzma` header (5 property bytes
    /// followed by an 8-byte size) rather than stock ConfuserEx's 9-byte one.
    ///
    /// 51 bytes of payload decode to 44 bytes of output — the compressed form
    /// is *larger* than the decompressed form, because the constants blob is
    /// XOR-encrypted before compression and LZMA cannot shrink high-entropy
    /// input that small.
    const FORK_BLOB: [u8; 64] = [
        0x5D, 0x00, 0x00, 0x80, 0x00, // props: lc=3 lp=0 pb=2, 8 MB dictionary
        0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // size: 44, as u64
        0x00, 0x04, 0x00, 0x35, 0x03, 0xA1, 0xBC, 0x67, 0x7D, 0x8E, 0xD0, 0x35, 0x60, 0x52, 0x59,
        0x6E, 0x4A, 0xF6, 0x76, 0x12, 0xF7, 0xD1, 0x80, 0xD2, 0xA5, 0xEA, 0x78, 0xC3, 0x73, 0x0E,
        0x4B, 0x7C, 0xD8, 0x8E, 0xF4, 0xE6, 0x1C, 0x93, 0x81, 0x81, 0x68, 0xCC, 0xEC, 0x3A, 0x04,
        0x8E, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_confuserex_lzma_standard_13_byte_header() {
        assert!(is_confuserex_lzma(&FORK_BLOB));

        let out = decompress_confuserex_lzma(&FORK_BLOB).unwrap();
        assert_eq!(out.len(), 44, "must honour the declared size");
        // Length-prefixed UTF-8 constants, as ConfuserEx stores them.
        assert!(out.windows(8).any(|w| w == b"Result: "));
        assert!(out.windows(27).any(|w| w == b"Hello From ConfuserEx test."));
    }

    #[test]
    fn test_confuserex_lzma_accepts_payload_larger_than_output() {
        // Guards a heuristic that used to reject any blob whose payload was
        // bigger than its declared output, on the reasoning that compression
        // shrinks data. It does not, for small high-entropy inputs — and that
        // rejected precisely the assemblies this path exists to decompress.
        assert!(FORK_BLOB.len() - 13 > 44);
        assert!(is_confuserex_lzma(&FORK_BLOB));
    }

    #[test]
    fn test_confuserex_lzma_stock_9_byte_header() {
        // Stock ConfuserEx writes the size as 4 bytes, putting the payload at
        // offset 9. Rebuild that layout from an alone-format stream.
        let original = b"ConfuserEx constants blob, repeated repeated repeated repeated.";
        let mut alone = Vec::new();
        lzma_rs::lzma_compress(&mut Cursor::new(&original[..]), &mut alone).unwrap();

        let mut stock = Vec::with_capacity(alone.len());
        stock.extend_from_slice(&alone[0..5]);
        stock.extend_from_slice(&(original.len() as u32).to_le_bytes());
        stock.extend_from_slice(&alone[13..]);

        assert!(is_confuserex_lzma(&stock));
        assert_eq!(decompress_confuserex_lzma(&stock).unwrap(), original);
    }

    #[test]
    fn test_confuserex_lzma_rejects_non_lzma() {
        // Plausible length, but the dictionary size is nonsense.
        let junk = [
            0x5D, 0x11, 0x22, 0x33, 0x44, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(!is_confuserex_lzma(&junk));
        assert!(decompress_confuserex_lzma(&junk).is_err());
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
