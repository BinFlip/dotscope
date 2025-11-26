//! Custom debug information parser for Portable PDB `CustomDebugInformation` table.
//!
//! This module provides comprehensive parsing capabilities for the custom debug information
//! blob format used in Portable PDB files. The blob format varies depending on the GUID kind,
//! supporting various types of debugging metadata including source link mappings, embedded
//! source files, compilation metadata, and compiler-specific debugging information.
//!
//! # Architecture
//!
//! The parser implements a GUID-based dispatch system that handles different blob formats
//! according to the Portable PDB specification. Each GUID identifies a specific debug
//! information format with its own binary layout and encoding scheme.
//!
//! ## Core Components
//!
//! - **Parser State**: [`crate::metadata::customdebuginformation::parser::CustomDebugParser`] with position tracking
//! - **Format Dispatch**: GUID-based format identification and parsing strategy selection
//! - **String Handling**: UTF-8 decoding with optional length prefixes
//! - **Error Recovery**: Graceful handling of malformed or unknown formats
//!
//! # Key Components
//!
//! - [`crate::metadata::customdebuginformation::parser::CustomDebugParser`] - Main parser implementation
//! - [`crate::metadata::customdebuginformation::parser::parse_custom_debug_blob`] - Convenience parsing function
//! - Support for multiple debug information formats based on GUID identification
//! - Robust UTF-8 string parsing with fallback strategies
//!
//! # Supported Debug Information Formats
//!
//! ## Source Link Format (GUID: CC110556-A091-4D38-9FEC-25AB9A351A6A)
//! ```text
//! SourceLinkBlob ::= utf8_json_document
//! ```
//! Contains raw UTF-8 JSON mapping source files to repository URLs for debugging.
//! No length prefix - the entire blob is the JSON document.
//!
//! ## Embedded Source Format (GUID: 0E8A571B-6926-466E-B4AD-8AB04611F5FE)
//! ```text
//! EmbeddedSourceBlob ::= int32_format content_bytes
//! ```
//! Where `int32_format` is:
//! - `0`: Content is raw uncompressed UTF-8
//! - `> 0`: Content is deflate-compressed, value is decompressed size in bytes
//!
//! **Note**: The filename is NOT in this blob. It comes from the parent Document row
//! in the CustomDebugInformation table.
//!
//! ## Compilation Metadata Format (GUID: B5FEEC05-8CD0-4A83-96DA-466284BB4BD8)
//! ```text
//! CompilationMetadataBlob ::= utf8_metadata_text
//! ```
//! Contains raw UTF-8 text with compiler and build environment metadata.
//!
//! ## Compilation Options Format (GUID: B1C2ABE1-8BF0-497A-A9B1-02FA8571E544)
//! ```text
//! CompilationOptionsBlob ::= utf8_options_text
//! ```
//! Contains raw UTF-8 text with compiler options and flags.
//!
//! ## Unknown Formats
//! For unrecognized GUIDs, the blob is returned as raw bytes for future extension.
//!
//! # Usage Examples
//!
//! ## Basic Debug Information Parsing
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugKind, CustomDebugInfo};
//!
//! let kind = CustomDebugKind::SourceLink;
//! let blob_data = b"{\"documents\":{}}";
//!
//! let debug_info = parse_custom_debug_blob(blob_data, kind)?;
//! match debug_info {
//!     CustomDebugInfo::SourceLink { document } => {
//!         println!("Source Link JSON: {}", document);
//!         assert!(document.contains("documents"));
//!     }
//!     CustomDebugInfo::EmbeddedSource { filename, content, .. } => {
//!         println!("Embedded source: {} ({} bytes)", filename, content.len());
//!     }
//!     CustomDebugInfo::Unknown { kind, data } => {
//!         println!("Unknown debug info: {:?} ({} bytes)", kind, data.len());
//!     }
//!     _ => println!("Other debug info type"),
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Advanced Parser Usage
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{CustomDebugParser, CustomDebugKind};
//!
//! let blob_data = b"compiler: csc 4.0";
//! let kind = CustomDebugKind::CompilationMetadata;
//!
//! // Create parser with specific debug kind
//! let mut parser = CustomDebugParser::new(blob_data, kind);
//! let debug_info = parser.parse_debug_info()?;
//!
//! // Process parsed information
//! println!("Parsed debug info: {:?}", debug_info);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Working with Multiple Debug Entries
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind};
//!
//! // Simulate multiple debug entries from an assembly
//! let debug_entries: Vec<(CustomDebugKind, Vec<u8>)> = vec![
//!     (CustomDebugKind::SourceLink, b"{\"documents\":{}}".to_vec()),
//!     (CustomDebugKind::CompilationMetadata, b"compiler: csc".to_vec()),
//! ];
//!
//! for (kind, blob_data) in debug_entries {
//!     match parse_custom_debug_blob(&blob_data, kind)? {
//!         CustomDebugInfo::SourceLink { document } => {
//!             println!("Found Source Link configuration: {}", document.len());
//!         }
//!         CustomDebugInfo::EmbeddedSource { filename, content, .. } => {
//!             println!("Found embedded source: {}", filename);
//!         }
//!         CustomDebugInfo::CompilationMetadata { metadata } => {
//!             println!("Found compilation metadata: {}", metadata);
//!         }
//!         _ => println!("Found other debug information"),
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! The parser provides comprehensive error handling for various failure scenarios:
//! - **Invalid UTF-8**: Falls back to lossy conversion to continue parsing
//! - **Truncated Data**: Returns available data with appropriate error indication
//! - **Unknown Formats**: Preserves raw data for future format support
//! - **Malformed Blobs**: Graceful degradation with diagnostic information
//!
//! # Thread Safety
//!
//! All functions in this module are thread-safe. The [`crate::metadata::customdebuginformation::parser::CustomDebugParser`]
//! contains mutable state and is not [`std::marker::Send`] or [`std::marker::Sync`], requiring
//! separate instances per thread. The parsing functions are stateless and can be called
//! concurrently from multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customdebuginformation::types`] - Type definitions for debug information
//! - [`crate::file::parser`] - Low-level binary data parsing utilities
//! - [`crate::metadata::streams`] - Blob heap access for debug data storage
//! - [`crate::Error`] - Comprehensive error handling and reporting
//!
//! # Performance Considerations
//!
//! - **Zero-Copy Parsing**: Minimizes memory allocation during parsing
//! - **Lazy UTF-8 Conversion**: Only converts to strings when necessary
//! - **Streaming Parser**: Handles large debug blobs efficiently
//! - **Error Recovery**: Continues parsing despite individual format errors
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: Full compliance with Portable PDB format specification
//! - **UTF-8 Encoding**: Proper handling of text data in debug information
//! - **GUID Standards**: Correct GUID interpretation according to RFC 4122
//! - **JSON Format**: Proper handling of JSON-based debug information formats

use std::io::Read;

use crate::{
    file::parser::Parser,
    malformed_error,
    metadata::customdebuginformation::types::{CustomDebugInfo, CustomDebugKind},
    Result,
};

/// Parser for custom debug information blob binary data implementing the Portable PDB specification.
///
/// This parser handles different blob formats based on the debug information kind GUID.
/// It provides structured parsing of various debugging metadata formats.
///
/// # Thread Safety
///
/// The parser is not [`std::marker::Send`] or [`std::marker::Sync`] due to mutable state.
/// Each thread should create its own parser instance for concurrent parsing operations.
pub struct CustomDebugParser<'a> {
    /// Binary data parser for reading blob data
    parser: Parser<'a>,
    /// The kind of debug information being parsed
    kind: CustomDebugKind,
}

impl<'a> CustomDebugParser<'a> {
    /// Creates a new parser for the given custom debug information blob data.
    ///
    /// # Arguments
    /// * `data` - The byte slice containing the debug information blob to parse
    /// * `kind` - The debug information kind that determines the blob format
    ///
    /// # Returns
    /// A new parser ready to parse the provided data.
    #[must_use]
    pub fn new(data: &'a [u8], kind: CustomDebugKind) -> Self {
        CustomDebugParser {
            parser: Parser::new(data),
            kind,
        }
    }

    /// Parse the complete custom debug information blob into structured debug information.
    ///
    /// This method parses the blob according to the format specified by the debug information
    /// kind. Different kinds use different blob formats and encoding schemes.
    ///
    /// # Returns
    /// * [`Ok`]([`CustomDebugInfo`]) - Successfully parsed debug information
    /// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data or I/O errors
    ///
    /// # Errors
    /// This method returns an error in the following cases:
    /// - **Truncated Data**: Insufficient data for expected format
    /// - **Invalid UTF-8**: String data that cannot be decoded as UTF-8 (strict validation)
    /// - **Malformed Blob**: Invalid blob structure for the specified kind
    /// - **Decompression Failure**: Deflate decompression failed for EmbeddedSource
    pub fn parse_debug_info(&mut self) -> Result<CustomDebugInfo> {
        match self.kind {
            CustomDebugKind::SourceLink => {
                let document = self.read_utf8_string()?;
                Ok(CustomDebugInfo::SourceLink { document })
            }
            CustomDebugKind::EmbeddedSource => {
                // Parse according to Portable PDB specification:
                // - int32 format: 0 = raw UTF-8, >0 = deflate compressed (value = decompressed size)
                // - bytes content: source file content
                self.parse_embedded_source()
            }
            CustomDebugKind::CompilationMetadata => {
                let metadata = self.read_utf8_string()?;
                Ok(CustomDebugInfo::CompilationMetadata { metadata })
            }
            CustomDebugKind::CompilationOptions => {
                let options = self.read_utf8_string()?;
                Ok(CustomDebugInfo::CompilationOptions { options })
            }
            CustomDebugKind::Unknown(_) => {
                // For unknown kinds, return the raw data
                let remaining_data = self.read_remaining_bytes();
                Ok(CustomDebugInfo::Unknown {
                    kind: self.kind,
                    data: remaining_data,
                })
            }
        }
    }

    /// Parse an EmbeddedSource blob according to the Portable PDB specification.
    ///
    /// # Format
    /// - **int32 format**: Compression indicator (0 = raw, >0 = deflate with decompressed size)
    /// - **bytes content**: UTF-8 source content (raw or deflate-compressed)
    ///
    /// # Note
    /// The filename is NOT in the blob - it comes from the parent Document row.
    fn parse_embedded_source(&mut self) -> Result<CustomDebugInfo> {
        if self.parser.len() < 4 {
            return Err(malformed_error!(
                "EmbeddedSource blob too small: {} bytes (minimum 4 required)",
                self.parser.len()
            ));
        }

        let format = self.parser.read_le::<i32>()?;

        let remaining = self.read_remaining_bytes();

        if format == 0 {
            // Raw uncompressed UTF-8 content
            let content = String::from_utf8(remaining).map_err(|e| {
                malformed_error!("EmbeddedSource contains invalid UTF-8: {}", e.utf8_error())
            })?;

            Ok(CustomDebugInfo::EmbeddedSource {
                filename: String::new(), // Set by caller from Document table
                content,
                was_compressed: false,
            })
        } else if format > 0 {
            // Deflate-compressed content
            // format value is the decompressed size
            #[allow(clippy::cast_sign_loss)] // Safe: we checked format > 0
            let decompressed_size = format as usize;

            let content = self.decompress_deflate(&remaining, decompressed_size)?;

            Ok(CustomDebugInfo::EmbeddedSource {
                filename: String::new(), // Set by caller from Document table
                content,
                was_compressed: true,
            })
        } else {
            Err(malformed_error!(
                "EmbeddedSource has invalid format indicator: {} (expected >= 0)",
                format
            ))
        }
    }

    /// Decompress deflate-compressed data.
    ///
    /// # Arguments
    /// * `compressed` - The compressed byte data
    /// * `expected_size` - The expected decompressed size (for validation)
    ///
    /// # Returns
    /// The decompressed UTF-8 string
    fn decompress_deflate(&self, compressed: &[u8], expected_size: usize) -> Result<String> {
        let mut decoder = flate2::read::DeflateDecoder::new(compressed);
        let mut decompressed = Vec::with_capacity(expected_size);

        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| malformed_error!("Failed to decompress EmbeddedSource: {}", e))?;

        if decompressed.len() != expected_size {
            return Err(malformed_error!(
                "EmbeddedSource decompressed size mismatch: expected {}, got {}",
                expected_size,
                decompressed.len()
            ));
        }

        String::from_utf8(decompressed).map_err(|e| {
            malformed_error!(
                "EmbeddedSource decompressed content is not valid UTF-8: {}",
                e.utf8_error()
            )
        })
    }

    /// Read remaining data as a UTF-8 string with strict validation.
    ///
    /// This method reads all remaining bytes and attempts to decode them as UTF-8.
    /// Unlike lossy conversion, this returns an error if the data contains invalid UTF-8,
    /// ensuring data integrity and allowing the caller to handle encoding issues explicitly.
    ///
    /// # Errors
    /// Returns an error if the remaining data is not valid UTF-8.
    fn read_utf8_string(&mut self) -> Result<String> {
        let remaining = self.read_remaining_bytes();

        if remaining.is_empty() {
            return Ok(String::new());
        }

        String::from_utf8(remaining).map_err(|e| {
            malformed_error!(
                "Custom debug information contains invalid UTF-8 at byte {}: {}",
                e.utf8_error().valid_up_to(),
                e.utf8_error()
            )
        })
    }

    /// Read all remaining bytes from the parser.
    ///
    /// This is a safe helper that handles bounds checking and returns an owned copy
    /// of the remaining data.
    fn read_remaining_bytes(&mut self) -> Vec<u8> {
        let pos = self.parser.pos();
        let len = self.parser.len();

        if pos >= len {
            return Vec::new();
        }

        self.parser.data()[pos..len].to_vec()
    }
}

/// Parse a custom debug information blob into structured debug information.
///
/// This is a convenience function that creates a parser and parses a complete
/// custom debug information blob from the provided byte slice. The function handles the parsing
/// process based on the debug information kind.
///
/// # Arguments
/// * `data` - The byte slice containing the debug information blob to parse
/// * `kind` - The debug information kind that determines the blob format
///
/// # Returns
/// * [`Ok`]([`CustomDebugInfo`]) - Successfully parsed debug information
/// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data or I/O errors
///
/// # Errors
/// This function returns an error in the following cases:
/// - **Invalid Format**: Malformed or truncated debug information blob
/// - **Encoding Error**: String data that cannot be decoded as UTF-8
/// - **Decompression Error**: EmbeddedSource deflate decompression failed
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugKind, CustomDebugInfo};
///
/// let kind = CustomDebugKind::SourceLink;
/// let blob_data = b"{\"documents\":{}}"; // Source Link JSON
/// let debug_info = parse_custom_debug_blob(blob_data, kind)?;
///
/// match debug_info {
///     CustomDebugInfo::SourceLink { document } => {
///         println!("Source Link: {}", document);
///     }
///     _ => println!("Unexpected debug info type"),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_custom_debug_blob(data: &[u8], kind: CustomDebugKind) -> Result<CustomDebugInfo> {
    if data.is_empty() {
        return Ok(CustomDebugInfo::Unknown {
            kind,
            data: Vec::new(),
        });
    }

    let mut parser = CustomDebugParser::new(data, kind);
    parser.parse_debug_info()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_blob() {
        let kind = CustomDebugKind::SourceLink;
        let result = parse_custom_debug_blob(&[], kind).unwrap();
        assert!(matches!(result, CustomDebugInfo::Unknown { .. }));
    }

    #[test]
    fn test_custom_debug_parser_new() {
        let kind = CustomDebugKind::SourceLink;
        let data = b"test data";
        let parser = CustomDebugParser::new(data, kind);
        // Just test that creation works
        assert_eq!(parser.parser.len(), 9);
    }

    #[test]
    fn test_parse_source_link() {
        let kind = CustomDebugKind::SourceLink;
        let data = b"{\"documents\":{}}";
        let result = parse_custom_debug_blob(data, kind).unwrap();

        match result {
            CustomDebugInfo::SourceLink { document } => {
                assert_eq!(document, "{\"documents\":{}}");
            }
            _ => panic!("Expected SourceLink variant"),
        }
    }

    #[test]
    fn test_parse_unknown_kind() {
        let unknown_guid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let kind = CustomDebugKind::Unknown(unknown_guid);
        let data = b"raw data";
        let result = parse_custom_debug_blob(data, kind).unwrap();

        match result {
            CustomDebugInfo::Unknown {
                kind: parsed_kind,
                data: parsed_data,
            } => {
                assert_eq!(parsed_kind, kind);
                assert_eq!(parsed_data, b"raw data");
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_parse_embedded_source_uncompressed() {
        let kind = CustomDebugKind::EmbeddedSource;
        // Format: int32 (0 = uncompressed) + UTF-8 content
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes()); // format = 0 (uncompressed)
        data.extend_from_slice(b"// Hello, world!\nclass Test {}");

        let result = parse_custom_debug_blob(&data, kind).unwrap();

        match result {
            CustomDebugInfo::EmbeddedSource {
                filename,
                content,
                was_compressed,
            } => {
                assert!(
                    filename.is_empty(),
                    "Filename should be empty (set by caller)"
                );
                assert_eq!(content, "// Hello, world!\nclass Test {}");
                assert!(!was_compressed);
            }
            _ => panic!("Expected EmbeddedSource variant"),
        }
    }

    #[test]
    fn test_parse_embedded_source_too_small() {
        let kind = CustomDebugKind::EmbeddedSource;
        // Only 3 bytes - not enough for int32 format indicator
        let data = [0x00, 0x00, 0x00];

        let result = parse_custom_debug_blob(&data, kind);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn test_parse_embedded_source_negative_format() {
        let kind = CustomDebugKind::EmbeddedSource;
        // Negative format indicator is invalid
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i32).to_le_bytes());
        data.extend_from_slice(b"content");

        let result = parse_custom_debug_blob(&data, kind);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid format indicator"));
    }

    #[test]
    fn test_parse_invalid_utf8_returns_error() {
        let kind = CustomDebugKind::SourceLink;
        // Invalid UTF-8 sequence
        let data = [0xFF, 0xFE, 0x00, 0x01];

        let result = parse_custom_debug_blob(&data, kind);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid UTF-8"));
    }

    #[test]
    fn test_parse_compilation_metadata() {
        let kind = CustomDebugKind::CompilationMetadata;
        let data = b"compiler: csc 4.0";
        let result = parse_custom_debug_blob(data, kind).unwrap();

        match result {
            CustomDebugInfo::CompilationMetadata { metadata } => {
                assert_eq!(metadata, "compiler: csc 4.0");
            }
            _ => panic!("Expected CompilationMetadata variant"),
        }
    }

    #[test]
    fn test_parse_compilation_options() {
        let kind = CustomDebugKind::CompilationOptions;
        let data = b"/optimize+ /debug:full";
        let result = parse_custom_debug_blob(data, kind).unwrap();

        match result {
            CustomDebugInfo::CompilationOptions { options } => {
                assert_eq!(options, "/optimize+ /debug:full");
            }
            _ => panic!("Expected CompilationOptions variant"),
        }
    }
}
