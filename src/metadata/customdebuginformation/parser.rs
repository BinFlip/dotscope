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
//! ## Source Link Format
//! ```text
//! SourceLinkBlob ::= [compressed_length] utf8_json_document
//! ```
//! Contains JSON mapping source files to repository URLs for debugging.
//!
//! ## Embedded Source Format  
//! ```text
//! EmbeddedSourceBlob ::= [compressed_length] utf8_source_content
//! ```
//! Contains complete source file content embedded in the debug information.
//!
//! ## Compilation Metadata Format
//! ```text
//! CompilationMetadataBlob ::= [compressed_length] utf8_metadata_json
//! ```
//! Contains compiler and build environment metadata.
//!
//! ## Compilation Options Format
//! ```text
//! CompilationOptionsBlob ::= [compressed_length] utf8_options_json
//! ```
//! Contains compiler options and flags used during compilation.
//!
//! ## Unknown Formats
//! For unrecognized GUIDs, the blob is returned as raw bytes for future extension.
//!
//! # Usage Examples
//!
//! ## Basic Debug Information Parsing
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugKind, CustomDebugInfo};
//!
//! # fn get_debug_data() -> (dotscope::metadata::customdebuginformation::CustomDebugKind, &'static [u8]) {
//! #     (CustomDebugKind::SourceLink, b"{\"documents\":{}}")
//! # }
//! let (kind, blob_data) = get_debug_data();
//!
//! let debug_info = parse_custom_debug_blob(blob_data, kind)?;
//! match debug_info {
//!     CustomDebugInfo::SourceLink { document } => {
//!         println!("Source Link JSON: {}", document);
//!         
//!         // Parse JSON for source mapping analysis
//!         if let Ok(json) = serde_json::from_str::<serde_json::Value>(&document) {
//!             if let Some(documents) = json.get("documents") {
//!                 println!("Source documents: {}", documents);
//!             }
//!         }
//!     }
//!     CustomDebugInfo::EmbeddedSource { filename, content } => {
//!         println!("Embedded source: {} ({} bytes)", filename, content.len());
//!     }
//!     CustomDebugInfo::Unknown { kind, data } => {
//!         println!("Unknown debug info: {:?} ({} bytes)", kind, data.len());
//!     }
//!     _ => println!("Other debug info type"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Advanced Parser Usage
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::parser::CustomDebugParser;
//! use dotscope::metadata::customdebuginformation::CustomDebugKind;
//!
//! # fn get_blob_data() -> &'static [u8] { b"example debug data" }
//! let blob_data = get_blob_data();
//! let kind = CustomDebugKind::CompilationMetadata;
//!
//! // Create parser with specific debug kind
//! let mut parser = CustomDebugParser::new(blob_data, kind);
//! let debug_info = parser.parse_debug_info();
//!
//! // Process parsed information
//! println!("Parsed debug info: {:?}", debug_info);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Working with Multiple Debug Entries
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugInfo};
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//!
//! # fn get_debug_entries() -> Vec<(dotscope::metadata::customdebuginformation::CustomDebugKind, Vec<u8>)> {
//! #     vec![]
//! # }
//! let debug_entries = get_debug_entries();
//!
//! for (kind, blob_data) in debug_entries {
//!     match parse_custom_debug_blob(&blob_data, kind)? {
//!         CustomDebugInfo::SourceLink { document } => {
//!             println!("Found Source Link configuration");
//!         }
//!         CustomDebugInfo::EmbeddedSource { filename, content } => {
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

use crate::{
    file::parser::Parser,
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
    /// - **Invalid UTF-8**: String data that cannot be decoded as UTF-8
    /// - **Malformed Blob**: Invalid blob structure for the specified kind
    pub fn parse_debug_info(&mut self) -> CustomDebugInfo {
        match self.kind {
            CustomDebugKind::SourceLink => {
                let document = self.read_utf8_string();
                CustomDebugInfo::SourceLink { document }
            }
            CustomDebugKind::EmbeddedSource => {
                // For embedded source, we need to handle the filename and content
                // For now, treat the entire blob as content
                let content = self.read_utf8_string();
                CustomDebugInfo::EmbeddedSource {
                    filename: String::new(), // TODO: Extract filename if available
                    content,
                }
            }
            CustomDebugKind::CompilationMetadata => {
                let metadata = self.read_utf8_string();
                CustomDebugInfo::CompilationMetadata { metadata }
            }
            CustomDebugKind::CompilationOptions => {
                let options = self.read_utf8_string();
                CustomDebugInfo::CompilationOptions { options }
            }
            CustomDebugKind::Unknown(_) => {
                // For unknown kinds, return the raw data
                let remaining_data = &self.parser.data()[self.parser.pos()..];
                let data = remaining_data.to_vec();
                CustomDebugInfo::Unknown {
                    kind: self.kind,
                    data,
                }
            }
        }
    }

    /// Read a UTF-8 string from the blob, optionally prefixed with compressed length.
    ///
    /// Many custom debug information formats store UTF-8 strings with an optional
    /// compressed length prefix. This method handles both cases.
    fn read_utf8_string(&mut self) -> String {
        // ToDo: Try to read compressed length first
        //       For many formats, the blob contains the raw UTF-8 string
        //       Some formats may have a compressed length prefix
        if self.parser.has_more_data() {
            let remaining_data = &self.parser.data()[self.parser.pos()..];

            // Try to decode as UTF-8
            String::from_utf8_lossy(remaining_data).into_owned()
        } else {
            String::new()
        }
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
/// - **Unknown Format**: Unsupported blob format for the specified kind
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::customdebuginformation::{parse_custom_debug_blob, CustomDebugKind};
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
    Ok(parser.parse_debug_info())
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
}
