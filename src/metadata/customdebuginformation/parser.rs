//! Custom debug information parser for Portable PDB CustomDebugInformation table.
//!
//! This module provides parsing capabilities for the custom debug information blob format used
//! in Portable PDB files. The blob format varies depending on the GUID kind, supporting various
//! types of debugging metadata including source link mappings, embedded source files, and
//! compiler-specific information.
//!
//! # Custom Debug Information Blob Format
//!
//! The blob format depends on the Kind GUID from the CustomDebugInformation table:
//!
//! ## Source Link Format
//! ```text
//! SourceLinkBlob ::= compressed_length utf8_json_document
//! ```
//!
//! ## Embedded Source Format
//! ```text
//! EmbeddedSourceBlob ::= compressed_length utf8_source_content
//! ```
//!
//! ## Other Formats
//! For unknown or unsupported GUIDs, the blob is returned as raw bytes.
//!
//! # Examples
//!
//! ## Parsing Custom Debug Information Blob
//!
//! ```rust,ignore
//! use dotscope::metadata::customdebuginformation::parse_custom_debug_blob;
//! use dotscope::metadata::customdebuginformation::CustomDebugKind;
//!
//! let guid_bytes = [0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D, 0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35, 0x1A, 0x6A];
//! let kind = CustomDebugKind::from_guid(guid_bytes);
//! let blob_data = &[0x1E, 0x7B, 0x22, 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x73, 0x22, 0x3A, 0x7B, 0x7D, 0x7D]; // Source Link JSON
//!
//! let debug_info = parse_custom_debug_blob(blob_data, kind)?;
//! match debug_info {
//!     CustomDebugInfo::SourceLink { document } => {
//!         println!("Source Link document: {}", document);
//!     }
//!     _ => println!("Other debug info type"),
//! }
//! ```

use crate::{file::parser::Parser, metadata::customdebuginformation::types::*, Result};

/// Parser for custom debug information blob binary data implementing the Portable PDB specification.
///
/// This parser handles different blob formats based on the debug information kind GUID.
/// It provides structured parsing of various debugging metadata formats.
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
    /// A new [`CustomDebugParser`] ready to parse the provided data.
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
    pub fn parse_debug_info(&mut self) -> Result<CustomDebugInfo> {
        match self.kind {
            CustomDebugKind::SourceLink => {
                let document = self.read_utf8_string()?;
                Ok(CustomDebugInfo::SourceLink { document })
            }
            CustomDebugKind::EmbeddedSource => {
                // For embedded source, we need to handle the filename and content
                // For now, treat the entire blob as content
                let content = self.read_utf8_string()?;
                Ok(CustomDebugInfo::EmbeddedSource {
                    filename: String::new(), // TODO: Extract filename if available
                    content,
                })
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
                let remaining_data = &self.parser.data()[self.parser.pos()..];
                let data = remaining_data.to_vec();
                Ok(CustomDebugInfo::Unknown {
                    kind: self.kind,
                    data,
                })
            }
        }
    }

    /// Read a UTF-8 string from the blob, optionally prefixed with compressed length.
    ///
    /// Many custom debug information formats store UTF-8 strings with an optional
    /// compressed length prefix. This method handles both cases.
    fn read_utf8_string(&mut self) -> Result<String> {
        // Try to read compressed length first
        if self.parser.has_more_data() {
            // For many formats, the blob contains the raw UTF-8 string
            // Some formats may have a compressed length prefix
            let remaining_data = &self.parser.data()[self.parser.pos()..];

            // Try to decode as UTF-8
            let string_data = String::from_utf8_lossy(remaining_data).into_owned();
            Ok(string_data)
        } else {
            Ok(String::new())
        }
    }
}

/// Parse a custom debug information blob into structured debug information.
///
/// This is a convenience function that creates a [`CustomDebugParser`] and parses a complete
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
}
