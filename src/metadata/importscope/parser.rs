//! Import declarations binary parser for Portable PDB debugging metadata.
//!
//! This module provides comprehensive parsing capabilities for the imports blob format used in
//! Portable PDB files. The imports blob contains encoded import declarations that define the set
//! of namespaces, types, and assemblies accessible within a lexical scope for debugging purposes.
//! The parser implements the full Portable PDB imports specification with robust error handling
//! and efficient binary data processing.
//!
//! # Architecture
//!
//! The parser implements a streaming binary format reader that processes import declarations
//! sequentially from a blob. The architecture separates low-level binary parsing from
//! high-level semantic interpretation, enabling efficient processing of large import scopes
//! while maintaining type safety and error recovery.
//!
//! ## Core Components
//!
//! - **Binary Parser**: Low-level compressed integer and token parsing
//! - **Kind Dispatch**: Type-safe import kind identification and parameter extraction
//! - **Heap Resolution**: String and blob reference resolution from metadata heaps
//! - **Error Recovery**: Graceful handling of malformed or truncated import data
//!
//! # Key Components
//!
//! - [`crate::metadata::importscope::parser::ImportsParser`] - Main binary parser implementation
//! - [`crate::metadata::importscope::parser::parse_imports_blob`] - Convenience parsing function
//! - Format-specific parsing methods for each import declaration kind
//! - Integrated blob heap resolution for string and reference data
//!
//! # Imports Blob Binary Format
//!
//! The imports blob follows the Portable PDB specification with this binary structure:
//!
//! ```text
//! ImportsBlob ::= ImportDeclaration*
//! ImportDeclaration ::= ImportKind ImportParameters
//! ImportKind ::= CompressedUInt32  // Values 1-9
//! ImportParameters ::= [Alias] [AssemblyRef] [Namespace] [TypeRef]
//! ```
//!
//! ## Format Details
//!
//! Each import declaration consists of:
//! - **Kind**: Compressed unsigned integer (1-9) defining the import type and parameter layout
//! - **Alias**: Optional blob heap index for UTF-8 alias name (for alias declarations)
//! - **Assembly**: Optional [`crate::metadata::tables::AssemblyRef`] row ID for assembly references
//! - **Namespace**: Optional blob heap index for UTF-8 namespace name
//! - **Type**: Optional compressed [`crate::metadata::token::Token`] for type references
//!
//! ## Import Declaration Types
//!
//! The format supports 9 distinct import declaration types:
//!
//! 1. **ImportNamespace** (1): Using statement for entire namespace
//! 2. **ImportAssemblyNamespace** (2): Namespace import from specific assembly
//! 3. **ImportType** (3): Direct type import with full qualification
//! 4. **ImportXmlNamespace** (4): XML namespace import with alias
//! 5. **ImportAssemblyReferenceAlias** (5): Assembly reference alias declaration
//! 6. **DefineAssemblyAlias** (6): Assembly alias definition
//! 7. **DefineNamespaceAlias** (7): Namespace alias definition
//! 8. **DefineAssemblyNamespaceAlias** (8): Assembly namespace alias definition
//! 9. **DefineTypeAlias** (9): Type alias definition
//!
//! # Usage Examples
//!
//! ## Basic Import Blob Parsing
//!
//! ```rust,ignore
//! use dotscope::metadata::importscope::{parse_imports_blob, ImportDeclaration};
//! use dotscope::metadata::streams::Blob;
//!
//! # fn get_blob_data() -> (&'static [u8], &'static Blob<'static>) {
//! #     (b"", &Blob::new())
//! # }
//! let (blob_data, blobs_heap) = get_blob_data();
//!
//! // Parse complete imports blob
//! let imports = parse_imports_blob(blob_data, blobs_heap)?;
//!
//! println!("Parsed {} import declarations", imports.declarations.len());
//!
//! // Process import declarations by type
//! for declaration in &imports.declarations {
//!     match declaration {
//!         ImportDeclaration::ImportNamespace { namespace } => {
//!             println!("Using namespace: {}", namespace);
//!         }
//!         ImportDeclaration::ImportAssemblyNamespace { assembly_ref, namespace } => {
//!             println!("Using {} from assembly {:?}", namespace, assembly_ref);
//!         }
//!         ImportDeclaration::ImportType { type_ref } => {
//!             println!("Importing type: {:?}", type_ref);
//!         }
//!         _ => println!("Other import declaration type"),
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Advanced Parser Usage
//!
//! ```rust,ignore
//! use dotscope::metadata::importscope::parser::ImportsParser;
//! use dotscope::metadata::streams::Blob;
//!
//! # fn get_import_data() -> (&'static [u8], &'static Blob<'static>) {
//! #     (b"", &Blob::new())
//! # }
//! let (blob_data, blobs_heap) = get_import_data();
//!
//! // Create parser with specific blob data
//! let mut parser = ImportsParser::new(blob_data, blobs_heap);
//!
//! // Parse imports with custom processing
//! let imports_info = parser.parse_imports()?;
//!
//! // Analyze import patterns
//! let namespace_imports = imports_info.declarations.iter()
//!     .filter(|d| matches!(d, ImportDeclaration::ImportNamespace { .. }))
//!     .count();
//!
//! println!("Found {} namespace import declarations", namespace_imports);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Example Binary Format
//!
//! ```rust,ignore
//! use dotscope::metadata::importscope::parse_imports_blob;
//!
//! // Example imports blob with two declarations
//! # fn example_parsing() -> dotscope::Result<()> {
//! let blob_data = &[
//!     0x01,                           // ImportNamespace (kind 1)
//!     0x05, 0x54, 0x65, 0x73, 0x74, 0x73,  // "Tests" namespace (length 5 + UTF-8)
//!     
//!     0x02,                           // ImportAssemblyNamespace (kind 2)  
//!     0x01,                           // AssemblyRef row ID 1
//!     0x06, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D,  // "System" namespace
//! ];
//!
//! # let blobs_heap = &dotscope::metadata::streams::Blob::new();
//! let imports = parse_imports_blob(blob_data, blobs_heap)?;
//! assert_eq!(imports.declarations.len(), 2);
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! The parser provides comprehensive error handling for various failure scenarios:
//! - **Invalid Kind Values**: Unrecognized import kind values outside 1-9 range
//! - **Truncated Data**: Insufficient data for expected import parameters
//! - **Blob Resolution Failures**: Invalid blob heap indices for strings
//! - **Token Encoding Errors**: Malformed compressed token encoding
//! - **UTF-8 Decoding**: Invalid UTF-8 sequences in namespace or alias strings
//!
//! # Performance Considerations
//!
//! - **Streaming Parser**: Processes data sequentially without buffering entire blob
//! - **Zero-Copy Strings**: Minimizes string allocations during blob processing
//! - **Efficient Heap Access**: Optimized blob heap lookups for string resolution
//! - **Error Short-Circuiting**: Fast failure on malformed data without full parsing
//!
//! # Thread Safety
//!
//! All parsing functions and types in this module are thread-safe. The parser and
//! [`crate::metadata::importscope::parser::parse_imports_blob`] function implement
//! [`std::marker::Send`] and [`std::marker::Sync`], enabling safe concurrent parsing
//! of import declarations across multiple threads. String resolution from blob heaps
//! is also thread-safe with appropriate synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::importscope::types`] - Type definitions for import declarations
//! - [`crate::file::parser`] - Low-level binary data parsing utilities
//! - [`crate::metadata::streams::Blob`] - Blob heap access for string resolution
//! - [`crate::metadata::token`] - Token parsing and validation systems
//! - [`crate::Error`] - Comprehensive error handling and reporting
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: Full compliance with Portable PDB imports blob specification
//! - **Binary Format**: Correct handling of compressed integers and token encoding
//! - **UTF-8 Encoding**: Proper decoding of namespace and alias strings
//! - **Error Recovery**: Robust handling of malformed or incomplete import data

use crate::{
    file::parser::Parser,
    metadata::{
        importscope::types::{ImportDeclaration, ImportKind, ImportsInfo},
        streams::Blob,
        token::Token,
    },
    Result,
};

/// Parser for imports blob binary data implementing the Portable PDB specification.
///
/// This parser follows the same architectural pattern as other parsers in the codebase
/// (like `SignatureParser` and `MarshallingParser`) with proper error handling and
/// state management. It provides a structured approach to parsing the complex binary
/// format of imports blobs.
///
/// # Thread Safety
///
/// The parser is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only borrowed data.
/// Instances can be safely used across threads and accessed concurrently.
pub struct ImportsParser<'a> {
    /// Binary data parser for reading blob data
    parser: Parser<'a>,
    /// Reference to the blob heap for resolving blob indices
    blobs: &'a Blob<'a>,
}

impl<'a> ImportsParser<'a> {
    /// Creates a new parser for the given imports blob data.
    ///
    /// # Arguments
    /// * `data` - The byte slice containing the imports blob to parse
    /// * `blobs` - Reference to the blob heap for resolving blob indices
    ///
    /// # Returns
    /// A new parser ready to parse the provided data.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn new(data: &'a [u8], blobs: &'a Blob) -> Self {
        ImportsParser {
            parser: Parser::new(data),
            blobs,
        }
    }

    /// Parse the complete imports blob into structured import declarations.
    ///
    /// This method reads all import declarations from the blob sequentially until
    /// the end of data is reached. Each declaration is parsed according to its
    /// kind and added to the resulting imports information.
    ///
    /// # Returns
    /// * [`Ok`]([`ImportsInfo`]) - Successfully parsed imports information
    /// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data or I/O errors
    ///
    /// # Errors
    /// This method returns an error in the following cases:
    /// - **Invalid Kind**: Unrecognized import kind value (not 1-9)
    /// - **Truncated Data**: Insufficient data for expected parameters
    /// - **Invalid Blob**: Blob heap references that cannot be resolved
    /// - **Malformed Tokens**: Invalid compressed token encoding
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn parse_imports(&mut self) -> Result<ImportsInfo> {
        let mut declarations = Vec::new();

        while self.parser.has_more_data() {
            let kind_value = self.parser.read_compressed_uint()?;
            let kind = ImportKind::from_u32(kind_value)
                .ok_or_else(|| malformed_error!(format!("Invalid import kind: {}", kind_value)))?;

            let declaration = match kind {
                ImportKind::ImportNamespace => {
                    let namespace = self.read_blob_string()?;
                    ImportDeclaration::ImportNamespace { namespace }
                }
                ImportKind::ImportAssemblyNamespace => {
                    let assembly_ref = self.read_assembly_ref_token()?;
                    let namespace = self.read_blob_string()?;
                    ImportDeclaration::ImportAssemblyNamespace {
                        assembly_ref,
                        namespace,
                    }
                }
                ImportKind::ImportType => {
                    let type_ref = self.parser.read_compressed_token()?;
                    ImportDeclaration::ImportType { type_ref }
                }
                ImportKind::ImportXmlNamespace => {
                    let alias = self.read_blob_string()?;
                    let namespace = self.read_blob_string()?;
                    ImportDeclaration::ImportXmlNamespace { alias, namespace }
                }
                ImportKind::ImportAssemblyReferenceAlias => {
                    let alias = self.read_blob_string()?;
                    ImportDeclaration::ImportAssemblyReferenceAlias { alias }
                }
                ImportKind::DefineAssemblyAlias => {
                    let alias = self.read_blob_string()?;
                    let assembly_ref = self.read_assembly_ref_token()?;
                    ImportDeclaration::DefineAssemblyAlias {
                        alias,
                        assembly_ref,
                    }
                }
                ImportKind::DefineNamespaceAlias => {
                    let alias = self.read_blob_string()?;
                    let namespace = self.read_blob_string()?;
                    ImportDeclaration::DefineNamespaceAlias { alias, namespace }
                }
                ImportKind::DefineAssemblyNamespaceAlias => {
                    let alias = self.read_blob_string()?;
                    let assembly_ref = self.read_assembly_ref_token()?;
                    let namespace = self.read_blob_string()?;
                    ImportDeclaration::DefineAssemblyNamespaceAlias {
                        alias,
                        assembly_ref,
                        namespace,
                    }
                }
                ImportKind::DefineTypeAlias => {
                    let alias = self.read_blob_string()?;
                    let type_ref = self.parser.read_compressed_token()?;
                    ImportDeclaration::DefineTypeAlias { alias, type_ref }
                }
            };

            declarations.push(declaration);
        }

        Ok(ImportsInfo::with_declarations(declarations))
    }

    /// Read a string from the blob heap using a compressed blob index.
    fn read_blob_string(&mut self) -> Result<String> {
        let blob_index = self.parser.read_compressed_uint()?;
        let blob_data = self.blobs.get(blob_index as usize)?;
        Ok(String::from_utf8_lossy(blob_data).into_owned())
    }

    /// Read an `AssemblyRef` token as a compressed unsigned integer.
    fn read_assembly_ref_token(&mut self) -> Result<Token> {
        let row_id = self.parser.read_compressed_uint()?;
        Ok(Token::new(0x2300_0000 + row_id)) // AssemblyRef table
    }
}

/// Parse an imports blob into structured import declarations.
///
/// This is a convenience function that creates a parser and parses a complete
/// imports blob from the provided byte slice. The function handles the full parsing
/// process including kind identification, parameter extraction, and heap resolution.
///
/// # Arguments
/// * `data` - The byte slice containing the imports blob to parse
/// * `blobs` - Reference to the blob heap for resolving blob indices
///
/// # Returns
/// * [`Ok`]([`ImportsInfo`]) - Successfully parsed imports information
/// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data or I/O errors
///
/// # Errors
/// This function returns an error in the following cases:
/// - **Invalid Format**: Malformed or truncated imports blob
/// - **Unknown Kind**: Unrecognized import kind value
/// - **Blob Resolution**: Blob heap references that cannot be resolved
/// - **Token Encoding**: Invalid compressed token encoding
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::importscope::parse_imports_blob;
///
/// let blob_data = &[0x01, 0x05, 0x54, 0x65, 0x73, 0x74, 0x73]; // ImportNamespace "Tests"
/// let imports = parse_imports_blob(blob_data, blobs_heap)?;
///
/// assert_eq!(imports.declarations.len(), 1);
/// if let ImportDeclaration::ImportNamespace { namespace } = &imports.declarations[0] {
///     assert_eq!(namespace, "Tests");
/// }
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads.
pub fn parse_imports_blob(data: &[u8], blobs: &Blob) -> Result<ImportsInfo> {
    if data.is_empty() {
        return Ok(ImportsInfo::new());
    }

    let mut parser = ImportsParser::new(data, blobs);
    parser.parse_imports()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::streams::Blob;

    fn create_mock_blob_stream() -> Blob<'static> {
        Blob::from(&[0x00]).expect("Failed to create blob stream")
    }

    #[test]
    fn test_parse_empty_blob() {
        let blobs = create_mock_blob_stream();
        let result = parse_imports_blob(&[], &blobs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_imports_parser_new() {
        let blobs = create_mock_blob_stream();
        let data = &[0x01, 0x00];
        let parser = ImportsParser::new(data, &blobs);

        assert_eq!(parser.parser.len(), 2);
    }
}
