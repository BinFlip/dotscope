//! Import declarations parser for Portable PDB `ImportScope` table.
//!
//! This module provides parsing capabilities for the imports blob format used in Portable PDB files.
//! The imports blob contains encoded import declarations that define the set of namespaces, types,
//! and assemblies that are accessible within a lexical scope for debugging purposes.
//!
//! # Imports Blob Format
//!
//! The imports blob follows this binary structure:
//! ```text
//! Blob ::= Import*
//! Import ::= kind alias? target-assembly? target-namespace? target-type?
//! ```
//!
//! Each import declaration consists of:
//! - **kind**: Compressed unsigned integer (1-9) defining the import type
//! - **alias**: Optional blob heap index for UTF8 alias name
//! - **target-assembly**: Optional `AssemblyRef` row id for assembly references
//! - **target-namespace**: Optional blob heap index for UTF8 namespace name
//! - **target-type**: Optional `TypeDefOrRefOrSpecEncoded` type reference
//!
//! # Thread Safety
//!
//! All parsing functions and types in this module are thread-safe. The parser
//! and [`crate::metadata::importscope::parser::parse_imports_blob`] function are [`std::marker::Send`] and [`std::marker::Sync`],
//! enabling safe concurrent parsing of import declarations across multiple threads.
//!
//! # Examples
//!
//! ## Parsing Imports Blob
//!
//! ```rust,ignore
//! use dotscope::metadata::importscope::parse_imports_blob;
//!
//! let blob_data = &[
//!     0x01, // ImportNamespace
//!     0x05, 0x54, 0x65, 0x73, 0x74, 0x73, // "Tests" namespace
//!     0x02, // ImportAssemblyNamespace  
//!     0x01, 0x00, 0x00, 0x00, // AssemblyRef row id 1
//!     0x06, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, // "System" namespace
//! ];
//!
//! let imports = parse_imports_blob(blob_data, blobs_heap)?;
//! for import in &imports.declarations {
//!     match import {
//!         ImportDeclaration::ImportNamespace { namespace } => {
//!             println!("Import namespace: {}", namespace);
//!         }
//!         ImportDeclaration::ImportAssemblyNamespace { assembly_ref, namespace } => {
//!             println!("Import {} from assembly {}", namespace, assembly_ref);
//!         }
//!         _ => println!("Other import type"),
//!     }
//! }
//! ```

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
