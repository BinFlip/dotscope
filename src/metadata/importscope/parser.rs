//! Binary parser for import declarations in Portable PDB debugging metadata.
//!
//! This module provides the parsing implementation for the imports blob format.
//! See the parent module [`crate::metadata::importscope`] for the complete binary
//! format specification and usage examples.
//!
//! # Overview
//!
//! The parser reads import declarations sequentially from a binary blob, resolving
//! string references from the blob heap and constructing typed [`ImportDeclaration`]
//! values for each entry.
//!
//! # Error Handling
//!
//! The parser returns errors for:
//! - **Invalid Kind Values**: Import kind values outside the valid 1-9 range
//! - **Truncated Data**: Insufficient data for expected import parameters
//! - **Blob Resolution Failures**: Invalid blob heap indices
//! - **Token Encoding Errors**: Malformed compressed token encoding
//!
//! Note: Invalid UTF-8 sequences in strings are handled using lossy conversion
//! (replacement with U+FFFD) rather than returning errors, matching the behavior
//! of other parsers in the codebase.
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`].

use crate::{
    file::parser::Parser,
    metadata::{
        importscope::types::{ImportDeclaration, ImportKind, ImportsInfo},
        streams::Blob,
        tables::TableId,
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
                .ok_or_else(|| malformed_error!("Invalid import kind: {}", kind_value))?;

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

    /// Read a UTF-8 string from the blob heap using a compressed blob index.
    ///
    /// # UTF-8 Handling
    ///
    /// Invalid UTF-8 sequences are replaced with the Unicode replacement character (U+FFFD)
    /// using lossy conversion. No error is returned for invalid encoding - this matches
    /// the behavior of other parsers in the codebase (e.g., `security/permissionset.rs`).
    ///
    /// # Empty Strings
    ///
    /// Empty strings are permitted and returned as-is. The Portable PDB specification
    /// does not explicitly prohibit empty namespace or alias strings, and some edge
    /// cases (like default/global namespaces) may legitimately use empty strings.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob index is invalid or the blob heap lookup fails.
    fn read_blob_string(&mut self) -> Result<String> {
        let blob_index = self.parser.read_compressed_uint()?;
        let blob_data = self.blobs.get(blob_index as usize)?;
        Ok(String::from_utf8_lossy(blob_data).into_owned())
    }

    /// Read an AssemblyRef table token from a compressed unsigned integer row ID.
    ///
    /// The row ID is read as a compressed unsigned integer and combined with
    /// the AssemblyRef table identifier (0x23) to form a complete metadata token.
    ///
    /// # Token Format
    ///
    /// The returned token has format `(TableId::AssemblyRef << 24) | row_id`, where
    /// `row_id` is a 1-based index into the AssemblyRef table.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the compressed integer fails due to truncated data.
    fn read_assembly_ref_token(&mut self) -> Result<Token> {
        let row_id = self.parser.read_compressed_uint()?;
        Ok(Token::new((TableId::AssemblyRef as u32) << 24 | row_id))
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

    /// Creates a minimal blob heap with just the required null blob at index 0.
    fn create_empty_blob_stream() -> Blob<'static> {
        Blob::from(&[0x00]).expect("Failed to create blob stream")
    }

    /// Creates a blob heap with test strings.
    /// Layout:
    /// - Index 0: empty blob (required)
    /// - Index 1: "System" (6 bytes)
    /// - Index 8: "TestAlias" (9 bytes)
    /// - Index 18: "http://example.com" (18 bytes)
    fn create_test_blob_stream() -> Vec<u8> {
        let mut data = vec![0x00]; // Index 0: null blob

        // Index 1: "System" (length 6)
        data.push(0x06); // length = 6
        data.extend_from_slice(b"System");

        // Index 8: "TestAlias" (length 9)
        data.push(0x09); // length = 9
        data.extend_from_slice(b"TestAlias");

        // Index 18: "http://example.com" (length 18)
        data.push(0x12); // length = 18
        data.extend_from_slice(b"http://example.com");

        data
    }

    #[test]
    fn test_parse_empty_blob() {
        let blobs = create_empty_blob_stream();
        let result = parse_imports_blob(&[], &blobs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_imports_parser_new() {
        let blobs = create_empty_blob_stream();
        let data = &[0x01, 0x00];
        let parser = ImportsParser::new(data, &blobs);

        assert_eq!(parser.parser.len(), 2);
    }

    #[test]
    fn test_parse_import_namespace() {
        // ImportKind::ImportNamespace = 1, followed by blob index for namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 1 (ImportNamespace), blob index 1 ("System")
        let import_data = &[0x01, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportNamespace { namespace } => {
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected ImportNamespace declaration"),
        }
    }

    #[test]
    fn test_parse_import_assembly_namespace() {
        // ImportKind::ImportAssemblyNamespace = 2, followed by assembly ref row ID and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 2 (ImportAssemblyNamespace), assembly ref row 3, blob index 1 ("System")
        let import_data = &[0x02, 0x03, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportAssemblyNamespace {
                assembly_ref,
                namespace,
            } => {
                assert_eq!(assembly_ref.value(), 0x23000003); // AssemblyRef table (0x23) + row 3
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected ImportAssemblyNamespace declaration"),
        }
    }

    #[test]
    fn test_parse_import_type() {
        // ImportKind::ImportType = 3, followed by compressed token
        let blobs = create_empty_blob_stream();

        // Kind 3 (ImportType), compressed token for TypeRef row 5 (0x01000005)
        // Compressed token encoding: (row << 2) | table_index
        // TypeRef table index in TypeDefOrRefOrSpecEncoded = 1
        // So encoded = (5 << 2) | 1 = 21 = 0x15
        let import_data = &[0x03, 0x15];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportType { type_ref } => {
                assert_eq!(type_ref.value(), 0x01000005); // TypeRef table (0x01) + row 5
            }
            _ => panic!("Expected ImportType declaration"),
        }
    }

    #[test]
    fn test_parse_import_xml_namespace() {
        // ImportKind::ImportXmlNamespace = 4, followed by alias and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 4 (ImportXmlNamespace), alias blob index 8 ("TestAlias"), namespace blob index 18
        let import_data = &[0x04, 0x08, 0x12];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportXmlNamespace { alias, namespace } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(namespace, "http://example.com");
            }
            _ => panic!("Expected ImportXmlNamespace declaration"),
        }
    }

    #[test]
    fn test_parse_import_assembly_reference_alias() {
        // ImportKind::ImportAssemblyReferenceAlias = 5, followed by alias
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 5 (ImportAssemblyReferenceAlias), alias blob index 8 ("TestAlias")
        let import_data = &[0x05, 0x08];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::ImportAssemblyReferenceAlias { alias } => {
                assert_eq!(alias, "TestAlias");
            }
            _ => panic!("Expected ImportAssemblyReferenceAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_assembly_alias() {
        // ImportKind::DefineAssemblyAlias = 6, followed by alias and assembly ref
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 6 (DefineAssemblyAlias), alias blob index 8 ("TestAlias"), assembly ref row 2
        let import_data = &[0x06, 0x08, 0x02];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineAssemblyAlias {
                alias,
                assembly_ref,
            } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(assembly_ref.value(), 0x23000002);
            }
            _ => panic!("Expected DefineAssemblyAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_namespace_alias() {
        // ImportKind::DefineNamespaceAlias = 7, followed by alias and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 7 (DefineNamespaceAlias), alias blob index 8 ("TestAlias"), namespace blob index 1 ("System")
        let import_data = &[0x07, 0x08, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineNamespaceAlias { alias, namespace } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected DefineNamespaceAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_assembly_namespace_alias() {
        // ImportKind::DefineAssemblyNamespaceAlias = 8, followed by alias, assembly ref, and namespace
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 8, alias blob index 8 ("TestAlias"), assembly ref row 1, namespace blob index 1 ("System")
        let import_data = &[0x08, 0x08, 0x01, 0x01];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineAssemblyNamespaceAlias {
                alias,
                assembly_ref,
                namespace,
            } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(assembly_ref.value(), 0x23000001);
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected DefineAssemblyNamespaceAlias declaration"),
        }
    }

    #[test]
    fn test_parse_define_type_alias() {
        // ImportKind::DefineTypeAlias = 9, followed by alias and type ref token
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Kind 9 (DefineTypeAlias), alias blob index 8 ("TestAlias"), compressed token for TypeDef row 10
        // TypeDef table index in TypeDefOrRefOrSpecEncoded = 0
        // Encoded = (10 << 2) | 0 = 40 = 0x28
        let import_data = &[0x09, 0x08, 0x28];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 1);
        match &result.declarations[0] {
            ImportDeclaration::DefineTypeAlias { alias, type_ref } => {
                assert_eq!(alias, "TestAlias");
                assert_eq!(type_ref.value(), 0x0200000A); // TypeDef table (0x02) + row 10
            }
            _ => panic!("Expected DefineTypeAlias declaration"),
        }
    }

    #[test]
    fn test_parse_multiple_declarations() {
        // Test parsing multiple declarations in sequence
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Multiple declarations:
        // 1. ImportNamespace "System" (kind 1, blob index 1)
        // 2. ImportAssemblyReferenceAlias "TestAlias" (kind 5, blob index 8)
        let import_data = &[0x01, 0x01, 0x05, 0x08];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        assert_eq!(result.len(), 2);

        match &result.declarations[0] {
            ImportDeclaration::ImportNamespace { namespace } => {
                assert_eq!(namespace, "System");
            }
            _ => panic!("Expected ImportNamespace as first declaration"),
        }

        match &result.declarations[1] {
            ImportDeclaration::ImportAssemblyReferenceAlias { alias } => {
                assert_eq!(alias, "TestAlias");
            }
            _ => panic!("Expected ImportAssemblyReferenceAlias as second declaration"),
        }
    }

    #[test]
    fn test_parse_invalid_kind() {
        // Test that invalid kind values (0, 10+) return errors
        let blobs = create_empty_blob_stream();

        // Kind 0 is invalid
        let import_data = &[0x00];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());

        // Kind 10 is invalid
        let import_data = &[0x0A];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());

        // Kind 255 is invalid
        let import_data = &[0xFF];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_truncated_data() {
        // Test that truncated data returns errors
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // ImportAssemblyNamespace (kind 2) requires assembly ref and namespace, but only kind is provided
        let import_data = &[0x02];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());

        // ImportAssemblyNamespace with assembly ref but missing namespace
        let import_data = &[0x02, 0x01];
        let result = parse_imports_blob(import_data, &blobs);
        assert!(result.is_err());
    }

    #[test]
    fn test_imports_info_iteration() {
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        let import_data = &[0x01, 0x01, 0x05, 0x08];
        let result = parse_imports_blob(import_data, &blobs).unwrap();

        // Test iter()
        let mut count = 0;
        for _decl in result.iter() {
            count += 1;
        }
        assert_eq!(count, 2);

        // Test into_iter() for &ImportsInfo
        count = 0;
        for _decl in &result {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn test_assembly_ref_token_format() {
        // Verify that assembly ref tokens are correctly formatted
        let blob_data = create_test_blob_stream();
        let blobs = Blob::from(&blob_data).expect("Failed to create blob stream");

        // Test various row IDs (single byte compressed uint values: 0x00-0x7F)
        for row_id in [1u32, 10, 50, 127] {
            let import_data = vec![0x06, 0x08, row_id as u8]; // DefineAssemblyAlias
            let result = parse_imports_blob(&import_data, &blobs).unwrap();

            match &result.declarations[0] {
                ImportDeclaration::DefineAssemblyAlias { assembly_ref, .. } => {
                    let expected = (TableId::AssemblyRef as u32) << 24 | row_id;
                    assert_eq!(assembly_ref.value(), expected);
                }
                _ => panic!("Expected DefineAssemblyAlias"),
            }
        }
    }
}
