//! # Document Builder
//!
//! Provides a fluent API for building Document table entries for Portable PDB debug information.
//! The Document table stores information about source documents referenced in debug information,
//! including document names/paths, hash algorithms, content hashes, and source language identifiers.
//!
//! ## Overview
//!
//! The `DocumentBuilder` enables creation of document entries with:
//! - Document name/path specification (required)
//! - Hash algorithm GUID specification (optional)
//! - Document content hash specification (optional)
//! - Source language GUID specification (optional)
//! - Validation of document name and GUID formats
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a document entry with basic information
//! let document_token = DocumentBuilder::new()
//!     .name("Program.cs")
//!     .csharp_language()
//!     .sha256_hash_algorithm()
//!     .hash(vec![0x12, 0x34, 0x56, 0x78]) // Example hash
//!     .build(&mut context)?;
//!
//! // Create a document with minimal information
//! let minimal_doc_token = DocumentBuilder::new()
//!     .name("Script.cs")
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Document name is required and validated
//! - **GUID Handling**: Provides helper methods for common language and hash algorithm GUIDs
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Heap Management**: Strings, blobs, and GUIDs are added to appropriate heaps

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{DocumentRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Document table entries.
///
/// `DocumentBuilder` provides a fluent API for creating entries in the Document
/// metadata table, which stores source document information for Portable PDB debug data.
/// Each document entry associates a source file with hash information and language metadata.
///
/// # Purpose
///
/// The Document table serves several key functions:
/// - **Source Mapping**: Associates IL instructions with source code locations
/// - **Integrity Verification**: Provides hash information for verifying document content
/// - **Language Support**: Identifies source languages for syntax highlighting and debugging
/// - **Debug Information**: Enables rich debugging experiences with proper source association
/// - **Tool Integration**: Supports IDEs, debuggers, and other development tools
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing Document entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
///
/// let document_token = DocumentBuilder::new()
///     .name("MyFile.cs")
///     .csharp_language()
///     .sha256_hash_algorithm()
///     .hash(vec![0x01, 0x02, 0x03, 0x04])
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Document Name Required**: A document name/path must be provided
/// - **Name Validation**: Document name cannot be empty
/// - **GUID Format**: Hash algorithm and language GUIDs must be 16 bytes
/// - **Hash Validation**: Document hash must be valid bytes if provided
///
/// # Integration
///
/// Document entries integrate with other debug metadata structures:
/// - **MethodDebugInformation**: References documents for sequence point mapping
/// - **LocalScope**: Associates local variable scopes with source documents
/// - **CustomDebugInformation**: Links custom debug data to source documents
/// - **Portable PDB**: Provides core document information for debug symbol files
#[derive(Debug, Clone)]
pub struct DocumentBuilder {
    /// The document name/path
    name: Option<String>,
    /// The hash algorithm GUID (16 bytes)
    hash_algorithm: Option<[u8; 16]>,
    /// The document content hash bytes
    hash: Option<Vec<u8>>,
    /// The source language GUID (16 bytes)
    language: Option<[u8; 16]>,
}

impl Default for DocumentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentBuilder {
    /// Creates a new `DocumentBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            hash_algorithm: None,
            hash: None,
            language: None,
        }
    }

    /// Sets the document name or path.
    ///
    /// The name typically represents a file path or URI that identifies
    /// the source document. This is the primary identifier for the document
    /// and is required for building the document entry.
    ///
    /// # Arguments
    ///
    /// * `name` - The document name or path
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .name("Program.cs");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the hash algorithm GUID.
    ///
    /// Specifies the algorithm used to compute the document content hash.
    /// The GUID identifies the specific hash algorithm for integrity verification.
    ///
    /// # Arguments
    ///
    /// * `guid` - 16-byte GUID identifying the hash algorithm
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let sha256_guid = [
    ///     0x8b, 0x12, 0xd6, 0x2a, 0x37, 0x7a, 0x42, 0x8c,
    ///     0x9b, 0x8c, 0x41, 0x09, 0xc8, 0x5e, 0x29, 0xc6
    /// ];
    /// let builder = DocumentBuilder::new()
    ///     .hash_algorithm(&sha256_guid);
    /// ```
    #[must_use]
    pub fn hash_algorithm(mut self, guid: &[u8; 16]) -> Self {
        self.hash_algorithm = Some(*guid);
        self
    }

    /// Sets the hash algorithm to SHA-1.
    ///
    /// Convenience method that sets the hash algorithm GUID to the standard
    /// SHA-1 algorithm identifier used in Portable PDB files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .sha1_hash_algorithm();
    /// ```
    #[must_use]
    pub fn sha1_hash_algorithm(mut self) -> Self {
        // SHA-1 algorithm GUID: ff1816ec-aa5e-4d10-87f7-6f4963833460
        self.hash_algorithm = Some([
            0xff, 0x18, 0x16, 0xec, 0xaa, 0x5e, 0x4d, 0x10, 0x87, 0xf7, 0x6f, 0x49, 0x63, 0x83,
            0x34, 0x60,
        ]);
        self
    }

    /// Sets the hash algorithm to SHA-256.
    ///
    /// Convenience method that sets the hash algorithm GUID to the standard
    /// SHA-256 algorithm identifier used in Portable PDB files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .sha256_hash_algorithm();
    /// ```
    #[must_use]
    pub fn sha256_hash_algorithm(mut self) -> Self {
        // SHA-256 algorithm GUID: 8b12d62a-377a-428c-9b8c-4109c85e29c6
        self.hash_algorithm = Some([
            0x8b, 0x12, 0xd6, 0x2a, 0x37, 0x7a, 0x42, 0x8c, 0x9b, 0x8c, 0x41, 0x09, 0xc8, 0x5e,
            0x29, 0xc6,
        ]);
        self
    }

    /// Sets the document content hash.
    ///
    /// Specifies the hash bytes computed using the specified hash algorithm.
    /// This hash is used for integrity verification and change detection.
    ///
    /// # Arguments
    ///
    /// * `hash_bytes` - The computed hash bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    /// let builder = DocumentBuilder::new()
    ///     .hash(hash_bytes);
    /// ```
    #[must_use]
    pub fn hash(mut self, hash_bytes: Vec<u8>) -> Self {
        self.hash = Some(hash_bytes);
        self
    }

    /// Sets the source language GUID.
    ///
    /// Specifies the programming language used in this document.
    /// The GUID identifies the specific language for syntax highlighting
    /// and debugging support.
    ///
    /// # Arguments
    ///
    /// * `guid` - 16-byte GUID identifying the source language
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let csharp_guid = [
    ///     0x3f, 0x5f, 0x6f, 0x40, 0x15, 0x5c, 0x11, 0xd4,
    ///     0x95, 0x68, 0x00, 0x80, 0xc7, 0x05, 0x06, 0x26
    /// ];
    /// let builder = DocumentBuilder::new()
    ///     .language(&csharp_guid);
    /// ```
    #[must_use]
    pub fn language(mut self, guid: &[u8; 16]) -> Self {
        self.language = Some(*guid);
        self
    }

    /// Sets the language to C#.
    ///
    /// Convenience method that sets the language GUID to the standard
    /// C# language identifier used in Portable PDB files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .csharp_language();
    /// ```
    #[must_use]
    pub fn csharp_language(mut self) -> Self {
        // C# language GUID: 3f5f6f40-155c-11d4-9568-0080c7050626
        self.language = Some([
            0x3f, 0x5f, 0x6f, 0x40, 0x15, 0x5c, 0x11, 0xd4, 0x95, 0x68, 0x00, 0x80, 0xc7, 0x05,
            0x06, 0x26,
        ]);
        self
    }

    /// Sets the language to Visual Basic.
    ///
    /// Convenience method that sets the language GUID to the standard
    /// Visual Basic language identifier used in Portable PDB files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .vb_language();
    /// ```
    #[must_use]
    pub fn vb_language(mut self) -> Self {
        // VB.NET language GUID: 3a12d0b8-c26c-11d0-b442-00a0244a1dd2
        self.language = Some([
            0x3a, 0x12, 0xd0, 0xb8, 0xc2, 0x6c, 0x11, 0xd0, 0xb4, 0x42, 0x00, 0xa0, 0x24, 0x4a,
            0x1d, 0xd2,
        ]);
        self
    }

    /// Sets the language to F#.
    ///
    /// Convenience method that sets the language GUID to the standard
    /// F# language identifier used in Portable PDB files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = DocumentBuilder::new()
    ///     .fsharp_language();
    /// ```
    #[must_use]
    pub fn fsharp_language(mut self) -> Self {
        // F# language GUID: ab4f38c9-b6e6-43ba-be3b-58080b2ccce3
        self.language = Some([
            0xab, 0x4f, 0x38, 0xc9, 0xb6, 0xe6, 0x43, 0xba, 0xbe, 0x3b, 0x58, 0x08, 0x0b, 0x2c,
            0xcc, 0xe3,
        ]);
        self
    }

    /// Builds the Document entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the document name is valid,
    /// adds strings, blobs, and GUIDs to the appropriate heaps, creates the Document
    /// table entry, and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created Document entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The document name is not set
    /// - The document name is empty
    /// - There are issues adding strings/blobs/GUIDs to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    ///
    /// let document_token = DocumentBuilder::new()
    ///     .name("Program.cs")
    ///     .csharp_language()
    ///     .build(&mut context)?;
    ///
    /// println!("Created Document with token: {}", document_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let document_name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Document name is required for Document".to_string(),
            })?;

        if document_name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Document name cannot be empty".to_string(),
            });
        }

        let rid = context.next_rid(TableId::Document);
        let token = Token::new(((TableId::Document as u32) << 24) | rid);
        let name_index = context.blob_add(document_name.as_bytes())?;

        let hash_algorithm_index = if let Some(guid) = self.hash_algorithm {
            context.guid_add(&guid)?
        } else {
            0
        };

        let hash_index = if let Some(hash_bytes) = self.hash {
            context.blob_add(&hash_bytes)?
        } else {
            0
        };

        let language_index = if let Some(guid) = self.language {
            context.guid_add(&guid)?
        } else {
            0
        };

        let document = DocumentRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            name: name_index,
            hash_algorithm: hash_algorithm_index,
            hash: hash_index,
            language: language_index,
        };

        let table_data = TableDataOwned::Document(document);
        context.table_row_add(TableId::Document, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::TableId, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_document_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = DocumentBuilder::new()
            .name("Program.cs")
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_default() -> Result<()> {
        let builder = DocumentBuilder::default();
        assert!(builder.name.is_none());
        assert!(builder.hash_algorithm.is_none());
        assert!(builder.hash.is_none());
        assert!(builder.language.is_none());
        Ok(())
    }

    #[test]
    fn test_document_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = DocumentBuilder::new().csharp_language().build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Document name is required"));

        Ok(())
    }

    #[test]
    fn test_document_builder_empty_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = DocumentBuilder::new().name("").build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Document name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_document_builder_with_csharp_language() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = DocumentBuilder::new()
            .name("Test.cs")
            .csharp_language()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_with_vb_language() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = DocumentBuilder::new()
            .name("Test.vb")
            .vb_language()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_with_fsharp_language() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = DocumentBuilder::new()
            .name("Test.fs")
            .fsharp_language()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_with_sha1_hash() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let token = DocumentBuilder::new()
            .name("Test.cs")
            .sha1_hash_algorithm()
            .hash(hash_bytes)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_with_sha256_hash() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let token = DocumentBuilder::new()
            .name("Test.cs")
            .sha256_hash_algorithm()
            .hash(hash_bytes)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_full_specification() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let token = DocumentBuilder::new()
            .name("MyProgram.cs")
            .csharp_language()
            .sha256_hash_algorithm()
            .hash(hash_bytes)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_multiple_entries() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let doc1_token = DocumentBuilder::new()
            .name("File1.cs")
            .csharp_language()
            .build(&mut context)?;

        let doc2_token = DocumentBuilder::new()
            .name("File2.vb")
            .vb_language()
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(doc1_token, doc2_token);
        assert_eq!(doc1_token.table(), TableId::Document as u8);
        assert_eq!(doc2_token.table(), TableId::Document as u8);
        assert_eq!(doc2_token.row(), doc1_token.row() + 1);

        Ok(())
    }

    #[test]
    fn test_document_builder_custom_guid() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let custom_lang_guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let custom_hash_guid = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];

        let token = DocumentBuilder::new()
            .name("CustomDoc.txt")
            .language(&custom_lang_guid)
            .hash_algorithm(&custom_hash_guid)
            .hash(vec![0x99, 0x88, 0x77, 0x66])
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test fluent API chaining
        let token = DocumentBuilder::new()
            .name("FluentTest.cs")
            .csharp_language()
            .sha256_hash_algorithm()
            .hash(vec![0xaa, 0xbb, 0xcc, 0xdd])
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::Document as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_document_builder_clone() {
        let hash_bytes = vec![0x12, 0x34, 0x56, 0x78];
        let builder1 = DocumentBuilder::new()
            .name("Test.cs")
            .csharp_language()
            .hash(hash_bytes.clone());
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.language, builder2.language);
        assert_eq!(builder1.hash, builder2.hash);
    }

    #[test]
    fn test_document_builder_debug() {
        let builder = DocumentBuilder::new().name("Debug.cs").csharp_language();
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("DocumentBuilder"));
    }
}
