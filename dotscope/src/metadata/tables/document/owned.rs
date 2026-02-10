//! Owned Document table representation for Portable PDB format
//!
//! This module provides the [`crate::metadata::tables::document::owned::Document`] struct
//! which contains fully resolved document metadata with owned data and resolved heap references.
//! This is the primary data structure for representing Portable PDB documents in a usable form,
//! with parsed document names and resolved GUID references after the dual variant resolution phase.

use crate::metadata::token::Token;

/// Represents a Portable PDB document with fully resolved metadata and parsed data
///
/// This structure contains the complete document information from the Document
/// metadata table (0x30), with all heap indices resolved to concrete data values.
/// Unlike [`crate::metadata::tables::document::raw::DocumentRaw`], this provides
/// immediate access to structured document data without requiring additional parsing.
///
/// # Document Structure
///
/// A document consists of:
/// - **Name**: The resolved document name/path (typically a file path)
/// - **Hash Algorithm**: The GUID identifying the hash algorithm used
/// - **Hash**: The actual hash bytes computed from the document content
/// - **Language**: The GUID identifying the source programming language
///
/// # Reference
/// - [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)
pub struct Document {
    /// Row identifier within the Document metadata table
    ///
    /// The 1-based index of this document row. Used to uniquely identify
    /// this specific document instance within the table.
    pub rid: u32,

    /// Metadata token for this document
    ///
    /// Combines the table identifier (0x30 for Document) with the row ID to create
    /// a unique token that can be used to reference this document from other metadata.
    pub token: Token,

    /// Byte offset of this document row within the metadata tables stream
    ///
    /// Physical location of the raw document data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Resolved document name/path
    ///
    /// The fully parsed document name, typically a file path or URI that identifies
    /// the source document. This has been resolved from the blob heap and parsed
    /// according to the Portable PDB document name format.
    pub name: String,

    /// Hash algorithm identifier
    ///
    /// The GUID identifying the hash algorithm used to compute the document hash.
    /// Common algorithm GUIDs include SHA-1, SHA-256, and other cryptographic hash functions.
    pub hash_algorithm: uguid::Guid,

    /// Document content hash
    ///
    /// The actual hash bytes computed from the document content using the specified
    /// hash algorithm. Used for integrity verification and change detection during debugging.
    /// An empty vector indicates no hash is available.
    pub hash: Vec<u8>,

    /// Source language identifier
    ///
    /// The GUID identifying the programming language used in this document.
    /// Common language GUIDs include C#, VB.NET, F#, and other .NET languages.
    pub language: uguid::Guid,
}

impl Document {
    /// Create a new Document with the specified metadata
    ///
    /// # Arguments
    ///
    /// * `rid` - Row identifier within the Document table
    /// * `token` - Metadata token for this document
    /// * `offset` - Byte offset within the metadata stream
    /// * `name` - Resolved document name/path
    /// * `hash_algorithm` - Hash algorithm GUID
    /// * `hash` - Document content hash bytes
    /// * `language` - Source language GUID
    #[must_use]
    pub fn new(
        rid: u32,
        token: Token,
        offset: usize,
        name: String,
        hash_algorithm: uguid::Guid,
        hash: Vec<u8>,
        language: uguid::Guid,
    ) -> Self {
        Self {
            rid,
            token,
            offset,
            name,
            hash_algorithm,
            hash,
            language,
        }
    }

    /// Check if this document has a hash
    #[must_use]
    pub fn has_hash(&self) -> bool {
        !self.hash.is_empty()
    }

    /// Check if this is a C# document based on the language GUID
    ///
    /// C# language GUID: {3F5162F8-07C6-11D3-9053-00C04FA302A1}
    #[must_use]
    pub fn is_csharp(&self) -> bool {
        const CSHARP_GUID: uguid::Guid = uguid::guid!("3F5162F8-07C6-11D3-9053-00C04FA302A1");
        self.language == CSHARP_GUID
    }

    /// Check if this is a Visual Basic document based on the language GUID
    ///
    /// VB.NET language GUID: {3A12D0B8-C26C-11D0-B442-00A0244A1DD2}
    #[must_use]
    pub fn is_visual_basic(&self) -> bool {
        const VB_GUID: uguid::Guid = uguid::guid!("3A12D0B8-C26C-11D0-B442-00A0244A1DD2");
        self.language == VB_GUID
    }

    /// Check if this is an F# document based on the language GUID
    ///
    /// F# language GUID: {AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3}
    #[must_use]
    pub fn is_fsharp(&self) -> bool {
        const FSHARP_GUID: uguid::Guid = uguid::guid!("AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3");
        self.language == FSHARP_GUID
    }

    /// Get a human-readable description of the hash algorithm
    #[must_use]
    pub fn hash_algorithm_name(&self) -> &'static str {
        const SHA1_GUID: uguid::Guid = uguid::guid!("FF1816EC-AA5E-4D10-87F7-6F4963833460");
        const SHA256_GUID: uguid::Guid = uguid::guid!("8829D00F-11B8-4213-878B-770E8597AC16");

        match self.hash_algorithm {
            SHA1_GUID => "SHA-1",
            SHA256_GUID => "SHA-256",
            _ => "Unknown",
        }
    }

    /// Get a human-readable description of the programming language
    #[must_use]
    pub fn language_name(&self) -> &'static str {
        if self.is_csharp() {
            "C#"
        } else if self.is_visual_basic() {
            "Visual Basic"
        } else if self.is_fsharp() {
            "F#"
        } else {
            "Unknown"
        }
    }
}
