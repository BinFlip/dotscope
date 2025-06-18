//! Owned MethodDebugInformation table representation for Portable PDB format
//!
//! This module provides the [`MethodDebugInformation`] struct which contains
//! fully resolved method debugging metadata with owned data and resolved heap references.
//! This is the primary data structure for representing Portable PDB method debugging
//! information in a usable form, with parsed sequence points after the dual variant
//! resolution phase.

use crate::metadata::token::Token;

/// Represents a Portable PDB method debug information entry with fully resolved metadata
///
/// This structure contains the complete debugging information for a method from the
/// MethodDebugInformation metadata table (0x31), with all heap indices resolved to
/// concrete data values. Unlike [`crate::metadata::tables::methoddebuginformation::raw::MethodDebugInformationRaw`],
/// this provides immediate access to structured debug data without requiring additional parsing.
///
/// # Debug Information Structure
///
/// A method debug information entry consists of:
/// - **Document**: Coded index referencing the source document
/// - **Sequence Points**: Optional binary data containing IL-to-source mappings
///
/// # Sequence Points Format
///
/// The sequence points blob contains compressed data that maps IL instruction offsets
/// to source code locations (line/column numbers). This enables debuggers to provide
/// accurate step-through debugging by correlating executable code with source text.
///
/// # Reference
/// - [Portable PDB Format - MethodDebugInformation Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)
pub struct MethodDebugInformation {
    /// Row identifier within the MethodDebugInformation metadata table
    ///
    /// The 1-based index of this method debug information row. Used to uniquely
    /// identify this specific debugging entry within the table.
    pub rid: u32,

    /// Metadata token for this method debug information entry
    ///
    /// Combines the table identifier (0x31 for MethodDebugInformation) with the row ID
    /// to create a unique token that can be used to reference this debug information
    /// from other metadata.
    pub token: Token,

    /// Byte offset of this entry within the metadata tables stream
    ///
    /// Physical location of the raw method debug information data within the metadata
    /// binary format. Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Document table index
    ///
    /// Simple index that references the Document table entry containing the source
    /// document for this method. A value of 0 indicates no associated document.
    /// This index references a specific row in the Document table.
    pub document: u32,

    /// Sequence points data
    ///
    /// Optional binary data containing encoded sequence point information that maps
    /// IL instruction offsets to source code locations. None indicates no sequence
    /// points are available for this method. The data format is specific to the
    /// Portable PDB specification and requires specialized parsing.
    pub sequence_points: Option<Vec<u8>>,
}
