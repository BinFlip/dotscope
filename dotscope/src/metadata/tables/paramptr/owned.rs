//! # `ParamPtr` Owned Implementation
//!
//! This module provides the owned variant of `ParamPtr` table entries with resolved
//! references and complete metadata context for application use.

use crate::metadata::token::Token;

/// Owned representation of a `ParamPtr` table entry with complete metadata context.
///
/// This structure represents a fully processed entry from the `ParamPtr` metadata table
/// (ID 0x04), which provides indirection for parameter table access in optimized
/// metadata layouts. It contains resolved references and complete contextual information
/// for parameter pointer operations.
///
/// ## Purpose
///
/// The `ParamPtr` table serves as an indirection mechanism:
/// - **Parameter Indirection**: Maps logical parameter indexes to physical locations
/// - **Optimization Support**: Enables parameter table compression and reordering
/// - **Metadata Efficiency**: Reduces metadata size in optimized assemblies
/// - **Access Abstraction**: Maintains consistent parameter access patterns
///
/// ## Owned vs Raw
///
/// This owned variant provides:
/// - Complete metadata token and offset information
/// - Validated field values and structure integrity
/// - High-level access methods for parameter resolution
/// - Integration with the broader metadata resolution system
///
/// ## References
///
/// - ECMA-335, Partition II, §22.26 - `ParamPtr` table specification
/// - [`crate::metadata::tables::Param`] - Target parameter table entries
/// - [`crate::metadata::tables::ParamPtrRaw`] - Raw variant for comparison
pub struct ParamPtr {
    /// Row identifier within the `ParamPtr` table (1-based indexing).
    ///
    /// This field provides the logical position of this entry within the `ParamPtr` table,
    /// following the standard 1-based indexing convention used throughout .NET metadata.
    pub rid: u32,

    /// Metadata token uniquely identifying this `ParamPtr` entry.
    ///
    /// The token combines the table identifier (`ParamPtr` = 0x04) with the row ID,
    /// providing a unique reference for this parameter pointer across the entire
    /// metadata system.
    pub token: Token,

    /// Byte offset of this entry within the metadata stream.
    ///
    /// This offset indicates the exact position of this `ParamPtr` entry within the
    /// metadata stream, enabling direct access to the raw table data and supporting
    /// metadata analysis and debugging operations.
    pub offset: usize,

    /// One-based index into the Param table (target parameter).
    ///
    /// This field provides the indirection mapping from logical parameter positions
    /// to physical parameter table entries. When `ParamPtr` table is present, all
    /// parameter references should be resolved through this indirection mechanism
    /// rather than direct Param table indexing.
    pub param: u32,
}
