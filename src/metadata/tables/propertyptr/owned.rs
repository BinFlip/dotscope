//! # `PropertyPtr` Owned Implementation
//!
//! This module provides the owned variant of `PropertyPtr` table entries with resolved
//! references and complete metadata context for application use.

use crate::metadata::token::Token;

/// Owned representation of a `PropertyPtr` table entry with complete metadata context.
///
/// This structure represents a fully processed entry from the `PropertyPtr` metadata table
/// (ID 0x16), which provides indirection for property table access in optimized
/// metadata layouts. It contains resolved property references and complete contextual
/// information for property indirection operations.
///
/// ## Purpose
///
/// The `PropertyPtr` table serves as an indirection mechanism:
/// - **Property Indirection**: Maps logical property indexes to physical locations
/// - **Optimization Support**: Enables property table compression and reordering
/// - **Metadata Efficiency**: Reduces metadata size in optimized assemblies
/// - **Access Performance**: Provides efficient property lookup mechanisms
///
/// ## Owned vs Raw
///
/// This owned variant provides:
/// - Resolved property references from the property system
/// - Complete property metadata with parsed signatures and attributes
/// - Validated property-indirection relationships and constraints
/// - Integration with the broader metadata resolution system
/// - High-level access methods for property access operations
///
/// ## See Also
///
/// - [`PropertyPtrRaw`](crate::metadata::tables::PropertyPtrRaw) - Raw unresolved variant
/// - [ECMA-335 §II.22.38](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) - `PropertyPtr` table specification
pub struct PropertyPtr {
    /// The 1-based row identifier within the `PropertyPtr` table.
    ///
    /// This value corresponds to the logical position of the property pointer entry
    /// within the `PropertyPtr` table and is used to construct the metadata token.
    pub rid: u32,

    /// The metadata token for this `PropertyPtr` entry.
    ///
    /// Constructed as `0x16000000 | rid`, this token uniquely identifies
    /// the property pointer entry within the metadata system and enables
    /// efficient property indirection operations.
    pub token: Token,

    /// The byte offset of this entry within the metadata stream.
    ///
    /// Indicates the physical location of the property pointer entry in the
    /// original metadata stream, useful for debugging and low-level metadata analysis.
    pub offset: usize,

    /// The 1-based index into the Property table.
    ///
    /// This field provides the indirection mapping from logical property position
    /// to the actual physical position in the Property table. When property
    /// indirection is used, this value should be used instead of direct Property
    /// table indexing.
    pub property: u32,
}
