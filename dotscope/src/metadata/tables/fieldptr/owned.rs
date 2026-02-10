//! Owned `FieldPtr` structures for the `FieldPtr` metadata table.
//!
//! This module provides the [`crate::metadata::tables::fieldptr::owned::FieldPtr`] struct which represents field pointer
//! definitions with resolved references and owned data. Field pointers provide
//! an indirection mechanism for Field table access when logical and physical
//! field ordering differs.
//!
//! # Purpose
//! The `FieldPtr` table serves as an optimization mechanism in specific scenarios:
//! - **Field reordering**: When physical field layout differs from logical declaration order
//! - **Metadata optimization**: Reducing overall metadata size through strategic organization
//! - **Edit-and-continue**: Supporting field additions without breaking existing references
//! - **Incremental compilation**: Maintaining stable field references across builds
//! - **Compressed metadata**: Optimizing field access patterns in compressed streams
//!
//! # Indirection Mechanism
//! When `FieldPtr` table is present, field resolution follows this pattern:
//! - **Logical index**: The index used in source code and IL
//! - **`FieldPtr` entry**: Maps logical to physical index
//! - **Physical index**: Actual Field table entry location
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.18 for the `FieldPtr` table specification.

use crate::metadata::token::Token;

/// Represents a field pointer with resolved references and owned data.
///
/// A field pointer provides indirection for field access, mapping logical field
/// indexes to physical Field table entries. This indirection is used when the
/// logical field order (as seen in source code) differs from the physical
/// storage order in metadata tables.
///
/// # Indirection Context
/// Field pointers are used in optimization scenarios:
/// - **Field reordering**: Physical layout optimization for cache efficiency
/// - **Metadata compression**: Strategic field organization to reduce metadata size
/// - **Incremental compilation**: Stable references during development iterations
/// - **Edit-and-continue**: Adding fields without breaking existing references
/// - **Platform optimization**: Field ordering based on target platform characteristics
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.18 for the complete `FieldPtr` table specification.
pub struct FieldPtr {
    /// The row identifier in the `FieldPtr` table.
    ///
    /// This 1-based index uniquely identifies this field pointer within the `FieldPtr` table.
    /// The RID represents the logical field index used for indirection.
    pub rid: u32,

    /// The metadata token for this field pointer.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field pointer across the entire assembly.
    /// The token encodes both the table type (`FieldPtr`) and the row ID.
    pub token: Token,

    /// The byte offset of this field pointer in the metadata tables stream.
    ///
    /// This offset points to the start of this pointer's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Index into the Field table for the actual field definition.
    ///
    /// A 1-based index pointing to the physical Field table entry that this
    /// pointer references. This provides the indirection from logical field
    /// index (RID) to physical field location.
    ///
    /// # Indirection Mapping
    /// - **Logical index**: The RID of this `FieldPtr` entry
    /// - **Physical index**: This field value pointing to Field table
    /// - **Resolution**: `FieldPtr[logical_index].field → Field[physical_index]`
    pub field: u32,
}
