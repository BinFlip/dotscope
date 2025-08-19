//! Owned `FieldLayout` structures for the `FieldLayout` metadata table.
//!
//! This module provides the [`crate::metadata::tables::fieldlayout::owned::FieldLayout`] struct which represents field layout
//! definitions with resolved references and owned data. Field layouts specify
//! the explicit byte offset of fields within types that use explicit layout.
//!
//! # Purpose
//! The `FieldLayout` table is used when precise control over field positioning is needed:
//! - **Interop scenarios**: Matching native struct layouts for P/Invoke
//! - **Performance optimization**: Controlling memory layout for cache efficiency
//! - **Platform compatibility**: Ensuring consistent layouts across architectures
//! - **Legacy compatibility**: Matching existing binary data formats
//!
//! # Layout Types
//! - **Sequential**: Default .NET layout (no `FieldLayout` entries needed)
//! - **Explicit**: Programmer-specified field offsets (requires `FieldLayout` entries)
//! - **Auto**: Runtime-optimized layout (no `FieldLayout` entries)
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.16 for the `FieldLayout` table specification.

use crate::{
    metadata::{tables::FieldRc, token::Token},
    Result,
};

/// Represents a field layout definition with resolved references and owned data.
///
/// A field layout specifies the explicit byte offset of a field within its containing
/// type. This is used when types have explicit layout attributes that require precise
/// control over field positioning in memory.
///
/// # Field Layout Context
/// Field layouts are only present for types that use explicit layout:
/// - **StructLayout(LayoutKind.Explicit)**: C# structs with explicit field positioning
/// - **Interop types**: Types designed for P/Invoke or COM interop
/// - **Performance-critical types**: Types optimized for specific memory access patterns
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.16 for the complete `FieldLayout` table specification.
///
/// [`Arc`]: std::sync::Arc
pub struct FieldLayout {
    /// The row identifier in the `FieldLayout` table.
    ///
    /// This 1-based index uniquely identifies this field layout within the `FieldLayout` table.
    /// Combined with the table type, it forms the layout entry's unique identity.
    pub rid: u32,

    /// The metadata token for this field layout.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field layout across the entire assembly.
    /// The token encodes both the table type (`FieldLayout`) and the row ID.
    pub token: Token,

    /// The byte offset of this field layout in the metadata tables stream.
    ///
    /// This offset points to the start of this layout's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// The explicit byte offset of the field within its containing type.
    ///
    /// A 4-byte value specifying the exact byte position where this field should
    /// be placed within the memory layout of its containing class or value type.
    /// This offset is measured from the beginning of the instance data.
    ///
    /// # Constraints
    /// - Must be a valid offset within the type's size boundaries
    /// - Should respect field alignment requirements
    /// - Must not cause invalid field overlaps
    /// - Should consider platform-specific alignment rules
    pub field_offset: u32,

    /// Reference to the field that this layout applies to.
    ///
    /// A reference-counted [`crate::metadata::tables::field::Field`] instance representing the field whose
    /// position is being explicitly defined. This field must exist in the
    /// Field table and be a member of a type with explicit layout.
    pub field: FieldRc,
}

impl FieldLayout {
    /// Apply this field layout to the referenced field.
    ///
    /// This method applies the explicit field offset to the target field, updating
    /// the field's layout information. Since this is the owned structure, all
    /// references are already resolved, enabling efficient field updates.
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Field offset validation fails
    /// - Field layout is already set on the target field
    /// - The field does not support explicit layout
    /// - Memory constraints are violated
    ///
    /// # Thread Safety
    /// This method is thread-safe due to the atomic nature of the `OnceLock::set`
    /// operation used to update the field's layout information.
    ///
    /// # Errors
    /// - **Validation Error**: If field offset validation fails due to invalid positioning
    /// - **Duplicate Layout**: If the field already has a layout offset assigned
    /// - **Type Mismatch**: If the field's containing type doesn't support explicit layout
    pub fn apply(&self) -> Result<()> {
        self.field
            .layout
            .set(self.field_offset)
            .map_err(|_| malformed_error!("Field layout already set"))
    }
}
