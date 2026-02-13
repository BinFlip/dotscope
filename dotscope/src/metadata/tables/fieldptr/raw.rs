//! Raw `FieldPtr` structures for the `FieldPtr` metadata table.
//!
//! This module provides the [`crate::metadata::tables::fieldptr::raw::FieldPtrRaw`] struct for reading field pointer data
//! directly from metadata tables before index resolution. The `FieldPtr` table provides
//! an indirection mechanism for Field table access when logical and physical field
//! ordering differs.
//!
//! # Table Structure
//! The `FieldPtr` table (`TableId` = 0x03) contains a single column:
//! - `Field`: Index into Field table for the actual field definition
//!
//! # Indirection Purpose
//! The `FieldPtr` table enables field access optimization:
//! - **Field reordering**: Physical layout differs from logical declaration order
//! - **Metadata optimization**: Strategic field organization to reduce metadata size
//! - **Edit-and-continue**: Supporting field additions without breaking references
//! - **Incremental compilation**: Maintaining stable field references
//! - **Platform optimization**: Field ordering based on target characteristics
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.18 for the `FieldPtr` table specification.

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{FieldPtr, FieldPtrRc, TableId, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

/// Raw field pointer data read directly from the `FieldPtr` metadata table.
///
/// This structure represents a field pointer entry before index resolution and
/// processing. Field pointers provide indirection for field access when the
/// logical field order differs from the physical storage order in metadata.
///
/// # Binary Format
/// Each row in the `FieldPtr` table has this layout:
/// ```text
/// Offset | Size | Field | Description
/// -------|------|-------|----------------------------------
/// 0      | 2/4  | Field | Field table index
/// ```
///
/// The Field index size depends on the number of entries in the Field table.
///
/// # Indirection Mechanism
/// The `FieldPtr` table provides a mapping layer:
/// - **Logical index**: The RID of the `FieldPtr` entry (used in references)
/// - **Physical index**: The Field value pointing to actual Field table entry
/// - **Resolution**: `FieldPtr[logical] → Field[physical]`
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.18 for the complete `FieldPtr` table specification.
#[derive(Clone, Debug)]
pub struct FieldPtrRaw {
    /// The row identifier in the `FieldPtr` table.
    ///
    /// This 1-based index uniquely identifies this field pointer within the `FieldPtr` table.
    /// The RID serves as the logical field index used in field references.
    pub rid: u32,

    /// The metadata token for this field pointer.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field pointer across the entire assembly.
    /// The token value is calculated as `0x03000000 + rid`.
    pub token: Token,

    /// The byte offset of this field pointer in the metadata tables stream.
    ///
    /// This offset points to the start of this pointer's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Index into the Field table for the actual field definition.
    ///
    /// A 1-based index pointing to the physical Field table entry that this
    /// pointer references. This provides the indirection mapping from logical
    /// field index (RID) to physical field location.
    pub field: u32,
}

impl FieldPtrRaw {
    /// Convert this raw field pointer to an owned [`crate::metadata::tables::fieldptr::owned::FieldPtr`] with processed data.
    ///
    /// This method creates an owned structure from the raw field pointer data.
    /// Since `FieldPtr` entries contain only simple indirection information,
    /// no complex resolution or processing is required.
    ///
    /// # Returns
    /// Returns an [`crate::metadata::tables::fieldptr::FieldPtrRc`] with the same data as the raw entry.
    ///
    /// # Errors
    /// This method currently doesn't fail, but returns [`crate::Result`] for consistency
    /// with other table conversion methods and future extensibility.
    pub fn to_owned(&self) -> Result<FieldPtrRc> {
        Ok(Arc::new(FieldPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            field: self.field,
        }))
    }

    /// Apply field pointer logic during metadata loading.
    ///
    /// `FieldPtr` entries provide indirection for field access but don't directly
    /// modify other metadata structures during the loading phase. The indirection
    /// logic is handled at the table resolution level when field references are
    /// resolved through the `FieldPtr` table.
    ///
    /// # Returns
    /// Always returns `Ok(())` as `FieldPtr` entries don't modify other tables directly.
    ///
    /// # Errors
    ///
    /// This function never returns an error; it always returns `Ok(())`.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for FieldPtrRaw {
    /// Calculate the byte size of a `FieldPtr` table row
    ///
    /// Computes the total size based on variable-size table indexes.
    /// The size depends on whether the Field table uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout
    /// - `field`: 2 or 4 bytes (Field table index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for table index widths
    ///
    /// # Returns
    /// Total byte size of one `FieldPtr` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* field */ sizes.table_index_bytes(TableId::Field)
        )
    }
}
