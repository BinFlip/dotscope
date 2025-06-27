//! Raw `FieldRva` structures for the `FieldRva` metadata table.
//!
//! This module provides the [`FieldRvaRaw`] struct for reading field RVA data
//! directly from metadata tables before index resolution. The `FieldRva` table specifies
//! Relative Virtual Addresses for fields that have initial data stored in the PE file.
//!
//! # Table Structure
//! The `FieldRva` table (`TableId` = 0x1D) contains these columns:
//! - `RVA`: 4-byte Relative Virtual Address pointing to field data
//! - `Field`: Index into Field table identifying the field with initial data
//!
//! # RVA Purpose
//! `FieldRva` entries enable static field initialization and data embedding:
//! - **Static field initialization**: Pre-computed values for static fields
//! - **Constant data**: Read-only data embedded in the PE file
//! - **Global variables**: Module-level data with specific initial states
//! - **Interop data**: Native data for P/Invoke operations
//! - **Resource embedding**: Binary resources accessible through fields
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the `FieldRva` table specification.

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{FieldMap, FieldRVARc, FieldRva, TableId, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

/// Raw field RVA data read directly from the `FieldRva` metadata table.
///
/// This structure represents a field RVA entry before index resolution and field
/// dereferencing. Field RVAs specify the location of initial data for fields that
/// have pre-computed values stored in the PE file.
///
/// # Binary Format
/// Each row in the `FieldRva` table has this layout:
/// ```text
/// Offset | Size | Field | Description
/// -------|------|-------|----------------------------------
/// 0      | 4    | RVA   | Relative Virtual Address
/// 4      | 2/4  | Field | Field table index
/// ```
///
/// The Field index size depends on the number of entries in the Field table.
///
/// # RVA Context
/// `FieldRva` entries define data locations for:
/// - **Static arrays**: Pre-initialized array data embedded in PE file
/// - **Constant strings**: String literals stored in read-only sections
/// - **Numeric constants**: Pre-computed values for mathematical constants
/// - **Lookup tables**: Read-only data tables for algorithms
/// - **Binary resources**: Raw data accessible through field references
///
/// # PE Integration
/// RVAs integrate with PE file structure:
/// - **Section mapping**: RVAs resolve to specific PE sections
/// - **Memory layout**: Data positioned for efficient runtime access
/// - **File alignment**: Data aligned according to PE requirements
/// - **Protection flags**: Sections marked with appropriate permissions
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.19 for the complete `FieldRva` table specification.
#[derive(Clone, Debug)]
pub struct FieldRvaRaw {
    /// The row identifier in the `FieldRva` table.
    ///
    /// This 1-based index uniquely identifies this field RVA within the `FieldRva` table.
    pub rid: u32,

    /// The metadata token for this field RVA.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field RVA across the entire assembly.
    /// The token value is calculated as `0x1D000000 + rid`.
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this field RVA in the metadata tables stream.
    ///
    /// This offset points to the start of this RVA's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// The Relative Virtual Address of the field's initial data.
    ///
    /// A 4-byte RVA pointing to the location of the field's initial data within
    /// the PE file. This address is relative to the image base and provides
    /// access to embedded static data.
    pub rva: u32,

    /// Index into the Field table for the field with initial data.
    ///
    /// This index points to the field entry in the Field table that has
    /// initial data stored at the specified RVA location.
    pub field: u32,
}

impl FieldRvaRaw {
    /// Apply an `FieldRVARaw`  to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'fields'  - All parsed `Field` entries
    ///
    /// # Errors
    /// Returns an error if field lookup fails or if the RVA is already set
    pub fn apply(&self, fields: &FieldMap) -> Result<()> {
        match fields.get(&Token::new(self.field | 0x0400_0000)) {
            Some(field) => field
                .value()
                .rva
                .set(self.rva)
                .map_err(|_| malformed_error!("Field RVA already set")),
            None => Err(malformed_error!(
                "Failed to resolve field token - {}",
                self.field | 0x0400_0000
            )),
        }
    }

    /// Convert an `FieldRVARaw`, into a `FieldRVA` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'fields'      - All parsed `Field` entries
    ///
    /// # Errors
    /// Returns an error if field lookup fails
    pub fn to_owned(&self, fields: &FieldMap) -> Result<FieldRVARc> {
        Ok(Arc::new(FieldRva {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            rva: self.rva,
            field: match fields.get(&Token::new(self.field | 0x0400_0000)) {
                Some(parent) => parent.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve field token - {}",
                        self.field | 0x0400_0000
                    ))
                }
            },
        }))
    }
}

impl TableRow for FieldRvaRaw {
    /// Calculate the byte size of a FieldRva table row
    ///
    /// Computes the total size based on fixed-size fields and variable-size table indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.19)
    /// - `rva`: 4 bytes (fixed size Relative Virtual Address)
    /// - `field`: 2 or 4 bytes (Field table index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one FieldRva table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* rva */   4 +
            /* field */ sizes.table_index_bytes(TableId::Field)
        )
    }
}
