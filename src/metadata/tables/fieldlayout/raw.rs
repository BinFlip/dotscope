//! Raw `FieldLayout` structures for the `FieldLayout` metadata table.
//!
//! This module provides the [`crate::metadata::tables::fieldlayout::raw::FieldLayoutRaw`] struct for reading field layout data
//! directly from metadata tables before index resolution. The `FieldLayout` table specifies
//! explicit field positioning within types that use explicit layout.
//!
//! # Table Structure
//! The `FieldLayout` table (`TableId` = 0x10) contains these columns:
//! - `Offset`: 4-byte field offset within the containing type
//! - `Field`: Index into Field table identifying the positioned field
//!
//! # Usage Context
//! `FieldLayout` entries are only present for types that require explicit field positioning:
//! - **Interop types**: Types for P/Invoke or COM interop
//! - **Performance-critical types**: Cache-optimized data structures
//! - **Legacy compatibility**: Matching existing binary layouts
//! - **Platform-specific layouts**: Architecture-dependent positioning
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.16 for the `FieldLayout` table specification.

use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{FieldLayout, FieldLayoutRc, FieldMap, RowDefinition, TableId, TableInfoRef},
        token::Token,
        validation::FieldValidator,
    },
    Result,
};

/// Raw field layout data read directly from the `FieldLayout` metadata table.
///
/// This structure represents a field layout entry before index resolution and field
/// dereferencing. Field layouts specify the explicit byte offset of fields within
/// types that use explicit layout attributes.
///
/// # Binary Format
/// Each row in the `FieldLayout` table has this layout:
/// ```text
/// Offset | Size | Field      | Description
/// -------|------|------------|----------------------------------
/// 0      | 4    | Offset     | Field offset within type
/// 4      | 2/4  | Field      | Field table index
/// ```
///
/// The Field index size depends on the number of entries in the Field table.
///
/// # Layout Context
/// `FieldLayout` entries are created for types with explicit layout control:
/// - **C# StructLayout(LayoutKind.Explicit)**: Explicitly positioned fields
/// - **C++ CLI types**: Native interop data structures
/// - **P/Invoke types**: Matching native struct layouts
/// - **Performance types**: Cache-line aligned data structures
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.16 for the complete `FieldLayout` table specification.
#[derive(Clone, Debug)]
pub struct FieldLayoutRaw {
    /// The row identifier in the `FieldLayout` table.
    ///
    /// This 1-based index uniquely identifies this field layout within the `FieldLayout` table.
    pub rid: u32,

    /// The metadata token for this field layout.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this field layout across the entire assembly.
    /// The token value is calculated as `0x10000000 + rid`.
    pub token: Token,

    /// The byte offset of this field layout in the metadata tables stream.
    ///
    /// This offset points to the start of this layout's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// The explicit byte offset of the field within its containing type.
    ///
    /// A 4-byte value specifying the exact byte position where the field should
    /// be placed within the memory layout of its containing class or value type.
    /// This offset is measured from the beginning of the instance data.
    pub field_offset: u32,

    /// Index into the Field table for the positioned field.
    ///
    /// This index points to the field entry in the Field table that this layout
    /// rule applies to. The field must be a member of a type with explicit layout.
    pub field: u32,
}

impl FieldLayoutRaw {
    /// Apply this field layout to the referenced field during metadata loading.
    ///
    /// This method applies the explicit field offset to the target field by looking up
    /// the field in the provided field map and setting its layout information. This is
    /// used during the raw metadata processing phase before full structure resolution.
    ///
    /// # Arguments
    /// * `fields` - Map of all parsed Field entries indexed by token
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Field offset validation fails
    /// - Field lookup in the field map fails
    /// - Field layout is already set on the target field
    /// - Token resolution encounters issues
    ///
    /// # Errors
    /// - **Validation Error**: Invalid field offset value
    /// - **Lookup Error**: Field token not found in field map
    /// - **Duplicate Layout**: Field already has layout assigned
    /// - **Token Error**: Invalid field token calculation
    pub fn apply(&self, fields: &FieldMap) -> Result<()> {
        FieldValidator::validate_field_offset(self.field_offset, None)?;

        match fields.get(&Token::new(self.field | 0x0400_0000)) {
            Some(field) => field
                .value()
                .layout
                .set(self.field_offset)
                .map_err(|_| malformed_error!("Field layout already set")),
            None => Err(malformed_error!(
                "Failed to resolve field token - {}",
                self.field | 0x0400_0000
            )),
        }
    }

    /// Convert this raw field layout to an owned [`crate::metadata::tables::fieldlayout::owned::FieldLayout`] with resolved indexes.
    ///
    /// This method resolves the field index to an actual field reference and creates
    /// an owned structure with all dependencies resolved.
    ///
    /// # Arguments
    /// * `fields` - Map of all parsed Field entries indexed by token
    ///
    /// # Returns
    /// Returns an [`crate::metadata::tables::fieldlayout::FieldLayoutRc`] with resolved field reference and complete data.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Field lookup in the field map fails
    /// - Token calculation produces invalid results
    /// - Memory allocation fails during structure creation
    /// - Field reference resolution encounters issues
    pub fn to_owned(&self, fields: &FieldMap) -> Result<FieldLayoutRc> {
        Ok(Arc::new(FieldLayout {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            field_offset: self.field_offset,
            field: match fields.get(&Token::new(self.field | 0x0400_0000)) {
                Some(field) => field.value().clone(),
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

impl<'a> RowDefinition<'a> for FieldLayoutRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* field_offset */ 4 +
            /* field */       sizes.table_index_bytes(TableId::Field)
        )
    }

    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        let offset_org = *offset;

        let field_offset = read_le_at::<u32>(data, offset)?;
        let field = read_le_at_dyn(data, offset, sizes.is_large(TableId::Field))?;

        Ok(FieldLayoutRaw {
            rid,
            token: Token::new(0x1000_0000 + rid),
            offset: offset_org,
            field_offset,
            field,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // field_offset
            0x02, 0x02, // field
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldLayoutRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldLayoutRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x10000001);
            assert_eq!(row.field_offset, 0x01010101);
            assert_eq!(row.field, 0x0202);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // field_offset
            0x02, 0x02, 0x02, 0x02, // field
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<FieldLayoutRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: FieldLayoutRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x10000001);
            assert_eq!(row.field_offset, 0x01010101);
            assert_eq!(row.field, 0x02020202);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
