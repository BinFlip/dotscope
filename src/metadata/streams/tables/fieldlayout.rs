use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::{FieldMap, FieldRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
        validation::FieldValidator,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `FieldLayout`
pub type FieldLayoutMap = SkipMap<Token, FieldLayoutRc>;
/// A vector that holds a list of `FieldLayout`
pub type FieldLayoutList = Arc<boxcar::Vec<FieldLayoutRc>>;
/// A reference to a `FieldLayout`
pub type FieldLayoutRc = Arc<FieldLayout>;

/// The `FieldLayout` table specifies the offset of fields within a type with explicit layout. Similar to `FieldLayoutRaw` but
/// with resolved indexes and owned data
pub struct FieldLayout {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte value, specifying the byte offset of the field within the class
    pub field_offset: u32,
    /// The field that this layout applies to
    pub field: FieldRc,
}

impl FieldLayout {
    /// Apply a `FieldLayout` to update the parent field with layout offset.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent field without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the field layout is already set on the target field,
    /// or if the field offset validation fails.
    pub fn apply(&self) -> Result<()> {
        FieldValidator::validate_field_offset(self.field_offset, Some(&self.field))?;

        self.field
            .layout
            .set(self.field_offset)
            .map_err(|_| malformed_error!("Field layout already set"))
    }
}

#[derive(Clone, Debug)]
/// The `FieldLayout` table specifies the offset of fields within a type with explicit layout. `TableId` = 0x10
pub struct FieldLayoutRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte value, specifying the byte offset of the field within the class
    pub field_offset: u32,
    /// an index into the Field table
    pub field: u32,
}

impl FieldLayoutRaw {
    /// Apply an `FieldLayoutRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'value'       - The value to be converted
    /// * 'fields'      - All parsed `Field` entries
    ///
    /// # Errors
    /// Returns an error if field lookup fails, field offset validation fails,
    /// or if the layout is already set
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

    /// Convert an `FieldLayoutRaw`, into a `FieldLayout` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'value'       - The value to be converted
    /// * 'fields'      - All parsed `Field` entries
    ///
    /// # Errors
    /// Returns an error if field lookup fails
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

    fn read_row(
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
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

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
