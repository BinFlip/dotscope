use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{FieldMap, FieldRVARc, FieldRva, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `FieldRVA` table specifies the relative virtual address (RVA) of initial data for fields
/// with the `InitialValue` attribute. `TableId` = 0x1D
pub struct FieldRvaRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub rva: u32,
    /// an index into the Field table
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

impl<'a> RowDefinition<'a> for FieldRvaRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* rva */   4 +
            /* field */ sizes.table_index_bytes(TableId::Field)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(FieldRvaRaw {
            rid,
            token: Token::new(0x1D00_0000 + rid),
            offset: *offset,
            rva: read_le_at::<u32>(data, offset)?,
            field: read_le_at_dyn(data, offset, sizes.is_large(TableId::Field))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, // field
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::FieldRVA, 1), (TableId::Field, 10)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldRvaRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRvaRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1D000001);
            assert_eq!(row.rva, 0x01010101);
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
            0x01, 0x01, 0x01, 0x01, // rva
            0x02, 0x02, 0x02, 0x02, // field
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::FieldRVA, u16::MAX as u32 + 3),
                (TableId::Field, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<FieldRvaRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRvaRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1D000001);
            assert_eq!(row.rva, 0x01010101);
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
