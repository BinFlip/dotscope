use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{FieldLayoutRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for FieldLayoutRaw {
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
    use std::sync::Arc;

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
