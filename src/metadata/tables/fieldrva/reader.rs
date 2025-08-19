use crate::{
    metadata::{
        tables::{FieldRvaRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for FieldRvaRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
    use std::sync::Arc;

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
