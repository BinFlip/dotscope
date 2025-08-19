use crate::{
    metadata::{
        tables::{FieldPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for FieldPtrRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(FieldPtrRaw {
            rid,
            token: Token::new(0x0300_0000 + rid),
            offset: *offset,
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
            0x01, 0x01, // field (index into Field table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x03000001);
            assert_eq!(row.field, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // field (index into Field table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<FieldPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x03000001);
            assert_eq!(row.field, 0x01010101);
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
