use crate::{
    metadata::{
        tables::{MethodPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for MethodPtrRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MethodPtrRaw {
            rid,
            token: Token::new(0x0500_0000 + rid),
            offset: *offset,
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
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
            0x01, 0x01, // method (index into MethodDef table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x05000001);
            assert_eq!(row.method, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // method (index into MethodDef table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x05000001);
            assert_eq!(row.method, 0x01010101);
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
