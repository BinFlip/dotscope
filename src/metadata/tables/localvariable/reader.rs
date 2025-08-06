use crate::{
    metadata::{
        tables::{
            types::{RowReadable, TableInfoRef},
            LocalVariableRaw,
        },
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for LocalVariableRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(LocalVariableRaw {
            rid,
            token: Token::new(0x3300_0000 + rid),
            offset: *offset,
            attributes: read_le_at::<u16>(data, offset)?,
            index: read_le_at::<u16>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x00, // attributes (2 bytes) - 0x0001
            0x02, 0x00, // index (2 bytes) - 0x0002
            0x03, 0x00, // name (2 bytes, short strings heap) - 0x0003
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalVariable, 1)],
            false, // large tables
            false, // large strings
            false, // large blob
        ));
        let table = MetadataTable::<LocalVariableRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalVariableRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x33000001);
            assert_eq!(row.attributes, 0x0001);
            assert_eq!(row.index, 0x0002);
            assert_eq!(row.name, 0x0003);
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
            0x01, 0x00, // attributes (2 bytes) - 0x0001
            0x02, 0x00, // index (2 bytes) - 0x0002
            0x03, 0x00, 0x00, 0x00, // name (4 bytes, large strings heap) - 0x00000003
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalVariable, 1)],
            false, // large tables
            true,  // large strings
            false, // large blob
        ));
        let table = MetadataTable::<LocalVariableRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalVariableRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x33000001);
            assert_eq!(row.attributes, 0x0001);
            assert_eq!(row.index, 0x0002);
            assert_eq!(row.name, 0x00000003);
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
