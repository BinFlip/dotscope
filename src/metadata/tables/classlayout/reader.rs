use crate::{
    metadata::{
        tables::{ClassLayoutRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for ClassLayoutRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let packing_size = read_le_at::<u16>(data, offset)?;
        let class_size = read_le_at::<u32>(data, offset)?;
        let parent = read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?;

        Ok(ClassLayoutRaw {
            rid,
            token: Token::new(0x0F00_0000 + rid),
            offset: offset_org,
            packing_size,
            class_size,
            parent,
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
            0x01, 0x01, // packing_size
            0x02, 0x02, 0x02, 0x02, // class_size
            0x03, 0x03, // parent
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ClassLayoutRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ClassLayoutRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0F000001);
            assert_eq!(row.packing_size, 0x0101);
            assert_eq!(row.class_size, 0x02020202);
            assert_eq!(row.parent, 0x0303);
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
            0x01, 0x01, // packing_size
            0x02, 0x02, 0x02, 0x02, // class_size
            0x03, 0x03, 0x03, 0x03, // parent
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table =
            MetadataTable::<ClassLayoutRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: ClassLayoutRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x0F000001);
            assert_eq!(row.packing_size, 0x0101);
            assert_eq!(row.class_size, 0x02020202);
            assert_eq!(row.parent, 0x03030303);
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
