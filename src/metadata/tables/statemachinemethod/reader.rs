use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{RowReadable, StateMachineMethodRaw, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for StateMachineMethodRaw {
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(StateMachineMethodRaw {
            rid,
            token: Token::new(0x3600_0000 + rid),
            offset: *offset,
            move_next_method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
            kickoff_method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.table_index_bytes(TableId::MethodDef) +   // move_next_method (MethodDef table index)
            sizes.table_index_bytes(TableId::MethodDef)     // kickoff_method (MethodDef table index)
        )
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
            0x01, 0x00, // move_next_method (2 bytes, normal table) - 0x0001
            0x02, 0x00, // kickoff_method (2 bytes, normal table) - 0x0002
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::StateMachineMethod, 1), (TableId::MethodDef, 1000)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<StateMachineMethodRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StateMachineMethodRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x36000001);
            assert_eq!(row.move_next_method, 0x0001);
            assert_eq!(row.kickoff_method, 0x0002);
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
            0x01, 0x01, 0x00, 0x00, // move_next_method (4 bytes, large table) - 0x00000101
            0x02, 0x02, 0x00, 0x00, // kickoff_method (4 bytes, large table) - 0x00000202
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::StateMachineMethod, 1),
                (TableId::MethodDef, 100000),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<StateMachineMethodRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StateMachineMethodRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x36000001);
            assert_eq!(row.move_next_method, 0x00000101);
            assert_eq!(row.kickoff_method, 0x00000202);
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
