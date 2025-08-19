use crate::{
    metadata::{
        tables::{LocalScopeRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for LocalScopeRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(LocalScopeRaw {
            rid,
            token: Token::new(0x3200_0000 + rid),
            offset: *offset,
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
            import_scope: read_le_at_dyn(data, offset, sizes.is_large(TableId::ImportScope))?,
            variable_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::LocalVariable))?,
            constant_list: read_le_at_dyn(data, offset, sizes.is_large(TableId::LocalConstant))?,
            start_offset: read_le_at::<u32>(data, offset)?, // Always 4 bytes
            length: read_le_at::<u32>(data, offset)?,       // Always 4 bytes
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
            0x01, 0x01, // method (2 bytes)
            0x02, 0x02, // import_scope (2 bytes)
            0x03, 0x03, // variable_list (2 bytes)
            0x04, 0x04, // constant_list (2 bytes)
            0x05, 0x05, 0x05, 0x05, // start_offset (4 bytes)
            0x06, 0x06, 0x06, 0x06, // length (4 bytes)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::LocalScope, 1),
                (TableId::MethodDef, 1),
                (TableId::ImportScope, 1),
                (TableId::LocalVariable, 1),
                (TableId::LocalConstant, 1),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<LocalScopeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalScopeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x32000001);
            assert_eq!(row.method, 0x0101);
            assert_eq!(row.import_scope, 0x0202);
            assert_eq!(row.variable_list, 0x0303);
            assert_eq!(row.constant_list, 0x0404);
            assert_eq!(row.start_offset, 0x05050505);
            assert_eq!(row.length, 0x06060606);
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
            0x01, 0x01, 0x01, 0x01, // method (4 bytes)
            0x02, 0x02, 0x02, 0x02, // import_scope (4 bytes)
            0x03, 0x03, 0x03, 0x03, // variable_list (4 bytes)
            0x04, 0x04, 0x04, 0x04, // constant_list (4 bytes)
            0x05, 0x05, 0x05, 0x05, // start_offset (4 bytes)
            0x06, 0x06, 0x06, 0x06, // length (4 bytes)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::LocalScope, 1),
                (TableId::MethodDef, 100000),
                (TableId::ImportScope, 100000),
                (TableId::LocalVariable, 100000),
                (TableId::LocalConstant, 100000),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<LocalScopeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalScopeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x32000001);
            assert_eq!(row.method, 0x01010101);
            assert_eq!(row.import_scope, 0x02020202);
            assert_eq!(row.variable_list, 0x03030303);
            assert_eq!(row.constant_list, 0x04040404);
            assert_eq!(row.start_offset, 0x05050505);
            assert_eq!(row.length, 0x06060606);
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
