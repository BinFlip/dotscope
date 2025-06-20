use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{ImportScopeRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for ImportScopeRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ImportScopeRaw {
            rid,
            token: Token::new(0x3500_0000 + rid),
            offset: *offset,
            parent: read_le_at_dyn(data, offset, sizes.is_large(TableId::ImportScope))?,
            imports: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.table_index_bytes(TableId::ImportScope) +   // parent (ImportScope table index)
            sizes.blob_bytes()                          // imports (blob heap index)
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
            0x00, 0x00, // parent (2 bytes, normal table) - 0x0000 (root scope)
            0x01, 0x00, // imports (2 bytes, short blob heap) - 0x0001
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ImportScope, 1)],
            false, // large strings
            false, // large blob
            false, // large GUID
        ));
        let table = MetadataTable::<ImportScopeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImportScopeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x35000001);
            assert_eq!(row.parent, 0x0000);
            assert_eq!(row.imports, 0x0001);
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
            0x02, 0x00, 0x00, 0x00, // parent (4 bytes, large table) - 0x00000002
            0x01, 0x00, // imports (2 bytes, normal blob heap) - 0x0001
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ImportScope, 70000)], // Large table triggers 4-byte indices
            false,                            // large strings
            false,                            // large blob
            false,                            // large GUID
        ));
        let table = MetadataTable::<ImportScopeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImportScopeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x35000001);
            assert_eq!(row.parent, 0x00000002);
            assert_eq!(row.imports, 0x0001);
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
