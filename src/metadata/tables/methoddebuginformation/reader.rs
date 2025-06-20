use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{MethodDebugInformationRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for MethodDebugInformationRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(MethodDebugInformationRaw {
            rid,
            token: Token::new(0x3100_0000 + rid),
            offset: *offset,
            document: read_le_at_dyn(data, offset, sizes.is_large(TableId::Document))?,
            sequence_points: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.table_index_bytes(TableId::Document) + // document
            sizes.blob_bytes()  // sequence_points
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
            0x01, 0x01, // document (2 bytes)
            0x02, 0x02, // sequence_points (2 bytes)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDebugInformation, 1), (TableId::Document, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodDebugInformationRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDebugInformationRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x31000001);
            assert_eq!(row.document, 0x0101);
            assert_eq!(row.sequence_points, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // document (4 bytes)
            0x02, 0x02, 0x02, 0x02, // sequence_points (4 bytes)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodDebugInformation, 1),
                (TableId::Document, 100000),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodDebugInformationRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodDebugInformationRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x31000001);
            assert_eq!(row.document, 0x01010101);
            assert_eq!(row.sequence_points, 0x02020202);
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
