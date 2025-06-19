use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{CodedIndex, CodedIndexType, ManifestResourceRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for ManifestResourceRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* offset_field */   4 +
            /* flags */          4 +
            /* name */           sizes.str_bytes() +
            /* implementation */ sizes.coded_index_bytes(CodedIndexType::Implementation)
        )
    }

    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ManifestResourceRaw {
            rid,
            token: Token::new(0x2800_0000 + rid),
            offset: *offset,
            offset_field: read_le_at::<u32>(data, offset)?,
            flags: read_le_at::<u32>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            implementation: CodedIndex::read(data, offset, sizes, CodedIndexType::Implementation)?,
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
            0x01, 0x01, 0x01, 0x01, // offset_field
            0x02, 0x02, 0x02, 0x02, // flags
            0x03, 0x03, // name
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ManifestResource, 1),
                (TableId::File, 10),         // Add File table
                (TableId::AssemblyRef, 10),  // Add AssemblyRef table
                (TableId::ExportedType, 10), // Add ExportedType table
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ManifestResourceRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ManifestResourceRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x28000001);
            assert_eq!(row.offset_field, 0x01010101);
            assert_eq!(row.flags, 0x02020202);
            assert_eq!(row.name, 0x0303);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
                }
            );
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
            0x01, 0x01, 0x01, 0x01, // offset_field
            0x02, 0x02, 0x02, 0x02, // flags
            0x03, 0x03, 0x03, 0x03, // name
            0x04, 0x00, 0x00, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ManifestResource, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
                (TableId::ExportedType, u16::MAX as u32 + 3), // Add ExportedType table
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ManifestResourceRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ManifestResourceRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x28000001);
            assert_eq!(row.offset_field, 0x01010101);
            assert_eq!(row.flags, 0x02020202);
            assert_eq!(row.name, 0x03030303);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
                }
            );
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
