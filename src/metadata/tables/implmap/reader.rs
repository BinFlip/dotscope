use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{CodedIndex, CodedIndexType, ImplMapRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for ImplMapRaw {
    /// Calculates the byte size of an `ImplMap` table row based on table sizing information.
    ///
    /// The row size depends on the size of coded indexes and string/table references,
    /// which vary based on the total number of entries in referenced tables.
    ///
    /// # Row Layout
    /// - `mapping_flags`: 2 bytes (fixed size)
    /// - `member_forwarded`: Variable size `MemberForwarded` coded index
    /// - `import_name`: Variable size string heap index (2 or 4 bytes)
    /// - `import_scope`: Variable size `ModuleRef` table index (2 or 4 bytes)
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* mapping_flags */    2 +
            /* member_forwarded */ sizes.coded_index_bytes(CodedIndexType::MemberForwarded) +
            /* import_name */      sizes.str_bytes() +
            /* import_scope */     sizes.table_index_bytes(TableId::ModuleRef)
        )
    }

    /// Reads a single `ImplMap` table row from binary metadata stream.
    ///
    /// Parses the binary representation of an `ImplMap` entry, reading fields
    /// in the order specified by ECMA-335 and handling variable-size indexes
    /// based on table sizing information.
    ///
    /// # Arguments
    /// * `data` - Binary data containing the table row
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table sizing information for variable-width fields
    ///
    /// # Returns
    /// * `Ok(ImplMapRaw)` - Successfully parsed table row
    /// * `Err(_)` - Binary data reading or parsing error
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ImplMapRaw {
            rid,
            token: Token::new(0x1C00_0000 + rid),
            offset: *offset,
            mapping_flags: u32::from(read_le_at::<u16>(data, offset)?),
            member_forwarded: CodedIndex::read(
                data,
                offset,
                sizes,
                CodedIndexType::MemberForwarded,
            )?,
            import_name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            import_scope: read_le_at_dyn(data, offset, sizes.is_large(TableId::ModuleRef))?,
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
            0x01, 0x01, // mapping_flags
            0x02, 0x00, // member_forwarded (tag 0 = Field, index = 1)
            0x03, 0x03, // import_name
            0x04, 0x04, // import_scope
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ImplMap, 1),
                (TableId::Field, 10),
                (TableId::MethodDef, 10),
                (TableId::ModuleRef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ImplMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImplMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1C000001);
            assert_eq!(row.mapping_flags, 0x0101);
            assert_eq!(
                row.member_forwarded,
                CodedIndex {
                    tag: TableId::Field,
                    row: 1,
                    token: Token::new(1 | 0x04000000),
                }
            );
            assert_eq!(row.import_name, 0x0303);
            assert_eq!(row.import_scope, 0x0404);
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
            0x01, 0x01, // mapping_flags
            0x02, 0x00, 0x00, 0x00, // member_forwarded (tag 0 = Field, index = 1)
            0x03, 0x03, 0x03, 0x03, // import_name
            0x04, 0x04, 0x04, 0x04, // import_scope
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ImplMap, u16::MAX as u32 + 3),
                (TableId::Field, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::ModuleRef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ImplMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ImplMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1C000001);
            assert_eq!(row.mapping_flags, 0x0101);
            assert_eq!(
                row.member_forwarded,
                CodedIndex {
                    tag: TableId::Field,
                    row: 1,
                    token: Token::new(1 | 0x04000000),
                }
            );
            assert_eq!(row.import_name, 0x03030303);
            assert_eq!(row.import_scope, 0x04040404);
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
