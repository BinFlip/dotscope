use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, ExportedTypeRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for ExportedTypeRaw {
    /// Read an `ExportedType` row from the metadata tables stream
    ///
    /// Parses one `ExportedType` table row from the binary metadata stream, handling
    /// variable-size indexes based on table size information. Advances the offset
    /// to point to the next row after successful parsing.
    ///
    /// # Arguments
    ///
    /// * `data` - The metadata tables stream binary data
    /// * `offset` - Current position in the stream (updated after reading)
    /// * `rid` - Row identifier for this `ExportedType` entry (1-based)
    /// * `sizes` - Table size information for determining index sizes
    ///
    /// # Returns
    ///
    /// Returns a parsed [`ExportedTypeRaw`] instance with all fields populated
    /// from the binary data.
    ///
    /// # Errors
    ///
    /// - The data stream is truncated or corrupted
    /// - Index values exceed expected ranges
    /// - Implementation coded index reading fails
    /// - Binary parsing encounters invalid data
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ExportedTypeRaw {
            rid,
            token: Token::new(0x2700_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            type_def_id: read_le_at::<u32>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            namespace: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            implementation: CodedIndex::read(data, offset, sizes, CodedIndexType::Implementation)?,
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, // type_name
            0x04, 0x04, // type_namespace
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, 1),
                (TableId::File, 10),        // Add File table
                (TableId::AssemblyRef, 10), // Add AssemblyRef table
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ExportedTypeRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ExportedTypeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x27000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.type_def_id, 0x02020202);
            assert_eq!(row.name, 0x0303);
            assert_eq!(row.namespace, 0x0404);
            assert_eq!(
                row.implementation,
                CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation)
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // type_def_id
            0x03, 0x03, 0x03, 0x03, // type_name
            0x04, 0x04, 0x04, 0x04, // type_namespace
            0x04, 0x00, 0x00, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ExportedType, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ExportedTypeRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ExportedTypeRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x27000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.type_def_id, 0x02020202);
            assert_eq!(row.name, 0x03030303);
            assert_eq!(row.namespace, 0x04040404);
            assert_eq!(
                row.implementation,
                CodedIndex::new(TableId::File, 1, CodedIndexType::Implementation)
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
