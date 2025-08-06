use crate::{
    metadata::{
        tables::{EncLogRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at,
    Result,
};

impl RowReadable for EncLogRaw {
    /// Read and parse an `EncLog` table row from binary data
    ///
    /// Deserializes one `EncLog` table entry from the metadata tables stream.
    /// `EncLog` has a fixed 8-byte layout with two 4-byte integer fields.
    ///
    /// # Arguments
    /// * `data` - Binary metadata tables stream data
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - Row identifier for this `EncLog` entry
    /// * `_sizes` - Unused since `EncLog` has no heap indexes
    ///
    /// # Returns
    /// * `Ok(EncLogRaw)` - Successfully parsed `EncLog` row
    /// * `Err(`[`crate::Error`]`)` - If data is malformed or insufficient
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, _sizes: &TableInfoRef) -> Result<Self> {
        Ok(EncLogRaw {
            rid,
            token: Token::new(0x1E00_0000 + rid),
            offset: *offset,
            token_value: read_le_at::<u32>(data, offset)?,
            func_code: read_le_at::<u32>(data, offset)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn enclog_basic_parsing() {
        let data = vec![
            0x01, 0x00, 0x02, 0x06, // token_value (0x06020001 - MethodDef table, row 1)
            0x00, 0x00, 0x00, 0x00, // func_code (0 = Create)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::EncLog, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EncLogRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EncLogRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1E000001);
            assert_eq!(row.token_value, 0x06020001);
            assert_eq!(row.func_code, 0);
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
