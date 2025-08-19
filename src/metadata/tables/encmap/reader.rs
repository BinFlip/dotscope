use crate::{
    metadata::{
        tables::{EncMapRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at,
    Result,
};

impl RowReadable for EncMapRaw {
    /// Parse a single `EncMap` table row from binary metadata.
    ///
    /// Reads and validates an `EncMap` entry from the metadata stream according to the
    /// ECMA-335 specification. The method constructs a complete [`EncMapRaw`] instance
    /// with all fields populated from the binary data.
    ///
    /// ## Arguments
    /// * `data` - Binary metadata containing the `EncMap` table
    /// * `offset` - Current read position, updated after reading
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information (unused for `EncMap`)
    ///
    /// ## Returns
    /// Returns an [`EncMapRaw`] instance with all fields populated from the binary data.
    ///
    /// ## Errors
    /// Returns an error if the binary data is insufficient or malformed.
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, _sizes: &TableInfoRef) -> Result<Self> {
        Ok(EncMapRaw {
            rid,
            token: Token::new(0x1F00_0000 + rid),
            offset: *offset,
            original_token: Token::new(read_le_at::<u32>(data, offset)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn encmap_basic_parsing() {
        let data = vec![
            0x01, 0x00, 0x02, 0x06, // original_token (0x06020001 - MethodDef table, row 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::EncMap, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<EncMapRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: EncMapRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1F000001);
            assert_eq!(row.original_token.value(), 0x06020001);
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
