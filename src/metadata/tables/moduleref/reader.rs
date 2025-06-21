use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{ModuleRefRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for ModuleRefRaw {
    /// Reads a single `ModuleRef` table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.31:
    /// 1. **Name** (2-4 bytes): Index into string heap containing module name
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ModuleRefRaw`] instance with populated fields
    ///
    /// ## Errors
    ///
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid heap index values
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ModuleRefRaw {
            rid,
            token: Token::new(0x1A00_0000 + rid),
            offset: *offset,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ModuleRef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ModuleRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1A000001);
            assert_eq!(row.name, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ModuleRef, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ModuleRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1A000001);
            assert_eq!(row.name, 0x01010101);
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
