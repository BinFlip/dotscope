use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{ParamPtrRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for ParamPtrRaw {
    /// Reads a single `ParamPtr` table row from metadata bytes.
    ///
    /// This method parses a `ParamPtr` entry from the metadata stream, extracting
    /// the parameter table index and constructing the complete row structure
    /// with metadata context.
    ///
    /// ## Arguments
    ///
    /// * `data` - The metadata bytes to read from
    /// * `offset` - Current position in the data (updated after reading)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size configuration for index resolution
    ///
    /// ## Returns
    ///
    /// * `Ok(ParamPtrRaw)` - Successfully parsed `ParamPtr` entry
    /// * `Err(Error)` - Failed to read or parse the entry
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(ParamPtrRaw {
            rid,
            token: Token::new(0x0700_0000 + rid),
            offset: *offset,
            param: read_le_at_dyn(data, offset, sizes.is_large(TableId::Param))?,
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
            0x01, 0x01, // param (index into Param table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x07000001);
            assert_eq!(row.param, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // param (index into Param table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x07000001);
            assert_eq!(row.param, 0x01010101);
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
