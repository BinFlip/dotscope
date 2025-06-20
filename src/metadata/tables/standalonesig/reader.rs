use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{RowReadable, StandAloneSigRaw, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for StandAloneSigRaw {
    /// Calculates the byte size of a `StandAloneSig` table row.
    ///
    /// The row size depends on the blob heap size:
    /// - 2 bytes if blob heap has ≤ 65535 entries
    /// - 4 bytes if blob heap has > 65535 entries
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information for index size calculation
    ///
    /// ## Returns
    ///
    /// The size in bytes required for a single `StandAloneSig` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* signature */ sizes.blob_bytes()
        )
    }

    /// Reads a `StandAloneSig` table row from the metadata stream.
    ///
    /// Parses a single `StandAloneSig` entry from the raw metadata bytes,
    /// extracting the signature blob index and constructing the complete
    /// table entry with metadata token and offset information.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw metadata bytes containing the table
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - The 1-based row identifier for this entry
    /// * `sizes` - Table size information for proper index parsing
    ///
    /// ## Returns
    ///
    /// * `Ok(StandAloneSigRaw)` - Successfully parsed table entry
    /// * `Err(_)` - Parsing failed due to insufficient data or corruption
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        let offset_org = *offset;

        let signature = read_le_at_dyn(data, offset, sizes.is_large_blob())?;

        Ok(StandAloneSigRaw {
            rid,
            token: Token::new(0x1100_0000 + rid),
            offset: offset_org,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::metadata::tables::{MetadataTable, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(&[], false, false, false));
        let table = MetadataTable::<StandAloneSigRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: StandAloneSigRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x11000001);
            assert_eq!(row.signature, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(&[], true, true, true));
        let table =
            MetadataTable::<StandAloneSigRaw>::new(&data, u16::MAX as u32 + 3, sizes).unwrap();

        let eval = |row: StandAloneSigRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x11000001);
            assert_eq!(row.signature, 0x01010101);
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
