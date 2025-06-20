use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{PropertyRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl RowReadable for PropertyRaw {
    /// Calculates the byte size of a single Property table row.
    ///
    /// The size depends on the metadata heap size configuration:
    /// - **flags**: 2 bytes (`PropertyAttributes` bitmask)
    /// - **name**: String heap index size (2 or 4 bytes)
    /// - **signature**: Blob heap index size (2 or 4 bytes)
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size configuration information
    ///
    /// ## Returns
    ///
    /// * `u32` - Total row size in bytes (6-10 bytes typically)
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */          2 +
            /* name */           sizes.str_bytes() +
            /* type_signature */ sizes.blob_bytes()
        )
    }

    /// Reads a single Property table row from metadata bytes.
    ///
    /// This method parses a Property entry from the metadata stream, extracting
    /// the property flags, name index, and signature index to construct the
    /// complete row structure with metadata context.
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
    /// * `Ok(PropertyRaw)` - Successfully parsed Property entry
    /// * `Err(Error)` - Failed to read or parse the entry
    ///
    /// ## Errors
    ///
    /// * [`crate::error::Error::OutOfBounds`] - Insufficient data for complete entry
    /// * [`crate::error::Error::Malformed`] - Malformed table entry structure
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(PropertyRaw {
            rid,
            token: Token::new(0x1700_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.signature, 0x0303);
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // type_signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x17000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.signature, 0x03030303);
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
