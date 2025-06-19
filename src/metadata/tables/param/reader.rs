use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{ParamRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for ParamRaw {
    /// Calculates the byte size of a Param table row.
    ///
    /// The row size depends on string heap size and is calculated as:
    /// - `flags`: 2 bytes (fixed)
    /// - `sequence`: 2 bytes (fixed)
    /// - `name`: 2 or 4 bytes (depends on string heap size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating heap index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2 +
            /* sequence */  2 +
            /* name */      sizes.str_bytes()
        )
    }

    /// Reads a single Param table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.33:
    /// 1. **Flags** (2 bytes): Parameter attributes bitmask
    /// 2. **Sequence** (2 bytes): Parameter sequence number
    /// 3. **Name** (2-4 bytes): Index into string heap containing parameter name
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ParamRaw`] instance with populated fields
    ///
    /// ## Errors
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid string heap index values
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ParamRaw {
            rid,
            token: Token::new(0x0800_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            sequence: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // sequences
            0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x0303);
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
            0x02, 0x02, // sequence
            0x03, 0x03, 0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x03030303);
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
