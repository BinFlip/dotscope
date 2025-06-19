use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{ModuleRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for ModuleRaw {
    /// Calculates the byte size of a Module table row.
    ///
    /// The row size depends on the metadata heap sizes and is calculated as:
    /// - `generation`: 2 bytes (fixed)
    /// - `name`: 2 or 4 bytes (depends on string heap size)
    /// - `mvid`: 2 or 4 bytes (depends on GUID heap size)
    /// - `encid`: 2 or 4 bytes (depends on GUID heap size)
    /// - `encbaseid`: 2 or 4 bytes (depends on GUID heap size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating heap index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* generation */    2 +
            /* name */          sizes.str_bytes() +
            /* mvid */          sizes.guid_bytes() +
            /* encid */         sizes.guid_bytes() +
            /* encbaseid */     sizes.guid_bytes()
        )
    }

    /// Reads a single Module table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.30:
    /// 1. **Generation** (2 bytes): Reserved field, always zero
    /// 2. **Name** (2-4 bytes): Index into string heap containing module name
    /// 3. **Mvid** (2-4 bytes): Index into GUID heap containing module version identifier
    /// 4. **`EncId`** (2-4 bytes): Index into GUID heap for Edit and Continue
    /// 5. **`EncBaseId`** (2-4 bytes): Index into GUID heap for ENC base
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry (always 1 for Module table)
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ModuleRaw`] instance with populated fields
    ///
    /// ## Errors
    ///
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid heap index values
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ModuleRaw {
            rid,
            token: Token::new(rid),
            offset: *offset,
            generation: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            mvid: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
            encid: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
            encbaseid: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
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
            0x01, 0x01, // generation
            0x02, 0x02, // name
            0x03, 0x03, // mvid
            0x04, 0x04, // encid
            0x05, 0x05, // encbaseid
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Module, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ModuleRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x00000001);
            assert_eq!(row.generation, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.mvid, 0x0303);
            assert_eq!(row.encid, 0x0404);
            assert_eq!(row.encbaseid, 0x0505);
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
            0x01, 0x01, // generation
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // mvid
            0x04, 0x04, 0x04, 0x04, // encid
            0x05, 0x05, 0x05, 0x05, // encbaseid
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Module, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ModuleRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x00000001);
            assert_eq!(row.generation, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.mvid, 0x03030303);
            assert_eq!(row.encid, 0x04040404);
            assert_eq!(row.encbaseid, 0x05050505);
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
