use crate::{
    file::io::read_le_at,
    metadata::{
        tables::{AssemblyProcessorRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for AssemblyProcessorRaw {
    /// Calculate the byte size of an `AssemblyProcessor` table row
    ///
    /// Returns the fixed size since `AssemblyProcessor` contains only a single primitive integer field.
    /// Total size is always 4 bytes (1 × 4-byte integer).
    ///
    /// # Row Layout
    /// - processor: 4 bytes (fixed)
    ///
    /// # Arguments
    /// * `_sizes` - Unused for `AssemblyProcessor` since no heap indexes are present
    ///
    /// # Returns
    /// Fixed size of 4 bytes for all `AssemblyProcessor` rows
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* processor */ 4
    }

    /// Read and parse an `AssemblyProcessor` table row from binary data
    ///
    /// Deserializes one `AssemblyProcessor` table entry from the metadata tables stream.
    /// `AssemblyProcessor` has a fixed 4-byte layout with one integer field for the processor
    /// architecture identifier.
    ///
    /// # Arguments
    /// * `data` - Binary metadata tables stream data
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - Row identifier for this `AssemblyProcessor` entry
    /// * `_sizes` - Unused since `AssemblyProcessor` has no heap indexes
    ///
    /// # Returns
    /// * `Ok(AssemblyProcessorRaw)` - Successfully parsed `AssemblyProcessor` row
    /// * `Err(`[`crate::Error`]`)` - If data is malformed or insufficient
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(AssemblyProcessorRaw {
            rid,
            token: Token::new(0x2100_0000 + rid),
            offset: *offset,
            processor: read_le_at::<u32>(data, offset)?,
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
            0x01, 0x01, 0x01, 0x01, // processor
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyProcessor, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyProcessorRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyProcessorRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x21000001);
            assert_eq!(row.processor, 0x01010101);
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
