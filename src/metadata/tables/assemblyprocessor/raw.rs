use std::sync::Arc;

use crate::{
    file::io::read_le_at,
    metadata::{
        tables::{AssemblyProcessorRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `AssemblyProcessor` table specifies which processors this assembly is targeted for, `TableId` = 0x21
pub struct AssemblyProcessorRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub processor: u32,
}

impl AssemblyProcessorRaw {
    /// Convert an `AssemblyProcessorRaw` into an `AssemblyProcessor` which has indexes resolved and owns the referenced data.
    ///
    /// Since `AssemblyProcessor` is a type alias for `AssemblyProcessorRaw` (no resolution needed), this simply wraps
    /// the raw data in an Arc for consistency with the dual variant pattern.
    ///
    /// # Errors
    /// This method currently never fails and always returns `Ok`.
    pub fn to_owned(&self) -> Result<AssemblyProcessorRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Apply an `AssemblyProcessorRaw` entry to update related metadata structures.
    ///
    /// `AssemblyProcessor` entries specify processor architecture information for the current assembly.
    /// They are self-contained and don't require cross-table updates during the dual variant
    /// resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `AssemblyProcessor` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for AssemblyProcessorRaw {
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* processor */ 4
    }

    fn read_row(
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
