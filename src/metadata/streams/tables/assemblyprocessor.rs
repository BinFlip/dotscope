use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at,
    metadata::{
        streams::{RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `AssemblyProcessor`
pub type AssemblyProcessorMap = SkipMap<Token, AssemblyProcessorRc>;
/// A vector that holds a list of `AssemblyProcessor`
pub type AssemblyProcessorList = Arc<boxcar::Vec<AssemblyProcessorRc>>;
/// A reference to a `AssemblyProcessor`
pub type AssemblyProcessorRc = Arc<AssemblyProcessor>;

/// The `AssemblyProcessor` table specifies which processors this assembly is targeted for, `TableId` = 0x21
// In this case, there's nothing to resolve or own. All data in `AssemblyOsRaw` is already owned by the type
pub type AssemblyProcessor = AssemblyProcessorRaw;

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
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

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
