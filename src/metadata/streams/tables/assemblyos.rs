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

/// A map that holds the mapping of Token to parsed `AssemblyOs`
pub type AssemblyOsMap = SkipMap<Token, AssemblyOsRc>;
/// A vector that holds a list of `AssemblyOs`
pub type AssemblyOsList = Arc<boxcar::Vec<AssemblyOsRc>>;
/// A reference to a `AssemblyOs`
pub type AssemblyOsRc = Arc<AssemblyOs>;

/// The `AssemblyOS` table specifies which operating systems this assembly is targeted for, `TableId` = 0x22
// In this case, there's nothing to resolve or own. All data in `AssemblyOsRaw` is already owned by the type
pub type AssemblyOs = AssemblyOsRaw;

#[derive(Clone, Debug)]
/// The `AssemblyOS` table specifies which operating systems this assembly is targeted for, `TableId` = 0x22
pub struct AssemblyOsRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub os_platform_id: u32,
    /// a 4-byte constant
    pub os_major_version: u32,
    /// a 4-byte constant
    pub os_minor_version: u32,
}

impl<'a> RowDefinition<'a> for AssemblyOsRaw {
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* os_platform_id */   4_u32 +
        /* os_major_version */ 4_u32 +
        /* os_minor_version */ 4_u32
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(AssemblyOsRaw {
            rid,
            token: Token::new(0x2200_0000 + rid),
            offset: *offset,
            os_platform_id: read_le_at::<u32>(data, offset)?,
            os_major_version: read_le_at::<u32>(data, offset)?,
            os_minor_version: read_le_at::<u32>(data, offset)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // os_platform_id
            0x02, 0x02, 0x02, 0x02, // os_major_version
            0x03, 0x03, 0x03, 0x03, // os_minor_version
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyOS, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyOsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyOsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x22000001);
            assert_eq!(row.os_platform_id, 0x01010101);
            assert_eq!(row.os_major_version, 0x02020202);
            assert_eq!(row.os_minor_version, 0x03030303);
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
