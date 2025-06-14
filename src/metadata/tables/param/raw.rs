use std::sync::{atomic::AtomicBool, Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{Param, ParamRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `Param` table defines parameters for methods in the `MethodDef` table. `TableId` = 0x08
pub struct ParamRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `ParamAttributes`, §II.23.1.13
    pub flags: u32,
    /// a 2-byte constant
    pub sequence: u32,
    /// an index into the String heap
    pub name: u32,
}

impl ParamRaw {
    /// Apply a `ParamRaw` - no-op for Param as it doesn't directly modify other table entries
    ///
    /// The `Param` table entries are primarily modified through method signature processing
    /// and custom attribute application, not through inter-table dependencies.
    ///
    /// # Errors
    /// This method currently returns Ok(()) as Param entries don't require cross-table updates.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }

    /// Convert an `ParamRaw`, into a `Param` which has indexes resolved and owns the referenced data
    ///
    /// # Errors
    /// Returns an error if the parameter name cannot be retrieved from the strings heap.
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    pub fn to_owned(&self, strings: &Strings) -> Result<ParamRc> {
        Ok(Arc::new(Param {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            sequence: self.sequence,
            name: if self.name != 0 {
                Some(strings.get(self.name as usize)?.to_string())
            } else {
                None
            },
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(false),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for ParamRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2 +
            /* sequence */  2 +
            /* name */      sizes.str_bytes()
        )
    }

    fn read_row(
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
