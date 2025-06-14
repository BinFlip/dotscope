use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::Strings,
        tables::{RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

use super::owned::ModuleRef;

#[derive(Clone, Debug)]
/// The `ModuleRef` table contains references to external modules. `TableId` = 0x1A
pub struct ModuleRefRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the String heap
    pub name: u32,
}

impl ModuleRefRaw {
    /// Convert an `ModuleRefRaw`, into a `ModuleRef` which has indexes resolved and owns the referenced data
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues resolving the name from the String heap.
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    pub fn to_owned(&self, strings: &Strings) -> Result<Arc<ModuleRef>> {
        Ok(Arc::new(ModuleRef {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            name: strings.get(self.name as usize)?.to_string(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply a `ModuleRefRaw` entry to update related metadata structures.
    ///
    /// `ModuleRef` entries represent external module references. They are primarily used
    /// as targets by other tables but don't themselves modify other metadata during the
    /// dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `ModuleRef` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ModuleRefRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* name */ sizes.str_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ModuleRefRaw {
            rid,
            token: Token::new(0x1A00_0000 + rid),
            offset: *offset,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ModuleRef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ModuleRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1A000001);
            assert_eq!(row.name, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::ModuleRef, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ModuleRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ModuleRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1A000001);
            assert_eq!(row.name, 0x01010101);
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
