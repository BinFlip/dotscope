use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        imports::ImportRc,
        streams::{Guid, RowDefinition, Strings, TableInfoRef},
        token::Token,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `Module`
pub type ModuleMap = SkipMap<Token, ModuleRc>;
/// A vector that holds a list of `Module`
pub type ModuleList = Arc<boxcar::Vec<ModuleRc>>;
/// A reference to a `Module`
pub type ModuleRc = Arc<Module>;

/// The `Module` table provides information about the current module, including its name, GUID (`Mvid`), and generation. There
/// is only one row in this table for each PE file. Similar to `ModuleRaw` but with resolved indexes and owned data.
pub struct Module {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value, reserved, shall be zero
    pub generation: u32,
    /// Name of this module
    pub name: String,
    /// A Guid used to distinguish between two versions of the same module
    pub mvid: uguid::Guid,
    /// an index into the Guid heap; reserved, shall be zero
    pub encid: Option<uguid::Guid>,
    /// an index into the Guid heap; reserved, shall be zero
    pub encbaseid: Option<uguid::Guid>,
    /// All `CilType` and `MethodDef` entries that are imported from this module
    pub imports: Vec<ImportRc>,
}

#[derive(Clone, Debug)]
/// The `Module` table provides information about the current module, including its name, GUID (`Mvid`), and generation. There
/// is only one row in this table for each PE file. Table Id = 0x00
pub struct ModuleRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value, reserved, shall be zero
    pub generation: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Guid heap; simply a Guid used to distinguish between two versions of the same module
    pub mvid: u32,
    /// an index into the Guid heap; reserved, shall be zero
    pub encid: u32,
    /// an index into the Guid heap; reserved, shall be zero
    pub encbaseid: u32,
}

impl ModuleRaw {
    /// Convert an `ModuleRaw`, into a `Module` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings'     - The #String heap
    /// * 'guids'       - The #Guid heap
    ///
    /// # Errors
    ///
    /// Returns an error if there are issues resolving strings or GUIDs from the respective heaps.
    pub fn to_owned(&self, strings: &Strings, guids: &Guid) -> Result<ModuleRc> {
        Ok(Arc::new(Module {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            generation: self.generation,
            name: strings.get(self.name as usize)?.to_string(),
            mvid: guids.get(self.mvid as usize)?,
            encid: if self.encid == 0 {
                None
            } else {
                Some(guids.get(self.encid as usize)?)
            },
            encbaseid: if self.encbaseid == 0 {
                None
            } else {
                Some(guids.get(self.encbaseid as usize)?)
            },
            imports: Vec::new(),
        }))
    }

    /// Apply a `ModuleRaw` entry to update related metadata structures.
    ///
    /// Module entries define the module information for the current assembly. They are
    /// self-contained metadata descriptors and don't require cross-table updates during
    /// the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as Module entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ModuleRaw {
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

    fn read_row(
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
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

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
