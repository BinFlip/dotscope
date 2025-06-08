use crossbeam_skiplist::SkipMap;
use std::sync::{atomic::Ordering, Arc};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::{AssemblyRefMap, AssemblyRefRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `AssemblyRefOs`
pub type AssemblyRefOsMap = SkipMap<Token, AssemblyRefOsRc>;
/// A vector that holds a list of `AssemblyRefOs`
pub type AssemblyRefOsList = Arc<boxcar::Vec<AssemblyRefOsRc>>;
/// A reference to a `AssemblyRefOs`
pub type AssemblyRefOsRc = Arc<AssemblyRefOs>;

/// The `AssemblyRefOS` table specifies which operating systems a referenced assembly is targeted for,
/// similar to `AssemblyRefRaw` but with resolved indexes and fully owned data.
pub struct AssemblyRefOs {
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
    /// an index into the `AssemblyRef` table
    pub assembly_ref: AssemblyRefRc,
}

#[derive(Clone, Debug)]
/// The `AssemblyRefOS` table specifies which operating systems a referenced assembly is targeted for, `TableId` = 0x25
pub struct AssemblyRefOsRaw {
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
    /// an index into the `AssemblyRef` table
    pub assembly_ref: u32,
}

impl AssemblyRefOsRaw {
    /// Convert an `AssemblyRefOsRaw`, into a `AssemblyRefOs` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'refs' - The map of loaded `AssemblyRef` entities
    ///
    /// # Errors
    /// Returns an error if the assembly reference cannot be resolved
    pub fn to_owned(&self, refs: &AssemblyRefMap) -> Result<AssemblyRefOsRc> {
        Ok(Arc::new(AssemblyRefOs {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            os_platform_id: self.os_platform_id,
            os_major_version: self.os_major_version,
            os_minor_version: self.os_minor_version,
            assembly_ref: match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
                Some(refs) => refs.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve assemblyref token - {}",
                        self.assembly_ref | 0x2300_0000
                    ))
                }
            },
        }))
    }

    // Apply an `AssemblyRefOsRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'refs' - The map of loaded `AssemblyRef` entities
    ///
    /// # Errors
    /// Returns an error if the assembly reference cannot be found
    pub fn apply(&self, refs: &AssemblyRefMap) -> Result<()> {
        match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
            Some(entry) => {
                let entry = entry.value();
                entry
                    .os_major_version
                    .store(self.os_major_version, Ordering::Relaxed);
                entry
                    .os_minor_version
                    .store(self.os_minor_version, Ordering::Relaxed);
                entry
                    .os_platform_id
                    .store(self.os_platform_id, Ordering::Relaxed);

                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve assemblyref token - {}",
                self.assembly_ref | 0x2300_0000
            )),
        }
    }
}

impl<'a> RowDefinition<'a> for AssemblyRefOsRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* os_platform_id */   4 +
            /* os_major_version */ 4 +
            /* os_minor_version */ 4 +
            /* assembly_ref */     sizes.table_index_bytes(TableId::AssemblyRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(AssemblyRefOsRaw {
            rid,
            token: Token::new(0x2500_0000 + rid),
            offset: *offset,
            os_platform_id: read_le_at::<u32>(data, offset)?,
            os_major_version: read_le_at::<u32>(data, offset)?,
            os_minor_version: read_le_at::<u32>(data, offset)?,
            assembly_ref: read_le_at_dyn(data, offset, sizes.is_large(TableId::AssemblyRef))?,
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
            0x04, 0x04, // assembly_ref
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRefOS, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyRefOsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRefOsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x25000001);
            assert_eq!(row.os_platform_id, 0x01010101);
            assert_eq!(row.os_major_version, 0x02020202);
            assert_eq!(row.os_minor_version, 0x03030303);
            assert_eq!(row.assembly_ref, 0x0404);
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
            0x01, 0x01, 0x01, 0x01, // os_platform_id
            0x02, 0x02, 0x02, 0x02, // os_major_version
            0x03, 0x03, 0x03, 0x03, // os_minor_version
            0x04, 0x04, 0x04, 0x04, // assembly_ref
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRefOS, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<AssemblyRefOsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRefOsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x25000001);
            assert_eq!(row.os_platform_id, 0x01010101);
            assert_eq!(row.os_major_version, 0x02020202);
            assert_eq!(row.os_minor_version, 0x03030303);
            assert_eq!(row.assembly_ref, 0x0404);
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
