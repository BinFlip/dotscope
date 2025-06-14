use std::sync::{atomic::Ordering, Arc};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        tables::{
            AssemblyRefMap, AssemblyRefProcessor, AssemblyRefProcessorRc, RowDefinition, TableId,
            TableInfoRef,
        },
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `AssemblyRefProcessor` table specifies which processors a referenced assembly is targeted for, `TableId` = 0x24
pub struct AssemblyRefProcessorRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub processor: u32,
    /// an index into the `AssemblyRef` table
    pub assembly_ref: u32,
}

impl AssemblyRefProcessorRaw {
    /// Convert an `AssemblyRefProcessorRaw`, into a `AssemblyRefProcessor` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'refs' - The map of loaded `AssemblyRef` entities
    ///
    /// # Errors
    /// Returns an error if the assembly reference cannot be resolved
    pub fn to_owned(&self, refs: &AssemblyRefMap) -> Result<AssemblyRefProcessorRc> {
        Ok(Arc::new(AssemblyRefProcessor {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            processor: self.processor,
            assembly_ref: match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
                Some(refs) => refs.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve assemblyref token - {}",
                        0x2300_0000
                    ))
                }
            },
        }))
    }

    /// Apply an `AssemblyRefProcessorRaw` to the relevant entries of types (e.g. fields, methods and parameters)
    ///
    /// ## Arguments
    /// * 'refs' - The map of loaded `AssemblyRef` entities
    ///
    /// # Errors
    /// Returns an error if the assembly reference cannot be found
    pub fn apply(&self, refs: &AssemblyRefMap) -> Result<()> {
        match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
            Some(refs) => {
                refs.value()
                    .processor
                    .store(self.processor, Ordering::Relaxed);
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve assemblyref token - {}",
                0x2300_0000
            )),
        }
    }
}

impl<'a> RowDefinition<'a> for AssemblyRefProcessorRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* processor */    4 +
            /* assembly_ref */ sizes.table_index_bytes(TableId::AssemblyRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(AssemblyRefProcessorRaw {
            rid,
            token: Token::new(0x2400_0000 + rid),
            offset: *offset,
            processor: read_le_at::<u32>(data, offset)?,
            assembly_ref: read_le_at_dyn(data, offset, sizes.is_large(TableId::AssemblyRef))?,
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
            0x01, 0x01, 0x01, 0x01, // processor
            0x02, 0x02, // assembly_ref
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::AssemblyRefProcessor, 1),
                (TableId::AssemblyRef, 10), // Add AssemblyRef table
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyRefProcessorRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: AssemblyRefProcessorRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x24000001);
            assert_eq!(row.processor, 0x01010101);
            assert_eq!(row.assembly_ref, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // processor
            0x02, 0x02, 0x02, 0x02, // assembly_ref
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::AssemblyRefProcessor, u16::MAX as u32 + 3),
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table with large index
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<AssemblyRefProcessorRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: AssemblyRefProcessorRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x24000001);
            assert_eq!(row.processor, 0x01010101);
            assert_eq!(row.assembly_ref, 0x02020202);
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
