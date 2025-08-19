//! `AssemblyRefProcessor` table binary reader implementation
//!
//! Provides binary parsing implementation for the `AssemblyRefProcessor` metadata table (0x24) through
//! the [`crate::metadata::tables::RowReadable`] trait. This module handles the low-level
//! deserialization of `AssemblyRefProcessor` table entries from the metadata tables stream.
//!
//! # Binary Format Characteristics
//!
//! The `AssemblyRefProcessor` table has a simple binary format:
//! - **Fixed-size field**: Processor architecture identifier (4 bytes)
//! - **Variable-size index**: Assembly reference table index (2 or 4 bytes)
//! - **Total size**: 6-8 bytes per row depending on table index size
//!
//! # Row Layout
//!
//! `AssemblyRefProcessor` table rows have this binary structure:
//! - `processor` (4 bytes): Processor architecture identifier
//! - `assembly_ref` (2/4 bytes): Table index into `AssemblyRef` table
//!
//! # Architecture
//!
//! This implementation provides zero-copy parsing by reading data directly from the
//! metadata tables stream. The `AssemblyRef` table index is preserved for later
//! resolution during the dual variant phase.
//!
//! # Thread Safety
//!
//! All parsing operations are stateless and safe for concurrent access. The reader
//! does not modify any shared state during parsing operations.
//!
//! # Integration
//!
//! This reader integrates with the metadata table infrastructure:
//! - [`crate::metadata::tables::MetadataTable`]: Table container for parsed rows
//! - [`crate::metadata::tables::AssemblyRefProcessorRaw`]: Raw `AssemblyRefProcessor` data structure
//! - [`crate::metadata::loader`]: High-level metadata loading system
//!
//! # Reference
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification

use crate::{
    metadata::{
        tables::{AssemblyRefProcessorRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for AssemblyRefProcessorRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
    use std::sync::Arc;

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
