//! `AssemblyProcessor` table binary reader implementation
//!
//! Provides binary parsing implementation for the `AssemblyProcessor` metadata table (0x21) through
//! the [`crate::metadata::tables::RowReadable`] trait. This module handles the low-level
//! deserialization of `AssemblyProcessor` table entries from the metadata tables stream.
//!
//! # Binary Format Characteristics
//!
//! The `AssemblyProcessor` table has the simplest binary format among metadata tables:
//! - **Fixed-size layout**: All rows are exactly 4 bytes (1 × 4-byte integer)
//! - **No heap indexes**: Contains only a single primitive integer value
//! - **No variable-width fields**: Minimal parsing complexity
//!
//! # Row Layout
//!
//! `AssemblyProcessor` table rows have this binary structure:
//! - `processor` (4 bytes): Processor architecture identifier
//!
//! # Architecture
//!
//! This implementation provides zero-copy parsing by reading data directly from the
//! metadata tables stream. With only a single 4-byte field, this is the simplest
//! table reader in the entire metadata system.
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
//! - [`crate::metadata::tables::AssemblyProcessorRaw`]: Raw `AssemblyProcessor` data structure
//! - [`crate::metadata::loader`]: High-level metadata loading system
//!
//! # Reference
//! - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyProcessor` table specification

use crate::{
    metadata::{
        tables::{AssemblyProcessorRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at,
    Result,
};

impl RowReadable for AssemblyProcessorRaw {
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
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, _sizes: &TableInfoRef) -> Result<Self> {
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
