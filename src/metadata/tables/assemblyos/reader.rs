//! `AssemblyOS` table binary reader implementation
//!
//! Provides binary parsing implementation for the `AssemblyOS` metadata table (0x22) through
//! the [`crate::metadata::tables::RowReadable`] trait. This module handles the low-level
//! deserialization of `AssemblyOS` table entries from the metadata tables stream.
//!
//! # Binary Format Characteristics
//!
//! The `AssemblyOS` table has a simplified binary format compared to other metadata tables:
//! - **Fixed-size layout**: All rows are exactly 12 bytes (3 × 4-byte integers)
//! - **No heap indexes**: Contains only primitive integer values
//! - **No variable-width fields**: Simplifies parsing compared to string/blob-referencing tables
//!
//! # Row Layout
//!
//! `AssemblyOS` table rows have this binary structure:
//! - `os_platform_id` (4 bytes): Operating system platform identifier
//! - `os_major_version` (4 bytes): Major OS version number
//! - `os_minor_version` (4 bytes): Minor OS version number
//!
//! # Architecture
//!
//! This implementation provides zero-copy parsing by reading data directly from the
//! metadata tables stream. Since no heap resolution is required, the parsing is
//! significantly simpler than tables with string or blob references.
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
//! - [`crate::metadata::tables::AssemblyOsRaw`]: Raw `AssemblyOS` data structure
//! - [`crate::metadata::loader`]: High-level metadata loading system
//!
//! # Reference
//! - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification

use crate::{
    metadata::{
        tables::{AssemblyOsRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at,
    Result,
};

impl RowReadable for AssemblyOsRaw {
    /// Read and parse an `AssemblyOS` table row from binary data
    ///
    /// Deserializes one `AssemblyOS` table entry from the metadata tables stream.
    /// Unlike other tables with variable-width heap indexes, `AssemblyOS` has a fixed
    /// 12-byte layout with three 4-byte integer fields.
    ///
    /// # Arguments
    /// * `data` - Binary metadata tables stream data
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - Row identifier for this `AssemblyOS` entry
    /// * `_sizes` - Unused since `AssemblyOS` has no heap indexes
    ///
    /// # Returns
    /// * `Ok(AssemblyOsRaw)` - Successfully parsed `AssemblyOS` row
    /// * `Err(`[`crate::Error`]`)` - If data is malformed or insufficient
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, _sizes: &TableInfoRef) -> Result<Self> {
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
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

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
