//! `AssemblyRefOS` table binary reader implementation
//!
//! Provides binary parsing implementation for the `AssemblyRefOS` metadata table (0x25) through
//! the [`crate::metadata::tables::RowReadable`] trait. This module handles the low-level
//! deserialization of `AssemblyRefOS` table entries from the metadata tables stream.
//!
//! # Binary Format Characteristics
//!
//! The `AssemblyRefOS` table has a mixed binary format:
//! - **Fixed-size fields**: OS platform and version fields (12 bytes total)
//! - **Variable-size index**: Assembly reference table index (2 or 4 bytes)
//! - **Total size**: 14-16 bytes per row depending on table index size
//!
//! # Row Layout
//!
//! `AssemblyRefOS` table rows have this binary structure:
//! - `os_platform_id` (4 bytes): Operating system platform identifier
//! - `os_major_version` (4 bytes): Major OS version number
//! - `os_minor_version` (4 bytes): Minor OS version number
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
//! - [`crate::metadata::tables::AssemblyRefOsRaw`]: Raw `AssemblyRefOS` data structure
//! - [`crate::metadata::loader`]: High-level metadata loading system
//!
//! # Reference
//! - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification

use crate::{
    metadata::{
        tables::{AssemblyRefOsRaw, RowReadable, TableId, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for AssemblyRefOsRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
    use std::sync::Arc;

    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

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
