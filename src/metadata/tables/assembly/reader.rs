//! Assembly table binary reader implementation
//!
//! Provides binary parsing implementation for the Assembly metadata table (0x20) through
//! the [`crate::metadata::tables::RowReadable`] trait. This module handles the low-level
//! deserialization of Assembly table entries from the metadata tables stream.
//!
//! # Binary Format Support
//!
//! The reader supports both small and large heap index formats:
//! - **Small indexes**: 2-byte heap references (for assemblies with < 64K entries)
//! - **Large indexes**: 4-byte heap references (for larger assemblies)
//!
//! # Row Layout
//!
//! Assembly table rows have this binary structure:
//! - `hash_alg_id` (4 bytes): Hash algorithm identifier
//! - `major_version` (2 bytes): Major version number
//! - `minor_version` (2 bytes): Minor version number
//! - `build_number` (2 bytes): Build number
//! - `revision_number` (2 bytes): Revision number  
//! - `flags` (4 bytes): Assembly attributes bitmask
//! - `public_key` (2/4 bytes): Blob heap index for public key
//! - `name` (2/4 bytes): String heap index for assembly name
//! - `culture` (2/4 bytes): String heap index for culture
//!
//! # Architecture
//!
//! This implementation provides zero-copy parsing by reading data directly from the
//! metadata tables stream without intermediate buffering. All heap references are
//! preserved as indexes and resolved only when needed.
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
//! - [`crate::metadata::tables::AssemblyRaw`]: Raw assembly data structure
//! - [`crate::metadata::loader`]: High-level metadata loading system
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification

use crate::{
    metadata::{
        tables::{AssemblyRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for AssemblyRaw {
    /// Read and parse an Assembly table row from binary data
    ///
    /// Deserializes one Assembly table entry from the metadata tables stream, handling
    /// variable-width heap indexes based on the table size information.
    ///
    /// # Arguments
    /// * `data` - Binary metadata tables stream data
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - Row identifier for this assembly entry
    /// * `sizes` - Table sizing information for parsing heap indexes
    ///
    /// # Returns
    /// * `Ok(AssemblyRaw)` - Successfully parsed assembly row
    /// * `Err(`[`crate::Error`]`)` - If data is malformed or insufficient
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(AssemblyRaw {
            rid,
            token: Token::new(0x2000_0000 + rid),
            offset: *offset,
            hash_alg_id: read_le_at::<u32>(data, offset)?,
            major_version: u32::from(read_le_at::<u16>(data, offset)?),
            minor_version: u32::from(read_le_at::<u16>(data, offset)?),
            build_number: u32::from(read_le_at::<u16>(data, offset)?),
            revision_number: u32::from(read_le_at::<u16>(data, offset)?),
            flags: read_le_at::<u32>(data, offset)?,
            public_key: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            culture: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, 0x01, 0x01, // hash_alg_id
            0x02, 0x02, // major_version
            0x03, 0x03, // minor_version
            0x04, 0x04, // build_number
            0x05, 0x05, // revision_number
            0x06, 0x06, 0x06, 0x06, // flags
            0x07, 0x07, // public_key
            0x08, 0x08, // name
            0x09, 0x09, // culture
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Assembly, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x20000001);
            assert_eq!(row.hash_alg_id, 0x01010101);
            assert_eq!(row.major_version, 0x0202);
            assert_eq!(row.minor_version, 0x0303);
            assert_eq!(row.build_number, 0x0404);
            assert_eq!(row.revision_number, 0x0505);
            assert_eq!(row.flags, 0x06060606);
            assert_eq!(row.public_key, 0x0707);
            assert_eq!(row.name, 0x0808);
            assert_eq!(row.culture, 0x0909);
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
            0x01, 0x01, 0x01, 0x01, // hash_alg_id
            0x02, 0x02, // major_version
            0x03, 0x03, // minor_version
            0x04, 0x04, // build_number
            0x05, 0x05, // revision_number
            0x06, 0x06, 0x06, 0x06, // flags
            0x07, 0x07, 0x07, 0x07, // public_key
            0x08, 0x08, 0x08, 0x08, // name
            0x09, 0x09, 0x09, 0x09, // culture
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Assembly, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<AssemblyRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x20000001);
            assert_eq!(row.hash_alg_id, 0x01010101);
            assert_eq!(row.major_version, 0x0202);
            assert_eq!(row.minor_version, 0x0303);
            assert_eq!(row.build_number, 0x0404);
            assert_eq!(row.revision_number, 0x0505);
            assert_eq!(row.flags, 0x06060606);
            assert_eq!(row.public_key, 0x07070707);
            assert_eq!(row.name, 0x08080808);
            assert_eq!(row.culture, 0x09090909);
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
