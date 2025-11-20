//! `AssemblyRef` table binary reader implementation
//!
//! Provides binary parsing implementation for the `AssemblyRef` metadata table (0x23) through
//! the [`crate::metadata::tables::RowReadable`] trait. This module handles the low-level
//! deserialization of `AssemblyRef` table entries from the metadata tables stream.
//!
//! # Binary Format Support
//!
//! The reader supports both small and large heap index formats:
//! - **Small indexes**: 2-byte heap references (for assemblies with < 64K entries)
//! - **Large indexes**: 4-byte heap references (for larger assemblies)
//!
//! # Row Layout
//!
//! `AssemblyRef` table rows have this binary structure:
//! - `major_version` (2 bytes): Major version number
//! - `minor_version` (2 bytes): Minor version number
//! - `build_number` (2 bytes): Build number
//! - `revision_number` (2 bytes): Revision number
//! - `flags` (4 bytes): Assembly attributes bitmask
//! - `public_key_or_token` (2/4 bytes): Blob heap index for public key/token
//! - `name` (2/4 bytes): String heap index for assembly name
//! - `culture` (2/4 bytes): String heap index for culture
//! - `hash_value` (2/4 bytes): Blob heap index for hash data
//!
//! # Architecture
//!
//! This implementation provides zero-copy parsing by reading data directly from the
//! metadata tables stream without intermediate buffering. All heap references are
//! preserved as indexes and resolved only when needed during the dual variant phase.
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
//! - [`crate::metadata::tables::AssemblyRefRaw`]: Raw `AssemblyRef` data structure
//! - [`crate::metadata::loader`]: High-level metadata loading system
//!
//! # Reference
//! - [ECMA-335 II.22.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification

use crate::{
    metadata::{
        tables::{AssemblyRefRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::{read_le_at, read_le_at_dyn},
    Result,
};

impl RowReadable for AssemblyRefRaw {
    /// Read and parse an `AssemblyRef` table row from binary data
    ///
    /// Deserializes one `AssemblyRef` table entry from the metadata tables stream.
    /// `AssemblyRef` rows have a mixed layout with fixed-size version fields and
    /// variable-size heap indexes.
    ///
    /// # Arguments
    /// * `data` - Binary metadata tables stream data
    /// * `offset` - Current read position (updated after reading)
    /// * `rid` - Row identifier for this `AssemblyRef` entry
    /// * `sizes` - Table size information for heap index widths
    ///
    /// # Returns
    /// * `Ok(AssemblyRefRaw)` - Successfully parsed `AssemblyRef` row
    /// * `Err(`[`crate::Error`]`)` - If data is malformed or insufficient
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
        Ok(AssemblyRefRaw {
            rid,
            token: Token::new(0x2300_0000 + rid),
            offset: *offset,
            major_version: u32::from(read_le_at::<u16>(data, offset)?),
            minor_version: u32::from(read_le_at::<u16>(data, offset)?),
            build_number: u32::from(read_le_at::<u16>(data, offset)?),
            revision_number: u32::from(read_le_at::<u16>(data, offset)?),
            flags: read_le_at::<u32>(data, offset)?,
            public_key_or_token: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            culture: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            hash_value: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // major_version
            0x02, 0x02, // minor_version
            0x03, 0x03, // build_number
            0x04, 0x04, // revision_number
            0x05, 0x05, 0x05, 0x05, // flags
            0x06, 0x06, // public_key_or_token
            0x07, 0x07, // name
            0x08, 0x08, // culture
            0x09, 0x09, // hash_value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<AssemblyRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x23000001);
            assert_eq!(row.major_version, 0x0101);
            assert_eq!(row.minor_version, 0x0202);
            assert_eq!(row.build_number, 0x0303);
            assert_eq!(row.revision_number, 0x0404);
            assert_eq!(row.flags, 0x05050505);
            assert_eq!(row.public_key_or_token, 0x0606);
            assert_eq!(row.name, 0x0707);
            assert_eq!(row.culture, 0x0808);
            assert_eq!(row.hash_value, 0x0909);
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
            0x01, 0x01, // major_version
            0x02, 0x02, // minor_version
            0x03, 0x03, // build_number
            0x04, 0x04, // revision_number
            0x05, 0x05, 0x05, 0x05, // flags
            0x06, 0x06, 0x06, 0x06, // public_key_or_token
            0x07, 0x07, 0x07, 0x07, // name
            0x08, 0x08, 0x08, 0x08, // culture
            0x09, 0x09, 0x09, 0x09, // hash_value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::AssemblyRef, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<AssemblyRefRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: AssemblyRefRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x23000001);
            assert_eq!(row.major_version, 0x0101);
            assert_eq!(row.minor_version, 0x0202);
            assert_eq!(row.build_number, 0x0303);
            assert_eq!(row.revision_number, 0x0404);
            assert_eq!(row.flags, 0x05050505);
            assert_eq!(row.public_key_or_token, 0x06060606);
            assert_eq!(row.name, 0x07070707);
            assert_eq!(row.culture, 0x08080808);
            assert_eq!(row.hash_value, 0x09090909);
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
