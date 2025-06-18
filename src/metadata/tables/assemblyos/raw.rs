//! Raw `AssemblyOS` table representation.
//!
//! This module provides low-level access to `AssemblyOS` metadata table data through the
//! [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw`] structure. The `AssemblyOS` table
//! contains operating system targeting information for .NET assemblies, though it is rarely
//! used in modern applications.
//!
//! # Architecture
//!
//! Unlike other metadata tables that require heap resolution, `AssemblyOS` contains only primitive
//! integer values, making the "raw" and "owned" representations functionally identical. This
//! simplifies the dual variant pattern used throughout the metadata system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw`] - Raw table row structure
//! - [`crate::metadata::tables::assemblyos::AssemblyOsRc`] - Reference-counted owned representation
//! - [`crate::metadata::tables::RowDefinition`] - Table parsing interface implementation
//!
//! # `AssemblyOS` Table Format
//!
//! The `AssemblyOS` table (0x22) contains operating system targeting information:
//! - **`OSPlatformId`** (4 bytes): Operating system platform identifier
//! - **`OSMajorVersion`** (4 bytes): Major version number of the target OS
//! - **`OSMinorVersion`** (4 bytes): Minor version number of the target OS
//!
//! # Historical Context
//!
//! This table was designed for early .NET Framework scenarios where assemblies might
//! need explicit OS compatibility declarations. Modern .NET applications typically
//! rely on runtime platform abstraction instead of metadata-level OS targeting.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token representation for metadata references
//! - [`crate::file::io`] - Binary data reading utilities
//!
//! # References
//!
//! - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification

use std::sync::Arc;

use crate::{
    file::io::read_le_at,
    metadata::{
        tables::{AssemblyOsRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `AssemblyOS` table row representing operating system targeting information
///
/// Contains platform identification data for assemblies that specify explicit OS compatibility.
/// Unlike most metadata tables, `AssemblyOS` contains only primitive integer values and requires
/// no heap resolution, making this structure immediately usable without further processing.
///
/// The `AssemblyOS` table (0x22) is optional and rarely present in modern .NET assemblies,
/// which typically rely on runtime platform abstraction rather than compile-time OS targeting.
///
/// # Data Model
///
/// All fields contain direct integer values rather than heap indexes:
/// - No string heap references (unlike Assembly.Name)
/// - No blob heap references (unlike Assembly.PublicKey)
/// - All data is self-contained within the table row
///
/// # Reference
/// - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification
pub struct AssemblyOsRaw {
    /// Row identifier within the `AssemblyOS` metadata table
    ///
    /// The 1-based index of this `AssemblyOS` row. Multiple OS targets can be specified,
    /// though this is rarely used in practice.
    pub rid: u32,

    /// Metadata token for this `AssemblyOS` row
    ///
    /// Combines the table identifier (0x22 for `AssemblyOS`) with the row ID to create
    /// a unique token. Format: `0x22000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyOS` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Operating system platform identifier
    ///
    /// 4-byte value identifying the target operating system platform. Common values
    /// may include platform-specific identifiers, though specific constants are not
    /// standardized in ECMA-335.
    pub os_platform_id: u32,

    /// Major version number of the target operating system
    ///
    /// 4-byte value specifying the major version of the target OS. Combined with
    /// [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw::os_minor_version`] to specify exact OS version requirements.
    pub os_major_version: u32,

    /// Minor version number of the target operating system
    ///
    /// 4-byte value specifying the minor version of the target OS. Combined with
    /// [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw::os_major_version`] to specify exact OS version requirements.
    pub os_minor_version: u32,
}

impl AssemblyOsRaw {
    /// Convert raw `AssemblyOS` data to owned representation
    ///
    /// Since the `AssemblyOS` table contains only primitive values with no heap references,
    /// this method simply clones the data and wraps it in an [`Arc`] for consistency
    /// with the dual variant pattern used across all metadata tables.
    ///
    /// # Returns
    /// * `Ok(`[`crate::metadata::tables::AssemblyOsRc`]`)` - Reference-counted `AssemblyOS` data
    ///
    /// # Errors
    /// This function never returns an error as cloning primitive values cannot fail.
    pub fn to_owned(&self) -> Result<AssemblyOsRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Apply `AssemblyOS` row data to update related metadata structures
    ///
    /// `AssemblyOS` entries specify operating system targeting information and are self-contained.
    /// Unlike other metadata tables that may have cross-references, `AssemblyOS` entries don't
    /// require updates to other tables during the dual variant resolution phase.
    ///
    /// This method exists to satisfy the metadata processing interface but performs
    /// no actual operations since `AssemblyOS` data is purely descriptive.
    ///
    /// # Returns
    /// Always returns `Ok(())` since `AssemblyOS` entries don't modify other tables
    ///
    /// # Errors
    /// This function never returns an error as no operations are performed.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for AssemblyOsRaw {
    /// Calculate the byte size of an `AssemblyOS` table row
    ///
    /// Returns the fixed size since `AssemblyOS` contains only primitive integer fields
    /// with no variable-size heap indexes. Total size is always 12 bytes (3 × 4-byte integers).
    ///
    /// # Row Layout
    /// - `os_platform_id`: 4 bytes (fixed)
    /// - `os_major_version`: 4 bytes (fixed)
    /// - `os_minor_version`: 4 bytes (fixed)
    ///
    /// # Arguments
    /// * `_sizes` - Unused for `AssemblyOS` since no heap indexes are present
    ///
    /// # Returns
    /// Fixed size of 12 bytes for all `AssemblyOS` rows
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* os_platform_id */   4_u32 +
        /* os_major_version */ 4_u32 +
        /* os_minor_version */ 4_u32
    }

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
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        _sizes: &TableInfoRef,
    ) -> Result<Self> {
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
