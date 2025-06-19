//! Raw Assembly table representation
//!
//! Provides the [`crate::metadata::tables::assembly::AssemblyRaw`] struct for low-level access to Assembly metadata table data
//! with unresolved heap indexes. This represents the binary format of assembly records as
//! they appear in the metadata tables stream.
//!
//! # Assembly Table Format
//!
//! The Assembly table (0x20) contains exactly one row (if present) with these fields:
//! - **`HashAlgId`** (4 bytes): Hash algorithm identifier  
//! - **`MajorVersion`** (2 bytes): Major version number
//! - **`MinorVersion`** (2 bytes): Minor version number
//! - **`BuildNumber`** (2 bytes): Build number
//! - **`RevisionNumber`** (2 bytes): Revision number
//! - **Flags** (4 bytes): Assembly flags bitmask
//! - **`PublicKey`** (2/4 bytes): Blob heap index for public key data
//! - **Name** (2/4 bytes): String heap index for assembly name
//! - **Culture** (2/4 bytes): String heap index for culture name
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification

use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::{Blob, Strings},
        tables::{Assembly, AssemblyRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw Assembly table row with unresolved heap indexes
///
/// Represents the binary format of an Assembly metadata table entry (table ID 0x20) as stored
/// in the metadata tables stream. All string and blob references are stored as heap indexes
/// that must be resolved using the appropriate heaps to access the actual data.
///
/// The Assembly table contains the identity information for the current assembly, including
/// version numbers, flags, and references to the assembly name and public key data.
///
/// # Reference
/// - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification
pub struct AssemblyRaw {
    /// Row identifier within the Assembly metadata table
    ///
    /// The 1-based index of this assembly row. Since the Assembly table contains
    /// at most one row, this value is typically 1 when present.
    pub rid: u32,

    /// Metadata token for this assembly row
    ///
    /// Combines the table identifier (0x20 for Assembly) with the row ID to create
    /// a unique token. Format: `0x20000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw assembly data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Hash algorithm identifier (unresolved)
    ///
    /// 4-byte value specifying the cryptographic hash algorithm used for file integrity.
    /// See [`crate::metadata::tables::assembly::AssemblyHashAlgorithm`] for standard values.
    pub hash_alg_id: u32,

    /// Major version number (unresolved)
    ///
    /// 2-byte value stored as u32. First component of the four-part assembly version.
    pub major_version: u32,

    /// Minor version number (unresolved)
    ///
    /// 2-byte value stored as u32. Second component of the four-part assembly version.
    pub minor_version: u32,

    /// Build number (unresolved)
    ///
    /// 2-byte value stored as u32. Third component of the four-part assembly version.
    pub build_number: u32,

    /// Revision number (unresolved)
    ///
    /// 2-byte value stored as u32. Fourth component of the four-part assembly version.
    pub revision_number: u32,

    /// Assembly flags bitmask (unresolved)
    ///
    /// 4-byte bitmask controlling assembly behavior and characteristics.
    /// See [`crate::metadata::tables::assembly::AssemblyFlags`] for flag constants.
    pub flags: u32,

    /// Public key blob heap index (unresolved)
    ///
    /// Index into the blob heap containing the strong name public key data.
    /// Value of 0 indicates no public key (unsigned assembly).
    pub public_key: u32,

    /// Assembly name string heap index (unresolved)
    ///
    /// Index into the string heap containing the simple assembly name.
    /// This is the primary identifier for the assembly.
    pub name: u32,

    /// Culture string heap index (unresolved)
    ///
    /// Index into the string heap containing the culture name for localized assemblies.
    /// Value of 0 indicates a culture-neutral assembly.
    pub culture: u32,
}

impl AssemblyRaw {
    /// Convert raw assembly data to owned representation with resolved heap references
    ///
    /// Resolves all heap indexes to their actual string and blob data, creating an
    /// [`crate::metadata::tables::Assembly`] instance with owned data that doesn't
    /// require the original heaps for access.
    ///
    /// # Arguments
    /// * `strings` - The string heap for resolving name and culture indexes
    /// * `blobs` - The blob heap for resolving public key data
    ///
    /// # Returns
    /// * `Ok(`[`crate::metadata::tables::AssemblyRc`]`)` - Reference-counted owned assembly
    /// * `Err(`[`crate::Error`]`)` - If heap resolution fails
    ///
    /// # Errors
    /// This function will return an error if:
    /// - String heap lookup fails for the assembly name or culture
    /// - Blob heap lookup fails for the public key data
    ///
    /// # Heap Resolution
    /// - `name`: Resolved to owned String from string heap
    /// - `culture`: Resolved to optional String (None if index is 0)
    /// - `public_key`: Resolved to optional `Vec<u8>` (None if index is 0)
    pub fn to_owned(&self, strings: &Strings, blobs: &Blob) -> Result<AssemblyRc> {
        Ok(Arc::new(Assembly {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            hash_alg_id: self.hash_alg_id,
            major_version: self.major_version,
            minor_version: self.minor_version,
            build_number: self.build_number,
            revision_number: self.revision_number,
            flags: self.flags,
            public_key: if self.public_key == 0 {
                None
            } else {
                Some(blobs.get(self.public_key as usize)?.to_vec())
            },
            name: strings.get(self.name as usize)?.to_string(),
            culture: if self.culture == 0 {
                None
            } else {
                Some(strings.get(self.culture as usize)?.to_string())
            },
            security: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply assembly row data to update related metadata structures
    ///
    /// Assembly entries are self-contained and represent the current assembly metadata.
    /// Unlike other metadata tables that may have cross-references, Assembly table entries
    /// don't require updates to other tables during the dual variant resolution phase.
    ///
    /// This method exists to satisfy the metadata processing interface but performs
    /// no actual operations since assembly data is purely descriptive.
    ///
    /// # Returns
    /// Always returns `Ok(())` since Assembly entries don't modify other tables
    ///
    /// # Note
    /// This is part of the internal metadata loading infrastructure and should not
    /// be called directly by user code.
    ///
    /// # Errors
    /// Currently returns `Ok(())` in all cases as this is a placeholder implementation.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for AssemblyRaw {
    /// Calculate the byte size of an Assembly table row
    ///
    /// Computes the total size based on fixed-size fields plus variable-size heap indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte heap indexes.
    ///
    /// # Row Layout
    /// - `hash_alg_id`: 4 bytes (fixed)
    /// - `major_version`: 2 bytes (fixed)
    /// - `minor_version`: 2 bytes (fixed)
    /// - `build_number`: 2 bytes (fixed)
    /// - `revision_number`: 2 bytes (fixed)
    /// - `flags`: 4 bytes (fixed)
    /// - `public_key`: 2 or 4 bytes (blob heap index)
    /// - `name`: 2 or 4 bytes (string heap index)
    /// - `culture`: 2 or 4 bytes (string heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for heap index widths
    ///
    /// # Returns
    /// Total byte size of one Assembly table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* hash_alg_id */     4 +
            /* major_version */   2 +
            /* minor_version */   2 +
            /* build_number */    2 +
            /* revision_number */ 2 +
            /* flags */           4 +
            /* public_key */      sizes.blob_bytes() +
            /* name */            sizes.str_bytes() +
            /* culture */         sizes.str_bytes()
        )
    }

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
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
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
