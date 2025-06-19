//! Raw `AssemblyRef` table representation.
//!
//! This module provides the [`crate::metadata::tables::assemblyref::raw::AssemblyRefRaw`] struct
//! for low-level access to `AssemblyRef` metadata table data with unresolved heap indexes. This
//! represents the binary format of assembly reference records as they appear in the metadata
//! tables stream before heap resolution.
//!
//! # Architecture
//!
//! The raw representation stores data exactly as it appears in the metadata tables stream,
//! with heap indexes that require resolution through the string and blob heaps. This is
//! part of the dual variant pattern used throughout the metadata system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyref::raw::AssemblyRefRaw`] - Raw table row structure
//! - [`crate::metadata::tables::assemblyref::AssemblyRefRc`] - Reference-counted owned representation
//! - [`crate::metadata::tables::RowDefinition`] - Table parsing interface implementation
//!
//! # `AssemblyRef` Table Format
//!
//! The `AssemblyRef` table (0x23) contains zero or more rows with these fields:
//! - **`MajorVersion`** (2 bytes): Major version number
//! - **`MinorVersion`** (2 bytes): Minor version number  
//! - **`BuildNumber`** (2 bytes): Build number
//! - **`RevisionNumber`** (2 bytes): Revision number
//! - **Flags** (4 bytes): Assembly flags bitmask
//! - **`PublicKeyOrToken`** (2/4 bytes): Blob heap index for public key/token data
//! - **Name** (2/4 bytes): String heap index for assembly name
//! - **Culture** (2/4 bytes): String heap index for culture name
//! - **`HashValue`** (2/4 bytes): Blob heap index for hash data
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::streams`] - String and blob heap access
//! - [`crate::metadata::token`] - Token representation for metadata references
//! - [`crate::file::io`] - Binary data reading utilities
//!
//! # References
//!
//! - [ECMA-335 II.22.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification

use std::sync::{atomic::AtomicU32, Arc};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        identity::Identity,
        streams::{Blob, Strings},
        tables::{
            AssemblyFlags, AssemblyRef, AssemblyRefHash, AssemblyRefRc, RowDefinition, TableInfoRef,
        },
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `AssemblyRef` table row with unresolved heap indexes
///
/// Represents the binary format of an `AssemblyRef` metadata table entry (table ID 0x23) as stored
/// in the metadata tables stream. All string and blob references are stored as heap indexes
/// that must be resolved using the appropriate heaps to access the actual data.
///
/// The `AssemblyRef` table contains dependency information for external assemblies required by
/// the current assembly, including version requirements and strong name verification data.
///
/// # Table Layout
///
/// Each `AssemblyRef` table row occupies a fixed number of bytes determined by the heap index sizes:
/// - Version fields: 8 bytes (4 × 2-byte values)
/// - Flags: 4 bytes
/// - Heap indexes: Variable size based on heap sizes (2 or 4 bytes each)
pub struct AssemblyRefRaw {
    /// Row identifier within the `AssemblyRef` table
    ///
    /// Unique identifier for this row within the metadata table. Used for internal
    /// referencing and debugging purposes.
    pub rid: u32,

    /// Metadata token for this assembly reference
    ///
    /// Contains the table ID (0x23) and row ID packed into a single value.
    /// Used for cross-referencing from other metadata tables.
    pub token: Token,

    /// File offset where this table entry begins
    ///
    /// Byte offset from the start of the PE file to the beginning of this
    /// `AssemblyRef` table entry. Used for low-level file analysis.
    pub offset: usize,

    /// Major version number (first component of version)
    ///
    /// The first part of the four-part version number. Stored as a 2-byte value
    /// in the metadata but promoted to u32 for easier arithmetic.
    pub major_version: u32,

    /// Minor version number (second component of version)
    ///
    /// The second part of the four-part version number. Stored as a 2-byte value
    /// in the metadata but promoted to u32 for easier arithmetic.
    pub minor_version: u32,

    /// Build number (third component of version)
    ///
    /// The third part of the four-part version number. Stored as a 2-byte value
    /// in the metadata but promoted to u32 for easier arithmetic.
    pub build_number: u32,

    /// Revision number (fourth component of version)
    ///
    /// The fourth part of the four-part version number. Stored as a 2-byte value
    /// in the metadata but promoted to u32 for easier arithmetic.
    pub revision_number: u32,

    /// Assembly flags bit field (unresolved)
    ///
    /// Bitmask specifying assembly attributes using [`crate::metadata::tables::AssemblyFlags`]
    /// constants. Controls behavior like public key format and retargetability.
    pub flags: u32,

    /// Blob heap index for public key or public key token
    ///
    /// Index into the #Blob heap containing either the full public key (when `PUBLIC_KEY` flag is set)
    /// or the 8-byte public key token. A value of 0 indicates no strong name information.
    pub public_key_or_token: u32,

    /// String heap index for assembly name
    ///
    /// Index into the #String heap containing the simple assembly name (without file extension).
    /// Must be a valid non-zero index as all assemblies must have names.
    pub name: u32,

    /// String heap index for culture name
    ///
    /// Index into the #String heap containing the culture string for localized assemblies.
    /// A value of 0 indicates a culture-neutral assembly (the common case).
    pub culture: u32,

    /// Blob heap index for assembly hash
    ///
    /// Index into the #Blob heap containing a cryptographic hash of the referenced assembly
    /// for integrity verification. A value of 0 indicates no hash verification is required.
    pub hash_value: u32,
}

impl AssemblyRefRaw {
    /// Convert this raw assembly reference to an owned form with resolved heap data
    ///
    /// Resolves all heap indexes (strings and blobs) to create a fully owned [`AssemblyRef`]
    /// instance that doesn't require heap access for string/blob data. This is the primary
    /// way to obtain usable assembly reference information from raw metadata.
    ///
    /// # Arguments
    ///
    /// * `strings` - The #String heap for resolving name and culture indexes
    /// * `blob` - The #Blob heap for resolving public key/token and hash indexes
    ///
    /// # Returns
    ///
    /// Returns a reference-counted [`AssemblyRefRc`] containing the fully resolved assembly
    /// reference data with owned strings and byte arrays.
    ///
    /// # Errors
    ///
    /// - String heap indexes are invalid or point to non-UTF-8 data
    /// - Blob heap indexes are invalid or corrupted
    /// - Required string data (assembly name) is missing
    pub fn to_owned(&self, strings: &Strings, blob: &Blob) -> Result<AssemblyRefRc> {
        Ok(Arc::new(AssemblyRef {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            name: strings.get(self.name as usize)?.to_string(),
            culture: if self.culture == 0 {
                None
            } else {
                Some(strings.get(self.culture as usize)?.to_string())
            },
            major_version: self.major_version,
            minor_version: self.minor_version,
            build_number: self.build_number,
            revision_number: self.revision_number,
            flags: self.flags,
            identifier: if self.public_key_or_token == 0 {
                None
            } else {
                Some(Identity::from(
                    blob.get(self.public_key_or_token as usize)?,
                    self.flags & AssemblyFlags::PUBLIC_KEY > 0,
                )?)
            },
            hash: if self.hash_value == 0 {
                None
            } else {
                Some(AssemblyRefHash::new(blob.get(self.hash_value as usize)?)?)
            },
            os_platform_id: AtomicU32::new(0),
            os_major_version: AtomicU32::new(0),
            os_minor_version: AtomicU32::new(0),
            processor: AtomicU32::new(0),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply an `AssemblyRefRaw` entry to update related metadata structures.
    ///
    /// `AssemblyRef` entries represent external assembly references. They are primarily used
    /// as targets by other tables but don't themselves modify other metadata during the
    /// dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `AssemblyRef` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for AssemblyRefRaw {
    /// Calculate the byte size of an `AssemblyRef` table row
    ///
    /// Returns the size in bytes for an `AssemblyRef` table row, accounting for variable-width
    /// heap indexes. The size depends on whether the string and blob heaps require 2 or 4-byte indexes.
    ///
    /// # Row Layout
    /// - Version fields: 8 bytes (4 × 2-byte values)
    /// - Flags: 4 bytes
    /// - `PublicKeyOrToken`: 2 or 4 bytes (blob heap index)
    /// - Name: 2 or 4 bytes (string heap index)
    /// - Culture: 2 or 4 bytes (string heap index)
    /// - `HashValue`: 2 or 4 bytes (blob heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table size information containing heap index widths
    ///
    /// # Returns
    /// Total size in bytes for one `AssemblyRef` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* major_version */       2 +
            /* minor_version */       2 +
            /* build_number */        2 +
            /* revision_number */     2 +
            /* flags */               4 +
            /* public_key_or_token */ sizes.blob_bytes() +
            /* name */                sizes.str_bytes() +
            /* culture */             sizes.str_bytes() +
            /* hash_value */          sizes.blob_bytes()
        )
    }

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
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
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
