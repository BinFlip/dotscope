//! Raw File structures for the File metadata table.
//!
//! This module provides the [`FileRaw`] struct for reading file data directly
//! from metadata tables before index resolution. The File table lists files
//! that make up multi-file assemblies including modules, resources, and libraries.
//!
//! # Table Structure
//! The File table (TableId = 0x26) contains these columns:
//! - `Flags`: 4-byte FileAttributes bitmask indicating file type
//! - `Name`: Index into String heap containing filename
//! - `HashValue`: Index into Blob heap containing cryptographic hash
//!
//! # File Types
//! File entries can represent various file types:
//! - **Executable modules**: .netmodule files with .NET code
//! - **Resource files**: .resources files with binary data
//! - **Native libraries**: .dll files with unmanaged code
//! - **Documentation**: .xml files with API documentation
//! - **Configuration**: Data files with application settings
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the File table specification.
//!
//! # Thread Safety
//! [`FileRaw`] implements [`Clone`] and is safe to share between threads.

use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::{Blob, Strings},
        tables::{AssemblyRefHash, File, FileRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

/// Raw file data read directly from the File metadata table.
///
/// This structure represents a file entry before index resolution and string/blob
/// dereferencing. File entries describe components of multi-file assemblies including
/// modules, resources, and native libraries.
///
/// # Binary Format
/// Each row in the File table has this layout:
/// ```text
/// Offset | Size | Field     | Description
/// -------|------|-----------|----------------------------------
/// 0      | 4    | Flags     | FileAttributes bitmask
/// 4      | 2/4  | Name      | String heap index
/// 6/8    | 2/4  | HashValue | Blob heap index
/// ```
///
/// String and blob index sizes depend on heap sizes.
///
/// # File Context
/// File entries are used for:
/// - **Multi-module assemblies**: Additional .netmodule files with executable code
/// - **Resource files**: Binary data files (.resources, images, configuration)
/// - **Native libraries**: Unmanaged DLLs for P/Invoke operations
/// - **Documentation**: XML documentation and help files
/// - **Satellite assemblies**: Localization and culture-specific content
///
/// # File Attributes
/// The Flags field contains FileAttributes values:
/// - **CONTAINS_META_DATA (0x0000)**: File contains .NET metadata
/// - **CONTAINS_NO_META_DATA (0x0001)**: Resource file without metadata
///
/// # Hash Security
/// The HashValue provides integrity verification:
/// - **SHA-1 or SHA-256**: Algorithm depends on assembly version
/// - **Tamper detection**: Verifies file hasn't been modified
/// - **Loading validation**: Runtime can verify file authenticity
/// - **Security assurance**: Prevents malicious file substitution
///
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.19 for the complete File table specification.
#[derive(Clone, Debug)]
pub struct FileRaw {
    /// The row identifier in the File table.
    ///
    /// This 1-based index uniquely identifies this file within the File table.
    pub rid: u32,

    /// The metadata token for this file.
    ///
    /// A [`Token`] that uniquely identifies this file across the entire assembly.
    /// The token value is calculated as `0x26000000 + rid`.
    ///
    /// [`Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this file in the metadata tables stream.
    ///
    /// This offset points to the start of this file's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// File attribute flags indicating type and characteristics.
    ///
    /// A 4-byte bitmask of FileAttributes values that specify the nature
    /// of the file, particularly whether it contains .NET metadata.
    pub flags: u32,

    /// Index into the String heap for the filename.
    ///
    /// This index points to the filename string in the strings heap,
    /// which needs to be resolved during conversion to owned data.
    pub name: u32,

    /// Index into the Blob heap for the cryptographic hash.
    ///
    /// This index points to the hash data in the blob heap, containing
    /// the cryptographic hash used for file integrity verification.
    pub hash_value: u32,
}

impl FileRaw {
    /// Convert this raw file entry to an owned [`File`] with resolved references.
    ///
    /// This method resolves the string and blob heap references to create a complete
    /// file structure with owned data. The resulting [`File`] contains the actual
    /// filename string and hash data.
    ///
    /// # Arguments
    /// * `blob` - The blob heap for resolving hash data
    /// * `strings` - The string heap for resolving filenames
    ///
    /// # Returns
    /// Returns a reference-counted [`File`] with resolved data, or an error if:
    /// - String heap lookup fails for the filename
    /// - Blob heap lookup fails for the hash value
    /// - Hash data parsing encounters issues
    ///
    pub fn to_owned(&self, blob: &Blob, strings: &Strings) -> Result<FileRc> {
        Ok(Arc::new(File {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            name: strings.get(self.name as usize)?.to_string(),
            hash_value: AssemblyRefHash::new(blob.get(self.hash_value as usize)?)?,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply this file entry to update related metadata structures.
    ///
    /// File entries primarily serve as metadata descriptors for multi-file assemblies
    /// and don't require cross-table updates during the resolution phase. They are
    /// self-contained definitions that list assembly components.
    ///
    /// # Returns
    /// Always returns `Ok(())` since File entries don't modify other metadata tables.
    /// The file information is purely descriptive and used for assembly composition.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for FileRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */      4 +
            /* name */       sizes.str_bytes() +
            /* hash_value */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(FileRaw {
            rid,
            token: Token::new(0x2600_0000 + rid),
            offset: *offset,
            flags: read_le_at::<u32>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // hash_value
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::File, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FileRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FileRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x26000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.hash_value, 0x0303);
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
            0x01, 0x01, 0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // hash_value
        ];

        let sizes = Arc::new(TableInfo::new_test(&[(TableId::File, 1)], true, true, true));
        let table = MetadataTable::<FileRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FileRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x26000001);
            assert_eq!(row.flags, 0x01010101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.hash_value, 0x03030303);
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
