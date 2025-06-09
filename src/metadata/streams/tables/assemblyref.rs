use crossbeam_skiplist::SkipMap;
use md5::Md5;
use sha1::{Digest, Sha1};
use std::{
    fmt::Write,
    sync::{atomic::AtomicU32, Arc},
};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        identity::Identity,
        imports::{ImportContainer, ImportRc, Imports},
        streams::{
            tables::assembly::AssemblyHashAlgorithm, AssemblyFlags, Blob, RowDefinition, Strings,
            TableInfoRef,
        },
        token::Token,
    },
    Result,
};

/// Helper function to convert bytes to lowercase hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex_string, "{:02x}", byte).unwrap();
    }
    hex_string
}

/// The hash of a reference, is a variant of `AssemblyHashAlgorithm`
pub struct AssemblyRefHash {
    data: Vec<u8>,
}

impl AssemblyRefHash {
    /// Create a new `AssemblyRefHash` from the input data
    ///
    /// ## Arguments
    /// * 'data' - The data to parse from
    ///
    /// # Errors
    /// Returns an error if the input data is empty
    pub fn new(data: &[u8]) -> Result<AssemblyRefHash> {
        if data.is_empty() {
            return Err(malformed_error!(
                "AssemblyRefHash entries are not allowed to be empty"
            ));
        }

        Ok(AssemblyRefHash {
            data: data.to_vec(),
        })
    }

    /// Returns the hash data formatted as an MD5 hex string
    ///
    /// This method assumes the stored hash data is an MD5 hash (16 bytes)
    /// and formats it as a lowercase hexadecimal string.
    ///
    /// # Errors
    /// Returns an error if the data length is not 16 bytes (MD5 hash size)
    ///
    /// # Examples
    /// ```rust,no_run
    /// # use dotscope::metadata::streams::AssemblyRefHash;
    /// let hash_data = [0u8; 16]; // 16 bytes for MD5
    /// let hash = AssemblyRefHash::new(&hash_data)?;
    /// let md5_string = hash.as_md5()?;
    /// assert_eq!(md5_string.len(), 32); // 32 hex characters
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn as_md5(&self) -> Result<String> {
        if self.data.len() != 16 {
            return Err(malformed_error!(
                "Hash data length {} is not valid for MD5 (expected 16 bytes)",
                self.data.len()
            ));
        }

        Ok(bytes_to_hex(&self.data))
    }

    /// Returns the hash data formatted as a SHA1 hex string
    ///
    /// This method assumes the stored hash data is a SHA1 hash (20 bytes)
    /// and formats it as a lowercase hexadecimal string.
    ///
    /// # Errors
    /// Returns an error if the data length is not 20 bytes (SHA1 hash size)
    ///
    /// # Examples
    /// ```rust,no_run
    /// # use dotscope::metadata::streams::AssemblyRefHash;
    /// let hash_data = [0u8; 20]; // 20 bytes for SHA1
    /// let hash = AssemblyRefHash::new(&hash_data)?;
    /// let sha1_string = hash.as_sha1()?;
    /// assert_eq!(sha1_string.len(), 40); // 40 hex characters
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn as_sha1(&self) -> Result<String> {
        if self.data.len() != 20 {
            return Err(malformed_error!(
                "Hash data length {} is not valid for SHA1 (expected 20 bytes)",
                self.data.len()
            ));
        }

        Ok(bytes_to_hex(&self.data))
    }

    /// Verifies that the provided file matches this hash using the specified algorithm
    ///
    /// This method calculates the hash of the entire file content using the specified
    /// algorithm and compares it to the stored hash data.
    ///
    /// ## Arguments
    /// * `file` - The file to verify against this hash
    /// * `algorithm` - The hash algorithm to use (`AssemblyHashAlgorithm::MD5` or `AssemblyHashAlgorithm::SHA1`)
    ///
    /// # Errors
    /// Returns an error if:
    /// - The hash data length doesn't match the expected size for the algorithm
    /// - The calculated hash doesn't match the stored hash
    ///
    /// # Examples
    /// ```rust,no_run
    /// # use dotscope::{File, metadata::streams::{AssemblyRefHash, AssemblyHashAlgorithm}};
    /// # use std::path::Path;
    /// let file = File::from_file(Path::new("assembly.dll"))?;
    /// let hash_data = [0u8; 20]; // SHA1 hash from metadata
    /// let hash = AssemblyRefHash::new(&hash_data)?;
    ///
    /// // Verify the file matches the stored hash
    /// let is_valid = hash.verify_file(&file, AssemblyHashAlgorithm::SHA1)?;
    /// if is_valid {
    ///     println!("File integrity verified!");
    /// } else {
    ///     println!("File hash mismatch!");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn verify_file(&self, file: &crate::File, algorithm: u32) -> Result<bool> {
        let file_data = file.data();

        match algorithm {
            AssemblyHashAlgorithm::MD5 => {
                if self.data.len() != 16 {
                    return Err(malformed_error!(
                        "Hash data length {} is not valid for MD5 verification (expected 16 bytes)",
                        self.data.len()
                    ));
                }

                let mut hasher = Md5::new();
                hasher.update(file_data);
                let calculated_hash = hasher.finalize();

                Ok(self.data.as_slice() == calculated_hash.as_slice())
            }
            AssemblyHashAlgorithm::SHA1 => {
                if self.data.len() != 20 {
                    return Err(malformed_error!(
                        "Hash data length {} is not valid for SHA1 verification (expected 20 bytes)",
                        self.data.len()
                    ));
                }

                let mut hasher = Sha1::new();
                hasher.update(file_data);
                let calculated_hash = hasher.finalize();

                Ok(self.data.as_slice() == calculated_hash.as_slice())
            }
            _ => Err(malformed_error!(
                "Unsupported hash algorithm: {}. Only MD5 and SHA1 are supported.",
                algorithm
            )),
        }
    }
}

/// A map that holds the mapping of Token to parsed `AssemblyRef`
pub type AssemblyRefMap = SkipMap<Token, AssemblyRefRc>;
/// A vector that holds a list of `AssemblyRef`
pub type AssemblyRefList = Arc<boxcar::Vec<AssemblyRefRc>>;
/// A reference to a `AssemblyRef`
pub type AssemblyRefRc = Arc<AssemblyRef>;

impl ImportContainer for AssemblyRefRc {
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_assembly_ref(self)
    }
}

/// The `AssemblyRef` table contains references to external assemblies,
/// similar to `AssemblyRefRaw` but with resolved indexes and fully owned data.
pub struct AssemblyRef {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The name of the Assembly
    pub name: String,
    /// Culture string
    pub culture: Option<String>,
    /// a 2-byte value specifying the Major version number
    pub major_version: u32,
    /// a 2-byte value specifying the Minor version number
    pub minor_version: u32,
    /// a 2-byte value specifying the Build number
    pub build_number: u32,
    /// a 2-byte value specifying the Revision number
    pub revision_number: u32,
    /// a 4-byte bitmask of type `AssemblyFlags`, §II.23.1.2
    pub flags: u32,
    /// The identifier of the referenced assembly, either a pub-key or token
    pub identifier: Option<Identity>,
    /// The hash of the referenced assembly (ECMA-335 specifies SHA-1 or MD5, but MS seems to have extended...)
    pub hash: Option<AssemblyRefHash>,
    // --- from AssemblyRefOs ---
    /// a 4-byte constant
    pub os_platform_id: AtomicU32,
    /// a 4-byte constant
    pub os_major_version: AtomicU32,
    /// a 4-byte constant
    pub os_minor_version: AtomicU32,
    // --- from AssemblyRefProcessor ---
    /// a 4-byte constant
    pub processor: AtomicU32,
}

#[derive(Clone, Debug)]
/// The `AssemblyRef` table contains references to external assemblies, `TableId` = 0x23
pub struct AssemblyRefRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value specifying the Major version number
    pub major_version: u32,
    /// a 2-byte value specifying the Minor version number
    pub minor_version: u32,
    /// a 2-byte value specifying the Build number
    pub build_number: u32,
    /// a 2-byte value specifying the Revision number
    pub revision_number: u32,
    /// a 4-byte bitmask of type `AssemblyFlags`, §II.23.1.2
    pub flags: u32,
    /// an index into the Blob heap
    pub public_key_or_token: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the String heap
    pub culture: u32,
    /// an index into the Blob heap
    pub hash_value: u32,
}

impl AssemblyRefRaw {
    /// Convert an `AssemblyRefRaw`, into a `AssemblyRef` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if the string or blob data cannot be retrieved from the heaps
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
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

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
