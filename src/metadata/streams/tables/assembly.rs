use crossbeam_skiplist::SkipMap;
use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        customattributes::CustomAttributeValueList,
        security::Security,
        streams::{Blob, RowDefinition, Strings, TableInfoRef},
        token::Token,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `Assembly`
pub type AssemblyMap = SkipMap<Token, AssemblyRc>;
/// A vector that holds a list of `Assembly`
pub type AssemblyList = Arc<boxcar::Vec<AssemblyRc>>;
/// A reference to a `Assembly`
pub type AssemblyRc = Arc<Assembly>;

#[allow(non_snake_case)]
/// All possible flags for `AssemblyFlags`
pub mod AssemblyFlags {
    /// The assembly reference holds the full (unhashed) public key
    pub const PUBLIC_KEY: u32 = 0x0001;
    /// The implementation of this assembly used at runtime is not expected to match the version seen at compile time
    pub const RETARGETABLE: u32 = 0x0100;
    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    pub const DISABLE_JIT_COMPILE_OPTIMIZER: u32 = 0x4000;
    /// Reserved (a conforming implementation of the CLI may ignore this setting on read)
    pub const ENABLE_JIT_COMPILE_TRACKING: u32 = 0x8000;
}

#[allow(non_snake_case)]
/// All possible values for `AssemblyHashAlgorithm`
// ToDo: It seems that MS has extended this in future versions, without updating ECMA-335
pub mod AssemblyHashAlgorithm {
    /// No hash algorithm specified
    pub const NONE: u32 = 0x0000;
    /// MD5 hash algorithm
    pub const MD5: u32 = 0x8003;
    /// SHA1 hash algorithm
    pub const SHA1: u32 = 0x8004;
}

/// Represents a .NET CIL binary (assembly), similar to `AssemblyRaw` but with resolved indexes and owned data
pub struct Assembly {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant of type `AssemblyHashAlgorithm`, §II.23.1.1
    pub hash_alg_id: u32,
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
    pub public_key: Option<Vec<u8>>,
    /// an index into the String heap
    pub name: String,
    /// an index into the String heap
    pub culture: Option<String>,
    /// The .NET CIL Security Information (if present)
    pub security: OnceLock<Security>,
    /// Custom attributes attached to this assembly
    pub custom_attributes: CustomAttributeValueList,
}

#[derive(Clone, Debug)]
/// Represents a .NET CIL binary (assembly), `TableId` = 0x20
pub struct AssemblyRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant of type `AssemblyHashAlgorithm`, §II.23.1.1
    pub hash_alg_id: u32,
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
    pub public_key: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the String heap
    pub culture: u32,
}

impl AssemblyRaw {
    /// Convert an `AssemblyRaw`, into a `Assembly` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    /// * 'blob'    - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if the string or blob data cannot be retrieved from the heaps
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

    /// Apply an `AssemblyRaw` entry to update related metadata structures.
    ///
    /// Assembly entries are self-contained and represent the current assembly metadata.
    /// They don't require cross-table updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as Assembly entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for AssemblyRaw {
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

    fn read_row(
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
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

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
