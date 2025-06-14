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
