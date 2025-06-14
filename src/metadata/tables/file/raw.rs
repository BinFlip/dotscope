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

#[derive(Clone, Debug)]
/// The File table lists the files that make up the current assembly. `TableId` = 0x26
pub struct FileRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte bitmask of type `FileAttributes`, §II.23.1.6
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Blob heap
    pub hash_value: u32,
}

impl FileRaw {
    /// Convert an `FileRaw`, into a `File` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'    - The #Blob heap
    /// * 'strings' - All parsed `Param` entries
    ///
    /// # Errors
    /// Returns an error if string or blob lookup fails
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

    /// Apply a `FileRaw` entry to update related metadata structures.
    ///
    /// File entries define files that are part of this assembly. They are primarily metadata
    /// descriptors and don't require cross-table updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as File entries don't modify other tables.
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
