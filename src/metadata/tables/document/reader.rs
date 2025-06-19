use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{DocumentRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    Result,
};

impl<'a> RowReadable<'a> for DocumentRaw {
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(DocumentRaw {
            rid,
            token: Token::new(0x3000_0000 + rid),
            offset: *offset,
            name: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            hash_algorithm: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
            hash: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
            language: read_le_at_dyn(data, offset, sizes.is_large_guid())?,
        })
    }

    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.blob_bytes() +  // name
            sizes.guid_bytes() +  // hash_algorithm
            sizes.blob_bytes() +  // hash
            sizes.guid_bytes(), // language
        )
    }
}
