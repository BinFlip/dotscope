use crate::{
    metadata::{
        tables::{DocumentRaw, RowReadable, TableInfoRef},
        token::Token,
    },
    utils::read_le_at_dyn,
    Result,
};

impl RowReadable for DocumentRaw {
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self> {
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
}
