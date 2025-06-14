use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{MethodPtr, MethodPtrRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `MethodPtr` table provides indirection for `MethodDef` table access in `#-` streams.
/// Table ID = 0x05
///
/// This table is only present in assemblies using uncompressed metadata streams (`#-`).
/// It contains a single column with 1-based indices into the `MethodDef` table, providing
/// an indirection layer that allows for more flexible method ordering and access patterns.
///
/// ## ECMA-335 Specification
/// From ECMA-335, Partition II, Section 22.25:
/// > The MethodPtr table is an auxiliary table used by the CLI loaders to implement
/// > a more complex method layout than the simple sequential layout provided by the `MethodDef` table.
/// > Each row contains an index into the `MethodDef` table.
///
/// ## Usage in `#-` Streams
/// When the metadata uses the `#-` (uncompressed) stream format instead of `#~` (compressed),
/// the `MethodPtr` table may be present to provide indirection. If present:
/// 1. Method references should resolve through `MethodPtr` first
/// 2. If `MethodPtr` is empty or missing, fall back to direct `MethodDef` table indexing
/// 3. The indirection allows for non-sequential method ordering
pub struct MethodPtrRaw {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `MethodPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the `MethodDef` table
    pub method: u32,
}

impl MethodPtrRaw {
    /// Convert a `MethodPtrRaw` into a `MethodPtr` with resolved data
    ///
    /// # Errors
    /// This method currently doesn't fail, but returns Result for consistency
    /// with other table conversion methods.
    pub fn to_owned(&self) -> Result<MethodPtrRc> {
        Ok(Arc::new(MethodPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            method: self.method,
        }))
    }

    /// Apply a `MethodPtrRaw` entry to update related metadata structures.
    ///
    /// `MethodPtr` entries provide indirection for method access but don't directly
    /// modify other metadata structures during parsing. The indirection logic
    /// is handled at the table resolution level.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `MethodPtr` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for MethodPtrRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* method */ sizes.table_index_bytes(TableId::MethodDef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodPtrRaw {
            rid,
            token: Token::new(0x0500_0000 + rid),
            offset: *offset,
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
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
            0x01, 0x01, // method (index into MethodDef table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x05000001);
            assert_eq!(row.method, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // method (index into MethodDef table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::MethodDef, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x05000001);
            assert_eq!(row.method, 0x01010101);
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
