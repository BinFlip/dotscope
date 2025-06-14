use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{FieldPtr, FieldPtrRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// The `FieldPtr` table provides indirection for Field table access in `#-` streams.
/// Table ID = 0x03
///
/// This table is only present in assemblies using uncompressed metadata streams (`#-`).
/// It contains a single column with 1-based indices into the Field table, providing
/// an indirection layer that allows for more flexible field ordering and access patterns.
///
/// ## ECMA-335 Specification
/// From ECMA-335, Partition II, Section 22.16:
/// > The FieldPtr table is an auxiliary table used by the CLI loaders to implement
/// > a more complex field layout than the simple sequential layout provided by the Field table.
/// > Each row contains an index into the Field table.
///
/// ## Usage in `#-` Streams
/// When the metadata uses the `#-` (uncompressed) stream format instead of `#~` (compressed),
/// the `FieldPtr` table may be present to provide indirection. If present:
/// 1. Field references should resolve through `FieldPtr` first
/// 2. If `FieldPtr` is empty or missing, fall back to direct Field table indexing
/// 3. The indirection allows for non-sequential field ordering
pub struct FieldPtrRaw {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `FieldPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Field table
    pub field: u32,
}

impl FieldPtrRaw {
    /// Convert a `FieldPtrRaw` into a `FieldPtr` with resolved data
    ///
    /// # Errors
    /// This method currently doesn't fail, but returns Result for consistency
    /// with other table conversion methods.
    pub fn to_owned(&self) -> Result<FieldPtrRc> {
        Ok(Arc::new(FieldPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            field: self.field,
        }))
    }

    /// Apply a `FieldPtrRaw` entry to update related metadata structures.
    ///
    /// `FieldPtr` entries provide indirection for field access but don't directly
    /// modify other metadata structures during parsing. The indirection logic
    /// is handled at the table resolution level.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `FieldPtr` entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for FieldPtrRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* field */ sizes.table_index_bytes(TableId::Field)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(FieldPtrRaw {
            rid,
            token: Token::new(0x0300_0000 + rid),
            offset: *offset,
            field: read_le_at_dyn(data, offset, sizes.is_large(TableId::Field))?,
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
            0x01, 0x01, // field (index into Field table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x03000001);
            assert_eq!(row.field, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // field (index into Field table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<FieldPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x03000001);
            assert_eq!(row.field, 0x01010101);
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
