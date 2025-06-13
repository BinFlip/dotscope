use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        streams::{RowDefinition, TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `ParamPtr`
pub type ParamPtrMap = SkipMap<Token, ParamPtrRc>;
/// A vector that holds a list of `ParamPtr`
pub type ParamPtrList = Arc<boxcar::Vec<ParamPtrRc>>;
/// A reference to a `ParamPtr`
pub type ParamPtrRc = Arc<ParamPtr>;

/// The ParamPtr table provides an indirection layer for accessing Param table entries
/// in uncompressed metadata streams (`#-`). This table is only present in assemblies
/// that use the `#-` stream format instead of the standard `#~` compressed format.
///
/// Each row contains a single field: a 1-based index into the Param table. When ParamPtr
/// is present, parameter references should be resolved through this indirection table rather
/// than directly indexing into the Param table.
///
/// Similar to `ParamPtrRaw` but with resolved indexes and owned data.
pub struct ParamPtr {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this ParamPtr entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Param table
    pub param: u32,
}

impl ParamPtr {
    /// Create a new ParamPtr instance
    pub fn new(rid: u32, offset: usize, param: u32) -> Self {
        Self {
            rid,
            token: Token::new(0x0700_0000 + rid),
            offset,
            param,
        }
    }
}

#[derive(Clone, Debug)]
/// The ParamPtr table provides indirection for Param table access in `#-` streams.
/// Table ID = 0x07
///
/// This table is only present in assemblies using uncompressed metadata streams (`#-`).
/// It contains a single column with 1-based indices into the Param table, providing
/// an indirection layer that allows for more flexible parameter ordering and access patterns.
///
/// ## ECMA-335 Specification
/// From ECMA-335, Partition II, Section 22.33:
/// > The ParamPtr table is an auxiliary table used by the CLI loaders to implement
/// > a more complex parameter layout than the simple sequential layout provided by the Param table.
/// > Each row contains an index into the Param table.
///
/// ## Usage in `#-` Streams
/// When the metadata uses the `#-` (uncompressed) stream format instead of `#~` (compressed),
/// the ParamPtr table may be present to provide indirection. If present:
/// 1. Parameter references should resolve through ParamPtr first
/// 2. If ParamPtr is empty or missing, fall back to direct Param table indexing
/// 3. The indirection allows for non-sequential parameter ordering
pub struct ParamPtrRaw {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this ParamPtr entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Param table
    pub param: u32,
}

impl ParamPtrRaw {
    /// Convert a `ParamPtrRaw` into a `ParamPtr` with resolved data
    ///
    /// # Errors
    /// This method currently doesn't fail, but returns Result for consistency
    /// with other table conversion methods.
    pub fn to_owned(&self) -> Result<ParamPtrRc> {
        Ok(Arc::new(ParamPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            param: self.param,
        }))
    }

    /// Apply a `ParamPtrRaw` entry to update related metadata structures.
    ///
    /// ParamPtr entries provide indirection for parameter access but don't directly
    /// modify other metadata structures during parsing. The indirection logic
    /// is handled at the table resolution level.
    ///
    /// # Errors
    /// Always returns `Ok(())` as ParamPtr entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ParamPtrRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* param */ sizes.table_index_bytes(TableId::Param)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ParamPtrRaw {
            rid,
            token: Token::new(0x0700_0000 + rid),
            offset: *offset,
            param: read_le_at_dyn(data, offset, sizes.is_large(TableId::Param))?,
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
            0x01, 0x01, // param (index into Param table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x07000001);
            assert_eq!(row.param, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // param (index into Param table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x07000001);
            assert_eq!(row.param, 0x01010101);
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
