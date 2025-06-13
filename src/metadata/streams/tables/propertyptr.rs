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

/// A map that holds the mapping of Token to parsed `PropertyPtr`
pub type PropertyPtrMap = SkipMap<Token, PropertyPtrRc>;
/// A vector that holds a list of `PropertyPtr`
pub type PropertyPtrList = Arc<boxcar::Vec<PropertyPtrRc>>;
/// A reference to a `PropertyPtr`
pub type PropertyPtrRc = Arc<PropertyPtr>;

/// The PropertyPtr table provides an indirection layer for accessing Property table entries
/// in uncompressed metadata streams (`#-`). This table is only present in assemblies
/// that use the `#-` stream format instead of the standard `#~` compressed format.
///
/// Each row contains a single field: a 1-based index into the Property table. When PropertyPtr
/// is present, property references should be resolved through this indirection table rather
/// than directly indexing into the Property table.
///
/// Similar to `PropertyPtrRaw` but with resolved indexes and owned data.
pub struct PropertyPtr {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this PropertyPtr entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Property table
    pub property: u32,
}

impl PropertyPtr {
    /// Create a new PropertyPtr instance
    pub fn new(rid: u32, offset: usize, property: u32) -> Self {
        Self {
            rid,
            token: Token::new(0x1600_0000 + rid),
            offset,
            property,
        }
    }
}

#[derive(Clone, Debug)]
/// The PropertyPtr table provides indirection for Property table access in `#-` streams.
/// Table ID = 0x16
///
/// This table is only present in assemblies using uncompressed metadata streams (`#-`).
/// It contains a single column with 1-based indices into the Property table, providing
/// an indirection layer that allows for more flexible property ordering and access patterns.
///
/// ## ECMA-335 Specification
/// From ECMA-335, Partition II, Section 22.35:
/// > The PropertyPtr table is an auxiliary table used by the CLI loaders to implement
/// > a more complex property layout than the simple sequential layout provided by the Property table.
/// > Each row contains an index into the Property table.
///
/// ## Usage in `#-` Streams
/// When the metadata uses the `#-` (uncompressed) stream format instead of `#~` (compressed),
/// the PropertyPtr table may be present to provide indirection. If present:
/// 1. Property references should resolve through PropertyPtr first
/// 2. If PropertyPtr is empty or missing, fall back to direct Property table indexing
/// 3. The indirection allows for non-sequential property ordering
pub struct PropertyPtrRaw {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this PropertyPtr entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Property table
    pub property: u32,
}

impl PropertyPtrRaw {
    /// Convert a `PropertyPtrRaw` into a `PropertyPtr` with resolved data
    ///
    /// # Errors
    /// This method currently doesn't fail, but returns Result for consistency
    /// with other table conversion methods.
    pub fn to_owned(&self) -> Result<PropertyPtrRc> {
        Ok(Arc::new(PropertyPtr {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            property: self.property,
        }))
    }

    /// Apply a `PropertyPtrRaw` entry to update related metadata structures.
    ///
    /// PropertyPtr entries provide indirection for property access but don't directly
    /// modify other metadata structures during parsing. The indirection logic
    /// is handled at the table resolution level.
    ///
    /// # Errors
    /// Always returns `Ok(())` as PropertyPtr entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for PropertyPtrRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* property */ sizes.table_index_bytes(TableId::Property)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(PropertyPtrRaw {
            rid,
            token: Token::new(0x1600_0000 + rid),
            offset: *offset,
            property: read_le_at_dyn(data, offset, sizes.is_large(TableId::Property))?,
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
            0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // property (index into Property table)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Property, u16::MAX as u32 + 3)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<PropertyPtrRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: PropertyPtrRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x16000001);
            assert_eq!(row.property, 0x01010101);
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
