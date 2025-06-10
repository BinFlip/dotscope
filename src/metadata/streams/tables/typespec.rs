use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::{parse_type_spec_signature, SignatureTypeSpec},
        streams::{Blob, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `TypeSpec`
pub type TypeSpecMap = SkipMap<Token, TypeSpecRc>;
/// A vector that holds a list of `TypeSpec`
pub type TypeSpecList = Arc<boxcar::Vec<TypeSpecRc>>;
/// A reference to a `TypeSpec`
pub type TypeSpecRc = Arc<TypeSpec>;

/// The `TypeSpec` table defines type specifications through signatures. Similar to `TypeSpecRaw` but
/// with resolved indexes and owned data
pub struct TypeSpec {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parsed type specification signature
    pub signature: SignatureTypeSpec,
}

impl TypeSpec {
    /// Apply a `TypeSpec` entry to update related metadata structures.
    ///
    /// `TypeSpec` entries define type specifications through signatures. They are primarily
    /// type definitions and don't require cross-table updates during the dual variant
    /// resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `TypeSpec` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// `TypeSpec`, ID = 0x1B
pub struct TypeSpecRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the Blob heap
    pub signature: u32,
}

impl TypeSpecRaw {
    /// Convert a `TypeSpecRaw` into a `TypeSpec` which has indexes resolved and owns the referenced data.
    ///
    /// ## Arguments
    /// * 'blob' - The #Blob heap
    ///
    /// # Errors
    /// Returns an error if the signature cannot be parsed from the blob heap.
    pub fn to_owned(&self, blob: &Blob) -> Result<TypeSpecRc> {
        let signature_data = blob.get(self.signature as usize)?;
        let signature = parse_type_spec_signature(signature_data)?;

        Ok(Arc::new(TypeSpec {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            signature,
        }))
    }

    /// Apply a `TypeSpecRaw` entry to update related metadata structures.
    ///
    /// `TypeSpec` entries define type specifications through signatures. They are primarily
    /// type definitions and don't require cross-table updates during the dual variant
    /// resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `TypeSpec` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for TypeSpecRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(TypeSpecRaw {
            rid,
            token: Token::new(0x1B00_0000 + rid),
            offset: *offset,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
            assert_eq!(row.signature, 0x0101);
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
            0x01, 0x01, 0x01, 0x01, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::TypeSpec, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<TypeSpecRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: TypeSpecRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x1B000001);
            assert_eq!(row.signature, 0x01010101);
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
