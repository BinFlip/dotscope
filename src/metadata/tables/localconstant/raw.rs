//! Raw LocalConstant table representation for Portable PDB format
//!
//! This module provides the [`LocalConstantRaw`] struct that represents
//! the binary format of LocalConstant table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        signatures::{parse_field_signature, SignatureField, TypeSignature},
        streams::{Blob, Strings},
        tables::{types::*, LocalConstant, LocalConstantRc},
        token::Token,
    },
    Result,
};
use std::sync::Arc;

/// Raw binary representation of a LocalConstant table entry
///
/// This structure matches the exact binary layout of LocalConstant table
/// entries in the metadata tables stream. Both Name and Signature fields contain
/// unresolved indices into their respective heaps that must be resolved during
/// conversion to the owned [`LocalConstant`] variant.
///
/// # Binary Format
///
/// Each LocalConstant table entry consists of:
/// - Name: Index into #Strings heap for the constant name
/// - Signature: Index into #Blob heap for the constant signature
#[derive(Debug, Clone)]
pub struct LocalConstantRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this LocalConstant entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Index into #Strings heap for constant name
    ///
    /// Points to the constant's name string in the metadata #Strings heap.
    /// This index must be resolved to get the actual constant name string.
    /// May be 0 for anonymous or compiler-generated constants.
    pub name: u32,

    /// Index into #Blob heap for constant signature
    ///
    /// Points to the constant's signature blob in the metadata #Blob heap.
    /// The signature describes the constant's type and value information.
    /// This index must be resolved to get the actual signature data.
    pub signature: u32,
}

impl LocalConstantRaw {
    /// Converts this raw LocalConstant entry to an owned [`LocalConstant`] instance
    ///
    /// This method resolves the raw LocalConstant entry to create a complete LocalConstant
    /// object by resolving the name string from the #Strings heap and signature data
    /// from the #Blob heap.
    ///
    /// # Parameters
    /// - `strings`: Reference to the #Strings heap for resolving the name index
    /// - `blobs`: Reference to the #Blob heap for resolving the signature index
    ///
    /// # Returns
    /// Returns `Ok(LocalConstantRc)` with the resolved constant data, or an error if
    /// the name or signature indices are invalid or point to malformed data.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use dotscope::metadata::tables::localconstant::LocalConstantRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example() -> dotscope::Result<()> {
    /// let constant_raw = LocalConstantRaw {
    ///     rid: 1,
    ///     token: Token::new(0x34000001),
    ///     offset: 0,
    ///     name: 42,           // Index into #Strings heap
    ///     signature: 100,     // Index into #Blob heap
    /// };
    ///
    /// let constant = constant_raw.to_owned(strings, blobs)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_owned(&self, strings: &Strings, blobs: &Blob) -> Result<LocalConstantRc> {
        let name = if self.name == 0 {
            String::new()
        } else {
            strings.get(self.name as usize)?.to_string()
        };

        let signature = if self.signature == 0 {
            SignatureField {
                modifiers: Vec::new(),
                base: TypeSignature::Void,
            }
        } else {
            let signature_blob = blobs.get(self.signature as usize)?;
            parse_field_signature(signature_blob)?
        };

        let constant = LocalConstant {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            name,
            signature,
        };

        Ok(Arc::new(constant))
    }
}

impl<'a> RowDefinition<'a> for LocalConstantRaw {
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(LocalConstantRaw {
            rid,
            token: Token::new(0x3400_0000 + rid),
            offset: *offset,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            sizes.str_bytes() +   // name (strings heap index)
            sizes.blob_bytes()    // signature (blob heap index)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x00, // name (2 bytes, short strings heap) - 0x0001
            0x02, 0x00, // signature (2 bytes, short blob heap) - 0x0002
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalConstant, 1)],
            false, // large tables
            false, // large strings
            false, // large blob
        ));
        let table = MetadataTable::<LocalConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x34000001);
            assert_eq!(row.name, 0x0001);
            assert_eq!(row.signature, 0x0002);
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
            0x01, 0x00, 0x00, 0x00, // name (4 bytes, large strings heap) - 0x00000001
            0x02, 0x00, // signature (2 bytes, normal blob heap) - 0x0002
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalConstant, 1)],
            true,  // large strings
            false, // large blob
            false, // large GUID
        ));
        let table = MetadataTable::<LocalConstantRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalConstantRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x34000001);
            assert_eq!(row.name, 0x00000001);
            assert_eq!(row.signature, 0x0002);
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
