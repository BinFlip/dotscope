use crossbeam_skiplist::SkipMap;
use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        customattributes::CustomAttributeValueList,
        marshalling::MarshallingInfo,
        signatures::{parse_field_signature, SignatureField},
        streams::{Blob, RowDefinition, Strings, TableInfoRef},
        token::Token,
        typesystem::CilPrimitive,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `Field`
pub type FieldMap = SkipMap<Token, FieldRc>;
/// A vector that holds a list of `Field`
pub type FieldList = Arc<boxcar::Vec<FieldRc>>;
/// A reference to a field
pub type FieldRc = Arc<Field>;

#[allow(non_snake_case)]
/// All possible flags for `FieldAttributes`
pub mod FieldAttributes {
    /// These 3 bits contain one of the following values:
    pub const FIELD_ACCESS_MASK: u32 = 0x0007;
    /// Member not referenceable
    pub const COMPILER_CONTROLLED: u32 = 0x0000;
    /// Accessible only by the parent type
    pub const PRIVATE: u32 = 0x0001;
    /// Accessible by sub-types only in this Assembly
    pub const FAM_AND_ASSEM: u32 = 0x0002;
    /// Accessibly by anyone in the Assembly
    pub const ASSEMBLY: u32 = 0x0003;
    /// Accessible only by type and sub-types
    pub const FAMILY: u32 = 0x0004;
    /// Accessibly by sub-types anywhere, plus anyone in assembly
    pub const FAM_OR_ASSEM: u32 = 0x0005;
    /// Accessibly by anyone who has visibility to this scope field contract attributes
    pub const PUBLIC: u32 = 0x0006;
    /// Defined on type, else per instance
    pub const STATIC: u32 = 0x0010;
    /// Field can only be initialized, not written to after init
    pub const INIT_ONLY: u32 = 0x0020;
    /// Value is compile time constant
    pub const LITERAL: u32 = 0x0040;
    /// Reserved (to indicate this field should not be serialized when type is remoted)
    pub const NOT_SERIALIZED: u32 = 0x0080;
    /// Field is special
    pub const SPECIAL_NAME: u32 = 0x0200;
    //
    /// Implementation is forwarded through `PInvoke`
    pub const PINVOKE_IMPL: u32 = 0x2000;
    //
    /// CLI provides 'special' behavior, depending upon the name of the field
    pub const RTSPECIAL_NAME: u32 = 0x0400;
    /// Field has marshalling information
    pub const HAS_FIELD_MARSHAL: u32 = 0x1000;
    /// Field has default
    pub const HAS_DEFAULT: u32 = 0x8000;
    /// Field has RVA
    pub const HAS_FIELD_RVA: u32 = 0x0100;
}

/// The Field table defines fields for types in the `TypeDef` table. Similar to `FieldRaw` but
/// with resolved indexes and owned data
pub struct Field {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `FieldAttributes`, §II.23.1.5
    pub flags: u32,
    /// an index into the String heap
    pub name: String,
    /// an index into the Blob heap
    pub signature: SignatureField,
    /// A default value (flags.HasConstant)
    pub default: OnceLock<CilPrimitive>,
    /// RVA (flags.HasFieldRVA)
    pub rva: OnceLock<u32>,
    /// A 4-byte value, specifying the byte offset of the field within the class
    pub layout: OnceLock<u32>,
    /// `FieldMarshal` (flags.HasFieldMarshal)
    pub marshal: OnceLock<MarshallingInfo>,
    /// Custom attributes applied to this field
    pub custom_attributes: CustomAttributeValueList,
}

#[derive(Clone, Debug)]
/// The Field table defines fields for types in the `TypeDef` table. `TableId` = 0x04
pub struct FieldRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `FieldAttributes`, §II.23.1.5
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Blob heap
    pub signature: u32,
}

impl FieldRaw {
    /// Convert an `FieldRaw`, into a `Field` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'blob'        - The #Blob heap
    /// * 'strings'     - The #String heap
    ///
    /// # Errors
    /// Returns an error if string or blob lookup fails, or if signature parsing fails
    pub fn to_owned(&self, blob: &Blob, strings: &Strings) -> Result<FieldRc> {
        Ok(Arc::new(Field {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            name: strings.get(self.name as usize)?.to_string(),
            signature: parse_field_signature(blob.get(self.signature as usize)?)?,
            default: OnceLock::new(),
            rva: OnceLock::new(),
            layout: OnceLock::new(),
            marshal: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }

    /// Apply a `FieldRaw` entry to update related metadata structures.
    ///
    /// Field entries define the fields of types. They are associated with their parent types
    /// but don't themselves modify other metadata during the dual variant resolution phase.
    /// Field-specific metadata (defaults, RVA, layout, marshalling) is resolved separately.
    ///
    /// # Errors
    /// Always returns `Ok(())` as Field entries don't modify other tables directly.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for FieldRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2 +
            /* name */      sizes.str_bytes() +
            /* signature */ sizes.blob_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(FieldRaw {
            rid,
            token: Token::new(0x0400_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            signature: read_le_at_dyn(data, offset, sizes.is_large_blob())?,
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
            0x01, 0x01, // flags
            0x02, 0x02, // name
            0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<FieldRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x04000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x0202);
            assert_eq!(row.signature, 0x0303);
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
            0x01, 0x01, // flags
            0x02, 0x02, 0x02, 0x02, // name
            0x03, 0x03, 0x03, 0x03, // signature
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<FieldRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: FieldRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x04000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.name, 0x02020202);
            assert_eq!(row.signature, 0x03030303);
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
