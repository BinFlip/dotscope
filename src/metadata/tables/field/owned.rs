use std::sync::OnceLock;

use crate::metadata::{
    customattributes::CustomAttributeValueList, marshalling::MarshallingInfo,
    signatures::SignatureField, token::Token, typesystem::CilPrimitive,
};

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
