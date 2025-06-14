use crate::metadata::{
    customattributes::CustomAttributeValueList,
    signatures::SignatureMethodSpec,
    token::Token,
    typesystem::{CilTypeRefList, CilTypeReference},
};

/// The `MethodSpec` table represents instantiations of generic methods. Similar to `MethodSpecRaw` but
/// with resolved indexes and owned data
pub struct MethodSpec {
    /// `RowID`
    pub rid: u32,
    /// `Token`
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `MethodDefOrRef` coding index
    pub method: CilTypeReference,
    /// an index into the Blob heap
    pub instantiation: SignatureMethodSpec,
    /// Custom attributes applied to this `MethodSpec`
    pub custom_attributes: CustomAttributeValueList,
    /// Resolved generic arguments for this method specification
    pub generic_args: CilTypeRefList,
}
