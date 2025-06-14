//! Owned `MemberRef` structures and implementations

use std::sync::Arc;

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    tables::{MemberRefSignature, ParamRc},
    token::Token,
    typesystem::CilTypeReference,
};

/// The `MemberRef` table references members (fields or methods) of types defined in other modules. Similar to `MemberRefRaw` but
/// with resolved indexes and owned data
pub struct MemberRef {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parent type/module this reference belongs to
    pub declaredby: CilTypeReference,
    /// Member name
    pub name: String,
    /// The signature (could be method signature or field signature)
    pub signature: MemberRefSignature,
    /// Parameter information for method signatures (empty for field signatures)
    pub params: Arc<boxcar::Vec<ParamRc>>,
    /// Custom attributes applied to this member reference
    pub custom_attributes: CustomAttributeValueList,
}

impl MemberRef {
    /// Check if this member reference is a constructor (.ctor or .cctor)
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        (self.name.starts_with(".ctor") || self.name.starts_with(".cctor"))
            && matches!(self.signature, MemberRefSignature::Method(_))
    }
}
