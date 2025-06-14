use crossbeam_skiplist::SkipMap;
use std::sync::{Arc, OnceLock};

use crate::metadata::{
    customattributes::CustomAttributeValueList, method::MethodRef, signatures::SignatureProperty,
    token::Token, typesystem::CilPrimitive,
};

/// A map that holds the mapping of Token to parsed `Property`
pub type PropertyMap = SkipMap<Token, Arc<Property>>;
/// A vector that holds a list of `Property`
pub type PropertyList = Arc<boxcar::Vec<Arc<Property>>>;

/// The `Property` table defines properties for types. Each entry includes the property name, flags, and signature. Similar
/// to `PropertyRaw` but with resolved indexes and owned data.
pub struct Property {
    /// Token
    pub token: Token,
    /// a 2-byte bitmask of type `PropertyAttributes`, §II.23.1.14
    pub flags: u32,
    /// The name of this property
    pub name: String,
    /// Signature (type definition) of this property
    pub signature: SignatureProperty,
    /// `flags.HAS_DEFAULT` -> This is the default value of this property
    pub default: OnceLock<CilPrimitive>,
    /// The `Method` that sets this property
    pub fn_setter: OnceLock<MethodRef>,
    /// The `Method` that retrieves this property
    pub fn_getter: OnceLock<MethodRef>,
    /// 'Other' associated method with this property
    pub fn_other: OnceLock<MethodRef>,
    /// Custom attributes attached to this property
    pub custom_attributes: CustomAttributeValueList,
}
