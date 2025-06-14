use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

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
