use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `GenericParam`
pub type GenericParamMap = SkipMap<Token, GenericParamRc>;
/// A vector that holds a list of `GenericParam`
pub type GenericParamList = Arc<boxcar::Vec<GenericParamRc>>;
/// A reference to a `GenericParam`
pub type GenericParamRc = Arc<GenericParam>;

#[allow(non_snake_case)]
/// All possible flags for `GenericParamAttributes`
pub mod GenericParamAttributes {
    /// The generic parameter is covariant
    pub const VARIANCE_MASK: u32 = 0x0003;
    /// The generic parameter is covariant
    pub const COVARIANT: u32 = 0x0001;
    /// The generic parameter is contravariant
    pub const CONTRAVARIANT: u32 = 0x0002;
    /// The generic parameter has a special constraint
    pub const SPECIAL_CONSTRAINT_MASK: u32 = 0x001C;
    /// The generic parameter has a reference type constraint
    pub const REFERENCE_TYPE_CONSTRAINT: u32 = 0x0004;
    /// The generic parameter has a value type constraint
    pub const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT: u32 = 0x0008;
    /// The generic parameter has a constructor constraint
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: u32 = 0x0010;
}
