//! Property table implementation
//!
//! The Property table defines properties for types in .NET metadata. Each property entry includes
//! the property name, flags, and signature. Properties provide a way to define attributes that
//! can be accessed through getter and setter methods.
//!
//! The table contains both raw and owned variants:
//! - `PropertyRaw`: Direct representation of table data with heap indexes
//! - `Property`: Resolved variant with owned strings and parsed signatures
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `Property`
pub type PropertyMap = SkipMap<Token, PropertyRc>;
/// A vector that holds a list of `Property`
pub type PropertyList = Arc<boxcar::Vec<PropertyRc>>;
/// A reference to a `Property`
pub type PropertyRc = Arc<Property>;

#[allow(non_snake_case)]
/// All possible flags for `PropertyAttributes`
pub mod PropertyAttributes {
    /// Property is special
    pub const SPECIAL_NAME: u32 = 0x0200;
    /// Runtime (metadata internal APIs) should check name encoding
    pub const RT_SPECIAL_NAME: u32 = 0x0400;
    /// Property has default
    pub const HAS_DEFAULT: u32 = 0x1000;
}
