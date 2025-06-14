use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `DeclSecurity`
pub type DeclSecurityMap = SkipMap<Token, DeclSecurityRc>;
/// A vector that holds a list of `DeclSecurity`
pub type DeclSecurityList = Arc<boxcar::Vec<DeclSecurityRc>>;
/// A reference to a `DeclSecurity`
pub type DeclSecurityRc = Arc<DeclSecurity>;
