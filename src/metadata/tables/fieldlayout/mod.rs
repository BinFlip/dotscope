use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `FieldLayout`
pub type FieldLayoutMap = SkipMap<Token, FieldLayoutRc>;
/// A vector that holds a list of `FieldLayout`
pub type FieldLayoutList = Arc<boxcar::Vec<FieldLayoutRc>>;
/// A reference to a `FieldLayout`
pub type FieldLayoutRc = Arc<FieldLayout>;
