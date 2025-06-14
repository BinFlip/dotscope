use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `FieldRVA`
pub type FieldRVAMap = SkipMap<Token, FieldRVARc>;
/// A vector that holds a list of `FieldRVA`
pub type FieldRVAList = Arc<boxcar::Vec<FieldRVARc>>;
/// A reference to a `FieldRVA`
pub type FieldRVARc = Arc<FieldRva>;
