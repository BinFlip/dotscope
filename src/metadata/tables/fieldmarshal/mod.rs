use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `FieldMarshal`
pub type FieldMarshalMap = SkipMap<Token, FieldMarshalRc>;
/// A vector that holds a list of `FieldMarshal`
pub type FieldMarshalList = Arc<boxcar::Vec<FieldMarshalRc>>;
/// A reference to a `FieldMarshal`
pub type FieldMarshalRc = Arc<FieldMarshal>;
