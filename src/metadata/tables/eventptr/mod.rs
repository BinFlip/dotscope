use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `EventPtr`
pub type EventPtrMap = SkipMap<Token, EventPtrRc>;
/// A vector that holds a list of `EventPtr`
pub type EventPtrList = Arc<boxcar::Vec<EventPtrRc>>;
/// A reference to a `EventPtr`
pub type EventPtrRc = Arc<EventPtr>;
