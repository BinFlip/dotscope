use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed resolved `EventMapEntry`
pub type EventMapEntryMap = SkipMap<Token, EventMapEntryRc>;
/// A vector that holds a list of resolved `EventMapEntry`
pub type EventMapEntryList = Arc<boxcar::Vec<EventMapEntryRc>>;
/// A reference to a resolved `EventMapEntry`
pub type EventMapEntryRc = Arc<EventMapEntry>;
