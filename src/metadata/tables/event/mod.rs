use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `Event`
pub type EventMap = SkipMap<Token, EventRc>;
/// A vector that holds a list of `Event`
pub type EventList = Arc<boxcar::Vec<EventRc>>;
/// A reference to an `Event`
pub type EventRc = Arc<Event>;

#[allow(non_snake_case)]
/// All possible flags for `EventAttributes`
pub mod EventAttributes {
    /// Event is special
    pub const SPECIAL_NAME: u32 = 0x0200;
    /// CLI provides 'special' behavior, depending upon the name of the event
    pub const RTSPECIAL_NAME: u32 = 0x0400;
}
