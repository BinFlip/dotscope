//! `CustomAttribute` table module
//!
//! This module contains all components related to the `CustomAttribute` metadata table:
//! - `CustomAttributeRaw`: Raw table structure with unresolved indexes
//! - `CustomAttribute`: Owned variant with resolved indexes and owned data  
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `CustomAttribute`
pub type CustomAttributeMap = SkipMap<Token, CustomAttributeRc>;
/// A vector that holds a list of `CustomAttribute`
pub type CustomAttributeList = Arc<boxcar::Vec<Arc<CustomAttributeRc>>>;
/// A reference to a `CustomAttribute`
pub type CustomAttributeRc = Arc<CustomAttribute>;
