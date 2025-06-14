//! Constant table module
//!
//! This module contains all components related to the Constant metadata table:
//! - `ConstantRaw`: Raw table structure with unresolved indexes
//! - `Constant`: Owned variant with resolved indexes and owned data  
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

/// A map that holds the mapping of Token to parsed `Constant`
pub type ConstantMap = SkipMap<Token, ConstantRc>;
/// A vector that holds a list of `Constant`
pub type ConstantList = Arc<boxcar::Vec<ConstantRc>>;
/// A reference to a `Constant`
pub type ConstantRc = Arc<Constant>;
