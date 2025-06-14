//! `InterfaceImpl` table module
//!
//! This module contains all components related to the `InterfaceImpl` metadata table:
//! - `InterfaceImplRaw`: Raw table structure with unresolved indexes
//! - `InterfaceImpl`: Owned variant with resolved indexes and owned data  
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

/// A map that holds the mapping of Token to parsed `InterfaceImpl`
pub type InterfaceImplMap = SkipMap<Token, InterfaceImplRc>;
/// A vector that holds a list of `InterfaceImpl`
pub type InterfaceImplList = Arc<boxcar::Vec<InterfaceImplRc>>;
/// A reference to a `InterfaceImpl`
pub type InterfaceImplRc = Arc<InterfaceImpl>;
