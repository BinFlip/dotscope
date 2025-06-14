//! `ClassLayout` table module
//!
//! This module contains all components related to the `ClassLayout` metadata table:
//! - `ClassLayoutRaw`: Raw table structure with unresolved indexes
//! - `ClassLayout`: Owned variant with resolved indexes and owned data  
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

/// A map that holds the mapping of Token to parsed `ClassLayout`
pub type ClassLayoutMap = SkipMap<Token, ClassLayoutRc>;
/// A vector that holds a list of `ClassLayout`
pub type ClassLayoutList = Arc<boxcar::Vec<ClassLayoutRc>>;
/// A reference to a `ClassLayout`
pub type ClassLayoutRc = Arc<ClassLayout>;
