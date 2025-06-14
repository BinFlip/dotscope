//! `AssemblyRefOS` table module
//!
//! This module contains all components related to the `AssemblyRefOS` metadata table:
//! - `AssemblyRefOsRaw`: Raw table structure with unresolved indexes
//! - `AssemblyRefOs`: Owned variant with resolved indexes and owned data  
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

/// A map that holds the mapping of Token to parsed `AssemblyRefOs`
pub type AssemblyRefOsMap = SkipMap<Token, AssemblyRefOsRc>;
/// A vector that holds a list of `AssemblyRefOs`
pub type AssemblyRefOsList = Arc<boxcar::Vec<AssemblyRefOsRc>>;
/// A reference to a `AssemblyRefOs`
pub type AssemblyRefOsRc = Arc<AssemblyRefOs>;
