//! `AssemblyRefProcessor` table module
//!
//! This module contains all components related to the `AssemblyRefProcessor` metadata table:
//! - `AssemblyRefProcessorRaw`: Raw table structure with unresolved indexes
//! - `AssemblyRefProcessor`: Owned variant with resolved indexes and owned data  
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

/// A map that holds the mapping of Token to parsed `AssemblyRefProcessor`
pub type AssemblyRefProcessorMap = SkipMap<Token, AssemblyRefProcessorRc>;
/// A vector that holds a list of `AssemblyRefProcessor`
pub type AssemblyRefProcessorList = Arc<boxcar::Vec<AssemblyRefProcessorRc>>;
/// A reference to a `AssemblyRefProcessor`
pub type AssemblyRefProcessorRc = Arc<AssemblyRefProcessor>;
