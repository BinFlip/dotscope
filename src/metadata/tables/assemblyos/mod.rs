//! `AssemblyOS` table module
//!
//! This module contains all components related to the `AssemblyOS` metadata table:
//! - `AssemblyOsRaw`: Raw table structure with unresolved indexes
//! - `AssemblyOs`: Owned variant (type alias to Raw since no resolution needed)
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)

use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `AssemblyOs`
pub type AssemblyOsMap = SkipMap<Token, AssemblyOsRc>;
/// A vector that holds a list of `AssemblyOs`
pub type AssemblyOsList = Arc<boxcar::Vec<AssemblyOsRc>>;
/// A reference to a `AssemblyOs`
pub type AssemblyOsRc = Arc<AssemblyOs>;

/// The `AssemblyOS` table specifies which operating systems this assembly is targeted for, `TableId` = 0x22
// In this case, there's nothing to resolve or own. All data in `AssemblyOsRaw` is already owned by the type
pub type AssemblyOs = AssemblyOsRaw;
