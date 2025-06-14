//! `AssemblyProcessor` table module
//!
//! This module contains all components related to the `AssemblyProcessor` metadata table:
//! - `AssemblyProcessorRaw`: Raw table structure with unresolved indexes
//! - `AssemblyProcessor`: Owned variant (type alias to Raw since no resolution needed)
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `AssemblyProcessor`
pub type AssemblyProcessorMap = SkipMap<Token, AssemblyProcessorRc>;
/// A vector that holds a list of `AssemblyProcessor`
pub type AssemblyProcessorList = Arc<boxcar::Vec<AssemblyProcessorRc>>;
/// A reference to a `AssemblyProcessor`
pub type AssemblyProcessorRc = Arc<AssemblyProcessor>;

/// The `AssemblyProcessor` table specifies which processors this assembly is targeted for, `TableId` = 0x21
// In this case, there's nothing to resolve or own. All data in `AssemblyProcessorRaw` is already owned by the type
pub type AssemblyProcessor = AssemblyProcessorRaw;
