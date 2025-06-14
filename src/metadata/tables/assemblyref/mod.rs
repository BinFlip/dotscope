//! `AssemblyRef` table module
//!
//! This module contains all components related to the `AssemblyRef` metadata table:
//! - `AssemblyRefRaw`: Raw table structure with unresolved indexes
//! - `AssemblyRef`: Owned variant with resolved indexes and owned data  
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::{
    imports::{ImportContainer, ImportRc, Imports},
    token::Token,
};

mod assemblyrefhash;
mod loader;
mod owned;
mod raw;

pub use assemblyrefhash::*;
pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `AssemblyRef`
pub type AssemblyRefMap = SkipMap<Token, AssemblyRefRc>;
/// A vector that holds a list of `AssemblyRef`
pub type AssemblyRefList = Arc<boxcar::Vec<AssemblyRefRc>>;
/// A reference to a `AssemblyRef`
pub type AssemblyRefRc = Arc<AssemblyRef>;

impl ImportContainer for AssemblyRefRc {
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_assembly_ref(self)
    }
}
