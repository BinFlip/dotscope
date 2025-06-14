//! # `ModuleRef` Table Module
//!
//! This module provides access to the `ModuleRef` metadata table, which contains references
//! to external modules. This table is essential for tracking module dependencies and
//! cross-module references in .NET assemblies.
//!
//! The module follows a dual-variant pattern:
//! - `ModuleRefRaw`: Raw table data with unresolved indexes
//! - `ModuleRef`: Processed data with resolved references and owned strings
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{ModuleRef, ModuleRefRaw};
//! ```
use crate::metadata::{
    imports::{ImportContainer, ImportRc, Imports},
    token::Token,
};
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `ModuleRef`
pub type ModuleRefMap = SkipMap<Token, ModuleRefRc>;
/// A vector that holds a list of `ModuleRef`
pub type ModuleRefList = Arc<boxcar::Vec<ModuleRefRc>>;
/// A reference to a `ModuleRef`
pub type ModuleRefRc = Arc<ModuleRef>;

impl ImportContainer for Arc<ModuleRef> {
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
        imports.from_module_ref(self)
    }
}
