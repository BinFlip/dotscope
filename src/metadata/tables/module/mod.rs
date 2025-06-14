//! # Module Table Module
//!
//! This module provides access to the Module metadata table, which provides information
//! about the current module, including its name, GUID (Mvid), and generation. There is
//! only one row in this table for each PE file.
//!
//! The module follows a dual-variant pattern:
//! - `ModuleRaw`: Raw table data with unresolved indexes
//! - `Module`: Processed data with resolved references and owned strings
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{Module, ModuleRaw};
//! ```
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `Module`
pub type ModuleMap = SkipMap<Token, ModuleRc>;
/// A vector that holds a list of `Module`
pub type ModuleList = Arc<boxcar::Vec<ModuleRc>>;
/// A reference to a `Module`
pub type ModuleRc = Arc<Module>;
