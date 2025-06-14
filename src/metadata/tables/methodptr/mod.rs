//! # `MethodPtr` Table Module
//!
//! This module provides access to the `MethodPtr` metadata table, which provides an indirection
//! layer for accessing `MethodDef` table entries in uncompressed metadata streams (`#-`).
//!
//! The module follows a dual-variant pattern:
//! - `MethodPtrRaw`: Raw table data with unresolved indexes
//! - `MethodPtr`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{MethodPtr, MethodPtrRaw};
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

/// A map that holds the mapping of Token to parsed `MethodPtr`
pub type MethodPtrMap = SkipMap<Token, MethodPtrRc>;
/// A vector that holds a list of `MethodPtr`
pub type MethodPtrList = Arc<boxcar::Vec<MethodPtrRc>>;
/// A reference to a `MethodPtr`
pub type MethodPtrRc = Arc<MethodPtr>;
