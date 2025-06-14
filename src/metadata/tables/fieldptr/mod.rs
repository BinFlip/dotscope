//! # `FieldPtr` Table Module
//!
//! This module provides access to the `FieldPtr` metadata table, which provides an indirection
//! layer for accessing Field table entries in uncompressed metadata streams (`#-`).
//!
//! The module follows a dual-variant pattern:
//! - `FieldPtrRaw`: Raw table data with unresolved indexes
//! - `FieldPtr`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{FieldPtr, FieldPtrRaw};
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

/// A map that holds the mapping of Token to parsed `FieldPtr`
pub type FieldPtrMap = SkipMap<Token, FieldPtrRc>;
/// A vector that holds a list of `FieldPtr`
pub type FieldPtrList = Arc<boxcar::Vec<FieldPtrRc>>;
/// A reference to a `FieldPtr`
pub type FieldPtrRc = Arc<FieldPtr>;
