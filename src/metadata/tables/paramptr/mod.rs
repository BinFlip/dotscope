//! # `ParamPtr` Table Module
//!
//! This module provides access to the `ParamPtr` metadata table, which provides an indirection
//! layer for accessing Param table entries in uncompressed metadata streams (`#-`).
//!
//! The module follows a dual-variant pattern:
//! - `ParamPtrRaw`: Raw table data with unresolved indexes
//! - `ParamPtr`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{ParamPtr, ParamPtrRaw};
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

/// A map that holds the mapping of Token to parsed `ParamPtr`
pub type ParamPtrMap = SkipMap<Token, ParamPtrRc>;
/// A vector that holds a list of `ParamPtr`
pub type ParamPtrList = Arc<boxcar::Vec<ParamPtrRc>>;
/// A reference to a `ParamPtr`
pub type ParamPtrRc = Arc<ParamPtr>;
