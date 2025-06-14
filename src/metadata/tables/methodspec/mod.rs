//! # `MethodSpec` Table Module
//!
//! This module provides access to the `MethodSpec` metadata table, which represents
//! instantiations of generic methods. This table is crucial for handling generic
//! method resolution in .NET assemblies.
//!
//! The module follows a dual-variant pattern:
//! - `MethodSpecRaw`: Raw table data with unresolved indexes
//! - `MethodSpec`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{MethodSpec, MethodSpecRaw};
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

/// A map that holds the mapping of Token to parsed `MethodSpec`
pub type MethodSpecMap = SkipMap<Token, MethodSpecRc>;
/// A vector that holds a list of `MethodSpec`
pub type MethodSpecList = Arc<boxcar::Vec<MethodSpecRc>>;
/// A reference to a `MethodSpec`
pub type MethodSpecRc = Arc<MethodSpec>;
