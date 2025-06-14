//! # `NestedClass` Table Module
//!
//! This module provides access to the `NestedClass` metadata table, which defines the
//! relationship between nested types and their enclosing types. This table is essential
//! for properly representing the type hierarchy in .NET assemblies.
//!
//! The module follows a dual-variant pattern:
//! - `NestedClassRaw`: Raw table data with unresolved indexes
//! - `NestedClass`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{NestedClass, NestedClassRaw};
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

/// A map that holds the mapping of Token to parsed `NestedClass`
pub type NestedClassMap = SkipMap<Token, NestedClassRc>;
/// A vector that holds a list of `NestedClass`
pub type NestedClassList = Arc<boxcar::Vec<NestedClassRc>>;
/// A reference to a `NestedClass`
pub type NestedClassRc = Arc<NestedClass>;
