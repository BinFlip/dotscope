//! # `MethodImpl` Table Module
//!
//! This module provides access to the `MethodImpl` metadata table, which specifies which
//! methods implement which methods for a class. This table is crucial for managing
//! interface implementations and method overrides.
//!
//! The module follows a dual-variant pattern:
//! - `MethodImplRaw`: Raw table data with unresolved indexes
//! - `MethodImpl`: Processed data with resolved references and owned data
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{MethodImpl, MethodImplRaw};
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

/// A map that holds the mapping of Token to parsed `MethodImpl`
pub type MethodImplMap = SkipMap<Token, MethodImplRc>;
/// A vector that holds a list of `MethodImpl`
pub type MethodImplList = Arc<boxcar::Vec<MethodImplRc>>;
/// A reference to a `MethodImpl`
pub type MethodImplRc = Arc<MethodImpl>;
