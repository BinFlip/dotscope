//! # `ExportedType` Table Module
//!
//! This module provides access to the `ExportedType` metadata table, which contains information
//! about types that are exported from the current assembly but defined in other modules.
//!
//! The module follows a dual-variant pattern:
//! - `ExportedTypeRaw`: Raw table data with unresolved indexes
//! - `ExportedType`: Processed data with resolved references and owned strings
//!
//! ## Usage
//!
//! ```rust
//! use dotscope::metadata::tables::{ExportedType, ExportedTypeRaw};
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

/// A map that holds the mapping of Token to parsed `ExportedType`
pub type ExportedTypeMap = SkipMap<Token, ExportedTypeRc>;
/// A vector that holds a list of `ExportedType`
pub type ExportedTypeList = Arc<boxcar::Vec<ExportedTypeRc>>;
/// A reference to a `ExportedType`
pub type ExportedTypeRc = Arc<ExportedType>;
