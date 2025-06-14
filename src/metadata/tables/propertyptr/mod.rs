//! `PropertyPtr` table support for .NET metadata.
//!
//! The `PropertyPtr` table provides an indirection layer for accessing Property table entries
//! in uncompressed metadata streams (`#-`). This table is only present in assemblies
//! that use the `#-` stream format instead of the standard `#~` compressed format.
//!
//! Each row contains a single field: a 1-based index into the Property table. When `PropertyPtr`
//! is present, property references should be resolved through this indirection table rather
//! than directly indexing into the Property table.
//!
//! ## ECMA-335 Specification
//! From ECMA-335, Partition II, Section 22.35:
//! > The PropertyPtr table is an auxiliary table used by the CLI loaders to implement
//! > indirect access to the Property table.
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// Type alias for owned `PropertyPtr` references
pub type PropertyPtrRc = std::sync::Arc<PropertyPtr>;
/// A map that holds the mapping of Token to parsed `PropertyPtr`
pub type PropertyPtrMap = SkipMap<Token, Arc<PropertyPtr>>;
/// A vector that holds a list of `PropertyPtr`
pub type PropertyPtrList = Arc<boxcar::Vec<Arc<PropertyPtr>>>;
