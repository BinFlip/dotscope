//! `TypeSpec` table support for .NET metadata.
//!
//! The `TypeSpec` table defines type specifications through signatures. These are used for
//! complex types that cannot be represented in the simpler `TypeDef` or `TypeRef` tables,
//! such as generic instantiations, arrays, pointers, and other constructed types.
//!
//! ## ECMA-335 Specification
//! From ECMA-335, Partition II, Section 22.39:
//! > The TypeSpec table has the following column:
//! > - Signature (an index into the Blob heap, where the blob is formatted according to the TypeSpec signature format)
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `TypeSpec`
pub type TypeSpecMap = SkipMap<Token, TypeSpecRc>;
/// A vector that holds a list of `TypeSpec`
pub type TypeSpecList = Arc<boxcar::Vec<TypeSpecRc>>;
/// A reference to a `TypeSpec`
pub type TypeSpecRc = Arc<TypeSpec>;
