//! `GenericParamConstraint` table module
//!
//! This module contains all components related to the `GenericParamConstraint` metadata table:
//! - `GenericParamConstraintRaw`: Raw table structure with unresolved indexes
//! - `GenericParamConstraint`: Owned variant with resolved indexes and owned data  
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)

use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `GenericParamConstraint`
pub type GenericParamConstraintMap = SkipMap<Token, GenericParamConstraintRc>;
/// A vector that holds a list of `GenericParamConstraint`
pub type GenericParamConstraintList = Arc<boxcar::Vec<GenericParamConstraintRc>>;
/// A reference to a `GenericParamConstraint`
pub type GenericParamConstraintRc = Arc<GenericParamConstraint>;
