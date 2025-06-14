//! `StandAloneSig` table support for .NET metadata.
//!
//! The `StandAloneSig` table stores signatures that are referenced directly rather than through a member.
//! These are primarily used for local variables and method parameters. Standalone signatures can be
//! referenced by various elements in the metadata but don't belong to a specific type or method.
//!
//! ## ECMA-335 Specification
//! From ECMA-335, Partition II, Section 22.36:
//! > The StandAloneSig table holds the signature for entries that don't fit elsewhere.
//! > These include standalone method signatures and local variable signatures.
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `StandAloneSig`
pub type StandAloneSigMap = SkipMap<Token, StandAloneSigRc>;
/// A vector that holds a list of `StandAloneSig`
pub type StandAloneSigList = Arc<boxcar::Vec<StandAloneSigRc>>;
/// A reference to a `StandAloneSig`
pub type StandAloneSigRc = Arc<StandAloneSig>;
