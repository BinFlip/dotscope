//! `MemberRef` table structures and utilities
//!
//! The `MemberRef` table references members (fields or methods) of types defined in other modules.
//! This module provides both raw metadata structures and owned/parsed representations.
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::{
    signatures::{SignatureField, SignatureMethod},
    token::Token,
};

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `MemberRef`
pub type MemberRefMap = SkipMap<Token, MemberRefRc>;
/// A vector that holds a list of `MemberRef`
pub type MemberRefList = Arc<boxcar::Vec<MemberRefRc>>;
/// A reference to a `MemberRef`
pub type MemberRefRc = Arc<MemberRef>;

/// Describes the signature of a `MemberRef`
pub enum MemberRefSignature {
    /// A `MethodSignature`
    Method(SignatureMethod),
    /// A `FieldSignature`
    Field(SignatureField),
}
