//! `ManifestResource` table module
//!
//! This module contains all components related to the `ManifestResource` metadata table:
//! - `ManifestResourceRaw`: Raw table structure with unresolved indexes
//! - `ManifestResource`: Owned variant with resolved indexes and owned data  
//! - Type aliases for collections and references
//! - Internal loader (pub(crate) only)
use bitflags::bitflags;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed `ManifestResource`
pub type ManifestResourceMap = SkipMap<Token, ManifestResourceRc>;
/// A vector that holds a list of `ManifestResource`
pub type ManifestResourceList = Arc<boxcar::Vec<ManifestResourceRc>>;
/// A reference to a `ManifestResource`
pub type ManifestResourceRc = Arc<ManifestResource>;

bitflags! {
    #[derive(PartialEq, Debug)]
    /// All possible flags for ManifestResourceAttributes
    pub struct ManifestResourceAttributes : u32 {
        /// The Resource is exported from the Assembly
        const PUBLIC = 0x0001;
        /// The Resource is private to the Assembly
        const PRIVATE = 0x0002;
    }
}
