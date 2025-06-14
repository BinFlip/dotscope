//! # `PropertyMap` Table Module
//!
//! This module contains the `PropertyMap` table definitions and related functionality.
//! The `PropertyMap` table maps properties to their parent types, providing both raw
//! and owned representations for different use cases.
//!
//! ## Table Information
//! - **Table ID**: 0x15 (21)
//! - **Purpose**: Maps properties to their parent types
//! - **Key Components**:
//!   - Parent type reference (index into `TypeDef` table)
//!   - Property list reference (index into Property table)
//!
//! ## Architecture
//!
//! This module follows a dual-representation pattern:
//! - **Raw variant** ([`PropertyMapRaw`]): Direct memory representation with unresolved indexes
//! - **Owned variant** ([`PropertyMapEntry`]): Resolved structure with owned data and resolved references
//!
//! The raw variant is used during initial parsing and provides efficient memory access,
//! while the owned variant resolves all references and provides a more convenient API
//! for metadata analysis.
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of Token to parsed resolved `PropertyMapEntry`
pub type PropertyMapEntryMap = SkipMap<Token, PropertyMapEntryRc>;
/// A vector that holds a list of resolved `PropertyMapEntry`
pub type PropertyMapEntryList = Arc<boxcar::Vec<PropertyMapEntryRc>>;
/// A reference to a resolved `PropertyMapEntry`
pub type PropertyMapEntryRc = Arc<PropertyMapEntry>;
