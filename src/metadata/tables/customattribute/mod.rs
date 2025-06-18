//! `CustomAttribute` table module.
//!
//! This module provides complete support for the ECMA-335 `CustomAttribute` metadata table (0x0C),
//! which associates custom attributes with elements throughout the metadata system. It includes
//! raw table access, resolved data structures, attribute value parsing, and integration
//! with the broader metadata system.
//!
//! # Components
//!
//! - [`CustomAttributeRaw`]: Raw table structure with unresolved coded indexes
//! - [`CustomAttribute`]: Owned variant with resolved references and parsed attribute values
//! - [`CustomAttributeLoader`]: Internal loader for processing `CustomAttribute` table data
//! - Type aliases for efficient collections and reference management
//!
//! # `CustomAttribute` Table Structure
//!
//! Each `CustomAttribute` table row contains these fields:
//! - **Parent**: Target element that the attribute is applied to (coded index)
//! - **Type**: Constructor method for the custom attribute (coded index)
//! - **Value**: Serialized attribute arguments and named parameters (blob)
//!
//! The parent can be any metadata element that supports the `HasCustomAttribute` coded index,
//! including types, methods, fields, assemblies, modules, and parameters.
//!
//! # Reference
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `CustomAttribute` table specification
//! - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`CustomAttribute`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved custom attributes by their metadata tokens.
pub type CustomAttributeMap = SkipMap<Token, CustomAttributeRc>;

/// A vector that holds a list of [`CustomAttribute`] references
///
/// Thread-safe append-only vector for storing custom attribute collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type CustomAttributeList = Arc<boxcar::Vec<Arc<CustomAttributeRc>>>;

/// A reference-counted pointer to a [`CustomAttribute`]
///
/// Provides shared ownership and automatic memory management for custom attribute instances.
/// Multiple references can safely point to the same custom attribute data across threads.
pub type CustomAttributeRc = Arc<CustomAttribute>;
