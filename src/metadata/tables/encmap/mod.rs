//! `EncMap` table support for .NET metadata.
//!
//! This module provides comprehensive support for the `EncMap` metadata table (ID 0x1F), which
//! manages token mapping during Edit-and-Continue debugging operations. The `EncMap` table
//! correlates original metadata tokens with their updated versions after code modifications,
//! enabling debuggers to maintain proper references across edit sessions.
//!
//! ## Table Structure
//!
//! The `EncMap` table contains the following columns as specified in ECMA-335:
//! - **Token** (4 bytes): Original metadata token before editing
//!
//! ## Usage in Edit-and-Continue
//!
//! During Edit-and-Continue debugging:
//! 1. Original metadata tokens are recorded in the `EncMap` table
//! 2. Code modifications generate new metadata tokens
//! 3. The `EncMap` table provides mapping between old and new tokens
//! 4. Debuggers use this mapping to update breakpoints and references
//!
//! ## Module Organization
//!
//! - [`raw`]: Raw table row representation and parsing logic
//! - [`loader`]: Metadata loader implementation for parallel processing
//! - [`EncMapRaw`]: Type alias for the raw table row structure
//! - [`EncMapMap`]: Type alias for the loaded table data structure
//! - [`EncMapLoader`]: Type alias for the metadata loader implementation
//!
//! ## Examples
//!
//! ```rust,ignore
//! use dotscope::metadata::{
//!     tables::{TableId, encmap::EncMapRaw},
//!     streams::TablesHeader
//! };
//!
//! // Access EncMap table from metadata stream
//! if let Some(encmap_table) = tables.table::<EncMapRaw>() {
//!     println!("Found {} token mappings", encmap_table.row_count);
//!     
//!     // Iterate through token mappings
//!     for mapping in encmap_table.iter() {
//!         println!("Original token: {:#010x}", mapping.token);
//!     }
//! }
//! ```
//!
//! ## ECMA-335 Reference
//!
//! See ECMA-335, Partition II, Section 22.13 for complete `EncMap` table specification.

use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod raw;
mod reader;

pub(crate) use loader::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::encmap::EncMap`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved `EncMap` entries by their metadata tokens.
pub type EncMapMap = SkipMap<Token, EncMapRc>;

/// A vector that holds a list of [`crate::metadata::tables::encmap::EncMap`] references
///
/// Thread-safe append-only vector for storing `EncMap` collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type EncMapList = Arc<boxcar::Vec<EncMapRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::encmap::EncMap`]
///
/// Provides shared ownership and automatic memory management for `EncMap` instances.
/// Multiple references can safely point to the same `EncMap` data across threads.
pub type EncMapRc = Arc<EncMap>;

/// Edit-and-Continue token mapping entry for debugging session operations
///
/// Type alias to [`crate::metadata::tables::encmap::EncMapRaw`] since the `EncMap` table contains only primitive values
/// that don't require heap resolution. All data in the raw structure is immediately usable.
///
/// The `EncMap` table maps original metadata tokens to their updated versions after Edit-and-Continue
/// operations, enabling debuggers to maintain proper references during active debugging sessions.
///
/// # Data Model
///
/// Unlike other metadata tables that reference string or blob heaps, `EncMap` contains
/// only integer values (tokens), making the "raw" and "owned" representations identical.
///
/// # Reference
/// - [ECMA-335 II.22.13](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncMap` table specification (Table ID = 0x1F)
pub type EncMap = EncMapRaw;
