//! `EncLog` table module
//!
//! Provides complete support for the ECMA-335 `EncLog` metadata table (0x1E), which contains
//! Edit-and-Continue log entries that track modifications made during debugging sessions.
//! This module includes raw table access, collection types, and edit operation support.
//!
//! # Components
//!
//! - [`crate::metadata::tables::enclog::EncLogRaw`]: Raw table structure (no heap resolution needed)
//! - [`crate::metadata::tables::enclog::EncLog`]: Type alias to Raw since all data is self-contained
//! - [`crate::metadata::tables::enclog::loader::EncLogLoader`]: Internal loader for processing `EncLog` table data
//! - Type aliases for efficient collections and reference management
//!
//! # `EncLog` Table Structure
//!
//! The `EncLog` table contains Edit-and-Continue operation records:
//! - **Token**: Metadata token identifying the affected element (4 bytes)
//! - **`FuncCode`**: Operation code (create/update/delete) (4 bytes)
//!
//! # Edit-and-Continue Support
//!
//! This table supports .NET's Edit-and-Continue debugging feature, which allows developers
//! to modify source code while the program is paused in the debugger. The `EncLog` table
//! tracks all metadata changes made during these edit sessions, enabling the runtime to
//! understand what elements have been modified, added, or removed.
//!
//! # Table Characteristics
//!
//! - **Optional**: Not all assemblies contain `EncLog` tables
//! - **Debugging-specific**: Primarily used during active debugging sessions
//! - **Self-contained**: Contains only primitive values, no heap references
//! - **Sequential**: Entries are typically ordered by edit session timestamp
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification

use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod raw;
mod reader;

pub(crate) use loader::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::enclog::EncLog`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved `EncLog` entries by their metadata tokens.
pub type EncLogMap = SkipMap<Token, EncLogRc>;

/// A vector that holds a list of [`crate::metadata::tables::enclog::EncLog`] references
///
/// Thread-safe append-only vector for storing `EncLog` collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type EncLogList = Arc<boxcar::Vec<EncLogRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::enclog::EncLog`]
///
/// Provides shared ownership and automatic memory management for `EncLog` instances.
/// Multiple references can safely point to the same `EncLog` data across threads.
pub type EncLogRc = Arc<EncLog>;

/// Edit-and-Continue log entry for tracking debugging session modifications
///
/// Type alias to [`crate::metadata::tables::enclog::EncLogRaw`] since the `EncLog` table contains only primitive values
/// that don't require heap resolution. All data in the raw structure is immediately usable.
///
/// The `EncLog` table records all metadata changes made during Edit-and-Continue debugging sessions,
/// enabling the runtime to understand what elements have been modified, added, or removed during
/// active debugging.
///
/// # Data Model
///
/// Unlike other metadata tables that reference string or blob heaps, `EncLog` contains
/// only integer values (tokens and operation codes), making the "raw" and "owned"
/// representations identical.
///
/// # Reference
/// - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification (Table ID = 0x1E)
pub type EncLog = EncLogRaw;
