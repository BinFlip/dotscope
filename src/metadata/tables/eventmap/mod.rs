//! EventMap table module.
//!
//! This module provides comprehensive support for the ECMA-335 EventMap metadata table (0x12),
//! which establishes the relationship between types and their owned events. EventMap
//! entries define contiguous ranges of events that belong to specific types, enabling
//! efficient enumeration and lookup of events by owning type. It includes raw table access,
//! resolved data structures, and integration with the broader metadata system.
//!
//! # Components
//!
//! - **Raw Representation**: [`EventMapRaw`] - Direct binary table format with unresolved indexes
//! - **Owned Data**: [`EventMapEntry`] - Resolved entries with owned data and cross-references  
//! - **Loading Infrastructure**: [`EventMapLoader`] - Processes raw entries during metadata loading
//! - **Type Aliases**: Collection types for managing EventMap entries efficiently
//!
//! # EventMap Table Structure
//!
//! Each EventMap entry contains:
//! - **Parent** (4 bytes): TypeDef token identifying the type that owns the events
//! - **EventList** (2/4 bytes): RID pointing to the first event owned by this type
//!
//! The table is sorted by Parent token, and event ownership is determined by ranges:
//! events from EventList\[i\] to EventList\[i+1\]-1 belong to Parent\[i\].
//!
//! # Reference
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - EventMap table specification

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map of metadata tokens to EventMap entries
///
/// Provides efficient concurrent access to EventMap entries indexed by their
/// metadata tokens. Uses a lock-free skip list implementation for high-performance
/// concurrent reads and writes during metadata loading.
pub type EventMapEntryMap = SkipMap<Token, EventMapEntryRc>;

/// Thread-safe vector of EventMap entries
///
/// Provides a growable collection of EventMap entries with thread-safe append
/// operations. Used for collecting entries during parallel processing phases
/// of metadata loading.
pub type EventMapEntryList = Arc<boxcar::Vec<EventMapEntryRc>>;

/// Reference-counted pointer to an EventMap entry
///
/// Provides shared ownership of [`EventMapEntry`] instances across multiple
/// threads and data structures. Enables efficient memory usage and safe
/// concurrent access to EventMap metadata.
pub type EventMapEntryRc = Arc<EventMapEntry>;
