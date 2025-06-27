//! `MethodDebugInformation` table implementation for Portable PDB format
//!
//! This module provides access to `MethodDebugInformation` table data, which contains debugging
//! information for methods including sequence points that map IL instructions to source code
//! locations. Essential for step-through debugging by establishing the connection between
//! compiled IL code and original source positions.
//!
//! The `MethodDebugInformation` table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`MethodDebugInformationRaw`] for raw binary data with unresolved heap indices
//! - [`MethodDebugInformation`] for processed data with resolved references
//!
//! # Architecture
//!
//! This table is part of the Portable PDB format and provides essential information
//! for step-through debugging by mapping IL instructions to source code locations.
//! Each method can have associated sequence points that define breakpoint locations
//! and step-through behavior during debugging sessions.
//!
//! # Key Components
//!
//! - [`MethodDebugInformationRaw`] - Raw table structure with unresolved heap indices
//! - [`MethodDebugInformation`] - Owned variant with resolved references and parsed debug data
//! - [`MethodDebugInformationLoader`] - Internal loader for processing table data
//! - [`MethodDebugInformationMap`] - Thread-safe concurrent map for caching entries
//! - [`MethodDebugInformationList`] - Thread-safe append-only vector for collections
//! - [`MethodDebugInformationRc`] - Reference-counted pointer for shared ownership
//!
//! # `MethodDebugInformation` Table Structure
//!
//! Each `MethodDebugInformation` table row contains these fields:
//! - **Document**: Simple index into Document table (0 = no associated document)
//! - **`SequencePoints`**: Blob heap index containing encoded sequence point data
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! # use dotscope::metadata::loader::LoaderContext;
//! # fn example(context: &LoaderContext) -> dotscope::Result<()> {
//! // Access method debug information through the loader context
//! let method_debug_infos = &context.method_debug_information;
//!
//! // Get debug info for a specific method by RID
//! if let Some(debug_info) = method_debug_infos.get(&1) {
//!     // Check if method has debugging information
//!     if debug_info.has_sequence_points() {
//!         println!("Method has {} bytes of sequence point data",
//!                  debug_info.sequence_points_size());
//!     }
//!
//!     // Check for associated document
//!     if debug_info.has_document() {
//!         println!("Method references document index: {}", debug_info.document);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`MethodDebugInformationMap`] and
//! [`MethodDebugInformationList`] use lock-free concurrent data structures for efficient
//! multi-threaded access.
//!
//! # References
//!
//! - [Portable PDB Format - MethodDebugInformation Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod builder;
mod loader;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`MethodDebugInformation`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved method debug information by their metadata tokens.
pub type MethodDebugInformationMap = SkipMap<Token, MethodDebugInformationRc>;

/// A vector that holds a list of [`MethodDebugInformation`] references
///
/// Thread-safe append-only vector for storing method debug information collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type MethodDebugInformationList = Arc<boxcar::Vec<MethodDebugInformationRc>>;

/// A reference-counted pointer to a [`MethodDebugInformation`]
///
/// Provides shared ownership and automatic memory management for method debug information instances.
/// Multiple references can safely point to the same method debug information data across threads.
pub type MethodDebugInformationRc = Arc<MethodDebugInformation>;
