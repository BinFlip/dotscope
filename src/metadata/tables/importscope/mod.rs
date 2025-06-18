//! `ImportScope` table implementation for Portable PDB format
//!
//! This module provides access to `ImportScope` table data, which contains information
//! about import scopes that define the set of namespaces and types that are accessible
//! within a lexical scope. Import scopes are used by debuggers to resolve symbol names
//! within the context of a specific scope.
//!
//! The `ImportScope` table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`ImportScopeRaw`] for raw binary data with unresolved heap indices
//! - [`ImportScope`] for processed data with resolved string and blob values
//!
//! # Usage
//!
//! ```rust,ignore
//! # use dotscope::metadata::loader::LoaderContext;
//! # fn example(context: &LoaderContext) -> dotscope::Result<()> {
//! // Access import scopes through the loader context
//! let import_scopes = &context.import_scopes;
//!
//! // Get a specific import scope by RID
//! if let Some(scope) = import_scopes.get(&1) {
//!     println!("Import scope parent: {:?}", scope.parent);
//!     println!("Import scope imports: {} bytes", scope.imports.len());
//! }
//! # Ok(())
//! # }
//! ```

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`ImportScope`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved import scope information by their metadata tokens.
pub type ImportScopeMap = SkipMap<Token, ImportScopeRc>;

/// A vector that holds a list of [`ImportScope`] references
///
/// Thread-safe append-only vector for storing import scope collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type ImportScopeList = Arc<boxcar::Vec<ImportScopeRc>>;

/// A reference-counted pointer to an [`ImportScope`]
///
/// Provides shared ownership and automatic memory management for import scope instances.
/// Multiple references can safely point to the same import scope data across threads.
pub type ImportScopeRc = Arc<ImportScope>;
