//! `LocalScope` table implementation for Portable PDB format
//!
//! This module provides access to `LocalScope` table data, which defines the scope ranges
//! where local variables and constants are active within methods. Used by debuggers to
//! determine variable and constant visibility at different execution points.
//!
//! The `LocalScope` table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`LocalScopeRaw`] for raw binary data with unresolved indices
//! - [`LocalScope`] for processed data with resolved scope information
//!
//! # Architecture
//!
//! This table is part of the Portable PDB format and provides essential information
//! for debuggers to determine variable and constant visibility at different execution points.
//! Each scope defines a range of IL instructions where specific variables and constants
//! are accessible, enabling proper debugging support for block-scoped variables.
//!
//! # Key Components
//!
//! - [`LocalScopeRaw`] - Raw table structure with unresolved indices
//! - [`LocalScope`] - Owned variant with resolved references and scope information
//! - [`LocalScopeLoader`] - Internal loader for processing `LocalScope` table data
//! - [`LocalScopeMap`] - Thread-safe concurrent map for caching scope entries
//! - [`LocalScopeList`] - Thread-safe append-only vector for scope collections
//! - [`LocalScopeRc`] - Reference-counted pointer for shared ownership
//!
//! # `LocalScope` Table Structure
//!
//! Each `LocalScope` table row contains these fields:
//! - **Method**: Simple index into `MethodDef` table (method containing scope)
//! - **`ImportScope`**: Simple index into `ImportScope` table (import context)
//! - **`VariableList`**: Simple index into `LocalVariable` table (first variable)
//! - **`ConstantList`**: Simple index into `LocalConstant` table (first constant)
//! - **`StartOffset`**: IL instruction offset where scope begins
//! - **Length**: Length of scope in IL instruction bytes
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! # use dotscope::metadata::loader::LoaderContext;
//! # fn example(context: &LoaderContext) -> dotscope::Result<()> {
//! // Access local scopes through the loader context
//! let local_scopes = &context.local_scopes;
//!
//! // Get a specific scope by RID
//! if let Some(scope) = local_scopes.get(&1) {
//!     // Check scope boundaries
//!     println!("Scope starts at IL offset: {}", scope.start_offset);
//!     println!("Scope length: {} bytes", scope.length);
//!     println!("Scope ends at IL offset: {}", scope.end_offset());
//!
//!     // Check scope contents
//!     if scope.has_variables() {
//!         println!("Scope contains variables starting at index: {}", scope.variable_list);
//!     }
//!     if scope.has_constants() {
//!         println!("Scope contains constants starting at index: {}", scope.constant_list);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`LocalScopeMap`] and
//! [`LocalScopeList`] use lock-free concurrent data structures for efficient
//! multi-threaded access.
//!
//! # References
//!
//! - [Portable PDB Format - LocalScope Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#localscope-table-0x32)

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::{Arc, Weak};

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

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`LocalScope`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved local scope information by their metadata tokens.
pub type LocalScopeMap = SkipMap<Token, LocalScopeRc>;

/// A vector that holds a list of [`LocalScope`] references
///
/// Thread-safe append-only vector for storing local scope collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type LocalScopeList = Arc<boxcar::Vec<LocalScopeRc>>;

/// A reference-counted pointer to a [`LocalScope`]
///
/// Provides shared ownership and automatic memory management for local scope instances.
/// Multiple references can safely point to the same local scope data across threads.
pub type LocalScopeRc = Arc<LocalScope>;

/// Weak reference to a `LocalScope` to avoid circular dependencies
///
/// Since scopes can form tree structures where parent scopes might reference
/// child scopes or vice versa, we use weak references to prevent memory leaks
/// from circular references.
#[derive(Clone)]
pub struct LocalScopeRef {
    /// Weak reference to the actual scope to avoid reference cycles
    weak_ref: Weak<LocalScope>,
}

impl LocalScopeRef {
    /// Create a new `LocalScopeRef` from a strong reference
    #[must_use]
    pub fn new(strong_ref: &LocalScopeRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Upgrade the weak reference to a strong reference if still valid
    #[must_use]
    pub fn upgrade(&self) -> Option<LocalScopeRc> {
        self.weak_ref.upgrade()
    }
}
