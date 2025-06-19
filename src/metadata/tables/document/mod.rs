//! Document table implementation for Portable PDB format
//!
//! This module provides access to Document table data, which stores information about
//! source documents referenced in debug information. It includes raw table access,
//! resolved data structures, document name parsing, and integration with the broader
//! metadata system.
//!
//! The Document table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`DocumentRaw`] for raw binary data with unresolved heap indices
//! - [`Document`] for processed data with resolved string and blob values
//!
//! # Architecture
//!
//! The Document table is part of the Portable PDB format and provides essential information
//! for mapping debug information back to source code locations. Each document entry contains
//! the document name/path, hash information for integrity verification, and language
//! identification for proper syntax highlighting and debugging support.
//!
//! # Key Components
//!
//! - [`DocumentRaw`] - Raw table structure with unresolved heap indices
//! - [`Document`] - Owned variant with resolved references and parsed document data
//! - [`DocumentLoader`] - Internal loader for processing Document table data
//! - [`DocumentMap`] - Thread-safe concurrent map for caching document entries
//! - [`DocumentList`] - Thread-safe append-only vector for document collections
//! - [`DocumentRc`] - Reference-counted pointer for shared ownership
//!
//! # Document Table Structure
//!
//! Each Document table row contains these fields:
//! - **Name**: Document name/path stored as blob (typically a file path)
//! - **`HashAlgorithm`**: Hash algorithm identifier stored as GUID
//! - **Hash**: Document content hash stored as blob
//! - **Language**: Source language identifier stored as GUID
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! # use dotscope::metadata::loader::LoaderContext;
//! # fn example(context: &LoaderContext) -> dotscope::Result<()> {
//! // Access documents through the loader context
//! let documents = &context.documents;
//!
//! // Get a specific document by RID
//! if let Some(document) = documents.get(&1) {
//!     println!("Document name: {:?}", document.name);
//!     println!("Hash algorithm: {:?}", document.hash_algorithm);
//!     println!("Language: {:?}", document.language);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`DocumentMap`] and [`DocumentList`]
//! use lock-free concurrent data structures for efficient multi-threaded access.
//!
//! # References
//!
//! - [Portable PDB Format - Document Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#document-table-0x30)

use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::metadata::token::Token;

mod loader;
mod owned;
mod raw;
mod reader;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`Document`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved documents by their metadata tokens.
pub type DocumentMap = SkipMap<Token, DocumentRc>;

/// A vector that holds a list of [`Document`] references
///
/// Thread-safe append-only vector for storing document collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type DocumentList = Arc<boxcar::Vec<Arc<DocumentRc>>>;

/// A reference-counted pointer to a [`Document`]
///
/// Provides shared ownership and automatic memory management for document instances.
/// Multiple references can safely point to the same document data across threads.
pub type DocumentRc = Arc<Document>;
