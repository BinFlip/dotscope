//! CustomDebugInformation table implementation for Portable PDB format
//!
//! This module provides access to CustomDebugInformation table data, which contains
//! custom debugging metadata that can be defined by compilers or tools. This table
//! provides extensibility for debugging scenarios beyond the standard Portable PDB tables.
//!
//! The CustomDebugInformation table follows the dual-representation pattern used throughout
//! the dotscope library:
//! - [`CustomDebugInformationRaw`] for raw binary data with unresolved indices
//! - [`CustomDebugInformation`] for processed data with resolved token values
//!
//! # Architecture
//!
//! The CustomDebugInformation table allows tools to store additional debugging information
//! that is specific to their implementation or language features. This information is
//! associated with various metadata elements (methods, types, fields, etc.) through
//! the Parent column and identified by a GUID in the Kind column.
//!
//! # Key Components
//!
//! - [`CustomDebugInformationRaw`] - Raw table structure with unresolved heap indices
//! - [`CustomDebugInformation`] - Owned variant with resolved references and blob data
//! - [`CustomDebugInformationLoader`] - Internal loader for processing table data
//! - [`CustomDebugInformationMap`] - Thread-safe concurrent map for caching entries
//! - [`CustomDebugInformationList`] - Thread-safe append-only vector for collections
//! - [`CustomDebugInformationRc`] - Reference-counted pointer for shared ownership
//!
//! # Common Custom Debug Information Types
//!
//! Several well-known custom debug information types are defined by Microsoft compilers:
//!
//! ### State Machine Information
//! - **State Machine Hoisted Local Scopes**: Scope information for variables hoisted to state machine fields
//! - **Edit and Continue Local Slot Map**: Maps local variables to their syntax positions for edit-and-continue
//! - **Edit and Continue Lambda and Closure Map**: Maps lambdas and closures to their implementing methods
//!
//! ### Dynamic and Source Information  
//! - **Dynamic Local Variables**: Tracks which types were originally declared as `dynamic` in C#
//! - **Default Namespace**: VB.NET project default namespace information
//! - **Embedded Source**: Source code embedded directly in the PDB
//! - **Source Link**: JSON configuration for retrieving source from version control
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! # use dotscope::metadata::loader::LoaderContext;
//! # fn example(context: &LoaderContext) -> dotscope::Result<()> {
//! // Access custom debug information for a method
//! use crate::metadata::tables::CustomDebugInformation;
//! use crate::metadata::token::Token;
//!
//! let method_token = Token::new(0x06000001); // MethodDef token
//!
//! for custom_info in context.custom_debug_information.values() {
//!     if custom_info.parent_token() == method_token {
//!         println!("Found custom debug info: {:?}", custom_info.kind);
//!         // Process the custom information blob
//!         let data = custom_info.value;
//!         // ... interpret based on the GUID in custom_info.kind
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The [`CustomDebugInformationMap`]
//! uses lock-free concurrent data structures for efficient multi-threaded access.
//!
//! # References
//!
//! - [Portable PDB Format - CustomDebugInformation Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#customdebuginformation-table-0x37)
//! - [Custom Debug Information Records](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#language-specific-custom-debug-information-records)

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`CustomDebugInformation`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved custom debug information by their metadata tokens.
pub type CustomDebugInformationMap = SkipMap<Token, CustomDebugInformationRc>;

/// A vector that holds a list of [`CustomDebugInformation`] references
///
/// Thread-safe append-only vector for storing custom debug information collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type CustomDebugInformationList = Arc<boxcar::Vec<CustomDebugInformationRc>>;

/// A reference-counted pointer to a [`CustomDebugInformation`]
///
/// Provides shared ownership and automatic memory management for custom debug information instances.
/// Multiple references can safely point to the same custom debug information data across threads.
pub type CustomDebugInformationRc = Arc<CustomDebugInformation>;
