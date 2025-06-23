//! `ImportScope` metadata table implementation for Portable PDB format.
//!
//! This module provides complete support for the `ImportScope` metadata table, which defines
//! hierarchical import scopes that control namespace and type visibility within lexical
//! contexts. Import scopes are essential for debugger symbol resolution and IDE navigation.
//!
//! # Overview
//! The `ImportScope` table enables debugger symbol resolution through:
//! - **Namespace imports**: Specifying which namespaces are accessible in a scope
//! - **Type aliases**: Defining local type name mappings and shortcuts
//! - **Extern aliases**: Creating aliases for external assemblies and modules
//! - **Hierarchical scoping**: Supporting nested scopes with inheritance rules
//! - **VB.NET imports**: Supporting Visual Basic.NET project-level imports
//!
//! # Components
//! - [`ImportScopeRaw`]: Raw import scope data read directly from metadata tables
//! - [`ImportScope`]: Owned import scope data with resolved references
//! - [`ImportScopeLoader`]: Processes and loads import scope metadata
//! - [`ImportScopeMap`]: Thread-safe collection of import scopes indexed by token
//! - [`ImportScopeList`]: Vector-based collection of import scopes
//! - [`ImportScopeRc`]: Reference-counted import scope for shared ownership
//!
//! # Table Structure
//! Each `ImportScope` entry contains:
//! - **Parent**: Reference to parent scope (for hierarchical organization)
//! - **Imports**: Blob containing serialized import declarations
//!
//! # Import Types
//! Import scopes can contain various import declarations:
//! ```text
//! ┌─────────────────────┬─────────────────────────────────────────┐
//! │ Import Type         │ Example                                 │
//! ├─────────────────────┼─────────────────────────────────────────┤
//! │ Namespace           │ using System.Collections.Generic;       │
//! │ Type alias          │ using List = System.Collections.List;   │
//! │ Extern alias        │ extern alias MyLib;                     │
//! │ VB.NET project      │ Project-level Imports statement         │
//! │ Nested namespace    │ using ns = MyProject.Utilities.Helpers; │
//! └─────────────────────┴─────────────────────────────────────────┘
//! ```
//!
//! # Scope Hierarchy
//! Import scopes form a hierarchical structure:
//! - **Global scope**: Top-level imports applying to the entire module
//! - **File scope**: Imports applying to a specific source file
//! - **Method scope**: Local imports and aliases within method bodies
//! - **Block scope**: Imports within specific code blocks or regions
//!
//! # Debugger Integration
//! Import scopes enable debugger functionality:
//! - **Symbol resolution**: Resolving unqualified type names to full types
//! - **IntelliSense**: Providing accurate completion lists in IDE contexts
//! - **Navigation**: Supporting "Go to Definition" for imported symbols
//! - **Refactoring**: Maintaining correct references during code changes
//!
//! # Import Resolution Process
//! When resolving symbols within a scope:
//! 1. **Local scope**: Check current scope's imports first
//! 2. **Parent traversal**: Walk up the parent chain checking each scope
//! 3. **Global fallback**: Use global/module-level imports as last resort
//! 4. **Conflict resolution**: Handle naming conflicts through precedence rules
//!
//! # Usage Example
//! ```rust,ignore
//! # use dotscope::metadata::loader::LoaderContext;
//! # fn example(context: &LoaderContext) -> dotscope::Result<()> {
//! // Access import scopes through the loader context
//! let import_scopes = &context.import_scopes;
//!
//! // Get a specific import scope by token
//! if let Some(scope) = import_scopes.get(&1) {
//!     println!("Import scope parent: {:?}", scope.parent);
//!     println!("Import declarations: {} bytes", scope.imports.len());
//!     
//!     // Walk up the scope hierarchy
//!     let mut current = Some(scope.clone());
//!     while let Some(scope) = current {
//!         println!("Processing scope imports...");
//!         current = scope.parent.and_then(|token| import_scopes.get(&token));
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.35 for the complete `ImportScope` table specification.

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
