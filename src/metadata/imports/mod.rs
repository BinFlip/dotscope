//! Analysis and representation of imported types and methods in .NET assemblies.
//!
//! This module provides comprehensive functionality for tracking and analyzing all external
//! dependencies (imports) of a .NET assembly, including methods and types imported from other
//! assemblies, modules, native DLLs, or file resources. Essential for dependency analysis,
//! interoperability scenarios, and assembly resolution workflows.
//!
//! # Architecture
//!
//! The imports system uses a multi-index approach built on concurrent data structures for
//! thread-safe access patterns. The architecture separates import classification, source
//! tracking, and lookup optimization into distinct but integrated components.
//!
//! ## Core Design Principles
//!
//! - **Reference Cycle Prevention**: Token-based source identification avoids circular dependencies
//! - **Multi-Index Strategy**: Separate indices for name, namespace, and source-based lookups
//! - **Concurrent Safety**: Lock-free data structures for high-performance multi-threaded access
//! - **Memory Efficiency**: Reference counting and weak references minimize memory overhead
//!
//! # Key Components
//!
//! ## Primary Types
//!
//! - [`Import`] - Individual imported entity with complete metadata
//! - [`Imports`] - Main container with multi-index lookup capabilities
//! - [`ImportType`] - Classification as method or type import
//! - [`ImportSourceId`] - Token-based source identification
//! - [`ImportContainer`] - Trait for source aggregation patterns
//!
//! ## Import Categories
//!
//! - **Type Imports**: External types from other .NET assemblies
//! - **Method Imports**: Platform Invoke (P/Invoke) methods from native DLLs
//! - **Module References**: Types and methods from separate compilation units
//! - **File References**: Resources and embedded types from external files
//!
//! # Usage Examples
//!
//! ## Basic Import Analysis
//!
//! ```rust,ignore
//! use dotscope::metadata::imports::{Imports, ImportType};
//!
//! let imports = Imports::new();
//!
//! // Find all imports from System namespace
//! let system_imports = imports.by_namespace("System");
//! for import in system_imports {
//!     println!("System import: {}", import.fullname());
//! }
//! ```
//!
//! # Thread Safety
//!
//! All primary types in this module are designed for concurrent access using lock-free
//! data structures. The thread safety model follows these patterns:
//!
//! - **Read-Heavy Workloads**: Optimized for frequent concurrent reads
//! - **Atomic Updates**: All modifications are performed atomically
//! - **Memory Ordering**: Uses appropriate memory ordering for performance
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - For metadata table access and token resolution
//! - [`crate::cilassembly`] - For assembly-level import coordination
//! - [`crate::metadata::exports`] - For cross-assembly reference resolution

pub use builder::NativeImportsBuilder;
pub use cil::*;
pub use container::{
    DllDependency, DllSource, ImportEntry, NativeImportRef, UnifiedImportContainer,
};
pub use native::NativeImports;

mod builder;
mod cil;
mod container;
mod native;
