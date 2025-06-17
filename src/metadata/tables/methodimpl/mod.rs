//! MethodImpl table implementation for method implementation mappings.
//!
//! This module provides complete support for the MethodImpl metadata table, which defines
//! method implementation mappings that specify which concrete method implementations provide
//! the behavior for method declarations. The MethodImpl table is essential for interface
//! implementation, method overriding, and virtual dispatch in .NET object-oriented programming.
//!
//! # Module Components
//! - [`MethodImplRaw`] - Raw table structure with unresolved coded indexes
//! - [`MethodImpl`] - Owned variant with resolved references and implementation mappings
//! - [`MethodImplLoader`] - Internal loader for processing table entries (crate-private)
//! - Type aliases for collections: [`MethodImplMap`], [`MethodImplList`], [`MethodImplRc`]
//!
//! # Table Structure (ECMA-335 §22.27)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | Class | TypeDef table index | Type containing the implementation mapping |
//! | MethodBody | MethodDefOrRef coded index | Concrete method implementation |
//! | MethodDeclaration | MethodDefOrRef coded index | Method declaration being implemented |
//!
//! # Implementation Mapping Scenarios
//! The MethodImpl table supports various method implementation patterns:
//! - **Interface implementation**: Maps interface method declarations to concrete class implementations
//! - **Virtual method override**: Specifies derived class methods that override base class virtual methods
//! - **Explicit interface implementation**: Handles explicit implementation of interface members
//! - **Generic method specialization**: Links generic method declarations to specialized implementations
//! - **Abstract method implementation**: Connects abstract method declarations to concrete implementations
//!
//! # Method Resolution Process
//! Implementation mappings enable sophisticated method resolution:
//! - **Declaration identification**: Determines which method declaration is being implemented
//! - **Implementation binding**: Links declarations to their concrete implementation methods
//! - **Virtual dispatch**: Supports polymorphic method calls through implementation mappings
//! - **Interface contracts**: Ensures interface method contracts are properly implemented
//! - **Inheritance hierarchies**: Manages method overriding in class inheritance chains
//!
//! # Coded Index Resolution
//! Both MethodBody and MethodDeclaration use MethodDefOrRef coded index encoding:
//! - **Tag 0**: MethodDef table (methods defined in current assembly)
//! - **Tag 1**: MemberRef table (methods referenced from external assemblies)
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.27: MethodImpl table specification
//! - ECMA-335, Partition II, §23.2.4: MethodDefOrRef coded index encoding
//! - ECMA-335, Partition I, §8.10.4: Interface implementation and method overriding
//!
//! [`SkipMap`]: crossbeam_skiplist::SkipMap
//! [`Arc<boxcar::Vec>`]: std::sync::Arc
use crate::metadata::token::Token;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

mod loader;
mod owned;
mod raw;

pub(crate) use loader::*;
pub use owned::*;
pub use raw::*;

/// Concurrent map for storing MethodImpl entries indexed by [`Token`].
///
/// This thread-safe map enables efficient lookup of method implementation mappings
/// by their associated tokens during metadata processing and method resolution operations.
pub type MethodImplMap = SkipMap<Token, MethodImplRc>;

/// Thread-safe list for storing collections of MethodImpl entries.
///
/// Used for maintaining ordered sequences of method implementation mappings during
/// metadata loading and for iteration over all implementations in a type system.
pub type MethodImplList = Arc<boxcar::Vec<MethodImplRc>>;

/// Reference-counted pointer to a [`MethodImpl`] instance.
///
/// Enables efficient sharing of method implementation mapping data across multiple
/// contexts without duplication, supporting concurrent access patterns in method resolution.
pub type MethodImplRc = Arc<MethodImpl>;
