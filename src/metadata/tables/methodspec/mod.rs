//! # `MethodSpec` Table Module
//!
//! This module provides comprehensive access to the **`MethodSpec`** metadata table (ID 0x2B),
//! which represents instantiations of generic methods in .NET assemblies. The table is essential
//! for resolving generic method calls with concrete type arguments, enabling proper generic
//! method dispatch and type safety at runtime.
//!
//! ## Overview
//!
//! The `MethodSpec` table handles generic method instantiation by:
//! - **Method References**: Linking to the generic method definition or member reference
//! - **Type Arguments**: Specifying concrete types for generic parameters
//! - **Instantiation**: Creating concrete method instances from generic templates
//! - **Resolution**: Enabling runtime dispatch to properly typed method implementations
//!
//! Each entry represents a specific instantiation of a generic method with concrete type
//! arguments, allowing the runtime to generate optimized code for each unique instantiation.
//!
//! ## Components
//!
//! The module implements a dual-representation pattern for optimal performance:
//!
//! - [`MethodSpecRaw`] - Raw table data with unresolved indexes for initial parsing
//! - [`MethodSpec`] - Processed data with resolved references and parsed signatures
//! - [`MethodSpecLoader`] - Handles conversion between raw and processed representations
//! - [`MethodSpecMap`] - Thread-safe storage mapping tokens to processed entries
//! - [`MethodSpecList`] - Thread-safe collection of all method spec entries
//!
//! ## Table Structure
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Method` | `u32` | `MethodDefOrRef` coded index to the generic method |
//! | `Instantiation` | `u32` | Index into blob heap containing method spec signature |
//!
//! The `Instantiation` blob contains a [`MethodSpecSignature`](crate::metadata::signatures::SignatureMethodSpec)
//! specifying the concrete type arguments for the generic method parameters.
//!
//! ## Generic Method Instantiation
//!
//! Generic methods are instantiated using the following process:
//!
//! 1. **Method Resolution**: The `Method` field is resolved to the actual generic method
//! 2. **Signature Parsing**: The `Instantiation` blob is parsed to extract type arguments
//! 3. **Type Resolution**: Each type argument is resolved using the type registry
//! 4. **Application**: The instantiation is applied to the target method
//! 5. **Registration**: The instantiated method is registered for runtime use
//!
//! ## ECMA-335 Specification
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22.29** - `MethodSpec` table structure and semantics
//! - **§II.24.2.7** - `MethodDefOrRef` coded index encoding
//! - **§II.23.2.15** - `MethodSpec` signature format
//! - **§II.10.1.7** - Generic method instantiation semantics
//!
//! For detailed specifications, see [ECMA-335 6th Edition](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).

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

/// Thread-safe map holding the mapping of [`crate::metadata::token::Token`] to parsed [`MethodSpec`] entries.
///
/// This concurrent skip list provides efficient O(log n) access to method specification entries
/// by their metadata token, supporting multiple concurrent readers and writers.
pub type MethodSpecMap = SkipMap<Token, MethodSpecRc>;

/// Thread-safe vector holding a list of [`MethodSpec`] entries.
///
/// Uses a lock-free vector implementation for efficient concurrent access to
/// the collection of all method specification entries in the metadata.
pub type MethodSpecList = Arc<boxcar::Vec<MethodSpecRc>>;

/// Reference-counted pointer to a [`MethodSpec`] entry.
///
/// Enables efficient sharing of method specification data across multiple contexts
/// while maintaining memory safety through automatic reference counting.
pub type MethodSpecRc = Arc<MethodSpec>;
