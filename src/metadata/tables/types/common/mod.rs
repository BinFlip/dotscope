//! Common types and infrastructure shared between read and write operations.
//!
//! This module contains the core metadata table types that are used by both
//! read-only and write-capable operations. These foundational types provide
//! the basic building blocks for table identification, size calculation,
//! and cross-table references.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::types::TableId`] - Enumeration of all metadata table types with ECMA-335 identifiers
//! - [`crate::metadata::tables::types::TableInfo`] - Size and configuration metadata for heap indices and table dimensions
//! - [`crate::metadata::tables::types::CodedIndex`] - Type-safe compact references between metadata tables
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`], enabling safe concurrent
//! access across multiple threads without additional synchronization.

mod codedindex;
mod id;
mod info;

pub use codedindex::*;
pub use id::*;
pub use info::*;
