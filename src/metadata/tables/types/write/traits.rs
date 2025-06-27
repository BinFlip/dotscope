//! Trait definitions for metadata table serialization and binary writing.
//!
//! This module provides the core trait abstractions for serializing metadata table entries
//! back to their binary representation. It enables the modification and reconstruction of
//! .NET metadata tables, supporting scenarios like metadata editing, patching, and custom
//! assembly generation.
//!
//! ## Core Traits
//!
//! - [`RowWritable`] - Primary trait for serializing individual table rows
//!
//! ## Design Principles
//!
//! The write traits follow these design principles:
//! - **Type Safety**: All serialization operations are compile-time checked
//! - **Memory Safety**: Buffer bounds are validated during write operations
//! - **Performance**: Traits support parallel processing of table entries
//! - **Specification Compliance**: All output follows ECMA-335 binary format
//!
//! ## Thread Safety
//!
//! All traits in this module are designed for concurrent use, with implementations
//! required to be `Send` and optionally `Sync` depending on the specific trait.
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::types::read::traits`] - Corresponding read traits
//! - [`crate::metadata::tables::types::write::table`] - Table-level write operations
//! - [`crate::metadata::tables::types::write::data`] - Low-level data serialization

use crate::{
    metadata::tables::{TableInfoRef, TableRow},
    Result,
};

/// Trait defining the interface for serializing and writing metadata table rows.
///
/// This trait must be implemented by any type that represents a row in a metadata table
/// and supports writing its data back to a byte buffer. It provides the necessary methods
/// for serializing row data, enabling generic table write operations.
///
/// ## Implementation Requirements
///
/// Types implementing this trait must:
/// - Be `Sync` to support parallel writing
/// - Handle serialization errors gracefully
/// - Support 1-based row indexing (as per CLI specification)
pub trait RowWritable: Sized + Send + TableRow {
    /// Serializes and writes a single row into the provided byte buffer.
    ///
    /// This method encodes one complete row into the metadata table data,
    /// advancing the offset pointer to the next row position. The row ID follows
    /// the CLI specification's 1-based indexing scheme.
    ///
    /// ## Arguments
    ///
    /// * `self` - The row instance to serialize
    /// * `data` - The mutable byte buffer to write the row data into
    /// * `offset` - Mutable reference to the current write position, automatically
    ///   advanced by the number of bytes written
    /// * `rid` - The 1-based row identifier for this entry (starts at 1, not 0)
    /// * `sizes` - Table size information for serializing variable-sized fields
    ///
    /// ## Returns
    ///
    /// Returns a [`crate::Result`] indicating success or failure.
    ///
    /// ## Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - [`crate::Error`] - When the buffer lacks space or row data is invalid
    /// - [`crate::Error`] - When heap indices reference invalid locations
    /// - [`crate::Error`] - When row identifiers are out of valid range
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()>;
}
