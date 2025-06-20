//! Core infrastructure for .NET metadata table processing.
//!
//! This module provides the foundational types and traits for working with .NET CLI
//! metadata tables. It enables type-safe, efficient reading, iteration, and parallel
//! processing of metadata table entries from CLI assemblies, supporting both sequential
//! and concurrent access patterns.
//!
//! # Architecture
//!
//! The .NET metadata format organizes type, method, field, and other information in
//! structured tables following the ECMA-335 specification. This module provides generic
//! abstractions that work across all metadata table types while maintaining type safety
//! and performance. The design separates concerns between data access, iteration, and
//! row parsing to enable flexible usage patterns.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::types::MetadataTable`] - Generic container providing typed access to table data
//! - [`crate::metadata::tables::types::RowReadable`] - Trait for parsing table rows from byte data
//! - [`crate::metadata::tables::types::RowWritable`] - Trait for serializing table rows to byte data
//! - [`crate::metadata::tables::types::TableIterator`] - Sequential iterator for table rows
//! - [`crate::metadata::tables::types::TableParIterator`] - Parallel iterator for high-performance processing
//! - [`crate::metadata::tables::types::CodedIndex`] - Compact cross-table references with type safety
//! - [`crate::metadata::tables::types::TableId`] - Enumeration of all metadata table types
//! - [`crate::metadata::tables::types::TableInfo`] - Table size and configuration metadata
//! - [`crate::metadata::tables::types::TableData`] - Container for raw table data and metadata
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::tables::{MetadataTable, RowReadable, TableInfoRef};
//! use dotscope::Result;
//!
//! # struct ExampleRow { id: u32 }
//! # impl RowReadable for ExampleRow {
//! #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
//! #     fn row_read(_: &[u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> Result<Self> {
//! #         *offset += 4;
//! #         Ok(ExampleRow { id: rid })
//! #     }
//! # }
//! # fn example(data: &[u8], table_info: TableInfoRef) -> Result<()> {
//! // Create a metadata table with typed row access
//! let table: MetadataTable<ExampleRow> = MetadataTable::new(data, 100, table_info)?;
//!
//! // Sequential iteration over all rows
//! for row in &table {
//!     println!("Processing row ID: {}", row.id);
//! }
//!
//! // Parallel processing with error propagation
//! table.par_iter().try_for_each(|row| {
//!     // Each row processed in parallel threads
//!     process_row_data(&row)?;
//!     Ok(())
//! })?;
//! # Ok(())
//! # }
//! # fn process_row_data(_: &ExampleRow) -> Result<()> { Ok(()) }
//! ```
//!
//! # Error Handling
//!
//! This module defines error conditions for table processing:
//! - Row parsing errors when table data is malformed or incomplete
//! - Index validation errors for out-of-bounds heap references
//! - Buffer size errors when insufficient data is available
//!
//! # Thread Safety
//!
//! All types in this module are designed for concurrent access:
//! - [`crate::metadata::tables::types::MetadataTable`] is [`Send`] and [`Sync`] for sharing across threads
//! - Row types must implement [`Send`] (for [`crate::metadata::tables::types::RowReadable`]) or [`Sync`] (for [`crate::metadata::tables::types::RowWritable`])
//! - Parallel iterators provide lock-free concurrent processing
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Concrete table implementations using these types
//! - [`crate::metadata::heaps`] - String and blob heap access for resolving indices
//! - [`crate::file::physical`] - Physical file structure for data access
//!
//! # References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Partition II, Section 22
//! - [.NET Runtime Documentation](https://github.com/dotnet/runtime/tree/main/docs/design/coreclr/metadata)

mod access;
mod codedindex;
mod data;
mod id;
mod info;
mod iter;
mod table;

pub(crate) use access::TableAccess;
pub use codedindex::{CodedIndex, CodedIndexType, CodedIndexTypeIter};
pub use data::TableData;
pub use id::TableId;
pub use info::{TableInfo, TableInfoRef, TableRowInfo};
pub use iter::{TableIterator, TableParIterator};
pub use table::MetadataTable;

use crate::Result;

/// Trait defining the interface for reading and parsing metadata table rows.
///
/// This trait must be implemented by any type that represents a row in a metadata table.
/// It provides the necessary methods for determining row size and parsing row data from
/// byte buffers, enabling generic table operations.
///
/// ## Implementation Requirements
///
/// Types implementing this trait must:
/// - Be `Send` to support parallel processing
/// - Provide accurate row size calculations
/// - Handle parsing errors gracefully
/// - Support 1-based row indexing (as per CLI specification)
pub trait RowReadable: Sized + Send {
    /// Calculates the size in bytes of a single row for this table type.
    ///
    /// This method determines the total byte size needed to store one row of this
    /// table type, taking into account variable-sized fields such as string heap
    /// indices and blob heap indices that may be 2 or 4 bytes depending on heap size.
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information containing heap sizes and table row counts
    ///   used to determine the appropriate index sizes
    ///
    /// ## Returns
    ///
    /// The size in bytes required for one complete row of this table type.
    fn row_size(sizes: &TableInfoRef) -> u32;

    /// Reads and parses a single row from the provided byte buffer.
    ///
    /// This method extracts and parses one complete row from the metadata table data,
    /// advancing the offset pointer to the next row position. The row ID follows
    /// the CLI specification's 1-based indexing scheme.
    ///
    /// ## Arguments
    ///
    /// * `data` - The byte buffer containing the table data to read from
    /// * `offset` - Mutable reference to the current read position, automatically
    ///   advanced by the number of bytes consumed
    /// * `rid` - The 1-based row identifier for this entry (starts at 1, not 0)
    /// * `sizes` - Table size information for parsing variable-sized fields
    ///
    /// ## Returns
    ///
    /// Returns a [`Result`] containing the parsed row instance on success.
    ///
    /// ## Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - [`crate::Error`] - When the buffer contains insufficient data or malformed row structure
    /// - [`crate::Error`] - When heap indices reference invalid locations
    /// - [`crate::Error`] - When row identifiers are out of valid range
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self>;
}

/// Trait defining the interface for serializing and writing metadata table rows.
///
/// This trait must be implemented by any type that represents a row in a metadata table
/// and supports writing its data back to a byte buffer. It provides the necessary methods
/// for determining row size and serializing row data, enabling generic table write operations.
///
/// ## Implementation Requirements
///
/// Types implementing this trait must:
/// - Be `Sync` to support parallel writing
/// - Provide accurate row size calculations
/// - Handle serialization errors gracefully
/// - Support 1-based row indexing (as per CLI specification)
pub trait RowWritable: Sized + Sync {
    /// Calculates the size in bytes of a single row for this table type.
    ///
    /// This method determines the total byte size needed to serialize one row of this
    /// table type, taking into account variable-sized fields such as string heap
    /// indices and blob heap indices that may be 2 or 4 bytes depending on heap size.
    ///
    /// ## Arguments
    ///
    /// * `sizes` - Table size information containing heap sizes and table row counts
    ///   used to determine the appropriate index sizes
    ///
    /// ## Returns
    ///
    /// The size in bytes required for one complete row of this table type.
    fn row_size(sizes: &TableInfoRef) -> u32;

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
    /// Returns a [`Result`] indicating success or failure.
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
