//! # Metadata Table Types Module
//!
//! This module provides the core infrastructure for working with .NET metadata tables.
//! It defines generic types and traits that enable efficient reading, iteration, and
//! parallel processing of metadata table entries from CLI assemblies.
//!
//! ## Overview
//!
//! The .NET metadata format stores type, method, field, and other information in a
//! series of structured tables. This module provides the foundational abstractions
//! for working with these tables in a type-safe and efficient manner.
//!
//! ## Key Components
//!
//! ### Core Types
//!
//! - [`MetadataTable`]: Generic container for metadata table data with typed row access
//! - [`RowDefinition`]: Trait defining how to read and parse individual table rows
//! - [`TableIterator`]: Sequential iterator for table rows
//! - [`TableParIterator`]: Parallel iterator for high-performance table processing
//!
//! ### Supporting Infrastructure
//!
//! - [`CodedIndex`] and [`CodedIndexType`]: Compact cross-table references
//! - [`TableId`]: Enumeration of all metadata table types
//! - [`TableInfo`] and [`TableInfoRef`]: Table size and configuration information
//! - [`TableData`]: Container for raw table data and metadata
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use dotscope::metadata::tables::types::{MetadataTable, RowDefinition};
//! use dotscope::metadata::tables::TableInfoRef;
//!
//! // Example of working with a metadata table
//! # struct ExampleRow { id: u32 }
//! # impl<'a> RowDefinition<'a> for ExampleRow {
//! #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
//! #     fn read_row(_: &'a [u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
//! #         *offset += 4;
//! #         Ok(ExampleRow { id: rid })
//! #     }
//! # }
//! #
//! # fn example(data: &[u8], table_info: TableInfoRef) -> dotscope::Result<()> {
//! let table: MetadataTable<ExampleRow> = MetadataTable::new(data, 100, table_info)?;
//!
//! // Sequential iteration
//! for row in &table {
//!     println!("Row ID: {}", row.id);
//! }
//!
//! // Parallel processing with error handling
//! table.par_iter().try_for_each(|row| {
//!     // Process row in parallel
//!     println!("Processing row: {}", row.id);
//!     Ok(())
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! ## References
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
    /// Returns an error if:
    /// - The buffer contains insufficient data for a complete row
    /// - The row data is malformed or contains invalid values
    /// - Heap indices reference invalid or out-of-bounds locations
    /// - The row structure doesn't match the expected format
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self>;
}
