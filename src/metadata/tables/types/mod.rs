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

mod codedindex;
mod tableaccess;
mod tabledata;
mod tableid;
mod tableinfo;

use crate::Result;
use rayon::iter::{plumbing, IndexedParallelIterator, ParallelIterator};
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

pub use codedindex::{CodedIndex, CodedIndexType, CodedIndexTypeIter};
pub use tabledata::TableData;
pub use tableid::TableId;
pub use tableinfo::{TableInfo, TableInfoRef, TableRowInfo};

pub(crate) use tableaccess::TableAccess;

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

/// Generic container for metadata table data with typed row access.
///
/// This structure provides a high-level interface for working with .NET metadata tables,
/// offering both sequential and parallel iteration capabilities. It wraps raw table data
/// and provides type-safe access to individual rows through the [`RowDefinition`] trait.
///
/// ## Type Parameters
///
/// * `'a` - Lifetime of the underlying byte data
/// * `T` - The row type that implements [`RowDefinition`]
///
/// ## Examples
///
/// ### Basic Usage
/// ```rust,ignore
/// # use dotscope::metadata::tables::types::{MetadataTable, RowDefinition};
/// # use dotscope::metadata::tables::TableInfoRef;
/// # struct MyRow { id: u32 }
/// # impl<'a> RowDefinition<'a> for MyRow {
/// #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
/// #     fn read_row(_: &'a [u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
/// #         *offset += 4; Ok(MyRow { id: rid })
/// #     }
/// # }
/// # fn example(data: &[u8], table_info: TableInfoRef) -> dotscope::Result<()> {
/// let table: MetadataTable<MyRow> = MetadataTable::new(data, 100, table_info)?;
///
/// // Access specific rows
/// if let Some(first_row) = table.get(1) {
///     println!("First row ID: {}", first_row.id);
/// }
///
/// // Sequential iteration
/// for (index, row) in table.iter().enumerate() {
///     println!("Row {}: ID = {}", index + 1, row.id);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Parallel Processing
/// ```rust,ignore
/// # use dotscope::metadata::tables::types::{MetadataTable, RowDefinition};
/// # use dotscope::metadata::tables::TableInfoRef;
/// # use rayon::prelude::*;
/// # struct MyRow { id: u32 }
/// # impl<'a> RowDefinition<'a> for MyRow {
/// #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
/// #     fn row_read(_: &'a [u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
/// #         *offset += 4; Ok(MyRow { id: rid })
/// #     }
/// # }
/// # impl Send for MyRow {}
/// # impl Sync for MyRow {}
/// # fn example(data: &[u8], table_info: TableInfoRef) -> dotscope::Result<()> {
/// let table: MetadataTable<MyRow> = MetadataTable::new(data, 100, table_info)?;
///
/// // Parallel processing with automatic error handling
/// table.par_iter().try_for_each(|row| {
///     // Process each row in parallel
///     println!("Processing row: {}", row.id);
///     Ok(())
/// })?;
/// # Ok(())
/// # }
/// ```
pub struct MetadataTable<'a, T> {
    /// Reference to the raw table data bytes
    data: &'a [u8],
    /// Total number of rows in this table
    row_count: u32,
    /// Size in bytes of each row
    row_size: u32,
    /// Table configuration and size information
    sizes: TableInfoRef,
    /// Phantom data to maintain type information
    _phantom: Arc<PhantomData<T>>,
}

impl<'a, T: RowReadable> MetadataTable<'a, T> {
    /// Creates a new metadata table from raw byte data.
    ///
    /// This constructor initializes a new table wrapper around the provided byte data,
    /// calculating the appropriate row size based on the table configuration and
    /// setting up the necessary metadata for efficient access operations.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw byte buffer containing the table data
    /// * `row_count` - The total number of rows present in the table
    /// * `sizes` - Table configuration containing heap sizes and other metadata
    ///   required for proper row size calculation
    ///
    /// ## Returns
    ///
    /// Returns a [`Result`] containing the new [`MetadataTable`] instance on success.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The provided data buffer is too small for the specified row count
    /// - The table configuration is invalid or inconsistent
    /// - Row size calculation fails due to invalid size parameters
    pub fn new(data: &'a [u8], row_count: u32, sizes: TableInfoRef) -> Result<Self> {
        Ok(MetadataTable {
            data,
            row_count,
            row_size: T::row_size(&sizes),
            sizes,
            _phantom: Arc::new(PhantomData),
        })
    }

    /// Returns the total size of this table in bytes.
    ///
    /// Calculates the total memory footprint of the table by multiplying
    /// the number of rows by the size of each row.
    ///
    /// ## Returns
    ///
    /// The total size in bytes as a `u64` to accommodate large tables.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::from(self.row_count) * u64::from(self.row_size)
    }

    /// Returns the size of a single row in bytes.
    ///
    /// This value is calculated once during table construction based on the
    /// table configuration and remains constant for the lifetime of the table.
    ///
    /// ## Returns
    ///
    /// The size in bytes of each row in this table.
    #[must_use]
    pub fn row_size(&self) -> u32 {
        self.row_size
    }

    /// Returns the total number of rows in this table.
    ///
    /// This count represents the number of entries present in the metadata table
    /// and is used for bounds checking and iteration control.
    ///
    /// ## Returns
    ///
    /// The total number of rows available in this table.
    #[must_use]
    pub fn row_count(&self) -> u32 {
        self.row_count
    }

    /// Retrieves a specific row by its 1-based index.
    ///
    /// This method provides direct access to individual table rows using the
    /// CLI specification's 1-based indexing scheme. Row 0 is reserved and
    /// represents a null reference in the metadata format.
    ///
    /// ## Arguments
    ///
    /// * `index` - The 1-based row index to retrieve (must be between 1 and `row_count` inclusive)
    ///
    /// ## Returns
    ///
    /// Returns `Some(T)` if the row exists and can be parsed successfully,
    /// or `None` if the index is out of bounds or parsing fails.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<T> {
        if index == 0 || self.row_count < index {
            return None;
        }

        T::row_read(
            self.data,
            &mut ((index as usize - 1) * self.row_size as usize),
            index,
            &self.sizes,
        )
        .ok()
    }

    /// Creates a sequential iterator over all rows in the table.
    ///
    /// This method returns an iterator that will process each row in the table
    /// sequentially, parsing rows on-demand as the iterator advances. The iterator
    /// follows standard Rust iterator conventions and can be used with iterator
    /// combinators and for-loops.
    ///
    /// ## Returns
    ///
    /// A [`TableIterator`] that yields each row in sequence.
    #[must_use]
    pub fn iter(&'a self) -> TableIterator<'a, T> {
        TableIterator {
            table: self,
            current_row: 0,
            current_offset: 0,
        }
    }

    /// Creates a parallel iterator over all rows in the table.
    ///
    /// This method returns a parallel iterator that can process rows concurrently
    /// across multiple threads, providing significant performance improvements for
    /// large tables. The iterator integrates with the Rayon parallel processing
    /// framework and supports all standard parallel iterator operations.
    ///
    /// ## Returns
    ///
    /// A [`TableParIterator`] that can process rows in parallel.
    #[must_use]
    pub fn par_iter(&'a self) -> TableParIterator<'a, T> {
        TableParIterator {
            table: self,
            range: 0..self.row_count,
        }
    }
}

impl<'a, T: RowReadable> IntoIterator for &'a MetadataTable<'a, T> {
    type Item = T;
    type IntoIter = TableIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Sequential iterator for metadata table rows.
///
/// This iterator provides lazy, on-demand access to table rows in sequential order.
/// It maintains minimal state and parses rows only as they are requested, making
/// it memory-efficient for large tables.
///
/// ## Characteristics
///
/// - **Lazy evaluation**: Rows are parsed only when accessed
/// - **Memory efficient**: Constant memory usage regardless of table size
/// - **Error resilient**: Parsing errors result in `None` rather than panics
/// - **Cache friendly**: Sequential access pattern optimizes memory locality
pub struct TableIterator<'a, T> {
    /// Reference to the table being iterated
    table: &'a MetadataTable<'a, T>,
    /// Current row number (0-based for internal tracking)
    current_row: u32,
    /// Current byte offset in the table data
    current_offset: usize,
}

impl<'a, T: RowReadable> Iterator for TableIterator<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_row >= self.table.row_count {
            return None;
        }

        match T::row_read(
            self.table.data,
            &mut self.current_offset,
            self.current_row + 1,
            &self.table.sizes,
        ) {
            Ok(row) => {
                self.current_row += 1;
                Some(row)
            }
            Err(_) => None,
        }
    }
}

/// Parallel iterator for metadata table rows.
///
/// This iterator enables concurrent processing of table rows across multiple threads
/// using the Rayon parallel processing framework. It automatically distributes work
/// and handles synchronization, providing significant performance improvements for
/// CPU-intensive operations on large tables.
///
/// ## Features
///
/// - **Automatic parallelization**: Work is distributed across available CPU cores
/// - **Load balancing**: Dynamic work stealing ensures optimal CPU utilization  
/// - **Error handling**: Built-in support for early termination on errors
/// - **Type safety**: Compile-time guarantees about thread safety requirements
///
/// ## Requirements
///
/// The row type `T` must implement `Send + Sync` to enable safe parallel processing.
/// This ensures that rows can be safely transferred between threads and accessed
/// concurrently.
///
/// ## Usage
///
/// Created through [`MetadataTable::par_iter()`] and supports all Rayon parallel
/// iterator operations
pub struct TableParIterator<'a, T> {
    /// Reference to the table being iterated
    table: &'a MetadataTable<'a, T>,
    /// Range of row indices to process
    range: std::ops::Range<u32>,
}

// Extension methods for more efficient parallel operations
impl<'a, T: RowReadable + Send + Sync + 'a> TableParIterator<'a, T> {
    /// Processes the iterator in parallel with early error detection and termination.
    ///
    /// This method provides a parallel equivalent to the standard iterator's `try_for_each`,
    /// executing the provided operation on each row concurrently while monitoring for
    /// errors. If any operation fails, processing stops and the first error encountered
    /// is returned.
    ///
    /// ## Arguments
    ///
    /// * `op` - A closure that takes each row and returns a [`Result`]. Must be `Send + Sync`
    ///   to enable safe parallel execution.
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` if all operations complete successfully, or the first error
    /// encountered during parallel processing.
    ///
    /// # Panics
    ///
    /// This function will panic if the mutex is poisoned during error handling.
    ///
    /// # Errors
    ///
    /// Returns an error if any operation applied to an item returns an error. The first error encountered is returned.
    pub fn try_for_each<F>(self, op: F) -> crate::Result<()>
    where
        F: Fn(T) -> crate::Result<()> + Send + Sync,
    {
        let error = Arc::new(Mutex::new(None));

        self.for_each(|item| {
            if error.lock().unwrap().is_some() {
                return;
            }

            if let Err(e) = op(item) {
                let mut guard = error.lock().unwrap();
                if guard.is_none() {
                    *guard = Some(e);
                }
            }
        });

        match Arc::into_inner(error).unwrap().into_inner().unwrap() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<'a, T: RowReadable + Send + Sync> ParallelIterator for TableParIterator<'a, T> {
    type Item = T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        plumbing::bridge(self, consumer)
    }
}

impl<'a, T: RowReadable + Send + Sync> IndexedParallelIterator for TableParIterator<'a, T> {
    fn len(&self) -> usize {
        self.range.len()
    }

    fn drive<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::Consumer<Self::Item>,
    {
        plumbing::bridge(self, consumer)
    }

    fn with_producer<CB>(self, callback: CB) -> CB::Output
    where
        CB: rayon::iter::plumbing::ProducerCallback<Self::Item>,
    {
        callback.callback(TableProducer {
            table: self.table,
            range: self.range,
        })
    }
}

/// Internal producer for parallel iteration work distribution.
///
/// This struct implements the Rayon `Producer` trait to enable efficient work
/// distribution for parallel table iteration. It handles the splitting of table
/// ranges into smaller chunks that can be processed independently by different
/// threads.
///
/// ## Purpose
///
/// The producer is responsible for:
/// - Dividing table ranges into manageable chunks for parallel processing
/// - Creating iterators for each chunk that can be processed independently
/// - Supporting Rayon's work-stealing algorithm for optimal load balancing
///
/// ## Implementation Details
///
/// This is an internal implementation detail of the parallel iteration system
/// and is not intended for direct use by library consumers. It supports the
/// [`TableParIterator`] functionality transparently.
struct TableProducer<'a, T> {
    /// Reference to the table being processed
    table: &'a MetadataTable<'a, T>,
    /// Range of row indices for this producer to handle
    range: std::ops::Range<u32>,
}

impl<'a, T: RowReadable + Send + Sync> rayon::iter::plumbing::Producer for TableProducer<'a, T> {
    type Item = T;
    type IntoIter = TableProducerIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        TableProducerIterator {
            table: self.table,
            range: self.range,
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        // Index represents table row positions which are expected to fit in u32
        #[allow(clippy::cast_possible_truncation)]
        let mid = self.range.start + index as u32;
        let left = TableProducer {
            table: self.table,
            range: self.range.start..mid,
        };
        let right = TableProducer {
            table: self.table,
            range: mid..self.range.end,
        };
        (left, right)
    }
}

/// Internal iterator for parallel iteration chunks.
///
/// This iterator processes a specific range of table rows as part of the parallel
/// iteration system. Each thread in the parallel processing pool receives its own
/// instance of this iterator to process a subset of the total table rows.
///
/// ## Characteristics
///
/// - **Bounded range**: Processes only a specific subset of table rows
/// - **Double-ended**: Supports iteration from both ends for work stealing
/// - **Exact size**: Provides precise size information for optimization
/// - **Thread-local**: Each thread operates on its own iterator instance
///
/// ## Implementation Details
///
/// This is an internal component of the parallel iteration infrastructure and
/// is not exposed directly to library users. It enables the work-stealing
/// algorithm used by Rayon for optimal parallel performance.
struct TableProducerIterator<'a, T> {
    /// Reference to the table being processed
    table: &'a MetadataTable<'a, T>,
    /// Range of row indices for this iterator to process
    range: std::ops::Range<u32>,
}

impl<'a, T: RowReadable + Send + Sync> Iterator for TableProducerIterator<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.start >= self.range.end {
            return None;
        }

        let row_index = self.range.start;
        self.range.start += 1;

        // Get the row directly from the table
        // +1 because row indices start at 1
        self.table.get(row_index + 1)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.range.len();
        (len, Some(len))
    }
}

impl<'a, T: RowReadable + Send + Sync> ExactSizeIterator for TableProducerIterator<'a, T> {}

// Implement DoubleEndedIterator for compatibility with Rayon
impl<'a, T: RowReadable + Send + Sync> DoubleEndedIterator for TableProducerIterator<'a, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.range.start >= self.range.end {
            return None;
        }

        self.range.end -= 1;

        // Get the row directly from the table
        // +1 because row indices start at 1
        self.table.get(self.range.end + 1)
    }
}
