//! Generic metadata table container with typed row access and iteration support.
//!
//! This module provides the [`MetadataTable`] type, which serves as the primary interface
//! for working with .NET metadata tables. It offers type-safe access to table rows,
//! supporting both sequential and parallel iteration patterns commonly used in metadata
//! processing scenarios.
//!
//! ## Key Features
//!
//! - **Type Safety**: Compile-time guarantees for row type correctness
//! - **Performance**: Zero-copy access to underlying table data
//! - **Concurrency**: Built-in support for parallel row processing
//! - **Memory Efficiency**: Lazy parsing of rows on access
//!
//! ## Usage Patterns
//!
//! The table container supports several common access patterns:
//! - **Direct Access**: Random access to specific rows by index
//! - **Sequential Iteration**: Forward iteration through all rows
//! - **Parallel Processing**: Concurrent processing of multiple rows
//! - **Filtered Processing**: Selective row processing with iterator combinators
//!
//! ## Thread Safety
//!
//! `MetadataTable` is designed for concurrent read access, allowing multiple threads
//! to safely iterate over and access table data simultaneously without synchronization.
//!
//! ## Related Types
//!
//! - [`crate::metadata::tables::types::read::iter`] - Iterator implementations
//! - [`crate::metadata::tables::types::read::access`] - Low-level access utilities
//! - [`crate::metadata::tables::types::read::traits`] - Core trait definitions

use crate::{
    metadata::tables::{RowReadable, TableInfoRef, TableIterator, TableParIterator},
    Result,
};
use std::{marker::PhantomData, sync::Arc};

/// Generic container for metadata table data with typed row access.
///
/// This structure provides a high-level interface for working with .NET metadata tables,
/// offering both sequential and parallel iteration capabilities. It wraps raw table data
/// and provides type-safe access to individual rows through the [`crate::metadata::tables::types::RowReadable`] trait.
///
/// ## Type Parameters
///
/// * `'a` - Lifetime of the underlying byte data
/// * `T` - The row type that implements [`crate::metadata::tables::types::RowReadable`]
///
/// ## Examples
///
/// ### Basic Usage
/// ```rust,ignore
/// # use dotscope::metadata::tables::types::{MetadataTable, RowReadable};
/// # use dotscope::metadata::tables::TableInfoRef;
/// # struct MyRow { id: u32 }
/// # impl RowReadable for MyRow {
/// #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
/// #     fn row_read(_: &[u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
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
/// # use dotscope::metadata::tables::types::{MetadataTable, RowReadable};
/// # use dotscope::metadata::tables::TableInfoRef;
/// # use rayon::prelude::*;
/// # struct MyRow { id: u32 }
/// # impl RowReadable for MyRow {
/// #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
/// #     fn row_read(_: &[u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
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
    pub data: &'a [u8],
    /// Total number of rows in this table
    pub row_count: u32,
    /// Size in bytes of each row
    pub row_size: u32,
    /// Table configuration and size information
    pub sizes: TableInfoRef,
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
