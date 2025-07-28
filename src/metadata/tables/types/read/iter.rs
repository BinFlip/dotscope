//! Iterator implementations for sequential and parallel metadata table processing.
//!
//! This module provides iterator types that enable efficient traversal of metadata table rows
//! in both sequential and parallel modes. The iterators are designed to work seamlessly with
//! the Rust iterator ecosystem while providing specialized optimizations for metadata table
//! access patterns.
//!
//! ## Iterator Types
//!
//! - [`TableIterator`] - Sequential iterator for memory-efficient row-by-row processing
//! - [`TableParIterator`] - Parallel iterator leveraging Rayon for concurrent processing
//! - [`TableProducer`] - Internal work distribution for parallel iteration
//! - [`TableProducerIterator`] - Internal chunk processing for parallel iteration
//!
//! ## Design Goals
//!
//! The iterator design prioritizes:
//! - **Lazy evaluation**: Rows are parsed only when accessed, reducing memory usage
//! - **Error resilience**: Parse failures result in `None` rather than panics
//! - **Performance**: Optimal memory access patterns and parallel processing support
//!
//! ## Thread Safety
//!
//! All iterator types support concurrent access with appropriate safety guarantees:
//! - Sequential iterators are `Send` for thread transfer
//! - Parallel iterators require `Send + Sync` row types for safe concurrent processing
//! - Work-stealing algorithms ensure optimal load balancing across threads
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::types::read::table`] - Table container that creates iterators
//! - [`crate::metadata::tables::types::read::traits`] - Core parsing traits
//! - [`crate::metadata::tables::types::read::access`] - Low-level access utilities

use rayon::iter::{plumbing, IndexedParallelIterator, ParallelIterator};
use std::sync::{Arc, Mutex};

use crate::metadata::tables::{MetadataTable, RowReadable};

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
    pub table: &'a MetadataTable<'a, T>,
    /// Current row number (0-based for internal tracking)
    pub current_row: u32,
    /// Current byte offset in the table data
    pub current_offset: usize,
}

impl<T: RowReadable> Iterator for TableIterator<'_, T> {
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
    pub table: &'a MetadataTable<'a, T>,
    /// Range of row indices to process
    pub range: std::ops::Range<u32>,
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

impl<T: RowReadable + Send + Sync> ParallelIterator for TableParIterator<'_, T> {
    type Item = T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        plumbing::bridge(self, consumer)
    }
}

impl<T: RowReadable + Send + Sync> IndexedParallelIterator for TableParIterator<'_, T> {
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

impl<T: RowReadable + Send + Sync> Iterator for TableProducerIterator<'_, T> {
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

impl<T: RowReadable + Send + Sync> ExactSizeIterator for TableProducerIterator<'_, T> {}

// Implement DoubleEndedIterator for compatibility with Rayon
impl<T: RowReadable + Send + Sync> DoubleEndedIterator for TableProducerIterator<'_, T> {
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
