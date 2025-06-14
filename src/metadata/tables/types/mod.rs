mod codedindex;
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

/// Trait for common row functionality
pub trait RowDefinition<'a>: Sized + Send {
    /// Get the size of the current table row
    ///
    /// ## Arguments
    /// * 'sizes' - Provide input of the metadata heapsizes for the calculation
    fn row_size(sizes: &TableInfoRef) -> u32;
    /// Get a specific row, at a specific offset
    ///
    /// ## Arguments
    /// * 'data'    - The data buffer to read from
    /// * 'offset'  - The offset in the buffer to read from
    /// * 'rid'     - The row id of this entry (starting at 1)
    /// * 'sizes'   - Indicator of sizes taken from the metadata
    ///
    /// # Errors
    /// Returns an error if the data cannot be parsed or is insufficient
    fn read_row(data: &'a [u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef)
        -> Result<Self>;
}

/// The foundation of any metadata table
pub struct MetadataTable<'a, T> {
    data: &'a [u8],
    row_count: u32,
    row_size: u32,
    sizes: TableInfoRef,
    _phantom: Arc<PhantomData<T>>,
}

impl<'a, T: RowDefinition<'a>> MetadataTable<'a, T> {
    /// Create a new table from a data stream
    ///
    /// ## Arguments
    /// * 'data'        - The data buffer to read from
    /// * '`row_count`'   - The amount of rows in this table
    /// * 'sizes'       - Indicator of sizes taken from the metadata
    ///
    /// # Errors
    /// Returns an error if the table cannot be created from the provided data
    pub fn new(data: &'a [u8], row_count: u32, sizes: TableInfoRef) -> Result<Self> {
        Ok(MetadataTable {
            data,
            row_count,
            row_size: T::row_size(&sizes),
            sizes,
            _phantom: Arc::new(PhantomData),
        })
    }

    /// Get the full size of this table in bytes
    // ToDo: Maybe don't return u64 but usize
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::from(self.row_count) * u64::from(self.row_size)
    }

    /// Get the size of one single row in bytes
    #[must_use]
    pub fn size_row(&self) -> u32 {
        self.row_size
    }

    /// Get the row count of this table
    #[must_use]
    pub fn row_count(&self) -> u32 {
        self.row_count
    }

    /// Get a specific row of this table
    ///
    /// ## Arguments
    /// * 'index' - The index of the row to be retrieved
    #[must_use]
    pub fn get(&self, index: u32) -> Option<T> {
        if index == 0 || self.row_count < index {
            return None;
        }

        T::read_row(
            self.data,
            &mut ((index as usize - 1) * self.row_size as usize),
            index,
            &self.sizes,
        )
        .ok()
    }

    /// Get an iterator to enumerate all rows of this table
    #[must_use]
    pub fn iter(&'a self) -> TableIterator<'a, T> {
        TableIterator {
            table: self,
            current_row: 0,
            current_offset: 0,
        }
    }

    /// Get a parallel iterator to enumerate all rows of this table
    #[must_use]
    pub fn par_iter(&'a self) -> TableParIterator<'a, T> {
        TableParIterator {
            table: self,
            range: 0..self.row_count,
        }
    }
}

impl<'a, T: RowDefinition<'a>> IntoIterator for &'a MetadataTable<'a, T> {
    type Item = T;
    type IntoIter = TableIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator to enumerate all rows of a table
pub struct TableIterator<'a, T> {
    table: &'a MetadataTable<'a, T>,
    current_row: u32,
    current_offset: usize,
}

impl<'a, T: RowDefinition<'a>> Iterator for TableIterator<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_row >= self.table.row_count {
            return None;
        }

        match T::read_row(
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

/// Parallel iterator to enumerate all rows of a table
pub struct TableParIterator<'a, T> {
    table: &'a MetadataTable<'a, T>,
    range: std::ops::Range<u32>,
}

// Extension methods for more efficient parallel operations
impl<'a, T: RowDefinition<'a> + Send + Sync + 'a> TableParIterator<'a, T> {
    /// Process the iterator in parallel with early error detection
    ///
    /// # Errors
    ///
    /// Returns an error if any operation fails during parallel processing.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
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

impl<'a, T: RowDefinition<'a> + Send + Sync> ParallelIterator for TableParIterator<'a, T> {
    type Item = T;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        plumbing::bridge(self, consumer)
    }
}

impl<'a, T: RowDefinition<'a> + Send + Sync> IndexedParallelIterator for TableParIterator<'a, T> {
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

struct TableProducer<'a, T> {
    table: &'a MetadataTable<'a, T>,
    range: std::ops::Range<u32>,
}

impl<'a, T: RowDefinition<'a> + Send + Sync> rayon::iter::plumbing::Producer
    for TableProducer<'a, T>
{
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

struct TableProducerIterator<'a, T> {
    table: &'a MetadataTable<'a, T>,
    range: std::ops::Range<u32>,
}

impl<'a, T: RowDefinition<'a> + Send + Sync> Iterator for TableProducerIterator<'a, T> {
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

impl<'a, T: RowDefinition<'a> + Send + Sync> ExactSizeIterator for TableProducerIterator<'a, T> {}

// Implement DoubleEndedIterator for compatibility with Rayon
impl<'a, T: RowDefinition<'a> + Send + Sync> DoubleEndedIterator for TableProducerIterator<'a, T> {
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
