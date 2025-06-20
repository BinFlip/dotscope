use crate::{metadata::tables::types::common::TableInfoRef, Result};

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
pub trait RowWritable: Sized + Send {
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
