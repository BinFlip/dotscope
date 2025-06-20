use crate::{metadata::tables::types::common::TableInfoRef, Result};

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
