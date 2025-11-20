//! Table metadata and size information for .NET metadata tables.
//!
//! This module provides utilities for tracking metadata table properties such as row counts,
//! index sizes, and coded index calculations. These structures are essential for properly
//! parsing .NET assemblies where table and heap sizes determine the byte width of various
//! reference fields.
//!
//! ## Key Components
//!
//! - [`crate::metadata::tables::types::TableRowInfo`] - Information about individual table sizes and indexing requirements
//! - [`crate::metadata::tables::types::TableInfo`] - Comprehensive metadata for all tables in an assembly
//! - [`crate::metadata::tables::types::TableInfoRef`] - Shared reference to table information
//!
//! ## Index Size Determination
//!
//! The .NET metadata format uses variable-width indices to optimize space usage:
//!
//! - **Table Indices**: 2 bytes if table has ≤65535 rows, 4 bytes otherwise
//! - **Heap Indices**: Size determined by heap size flags in metadata header
//! - **Coded Indices**: Size calculated based on maximum table size in the coded index union
//!
//! ## Reference
//!
//! * [ECMA-335 Partition II, Section 22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata Tables
//! * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded Indices

use std::sync::Arc;
use strum::{EnumCount, IntoEnumIterator};

use crate::{
    metadata::tables::types::{CodedIndexType, TableId},
    utils::{read_le, read_le_at},
    Result,
};

/// Information about the size and indexing properties of a metadata table.
///
/// This structure tracks essential properties of individual metadata tables that determine
/// how references to table entries are encoded in the assembly binary format.
///
/// ## Fields
///
/// - **`rows`**: Total number of entries in this table
/// - **`bits`**: Minimum bits required to represent any valid row index
/// - **`is_large`**: Whether this table requires 4-byte indices (>65535 rows)
///
/// ## Index Size Calculation
///
/// Tables with more than 65535 rows require 4-byte indices instead of the standard 2-byte
/// indices. This affects the binary layout of any structure that references this table.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct TableRowInfo {
    /// The total number of rows/entries in this table.
    ///
    /// This count determines whether the table requires 2-byte or 4-byte indices
    /// when referenced from other metadata structures.
    pub rows: u32,

    /// The minimum number of bits required to represent any valid row index.
    ///
    /// Calculated as `ceil(log2(rows))`, this value determines the minimum
    /// bit width needed for efficient storage of table indices.
    pub bits: u8,

    /// Whether this table requires large (4-byte) indices due to size.
    ///
    /// Set to `true` when `rows > 65535`, indicating that references to this
    /// table must use 4-byte indices instead of the standard 2-byte indices.
    pub is_large: bool,
}

impl TableRowInfo {
    /// Creates a new `TableRowInfo` instance with the given row count.
    ///
    /// Automatically calculates the number of bits required to represent
    /// indices into a table with the specified number of rows, and determines
    /// whether large (4-byte) indices are required.
    ///
    /// ## Algorithm
    ///
    /// - **Bit calculation**: `ceil(log2(rows))` or 1 for empty tables
    /// - **Large table detection**: `rows > 65535` requires 4-byte indices
    ///
    /// ## Arguments
    ///
    /// * `rows` - The number of rows in the table
    ///
    /// ## Returns
    ///
    /// A new [`TableRowInfo`] instance with calculated indexing properties.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(rows: u32) -> Self {
        let bits = if rows == 0 {
            1
        } else {
            let zeros = rows.leading_zeros();
            // Safe: 32 - zeros is always <= 32, fits in u8
            (32 - zeros) as u8
        };

        Self {
            rows,
            bits,
            is_large: rows > u32::from(u16::MAX),
        }
    }
}

/// Comprehensive metadata and size information for all .NET metadata tables.
///
/// This structure maintains detailed information about table sizes, heap properties,
/// and coded index calculations for an entire .NET assembly. It serves as the central
/// repository for layout information needed to correctly parse metadata structures.
///
/// ## Core Functionality
///
/// - **Table Sizing**: Tracks row counts and determines index sizes for all metadata tables
/// - **Heap Information**: Stores heap size flags that control string/GUID/blob index widths
/// - **Coded Index Caching**: Pre-calculates and caches coded index sizes for performance
///
/// ## Layout Determination
///
/// The .NET metadata format uses variable-width indices to optimize space:
///
/// ```text
/// Table Index Sizes:
/// - Tables with ≤65535 rows → 2-byte indices
/// - Tables with >65535 rows → 4-byte indices
///
/// Heap Index Sizes (from heap size flags):
/// - #String heap → 2 or 4 bytes
/// - #GUID heap   → 2 or 4 bytes  
/// - #Blob heap   → 2 or 4 bytes
/// ```
///
/// ## Related Types
///
/// - [`crate::metadata::tables::types::TableRowInfo`] - Individual table metadata
/// - [`crate::metadata::tables::types::TableInfoRef`] - Arc-wrapped shared reference
/// - [`crate::metadata::tables::types::CodedIndexType`] - Coded index type definitions
/// - [`crate::metadata::tables::types::TableId`] - Table identifier enumeration
#[derive(Clone, Default)]
pub struct TableInfo {
    /// Metadata for each table type, indexed by [`TableId`] as usize.
    ///
    /// Contains row count and indexing information for all possible metadata tables.
    /// Empty tables may have default values if not present in the assembly.
    rows: Vec<TableRowInfo>,

    /// Cached bit sizes for coded index types, indexed by [`CodedIndexType`] as usize.
    ///
    /// Pre-calculated during construction to avoid repeated computation during parsing.
    /// Values represent the number of bits needed to encode coded indices of each type.
    coded_indexes: Vec<u8>,

    /// Whether the #String heap requires 4-byte indices instead of 2-byte.
    ///
    /// Determined by bit 0 of the heap size flags in the metadata tables header.
    /// When `true`, all string heap references use 4 bytes; when `false`, 2 bytes.
    is_large_index_str: bool,

    /// Whether the #GUID heap requires 4-byte indices instead of 2-byte.
    ///
    /// Determined by bit 1 of the heap size flags in the metadata tables header.
    /// When `true`, all GUID heap references use 4 bytes; when `false`, 2 bytes.
    is_large_index_guid: bool,

    /// Whether the #Blob heap requires 4-byte indices instead of 2-byte.
    ///
    /// Determined by bit 2 of the heap size flags in the metadata tables header.
    /// When `true`, all blob heap references use 4 bytes; when `false`, 2 bytes.
    is_large_index_blob: bool,
}

/// Shared reference to a [`TableInfo`] structure for efficient multi-threaded access.
///
/// This type alias provides a convenient way to share table information across
/// multiple threads without copying the underlying data. The Arc wrapper ensures
/// thread-safe reference counting while maintaining immutability of the table metadata.
pub type TableInfoRef = Arc<TableInfo>;

impl TableInfo {
    /// Constructs a new `TableInfo` from metadata tables header data.
    ///
    /// Parses the metadata tables header to extract table row counts and heap size flags,
    /// then calculates all necessary index sizes and coded index bit requirements.
    ///
    /// ## Format Overview
    ///
    /// The metadata tables header contains:
    /// ```text
    /// Offset | Size | Description
    /// -------|------|-------------
    /// 0      | 4    | Reserved (should be 0)
    /// 4      | 1    | Major version
    /// 5      | 1    | Minor version
    /// 6      | 1    | Heap size flags
    /// 7      | 1    | Reserved (should be 1)
    /// 8      | 8    | Valid table mask (bit vector)
    /// 16     | 8    | Sorted table mask
    /// 24+    | 4×N  | Row counts for valid tables
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `data` - Raw metadata tables header bytes starting from the tables header
    /// * `valid_bitvec` - 64-bit mask indicating which tables are present (bit N = `TableId` N)
    ///
    /// ## Returns
    ///
    /// A fully initialized [`TableInfo`] with calculated index sizes and cached coded index information.
    ///
    /// ## Errors
    ///
    /// - [`crate::Error::OutOfBounds`] - Insufficient data to read required header fields
    ///
    /// ## Reference
    ///
    /// * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - #~ Stream
    pub fn new(data: &[u8], valid_bitvec: u64) -> Result<Self> {
        let mut table_info =
            vec![TableRowInfo::default(); TableId::CustomDebugInformation as usize + 1];
        let mut next_row_offset = 24;

        for table_id in TableId::iter() {
            if data.len() < next_row_offset {
                return Err(out_of_bounds_error!());
            }

            if (valid_bitvec & (1 << table_id as usize)) == 0 {
                continue;
            }

            let row_count = read_le_at::<u32>(data, &mut next_row_offset)?;
            if row_count == 0 {
                // Empty tables should be omitted during compliation and not being present in a valid sample
                // return Err(Malformed)
                continue;
            }

            table_info[table_id as usize] = TableRowInfo::new(row_count);
        }

        let heap_size_flags = read_le::<u8>(&data[6..])?;
        let mut table_info = TableInfo {
            rows: table_info,
            coded_indexes: vec![0; CodedIndexType::COUNT],
            is_large_index_str: heap_size_flags & 1 == 1,
            is_large_index_guid: heap_size_flags & 2 == 2,
            is_large_index_blob: heap_size_flags & 4 == 4,
        };

        table_info.calculate_coded_index_bits();

        Ok(table_info)
    }

    #[cfg(test)]
    /// Special constructor for unit tests with controlled table configuration.
    ///
    /// This method allows precise control over table sizes and heap configurations
    /// for testing scenarios without requiring actual metadata header data.
    ///
    /// ## Arguments
    ///
    /// * `valid_tables` - Slice of (table_id, row_count) pairs for tables to populate
    /// * `large_str` - Whether the #String heap uses 4-byte indices
    /// * `large_blob` - Whether the #Blob heap uses 4-byte indices  
    /// * `large_guid` - Whether the #GUID heap uses 4-byte indices
    ///
    /// ## Returns
    ///
    /// A [`TableInfo`] instance configured with the specified parameters and
    /// calculated coded index sizes.
    pub fn new_test(
        valid_tables: &[(TableId, u32)],
        large_str: bool,
        large_blob: bool,
        large_guid: bool,
    ) -> Self {
        let mut table_info = TableInfo {
            rows: vec![TableRowInfo::default(); TableId::CustomDebugInformation as usize + 1],
            coded_indexes: vec![0; CodedIndexType::COUNT],
            is_large_index_str: large_str,
            is_large_index_guid: large_guid,
            is_large_index_blob: large_blob,
        };

        for valid_table in valid_tables {
            table_info.rows[valid_table.0 as usize] = TableRowInfo::new(valid_table.1);
        }

        table_info.calculate_coded_index_bits();
        table_info
    }

    /// Decodes a coded index value into its component table and row index.
    ///
    /// Coded indices pack both a table identifier and row index into a single value
    /// using a tag-based encoding scheme. The lower bits contain a tag that identifies
    /// which table the index refers to, while the upper bits contain the actual row index.
    ///
    /// ## Encoding Format
    ///
    /// ```text
    /// Coded Index Value:
    /// ┌─────────────────────┬────────────┐
    /// │     Row Index       │    Tag     │
    /// │   (upper bits)      │(lower bits)│
    /// └─────────────────────┴────────────┘
    ///
    /// Tag bits = ceil(log2(number_of_tables_in_union))
    /// Row bits = remaining bits
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `value` - The encoded coded index value to decode
    /// * `coded_index_type` - The type of coded index being decoded (determines table union)
    ///
    /// ## Returns
    ///
    /// A tuple containing (`TableId`, `row_index`) where:
    /// - `TableId` - The specific table identified by the tag
    /// - `row_index` - The 1-based row index within that table
    ///
    /// ## Errors
    ///
    /// - [`crate::Error::OutOfBounds`] - Tag value exceeds the number of tables in the coded index union
    ///
    /// ## Reference
    ///
    /// * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded Indices
    pub fn decode_coded_index(
        &self,
        value: u32,
        coded_index_type: CodedIndexType,
    ) -> Result<(TableId, u32)> {
        let tables = coded_index_type.tables();
        // Calculate the number of bits needed for the tag
        // This casting is intentional for the coded index calculation
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let tag_bits = (tables.len() as f32).log2().ceil() as u8;
        let tag_mask = (1 << tag_bits) - 1;

        let tag = value & tag_mask;
        let index = value >> tag_bits;

        if tag as usize >= tables.len() {
            return Err(out_of_bounds_error!());
        }

        Ok((tables[tag as usize], index))
    }

    /// Encodes a table identifier and row index into a coded index value.
    ///
    /// This method performs the reverse operation of `decode_coded_index`, combining
    /// a table identifier and row index into a single encoded value using the tag-based
    /// encoding scheme defined by ECMA-335.
    ///
    /// ## Encoding Format
    ///
    /// ```text
    /// Coded Index Value:
    /// ┌─────────────────────┬────────────┐
    /// │     Row Index       │    Tag     │
    /// │   (upper bits)      │(lower bits)│
    /// └─────────────────────┴────────────┘
    ///
    /// Tag bits = ceil(log2(number_of_tables_in_union))
    /// Row bits = remaining bits
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] identifying which table the index refers to
    /// * `row` - The 1-based row index within the specified table
    /// * `coded_index_type` - The type of coded index being encoded (determines table union)
    ///
    /// ## Returns
    ///
    /// The encoded coded index value that can be written to metadata.
    ///
    /// ## Errors
    ///
    /// - [`crate::Error::OutOfBounds`] - Table ID is not valid for the specified coded index type
    ///
    /// ## Reference
    ///
    /// * [ECMA-335 Partition II, Section 24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Coded Indices
    pub fn encode_coded_index(
        &self,
        table_id: TableId,
        row: u32,
        coded_index_type: CodedIndexType,
    ) -> Result<u32> {
        let tables = coded_index_type.tables();

        let tag = tables
            .iter()
            .position(|&table| table == table_id)
            .ok_or(out_of_bounds_error!())?;

        // Calculate the number of bits needed for the tag
        // This casting is intentional for the coded index calculation
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let tag_bits = (tables.len() as f32).log2().ceil() as u8;

        // Encode: (row << tag_bits) | tag
        // Tag cast is safe as table count is limited by metadata format
        #[allow(clippy::cast_possible_truncation)]
        let encoded = (row << tag_bits) | (tag as u32);

        Ok(encoded)
    }

    /// Checks whether a specific table requires large (4-byte) indices due to size.
    ///
    /// Tables with more than 65535 rows cannot be addressed using 2-byte indices,
    /// requiring all references to that table to use 4-byte indices instead.
    ///
    /// ## Arguments
    ///
    /// * `id` - The [`TableId`] to query for large index requirement
    ///
    /// ## Returns
    ///
    /// `true` if the table has more than 65535 rows and requires 4-byte indices,
    /// `false` if 2-byte indices are sufficient.
    #[must_use]
    pub fn is_large(&self, id: TableId) -> bool {
        self.rows[id as usize].is_large
    }

    /// Returns whether the #String heap uses large (4-byte) indices.
    ///
    /// The size of string heap indices is determined by heap size flags in the
    /// metadata tables header. Large heaps require 4-byte indices instead of 2-byte.
    ///
    /// ## Returns
    ///
    /// `true` if string heap references use 4 bytes, `false` if they use 2 bytes.
    #[must_use]
    pub fn is_large_str(&self) -> bool {
        self.is_large_index_str
    }

    /// Returns whether the #GUID heap uses large (4-byte) indices.
    ///
    /// The size of GUID heap indices is determined by heap size flags in the
    /// metadata tables header. Large heaps require 4-byte indices instead of 2-byte.
    ///
    /// ## Returns
    ///
    /// `true` if GUID heap references use 4 bytes, `false` if they use 2 bytes.
    #[must_use]
    pub fn is_large_guid(&self) -> bool {
        self.is_large_index_guid
    }

    /// Returns whether the #Blob heap uses large (4-byte) indices.
    ///
    /// The size of blob heap indices is determined by heap size flags in the
    /// metadata tables header. Large heaps require 4-byte indices instead of 2-byte.
    ///
    /// ## Returns
    ///
    /// `true` if blob heap references use 4 bytes, `false` if they use 2 bytes.
    #[must_use]
    pub fn is_large_blob(&self) -> bool {
        self.is_large_index_blob
    }

    /// Returns the byte size of #String heap indices.
    ///
    /// ## Returns
    ///
    /// `4` if the string heap uses large indices, `2` otherwise.
    #[must_use]
    pub fn str_bytes(&self) -> u8 {
        if self.is_large_index_str {
            4
        } else {
            2
        }
    }

    /// Returns the byte size of #GUID heap indices.
    ///
    /// ## Returns
    ///
    /// `4` if the GUID heap uses large indices, `2` otherwise.
    #[must_use]
    pub fn guid_bytes(&self) -> u8 {
        if self.is_large_index_guid {
            4
        } else {
            2
        }
    }

    /// Returns the byte size of #Blob heap indices.
    ///
    /// ## Returns
    ///
    /// `4` if the blob heap uses large indices, `2` otherwise.
    #[must_use]
    pub fn blob_bytes(&self) -> u8 {
        if self.is_large_index_blob {
            4
        } else {
            2
        }
    }

    /// Returns the metadata information for a specific table.
    ///
    /// Provides access to the [`TableRowInfo`] structure containing row count,
    /// bit requirements, and large index status for the specified table.
    ///
    /// ## Arguments
    ///
    /// * `table` - The [`TableId`] for which to retrieve metadata
    ///
    /// ## Returns
    ///
    /// A reference to the [`TableRowInfo`] for the specified table.
    #[must_use]
    pub fn get(&self, table: TableId) -> &TableRowInfo {
        &self.rows[table as usize]
    }

    /// Returns the number of bits required to represent an index into a specific table.
    ///
    /// This value represents the minimum number of bits needed to address any valid
    /// row in the specified table. It's calculated as `ceil(log2(row_count))` or 1
    /// for empty tables.
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] for which to calculate the index bit size
    ///
    /// ## Returns
    ///
    /// The number of bits required to represent table indices (1-32).
    #[must_use]
    pub fn table_index_bits(&self, table_id: TableId) -> u8 {
        self.rows[table_id as usize].bits
    }

    /// Returns the number of bytes required to represent an index into a specific table.
    ///
    /// Converts the bit requirement into actual byte storage size. Tables requiring
    /// more than 16 bits (>65535 rows) use 4-byte indices, otherwise 2-byte indices.
    ///
    /// ## Arguments
    ///
    /// * `table_id` - The [`TableId`] for which to calculate the index byte size
    ///
    /// ## Returns
    ///
    /// Either `2` for small tables or `4` for large tables.
    #[must_use]
    pub fn table_index_bytes(&self, table_id: TableId) -> u8 {
        if self.rows[table_id as usize].bits > 16 {
            4
        } else {
            2
        }
    }

    /// Returns the cached bit size for a specific coded index type.
    ///
    /// Coded index bit sizes are pre-calculated during [`TableInfo`] construction
    /// and cached for efficient lookup. The size accounts for both the tag bits
    /// (to identify the table) and the row index bits.
    ///
    /// ## Arguments
    ///
    /// * `coded_index_type` - The [`CodedIndexType`] for which to retrieve the cached size
    ///
    /// ## Returns
    ///
    /// The number of bits required to represent coded indices of this type.
    #[must_use]
    pub fn coded_index_bits(&self, coded_index_type: CodedIndexType) -> u8 {
        self.coded_indexes[coded_index_type as usize]
    }

    /// Returns the cached byte size for a specific coded index type.
    ///
    /// Converts the cached bit size into actual byte storage requirements.
    /// Coded indices requiring more than 16 bits use 4-byte storage, otherwise 2-byte.
    ///
    /// ## Arguments
    ///
    /// * `coded_index_type` - The [`CodedIndexType`] for which to retrieve the byte size
    ///
    /// ## Returns
    ///
    /// Either `2` for coded indices that fit in 16 bits or `4` for larger coded indices.
    #[must_use]
    pub fn coded_index_bytes(&self, coded_index_type: CodedIndexType) -> u8 {
        if self.coded_indexes[coded_index_type as usize] > 16 {
            4
        } else {
            2
        }
    }

    /// Calculates the number of bits required for a specific coded index type.
    ///
    /// This internal method computes the bit requirements for coded indices based on:
    /// 1. The maximum table size among all tables in the coded index union
    /// 2. The number of tag bits needed to distinguish between tables
    ///
    /// ## Arguments
    ///
    /// * `coded_index_type` - The [`CodedIndexType`] for which to calculate the size
    ///
    /// ## Returns
    ///
    /// The total number of bits required for coded indices of this type.
    fn calculate_coded_index_size(&self, coded_index_type: CodedIndexType) -> u8 {
        let tables = coded_index_type.tables();
        let max_bits = tables
            .iter()
            .map(|table| self.table_index_bits(*table))
            .max()
            .unwrap_or(1);

        // Safe cast: tables.len() is limited by the enum size, log2 result is small
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let tag_bits = (tables.len() as f32).log2().ceil() as u8;
        max_bits + tag_bits
    }

    /// Calculates and caches the bit sizes required for all coded index types.
    ///
    /// This method is called during [`TableInfo`] construction to pre-compute coded index
    /// sizes for all possible coded index types. The cached values enable fast O(1) lookup
    /// during metadata parsing operations.
    fn calculate_coded_index_bits(&mut self) {
        for coded_index in CodedIndexType::iter() {
            let size = self.calculate_coded_index_size(coded_index);
            self.coded_indexes[coded_index as usize] = size;
        }
    }
}
