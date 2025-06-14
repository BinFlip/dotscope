use std::sync::Arc;
use strum::{EnumCount, IntoEnumIterator};

use crate::{
    file::io::{read_le, read_le_at},
    metadata::tables::types::{CodedIndexType, TableId},
    Error::OutOfBounds,
    Result,
};

/// Holds information about the size that reference index fields have
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct TableRowInfo {
    /// The count of rows in this table
    pub rows: u32,
    /// Number of bits required to represent any valid row index
    pub bits: u8,
    /// If the count is > `u16::max`, the indexes of other tables into this table will be 4 bytes instead of 2
    pub is_large: bool,
}

impl TableRowInfo {
    /// Creates a new `TableRowInfo` instance with the given row count.
    ///
    /// Automatically calculates the number of bits required to represent
    /// indices into a table with the specified number of rows.
    ///
    /// # Arguments
    /// * `row_count` - The number of rows in the table
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

/// `TableInfo` holds information regarding the row count and reference index field sizes
/// of all tables in this binary
#[derive(Clone, Default)]
pub struct TableInfo {
    rows: Vec<TableRowInfo>,
    coded_indexes: Vec<u8>,
    is_large_index_str: bool,
    is_large_index_guid: bool,
    is_large_index_blob: bool,
}

/// Cheap-copy reference to a `TableInfo` structure
pub type TableInfoRef = Arc<TableInfo>;

impl TableInfo {
    /// Build a new `TableInfo` struct
    ///
    /// ## Arguments
    /// * 'data' - The data from which the `TableInfo` will be parsed from
    /// * '`valid_bitvec`' - The valid bitvector from the header, showing which tables are present
    ///
    /// # Errors
    /// Returns an error if the table data is insufficient or malformed
    pub fn new(data: &[u8], valid_bitvec: u64) -> Result<Self> {
        let mut table_info =
            vec![TableRowInfo::default(); TableId::GenericParamConstraint as usize + 1];
        let mut next_row_offset = 24;

        for table_id in TableId::iter() {
            if data.len() < next_row_offset {
                return Err(OutOfBounds);
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
    /// Special constructor for unit-tests
    ///
    /// ## Arguments
    /// * 'valid_tables'    - A slice of touples, which provides (table_id, row_count) of the valid tables
    /// * 'large_str'       - Specify if the #String heap indexes are 4 or 2 bytes
    /// * 'large_blob'      - Specify if the #Blob heap indexes are 4 or 2 bytes
    /// * 'large_guid'      - Specify if the #GUID heap indexes are 4 or 2 bytes
    pub fn new_test(
        valid_tables: &[(TableId, u32)],
        large_str: bool,
        large_blob: bool,
        large_guid: bool,
    ) -> Self {
        let mut table_info = TableInfo {
            rows: vec![TableRowInfo::default(); TableId::GenericParamConstraint as usize + 1],
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
    /// # Arguments
    /// * `value` - The encoded value to decode
    /// * `coded_index_type` - The type of coded index being decoded
    ///
    /// # Returns
    /// A tuple containing (`TableId`, `row_index`)
    ///
    /// # Errors
    /// Returns an error if the tag value is out of bounds for the coded index type
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
            return Err(OutOfBounds);
        }

        Ok((tables[tag as usize], index))
    }

    /// Returns true, if a requested table is larger than 2^16 rows and hence requires 4 bytes instead of 2 bytes
    ///
    /// ## Arguments
    /// * `id` - The `TableId` to query
    #[must_use]
    pub fn is_large(&self, id: TableId) -> bool {
        self.rows[id as usize].is_large
    }

    /// Indicates the size of indexes referring into the '#String' heap. True means 4 bytes, False is 2 bytes
    #[must_use]
    pub fn is_large_str(&self) -> bool {
        self.is_large_index_str
    }

    /// Indicates the size of indexes referring into the '#Guid' heap. True means 4 bytes, False is 2 bytes
    #[must_use]
    pub fn is_large_guid(&self) -> bool {
        self.is_large_index_guid
    }

    /// Indicates the size of indexes referring into the '#Blob' heap. True means 4 bytes, False is 2 bytes
    #[must_use]
    pub fn is_large_blob(&self) -> bool {
        self.is_large_index_blob
    }

    /// Returns the size of the '#String' heap in bytes
    #[must_use]
    pub fn str_bytes(&self) -> u8 {
        if self.is_large_index_str {
            4
        } else {
            2
        }
    }

    /// Returns the size of the '#Guid' heap in bytes
    #[must_use]
    pub fn guid_bytes(&self) -> u8 {
        if self.is_large_index_guid {
            4
        } else {
            2
        }
    }

    /// Returns the size of the '#Blob' heap in bytes
    #[must_use]
    pub fn blob_bytes(&self) -> u8 {
        if self.is_large_index_blob {
            4
        } else {
            2
        }
    }

    /// Returns the metadata for a specific table.
    ///
    /// # Arguments
    /// * `table` - The `TableId` for which to retrieve metadata
    #[must_use]
    pub fn get(&self, table: TableId) -> &TableRowInfo {
        &self.rows[table as usize]
    }

    /// Returns the number of bits required to represent an index into a specific table.
    ///
    /// # Arguments
    /// * `table` - The `TableId` for which to calculate the index size
    #[must_use]
    pub fn table_index_bits(&self, table_id: TableId) -> u8 {
        self.rows[table_id as usize].bits
    }

    /// Returns the number of bytes required to represent an index into a specific table.
    ///
    /// # Arguments
    /// * `table` - The `TableId` for which to calculate the index size
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
    /// # Arguments
    /// * `coded_index_type` - The `CodedIndexType` for which to retrieve the size
    #[must_use]
    pub fn coded_index_bits(&self, coded_index_type: CodedIndexType) -> u8 {
        self.coded_indexes[coded_index_type as usize]
    }

    /// Returns the cached byte size for a specific coded index reference.
    ///
    /// # Arguments
    /// * `coded_index_type` - The `CodedIndexType` for which to retrieve the size
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
    /// # Arguments
    /// * `coded_index_type` - The `CodedIndexType` for which to calculate the size
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
    fn calculate_coded_index_bits(&mut self) {
        for coded_index in CodedIndexType::iter() {
            let size = self.calculate_coded_index_size(coded_index);
            self.coded_indexes[coded_index as usize] = size;
        }
    }
}
