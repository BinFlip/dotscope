//! # Param Raw Implementation
//!
//! This module provides the raw variant of Param table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::{atomic::AtomicBool, Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{Param, ParamRc, RowDefinition, TableInfoRef},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a Param table entry with unresolved indexes.
///
/// This structure represents the unprocessed entry from the Param metadata table
/// (ID 0x08), which contains information about method parameters including their
/// attributes, sequence numbers, and names. It contains raw index values that
/// require resolution to actual metadata objects.
///
/// ## Purpose
///
/// The Param table provides method parameter information:
/// - Parameter names for debugging and reflection
/// - Sequence numbers for parameter ordering in method signatures
/// - Attributes defining parameter characteristics (in/out, optional, defaults)
/// - Foundation for method signature construction and parameter binding
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved string heap indexes requiring lookup
/// - Minimal memory footprint for storage
/// - Direct representation of file format
///
/// Use [`Param`] for resolved references and runtime access.
///
/// ## Fields
///
/// - `rid`: Row identifier within the Param table
/// - `token`: Metadata token (0x08?????? format)
/// - `offset`: File offset of this entry's data
/// - `flags`: Raw parameter attributes bitmask
/// - `sequence`: Parameter sequence number (0 = return type, 1+ = parameters)
/// - `name`: Raw index into string heap containing parameter name
///
/// ## Parameter Sequencing
///
/// The sequence field determines parameter ordering:
/// - **0**: Reserved for return type information
/// - **1+**: Method parameters in declaration order
/// - Used for proper parameter binding during method invocation
///
/// ## ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.33 Param table structure.
pub struct ParamRaw {
    /// Row identifier within the Param table.
    ///
    /// Unique identifier for this Param entry within the table.
    /// Combined with table ID 0x08, forms the metadata token 0x08??????.
    pub rid: u32,

    /// Metadata token for this Param entry.
    ///
    /// Token in the format 0x08??????, where the high byte 0x08 identifies
    /// the Param table and the low 3 bytes contain the row ID.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Raw parameter attributes bitmask according to ECMA-335 §II.23.1.13.
    ///
    /// 2-byte bitmask defining parameter characteristics including direction,
    /// optional status, default values, and marshalling information.
    /// See [`ParamAttributes`](crate::metadata::tables::ParamAttributes) for flag definitions.
    pub flags: u32,

    /// Parameter sequence number defining order in method signature.
    ///
    /// 2-byte constant where:
    /// - 0: Return type parameter
    /// - 1+: Method parameters in declaration order
    ///   Used for proper parameter binding and signature construction.
    pub sequence: u32,

    /// Raw index into the string heap containing the parameter name.
    ///
    /// This unresolved index identifies the parameter name string in the #Strings heap.
    /// May be 0 for unnamed parameters (compiler-generated or return types).
    /// Must be resolved using the string heap to get the actual parameter name.
    pub name: u32,
}

impl ParamRaw {
    /// Applies a Param entry to update related metadata structures.
    ///
    /// Param entries are primarily containers for parameter information and don't
    /// directly modify other metadata tables during the dual variant resolution phase.
    /// They are updated through method signature processing and custom attribute
    /// application rather than through inter-table dependencies.
    ///
    /// This method is provided for consistency with the metadata loading architecture
    /// but performs no operations since Param entries don't modify other tables.
    ///
    /// ## Returns
    ///
    /// Always returns `Ok(())` as Param entries don't require cross-table updates.
    ///
    /// # Errors
    /// This function does not return an error under normal circumstances.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }

    /// Converts this raw entry to an owned [`Param`] with resolved references.
    ///
    /// This method resolves the raw string heap index to actual parameter name data,
    /// creating a fully usable [`Param`] instance for runtime access. The conversion
    /// prepares the parameter for signature application and type resolution.
    ///
    /// ## Arguments
    ///
    /// * `strings` - The string heap for resolving the parameter name
    ///
    /// ## Returns
    ///
    /// A reference-counted [`ParamRc`] containing the resolved parameter entry.
    ///
    /// ## Errors
    ///
    /// - String heap entry cannot be resolved or is malformed
    /// - Heap index is out of bounds
    /// - Data corruption is detected
    pub fn to_owned(&self, strings: &Strings) -> Result<ParamRc> {
        Ok(Arc::new(Param {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            sequence: self.sequence,
            name: if self.name != 0 {
                Some(strings.get(self.name as usize)?.to_string())
            } else {
                None
            },
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(false),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for ParamRaw {
    /// Calculates the byte size of a Param table row.
    ///
    /// The row size depends on string heap size and is calculated as:
    /// - `flags`: 2 bytes (fixed)
    /// - `sequence`: 2 bytes (fixed)
    /// - `name`: 2 or 4 bytes (depends on string heap size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating heap index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2 +
            /* sequence */  2 +
            /* name */      sizes.str_bytes()
        )
    }

    /// Reads a single Param table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.33:
    /// 1. **Flags** (2 bytes): Parameter attributes bitmask
    /// 2. **Sequence** (2 bytes): Parameter sequence number
    /// 3. **Name** (2-4 bytes): Index into string heap containing parameter name
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`ParamRaw`] instance with populated fields
    ///
    /// ## Errors
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid string heap index values
    fn row_read(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ParamRaw {
            rid,
            token: Token::new(0x0800_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            sequence: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // flags
            0x02, 0x02, // sequences
            0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x0303);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, // flags
            0x02, 0x02, // sequence
            0x03, 0x03, 0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x03030303);
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
