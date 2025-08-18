//! Implementation of `RowWritable` for `MethodDefRaw` metadata table entries.
//!
//! This module provides binary serialization support for the `MethodDef` table (ID 0x06),
//! enabling writing of method definition metadata back to .NET PE files. The MethodDef table
//! defines all methods within the current module, including constructors, static methods,
//! instance methods, and special methods.
//!
//! ## Table Structure (ECMA-335 §II.22.26)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `RVA` | `u32` | Relative virtual address of implementation |
//! | `ImplFlags` | `u16` | Method implementation attributes |
//! | `Flags` | `u16` | Method attributes and access modifiers |
//! | `Name` | String heap index | Method name identifier |
//! | `Signature` | Blob heap index | Method signature |
//! | `ParamList` | Param table index | First parameter belonging to this method |
//!
//! ## Method Attributes
//!
//! The `Flags` field contains method attributes with common values:
//! - `0x0001` - `CompilerControlled`
//! - `0x0002` - `Private`
//! - `0x0006` - `Public`
//! - `0x0010` - `Static`
//! - `0x0020` - `Final`
//! - `0x0040` - `Virtual`
//! - `0x0080` - `HideBySig`

use crate::{
    metadata::tables::{
        methoddef::MethodDefRaw,
        types::{RowWritable, TableId, TableInfoRef},
    },
    utils::{write_le_at, write_le_at_dyn},
    Result,
};

impl RowWritable for MethodDefRaw {
    /// Write a MethodDef table row to binary data
    ///
    /// Serializes one MethodDef table entry to the metadata tables stream format, handling
    /// variable-width heap and table indexes based on the table size information.
    ///
    /// # Field Serialization Order (ECMA-335)
    /// 1. `rva` - Relative virtual address as 4-byte little-endian value
    /// 2. `impl_flags` - Implementation attributes as 2-byte little-endian value
    /// 3. `flags` - Method attributes as 2-byte little-endian value
    /// 4. `name` - String heap index (2 or 4 bytes)
    /// 5. `signature` - Blob heap index (2 or 4 bytes)
    /// 6. `param_list` - Param table index (2 or 4 bytes)
    ///
    /// # Arguments
    /// * `data` - Target binary buffer for metadata tables stream
    /// * `offset` - Current write position (updated after writing)
    /// * `rid` - Row identifier (unused for MethodDef serialization)
    /// * `sizes` - Table size information for determining index widths
    ///
    /// # Returns
    /// `Ok(())` on successful serialization, error if buffer is too small
    ///
    /// # Errors
    /// Returns an error if:
    /// - The target buffer is too small for the row data
    fn row_write(
        &self,
        data: &mut [u8],
        offset: &mut usize,
        _rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<()> {
        // Write RVA (4 bytes)
        write_le_at(data, offset, self.rva)?;

        // Write implementation flags (2 bytes) - convert from u32 to u16 with range check
        let impl_flags_u16 =
            u16::try_from(self.impl_flags).map_err(|_| crate::Error::WriteLayoutFailed {
                message: "Method implementation flags value exceeds u16 range".to_string(),
            })?;
        write_le_at(data, offset, impl_flags_u16)?;

        // Write method flags (2 bytes) - convert from u32 to u16 with range check
        let flags_u16 = u16::try_from(self.flags).map_err(|_| crate::Error::WriteLayoutFailed {
            message: "Method flags value exceeds u16 range".to_string(),
        })?;
        write_le_at(data, offset, flags_u16)?;

        // Write name string heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.name, sizes.is_large_str())?;

        // Write signature blob heap index (2 or 4 bytes)
        write_le_at_dyn(data, offset, self.signature, sizes.is_large_blob())?;

        // Write param list table index (2 or 4 bytes)
        write_le_at_dyn(
            data,
            offset,
            self.param_list,
            sizes.is_large(TableId::Param),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::{
            types::{RowReadable, TableInfo, TableRow},
            TableId,
        },
        metadata::token::Token,
    };
    use std::sync::Arc;

    #[test]
    fn test_row_size() {
        // Test with small heaps
        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)], // Small param table
            false,                    // small string heap
            false,                    // small blob heap
            false,                    // small guid heap
        ));

        let size = <MethodDefRaw as TableRow>::row_size(&table_info);
        // rva(4) + impl_flags(2) + flags(2) + name(2) + signature(2) + param_list(2) = 14
        assert_eq!(size, 14);

        // Test with large heaps
        let table_info_large = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 70000)], // Large param table
            true,                       // large string heap
            true,                       // large blob heap
            false,                      // small guid heap
        ));
        let size_large = <MethodDefRaw as TableRow>::row_size(&table_info_large);
        // rva(4) + impl_flags(2) + flags(2) + name(4) + signature(4) + param_list(4) = 20
        assert_eq!(size_large, 20);
    }

    #[test]
    fn test_round_trip_serialization() {
        // Create test data using same values as reader tests
        let original_row = MethodDefRaw {
            rid: 1,
            token: Token::new(0x06000001),
            offset: 0,
            rva: 0x2048,
            impl_flags: 0x0000, // IL
            flags: 0x0006,      // Public
            name: 0x1234,
            signature: 0x5678,
            param_list: 1,
        };

        // Create minimal table info for testing
        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)], // Small param table
            false,                    // small string heap
            false,                    // small blob heap
            false,                    // small guid heap
        ));

        // Calculate buffer size and serialize
        let row_size = <MethodDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Serialization should succeed");

        // Deserialize and verify round-trip
        let mut read_offset = 0;
        let deserialized_row = MethodDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized_row.rid, original_row.rid);
        assert_eq!(deserialized_row.rva, original_row.rva);
        assert_eq!(deserialized_row.impl_flags, original_row.impl_flags);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.signature, original_row.signature);
        assert_eq!(deserialized_row.param_list, original_row.param_list);
    }

    #[test]
    fn test_known_binary_format() {
        // Test with known binary data from reader tests
        let data = vec![
            0x48, 0x20, 0x00, 0x00, // rva (0x2048)
            0x00, 0x00, // impl_flags (0x0000)
            0x06, 0x00, // flags (0x0006)
            0x34, 0x12, // name (0x1234)
            0x78, 0x56, // signature (0x5678)
            0x01, 0x00, // param_list (0x0001)
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)],
            false,
            false,
            false,
        ));

        // First read the original data to get a reference row
        let mut read_offset = 0;
        let reference_row = MethodDefRaw::row_read(&data, &mut read_offset, 1, &table_info)
            .expect("Reading reference data should succeed");

        // Now serialize and verify we get the same binary data
        let mut buffer = vec![0u8; data.len()];
        let mut write_offset = 0;
        reference_row
            .row_write(&mut buffer, &mut write_offset, 1, &table_info)
            .expect("Serialization should succeed");

        assert_eq!(
            buffer, data,
            "Serialized data should match original binary format"
        );
    }

    #[test]
    fn test_method_attributes() {
        // Test various method attribute combinations
        let test_cases = vec![
            (0x0001, "CompilerControlled"),
            (0x0002, "Private"),
            (0x0006, "Public"),
            (0x0010, "Static"),
            (0x0020, "Final"),
            (0x0040, "Virtual"),
            (0x0080, "HideBySig"),
            (0x0100, "CheckAccessOnOverride"),
            (0x0200, "Abstract"),
            (0x0400, "SpecialName"),
            (0x0800, "RTSpecialName"),
            (0x1000, "PinvokeImpl"),
            (0x0056, "Public|Virtual|HideBySig"), // Common combination
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)],
            false,
            false,
            false,
        ));

        for (flags, description) in test_cases {
            let method_row = MethodDefRaw {
                rid: 1,
                token: Token::new(0x06000001),
                offset: 0,
                rva: 0x2000,
                impl_flags: 0,
                flags,
                name: 0x100,
                signature: 0x200,
                param_list: 1,
            };

            let row_size = <MethodDefRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            method_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                MethodDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.flags, method_row.flags,
                "Flags should match for {description}"
            );
        }
    }

    #[test]
    fn test_implementation_flags() {
        // Test various implementation flag combinations
        let test_cases = vec![
            (0x0000, "IL"),
            (0x0001, "Native"),
            (0x0002, "OPTIL"),
            (0x0003, "Runtime"),
            (0x0004, "Unmanaged"),
            (0x0008, "ForwardRef"),
            (0x0010, "PreserveSig"),
            (0x0020, "InternalCall"),
            (0x0040, "Synchronized"),
            (0x0080, "NoInlining"),
            (0x0100, "MaxMethodImplVal"),
        ];

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)],
            false,
            false,
            false,
        ));

        for (impl_flags, description) in test_cases {
            let method_row = MethodDefRaw {
                rid: 1,
                token: Token::new(0x06000001),
                offset: 0,
                rva: 0x2000,
                impl_flags,
                flags: 0x0006, // Public
                name: 0x100,
                signature: 0x200,
                param_list: 1,
            };

            let row_size = <MethodDefRaw as TableRow>::row_size(&table_info) as usize;
            let mut buffer = vec![0u8; row_size];
            let mut offset = 0;

            method_row
                .row_write(&mut buffer, &mut offset, 1, &table_info)
                .unwrap_or_else(|_| panic!("Serialization should succeed for {description}"));

            // Verify round-trip
            let mut read_offset = 0;
            let deserialized_row =
                MethodDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
                    .unwrap_or_else(|_| panic!("Deserialization should succeed for {description}"));

            assert_eq!(
                deserialized_row.impl_flags, method_row.impl_flags,
                "Implementation flags should match for {description}"
            );
        }
    }

    #[test]
    fn test_large_heap_serialization() {
        // Test with large heaps to ensure 4-byte indexes are handled correctly
        let original_row = MethodDefRaw {
            rid: 1,
            token: Token::new(0x06000001),
            offset: 0,
            rva: 0x12345678,
            impl_flags: 0x0040, // Synchronized
            flags: 0x0056,      // Public|Virtual|HideBySig
            name: 0x123456,
            signature: 0x789ABC,
            param_list: 0x8000,
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 70000)], // Large param table
            true,                       // large string heap
            true,                       // large blob heap
            false,                      // small guid heap
        ));

        let row_size = <MethodDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        original_row
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Large heap serialization should succeed");

        // Verify round-trip
        let mut read_offset = 0;
        let deserialized_row = MethodDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Large heap deserialization should succeed");

        assert_eq!(deserialized_row.rva, original_row.rva);
        assert_eq!(deserialized_row.impl_flags, original_row.impl_flags);
        assert_eq!(deserialized_row.flags, original_row.flags);
        assert_eq!(deserialized_row.name, original_row.name);
        assert_eq!(deserialized_row.signature, original_row.signature);
        assert_eq!(deserialized_row.param_list, original_row.param_list);
    }

    #[test]
    fn test_edge_cases() {
        // Test with zero values (abstract method)
        let abstract_method = MethodDefRaw {
            rid: 1,
            token: Token::new(0x06000001),
            offset: 0,
            rva: 0, // Abstract method has zero RVA
            impl_flags: 0,
            flags: 0x0206, // Public|Abstract
            name: 0,
            signature: 0,
            param_list: 0,
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)],
            false,
            false,
            false,
        ));

        let row_size = <MethodDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        abstract_method
            .row_write(&mut buffer, &mut offset, 1, &table_info)
            .expect("Abstract method serialization should succeed");

        // Verify round-trip with zero values
        let mut read_offset = 0;
        let deserialized_row = MethodDefRaw::row_read(&buffer, &mut read_offset, 1, &table_info)
            .expect("Abstract method deserialization should succeed");

        assert_eq!(deserialized_row.rva, abstract_method.rva);
        assert_eq!(deserialized_row.impl_flags, abstract_method.impl_flags);
        assert_eq!(deserialized_row.flags, abstract_method.flags);
        assert_eq!(deserialized_row.name, abstract_method.name);
        assert_eq!(deserialized_row.signature, abstract_method.signature);
        assert_eq!(deserialized_row.param_list, abstract_method.param_list);
    }

    #[test]
    fn test_flags_range_validation() {
        // Test that large flag values are properly rejected
        let large_flags_row = MethodDefRaw {
            rid: 1,
            token: Token::new(0x06000001),
            offset: 0,
            rva: 0x2000,
            impl_flags: 0x12345678, // Large value that exceeds u16 range
            flags: 0x87654321,      // Large value that exceeds u16 range
            name: 0x100,
            signature: 0x200,
            param_list: 1,
        };

        let table_info = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 100)],
            false,
            false,
            false,
        ));
        let row_size = <MethodDefRaw as TableRow>::row_size(&table_info) as usize;
        let mut buffer = vec![0u8; row_size];
        let mut offset = 0;

        // Should fail with range error
        let result = large_flags_row.row_write(&mut buffer, &mut offset, 1, &table_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Method implementation flags value exceeds u16 range"));
    }
}
