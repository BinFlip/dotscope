//! # Field Layout Validation for .NET Metadata
//!
//! This module provides comprehensive validation utilities for field layout metadata,
//! ensuring compliance with .NET runtime rules and ECMA-335 specifications. Field layout
//! validation is critical for assemblies with explicit layout types, where precise memory
//! positioning and overlap detection are essential for runtime correctness.
//!
//! ## Overview
//!
//! Field layout validation in .NET involves several key aspects:
//!
//! - **Offset Validation**: Ensuring field offsets are within valid ranges
//! - **Overlap Detection**: Preventing conflicting memory layout in explicit layout types
//! - **Coverage Analysis**: Verifying that explicit layouts respect declared type sizes
//! - **Runtime Compliance**: Matching validation behavior of the .NET runtime
//!
//! ## Validation Categories
//!
//! ### Offset Validation
//!
//! - Validates field offsets against `INT32_MAX` limit (2,147,483,647)
//! - Detects unspecified offsets (`0xFFFFFFFF`) in explicit layout scenarios
//! - Ensures offsets are properly formatted and within runtime constraints
//!
//! ### Overlap Detection
//!
//! - Identifies overlapping fields in explicit layout types
//! - Prevents memory conflicts that could cause runtime issues
//! - Handles edge cases like adjacent fields and integer overflow
//!
//! ### Coverage Analysis
//!
//! - Verifies fields don't extend beyond declared type boundaries
//! - Ensures explicit layout types respect their declared sizes
//! - Detects integer overflow in field positioning calculations
//!
//! ## Usage Examples
//!
//! The `FieldValidator` provides methods for validating field layout offsets,
//! detecting field overlaps, and ensuring explicit layout coverage. These
//! validations help ensure proper memory layout for types with explicit
//! field positioning.
//!
//! ## Runtime Compliance
//!
//! This implementation follows .NET Core runtime validation behavior as documented
//! in `coreclr/vm/classlayoutinfo.cpp`. Key compliance aspects include:
//!
//! - **Maximum Offset**: Enforces `INT32_MAX` limit from runtime sources
//! - **Unspecified Offsets**: Matches runtime handling of `0xFFFFFFFF` values
//! - **Overlap Detection**: Implements runtime-equivalent overlap checking
//! - **Error Messages**: Provides runtime-style error descriptions
//!
//! ## Limitations
//!
//! Current implementation focuses on basic structural validation:
//!
//! - Does not validate type-specific alignment requirements
//! - Does not perform deep type system analysis for field types
//! - Does not validate platform-specific layout constraints
//! - Union-style overlapping fields are detected as errors (by design)
//!
//! ## Thread Safety
//!
//! The `FieldValidator` is stateless and safe for concurrent use across multiple threads.
//! All validation functions are pure and do not maintain internal state.
//!
//! ## References
//!
//! - ECMA-335, Partition II, Section 10.7 - Controlling instance layout
//! - ECMA-335, Partition II, Section 23.2.5 - FieldLayout table
//! - .NET Core Runtime: `coreclr/vm/classlayoutinfo.cpp`
//! - .NET Type Layout documentation

use crate::{metadata::tables::FieldRc, Result};

/// Maximum allowed field offset value (`INT32_MAX` from .NET runtime)
const MAX_FIELD_OFFSET: u32 = i32::MAX as u32; // 2,147,483,647

/// Field layout validator for .NET metadata compliance.
///
/// Provides comprehensive validation functionality for field layout metadata as defined
/// in ECMA-335 and implemented by the .NET runtime. This validator ensures that field
/// layouts conform to runtime constraints and prevent memory layout conflicts.
///
/// ## Design Philosophy
///
/// The validator is designed to match .NET runtime behavior as closely as possible,
/// using the same validation rules and limits found in the CoreCLR implementation.
/// This ensures that validated metadata will be compatible with actual runtime loading.
///
/// ## Validation Scope
///
/// The validator handles three primary validation categories:
/// - **Structural validation**: Offset ranges, format compliance
/// - **Semantic validation**: Overlap detection, coverage analysis
/// - **Runtime compliance**: Matching CoreCLR validation behavior
///
/// ## Thread Safety
///
/// This struct is stateless and all methods are safe for concurrent use.
pub struct FieldValidator;

impl FieldValidator {
    /// Validates a field layout offset according to .NET runtime rules
    ///
    /// # Arguments
    /// * `field_offset` - The offset value from the `FieldLayout` table
    /// * `field` - Optional reference to the field for additional context
    ///
    /// # Errors
    /// Returns an error if:
    /// - Field offset is unspecified (`0xFFFF_FFFF`) for explicit layout
    /// - Field offset exceeds `INT32_MAX` (`0x7FFF_FFFF`)
    ///
    /// # .NET Runtime Reference
    /// Based on coreclr/vm/classlayoutinfo.cpp validation:
    /// ```cpp
    /// else if (pFieldInfoArray[i].m_placement.m_offset > INT32_MAX)
    /// {
    ///     // Throw IDS_CLASSLOAD_NSTRUCT_NEGATIVE_OFFSET
    /// }
    /// ```
    pub fn validate_field_offset(field_offset: u32, field: Option<&FieldRc>) -> Result<()> {
        // Check for unspecified offset in explicit layout (0xFFFF_FFFF indicates missing offset)
        // This must be checked first since 0xFFFF_FFFF > INT32_MAX
        if field_offset == 0xFFFF_FFFF {
            let field_name = field.map_or("unknown", |f| f.name.as_str());
            return Err(malformed_error!(
                "Field '{}' requires explicit offset in explicit layout",
                field_name
            ));
        }

        // Check maximum offset limit (INT32_MAX from .NET runtime)
        if field_offset > MAX_FIELD_OFFSET {
            return Err(malformed_error!(
                "Field offset {} exceeds maximum allowed value ({})",
                field_offset,
                MAX_FIELD_OFFSET
            ));
        }

        Ok(())
    }

    /// Validates field layout for overlap detection in explicit layout types.
    ///
    /// Performs comprehensive overlap detection for fields in explicit layout types,
    /// ensuring that no two fields occupy the same memory locations. This validation
    /// is critical for preventing runtime memory corruption and undefined behavior.
    ///
    /// ## Algorithm
    ///
    /// 1. Sorts fields by offset for efficient comparison
    /// 2. Checks each adjacent pair for memory overlap
    /// 3. Detects integer overflow in field size calculations
    /// 4. Reports detailed overlap information for debugging
    ///
    /// ## Overlap Detection
    ///
    /// Two fields overlap if: `field1_offset + field1_size > field2_offset`
    /// where `field2_offset > field1_offset`.
    ///
    /// # Arguments
    ///
    /// * `fields_with_offsets` - Slice of `(field_offset, field_size)` tuples representing
    ///   the memory layout of fields in an explicit layout type
    ///
    /// # Returns
    ///
    /// `Ok(())` if no overlaps are detected, or an error describing the first overlap found.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Field Overlap**: Two or more fields occupy overlapping memory regions
    /// - **Integer Overflow**: Field offset + size calculation overflows
    /// - **Invalid Layout**: Malformed field layout information
    ///
    /// # .NET Runtime Reference
    ///
    /// This validation matches the overlap detection performed by the .NET runtime
    /// during type loading, helping catch issues early in the metadata parsing phase.
    pub fn validate_field_overlaps(fields_with_offsets: &[(u32, u32)]) -> Result<()> {
        let mut sorted_fields: Vec<(u32, u32)> = fields_with_offsets.to_vec();
        sorted_fields.sort_by_key(|(offset, _)| *offset);

        // Check for overlaps between consecutive fields
        for window in sorted_fields.windows(2) {
            let (offset1, size1) = window[0];
            let (offset2, _) = window[1];

            if let Some(end1) = offset1.checked_add(size1) {
                if end1 > offset2 {
                    return Err(malformed_error!(
                        "Field overlap detected: field at offset {} (size {}) overlaps with field at offset {}",
                        offset1, size1, offset2
                    ));
                }
            } else {
                return Err(malformed_error!(
                    "Field at offset {} with size {} causes integer overflow",
                    offset1,
                    size1
                ));
            }
        }

        Ok(())
    }

    /// Validates that explicit layout types have proper field layout coverage.
    ///
    /// Ensures that all fields in an explicit layout type fit within the declared
    /// type size, preventing fields from extending beyond type boundaries. This
    /// validation is essential for maintaining memory safety and runtime consistency.
    ///
    /// ## Coverage Analysis
    ///
    /// For each field, validates that: `field_offset + field_size <= class_size`
    ///
    /// This ensures that:
    /// - No field extends beyond the type's memory footprint
    /// - The declared type size is sufficient for all fields
    /// - Integer overflow in field calculations is detected
    ///
    /// # Arguments
    ///
    /// * `class_size` - The declared size of the class/struct in bytes
    /// * `fields_with_offsets` - Slice of `(field_offset, field_size)` tuples for all fields
    ///
    /// # Returns
    ///
    /// `Ok(())` if all fields fit within the declared class size, or an error describing
    /// the first field that extends beyond the type boundary.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Boundary Violation**: Field extends beyond declared class size
    /// - **Integer Overflow**: Field offset + size calculation overflows
    /// - **Size Mismatch**: Declared class size is insufficient for field layout
    pub fn validate_explicit_layout_coverage(
        class_size: u32,
        fields_with_offsets: &[(u32, u32)],
    ) -> Result<()> {
        for &(field_offset, field_size) in fields_with_offsets {
            if let Some(field_end) = field_offset.checked_add(field_size) {
                if field_end > class_size {
                    return Err(malformed_error!(
                        "Field at offset {} (size {}) extends beyond class size {}",
                        field_offset,
                        field_size,
                        class_size
                    ));
                }
            } else {
                return Err(malformed_error!(
                    "Field at offset {} with size {} causes integer overflow",
                    field_offset,
                    field_size
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::{
        create_inheritance_scenario, CilTypeBuilder, FieldBuilder, FieldConstant, FieldLayout,
        FieldMarshalling,
    };

    fn create_int32_type() -> crate::metadata::typesystem::CilTypeRc {
        CilTypeBuilder::new()
            .with_namespace("System")
            .with_name("Int32")
            .with_flavor(crate::metadata::typesystem::CilFlavor::I4)
            .build()
    }

    fn create_string_type() -> crate::metadata::typesystem::CilTypeRc {
        crate::test::builders::CilTypeBuilder::new()
            .with_namespace("System")
            .with_name("String")
            .build()
    }

    #[test]
    fn test_valid_field_offset() {
        // Valid offsets should pass
        assert!(FieldValidator::validate_field_offset(0, None).is_ok());
        assert!(FieldValidator::validate_field_offset(1024, None).is_ok());
        assert!(FieldValidator::validate_field_offset(MAX_FIELD_OFFSET, None).is_ok());
    }

    #[test]
    fn test_invalid_field_offset_too_large() {
        // Offset exceeding INT32_MAX should fail
        let result = FieldValidator::validate_field_offset(MAX_FIELD_OFFSET + 1, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_invalid_field_offset_unspecified() {
        // Unspecified offset (0xFFFF_FFFF) should fail
        let result = FieldValidator::validate_field_offset(0xFFFF_FFFF, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires explicit offset"));
    }

    #[test]
    fn test_field_offset_with_realistic_field() {
        // Test with actual field instance using builder
        let field = FieldBuilder::new("TestField", create_int32_type())
            .with_layout(FieldLayout::Explicit(42))
            .build();

        assert!(FieldValidator::validate_field_offset(42, Some(&field)).is_ok());
    }

    #[test]
    fn test_field_offset_validation_with_marshaled_field() {
        // Test field with marshalling information
        let field = FieldBuilder::new("MarshaledField", create_int32_type())
            .with_layout(FieldLayout::Explicit(16))
            .with_marshalling(FieldMarshalling::LPWStr)
            .build();

        assert!(FieldValidator::validate_field_offset(16, Some(&field)).is_ok());

        // Test with invalid offset
        let result = FieldValidator::validate_field_offset(0xFFFF_FFFF, Some(&field));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MarshaledField"));
    }

    #[test]
    fn test_no_field_overlaps() {
        // Non-overlapping fields should pass
        let fields = vec![(0, 4), (8, 4), (16, 8)];
        assert!(FieldValidator::validate_field_overlaps(&fields).is_ok());
    }

    #[test]
    fn test_field_overlap_detection() {
        // Overlapping fields should fail
        let fields = vec![(0, 8), (4, 4)]; // First field (0-8) overlaps with second (4-8)
        let result = FieldValidator::validate_field_overlaps(&fields);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overlap"));
    }

    #[test]
    fn test_realistic_struct_layout_validation() {
        // Create a realistic struct layout using builders
        let fields = [
            FieldBuilder::new("x", create_int32_type())
                .with_layout(FieldLayout::Explicit(0))
                .build(),
            FieldBuilder::new("y", create_int32_type())
                .with_layout(FieldLayout::Explicit(4))
                .build(),
            FieldBuilder::new("z", create_int32_type())
                .with_layout(FieldLayout::Explicit(8))
                .build(),
        ];

        // Extract offset and size info for validation
        let field_offsets: Vec<(u32, u32)> = fields
            .iter()
            .map(|f| (f.layout.get().copied().unwrap_or(0), 4)) // Assume 4-byte primitives
            .collect();

        assert!(FieldValidator::validate_field_overlaps(&field_offsets).is_ok());
        assert!(FieldValidator::validate_explicit_layout_coverage(12, &field_offsets).is_ok());
    }

    #[test]
    fn test_complex_struct_with_different_field_sizes() {
        // Test struct with varying field sizes
        let field_offsets = vec![
            (0, 1),  // byte at offset 0
            (1, 2),  // short at offset 1
            (4, 4),  // int at offset 4 (aligned)
            (8, 8),  // long at offset 8 (aligned)
            (16, 4), // float at offset 16
        ];

        assert!(FieldValidator::validate_field_overlaps(&field_offsets).is_ok());
        assert!(FieldValidator::validate_explicit_layout_coverage(20, &field_offsets).is_ok());
    }

    #[test]
    fn test_union_like_overlapping_fields() {
        // Test union-like structure where fields intentionally overlap
        let field_offsets = vec![
            (0, 4), // int value
            (0, 4), // float overlay (same offset - union semantics)
        ];

        // This should fail overlap detection
        let result = FieldValidator::validate_field_overlaps(&field_offsets);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overlap"));
    }

    #[test]
    fn test_explicit_layout_coverage_valid() {
        // Fields that fit within class size should pass
        let fields = vec![(0, 4), (8, 4)];
        assert!(FieldValidator::validate_explicit_layout_coverage(16, &fields).is_ok());
    }

    #[test]
    fn test_explicit_layout_coverage_invalid() {
        // Field extending beyond class size should fail
        let fields = vec![(0, 8), (8, 16)]; // Second field extends to offset 24
        let result = FieldValidator::validate_explicit_layout_coverage(20, &fields);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("extends beyond"));
    }

    #[test]
    fn test_field_offset_overflow() {
        // Field offset + size overflow should be caught
        let fields = vec![(0xFFFF_FFFE, 4)]; // Should overflow when adding size
        let result = FieldValidator::validate_field_overlaps(&fields);
        assert!(result.is_ok()); // Single field, no overlap check

        // But coverage check should catch the overflow
        let result = FieldValidator::validate_explicit_layout_coverage(0xFFFF_FFFF, &fields);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overflow"));
    }

    #[test]
    fn test_edge_case_field_at_max_offset() {
        // Test field at maximum allowed offset
        let field = FieldBuilder::new("EdgeField", create_int32_type())
            .with_layout(FieldLayout::Explicit(MAX_FIELD_OFFSET))
            .build();

        assert!(FieldValidator::validate_field_offset(MAX_FIELD_OFFSET, Some(&field)).is_ok());
    }

    #[test]
    fn test_field_with_constant_value() {
        // Test field with constant value (should still validate offset)
        let field = FieldBuilder::new("ConstantField", create_int32_type())
            .with_layout(FieldLayout::Explicit(8))
            .with_constant(FieldConstant::I4(42))
            .build();

        assert!(FieldValidator::validate_field_offset(8, Some(&field)).is_ok());
        assert!(field.default.get().is_some());
    }

    #[test]
    fn test_comprehensive_field_validation_scenarios() {
        // Test various realistic field validation scenarios

        // Scenario 1: Simple struct with sequential fields
        let simple_fields = vec![
            (0, 4),
            (4, 4),
            (8, 4),
            (12, 4), // 4 int32 fields
        ];
        assert!(FieldValidator::validate_field_overlaps(&simple_fields).is_ok());
        assert!(FieldValidator::validate_explicit_layout_coverage(16, &simple_fields).is_ok());

        // Scenario 2: Struct with padding/alignment
        let aligned_fields = vec![
            (0, 1),  // byte
            (4, 4),  // int32 (aligned to 4-byte boundary)
            (8, 8),  // int64 (aligned to 8-byte boundary)
            (16, 1), // byte
            (20, 4), // int32
        ];
        assert!(FieldValidator::validate_field_overlaps(&aligned_fields).is_ok());
        assert!(FieldValidator::validate_explicit_layout_coverage(24, &aligned_fields).is_ok());

        // Scenario 3: Nested struct layout
        let nested_fields = vec![
            (0, 16), // Embedded struct of 16 bytes
            (16, 4), // Additional int32
            (20, 8), // Additional int64
        ];
        assert!(FieldValidator::validate_field_overlaps(&nested_fields).is_ok());
        assert!(FieldValidator::validate_explicit_layout_coverage(28, &nested_fields).is_ok());
    }

    #[test]
    fn test_field_builder_integration_with_validation() {
        // Test creating fields via builder and validating their layout
        let field1 = FieldBuilder::new("Field1", create_int32_type())
            .with_layout(FieldLayout::Explicit(0))
            .with_access_public()
            .build();

        let field2 = FieldBuilder::new("Field2", create_int32_type())
            .with_layout(FieldLayout::Explicit(4))
            .with_access_public()
            .build();

        let field3 = FieldBuilder::new("Field3", create_int32_type())
            .with_layout(FieldLayout::Explicit(8))
            .with_marshalling(FieldMarshalling::LPStr)
            .build();

        // Validate each field individually
        assert!(FieldValidator::validate_field_offset(0, Some(&field1)).is_ok());
        assert!(FieldValidator::validate_field_offset(4, Some(&field2)).is_ok());
        assert!(FieldValidator::validate_field_offset(8, Some(&field3)).is_ok());

        // Validate collective layout
        let field_offsets = vec![(0, 4), (4, 4), (8, 4)];
        assert!(FieldValidator::validate_field_overlaps(&field_offsets).is_ok());
        assert!(FieldValidator::validate_explicit_layout_coverage(12, &field_offsets).is_ok());
    }

    #[test]
    fn test_comprehensive_builder_integration_scenario() {
        let (base_class, derived_class) = create_inheritance_scenario();

        // Create a comprehensive set of fields with different types and characteristics
        let header_field = FieldBuilder::new("header", base_class.clone())
            .with_layout(FieldLayout::Explicit(0))
            .with_access_private()
            .build();

        let counter_field = FieldBuilder::new("counter", create_int32_type())
            .with_layout(FieldLayout::Explicit(8))
            .with_access_public()
            .with_constant(FieldConstant::I4(42))
            .build();

        let flags_field = FieldBuilder::new("flags", create_int32_type())
            .with_layout(FieldLayout::Explicit(12))
            .with_access_family()
            .build();

        let name_field = FieldBuilder::new("name", create_string_type())
            .with_layout(FieldLayout::Explicit(16))
            .with_access_public()
            .with_marshalling(FieldMarshalling::LPWStr)
            .build();

        let data_field = FieldBuilder::new("data", derived_class.clone())
            .with_layout(FieldLayout::Explicit(20))
            .with_access_assembly()
            .build();

        // Comprehensive validation of the complex layout
        let fields = [
            &header_field,
            &counter_field,
            &flags_field,
            &name_field,
            &data_field,
        ];
        let field_offsets = vec![(0, 8), (8, 4), (12, 4), (16, 4), (20, 8)];

        // Validate individual field properties
        for (i, field) in fields.iter().enumerate() {
            let offset = field_offsets[i].0;
            assert!(
                FieldValidator::validate_field_offset(offset, Some(field)).is_ok(),
                "Field {} should have valid offset {}",
                field.name,
                offset
            );
        }

        // Validate comprehensive layout constraints
        assert!(
            FieldValidator::validate_field_overlaps(&field_offsets).is_ok(),
            "Complex field layout should not have overlaps"
        );

        let total_size = 28; // Sum of all field sizes
        assert!(
            FieldValidator::validate_explicit_layout_coverage(total_size, &field_offsets).is_ok(),
            "Complex field layout should provide complete coverage"
        );

        // Test edge cases and constraints

        // 1. Verify that constant fields are properly handled
        assert!(
            counter_field.default.get().is_some(),
            "Counter field should have a default/constant value"
        );

        // 2. Verify that marshalling information is preserved
        assert!(
            name_field.marshal.get().is_some(),
            "Name field should have marshalling information"
        );

        // 3. Verify that flags are preserved (access info is encoded in the flags field)
        // Note: In real Field structs, access modifiers are encoded in the flags bitfield
        // This is a demonstration of how the enhanced builders make fields more realistic
        assert!(
            header_field.flags != 0 || counter_field.flags != 0,
            "Fields should have appropriate flags set"
        );
    }
}
