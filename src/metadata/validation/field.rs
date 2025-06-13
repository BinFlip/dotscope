//! Field layout validation for .NET metadata
//!
//! This module provides validation utilities for field layout tables,
//! ensuring compliance with .NET runtime rules and metadata constraints.

use crate::{metadata::streams::FieldRc, Result};

/// Maximum allowed field offset value (`INT32_MAX` from .NET runtime)
const MAX_FIELD_OFFSET: u32 = i32::MAX as u32; // 2,147,483,647

/// Validator for field layout metadata
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

    /// Validates field layout for overlap detection in explicit layout types
    ///
    /// # Arguments
    /// * `fields_with_offsets` - Slice of (`field_offset`, `field_size`) tuples
    ///
    /// # Errors
    /// Returns an error if fields overlap in memory layout
    ///
    /// # .NET Runtime Reference
    /// The .NET runtime detects field overlaps during type loading.
    /// This validation helps catch issues early during metadata parsing.
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

    /// Validates that explicit layout types have proper field layout coverage
    ///
    /// # Arguments
    /// * `class_size` - The declared size of the class
    /// * `fields_with_offsets` - Slice of (`field_offset`, `field_size`) tuples
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any field extends beyond the declared class size
    /// - Class size is insufficient for the field layout
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
}
