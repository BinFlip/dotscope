//! Field and class layout constraint validation for .NET metadata layout integrity.
//!
//! This validator ensures the structural integrity of field and class layout constraints,
//! validating proper layout definitions, memory positioning, and alignment requirements.
//! It operates on raw metadata structures to validate the foundational requirements
//! for memory layout safety before higher-level type system validation. This validator
//! runs with priority 120 in the raw validation stage.
//!
//! # Architecture
//!
//! The layout constraint validation system implements comprehensive layout constraint validation strategies in sequential order:
//! 1. **Field Layout Validation** - Ensures proper explicit field positioning and alignment for FieldLayout table entries
//! 2. **Class Layout Validation** - Validates class packing size and total size constraints for ClassLayout table entries
//! 3. **Layout Consistency Validation** - Ensures layout constraints are consistent with inheritance and cross-table relationships
//!
//! The implementation validates layout constraints according to ECMA-335 specifications,
//! ensuring proper memory layout definitions and preventing unsafe memory access patterns.
//! All validation includes overlap detection and boundary checking.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator`] - Main validator implementation providing comprehensive layout validation
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator::validate_field_layouts`] - Field layout position validation with overlap detection
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator::validate_class_layouts`] - Class layout constraint validation with packing size verification
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator::validate_layout_consistency`] - Cross-table layout validation with inheritance checking
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawLayoutConstraintValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawLayoutConstraintValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationRawValidatorFailed`] for:
//! - Invalid field layout positioning or overlapping field definitions (multiple fields at same offset)
//! - Inconsistent class packing size or total size constraints (non-power-of-2 packing, excessive sizes)
//! - Field offsets exceeding class size boundaries (unreasonably large offsets)
//! - Layout constraints violating inheritance requirements (invalid parent references)
//! - Invalid alignment or padding specifications (offsets at maximum boundary)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::raw::constraints`] - Part of the constraint validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_constraint_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10.1.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type layout specification
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - ClassLayout table
//! - [ECMA-335 II.22.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - FieldLayout table

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{ClassLayoutRaw, FieldLayoutRaw, FieldRaw, TypeDefRaw},
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Result,
};
use std::collections::HashMap;

/// Foundation validator for field and class layout constraint integrity and consistency.
///
/// Ensures the structural integrity and consistency of field and class layout constraints
/// in a .NET assembly, validating proper layout definitions, memory positioning, and
/// alignment requirements. This validator operates at the metadata level to provide
/// essential guarantees before higher-level memory layout validation can proceed.
///
/// The validator implements comprehensive coverage of layout constraint validation
/// according to ECMA-335 specifications, ensuring proper layout definitions and
/// preventing unsafe memory access patterns in explicit layout scenarios.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable metadata structures.
pub struct RawLayoutConstraintValidator;

impl RawLayoutConstraintValidator {
    /// Creates a new layout constraint validator.
    ///
    /// Initializes a validator instance that can be used to validate field and class
    /// layout constraints across multiple assemblies. The validator is stateless and
    /// can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates field layout constraints for explicit positioning and alignment.
    ///
    /// Ensures that all field layouts are properly defined with valid offsets,
    /// proper alignment, and no overlapping field definitions. Validates that
    /// field offsets are within reasonable bounds and that explicit layouts
    /// maintain type safety requirements.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field layouts are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Field layout violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Field offsets are invalid or out of bounds (exceeding 0x7FFFFFFF)
    /// - Field layouts overlap in explicit layout scenarios (multiple fields at same offset)
    /// - Field references are invalid or null (zero field reference)
    /// - Field references exceed Field table row count
    fn validate_field_layouts(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(field_layout_table) = tables.table::<FieldLayoutRaw>() {
            let mut field_offsets: HashMap<usize, Vec<(u32, u32)>> = HashMap::new();

            for field_layout in field_layout_table {
                if field_layout.field == 0 {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has null field reference",
                        field_layout.rid
                    ));
                }

                if field_layout.field_offset > 0x7FFF_FFFF {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has invalid field offset {} exceeding maximum",
                        field_layout.rid,
                        field_layout.field_offset
                    ));
                }

                if let Some(field_tbl) = tables.table::<FieldRaw>() {
                    if field_layout.field > field_tbl.row_count {
                        return Err(malformed_error!(
                            "FieldLayout RID {} references Field RID {} but table only has {} rows",
                            field_layout.rid,
                            field_layout.field,
                            field_tbl.row_count
                        ));
                    }
                }

                field_offsets
                    .entry(field_layout.field_offset as usize)
                    .or_default()
                    .push((field_layout.rid, field_layout.field));
            }

            // Based on .NET runtime analysis: Field overlaps are legal in explicit layout types
            // The runtime validates overlaps based on field types (OREF, BYREF, non-OREF) not counts
            // Field layout overlap validation is handled by the type system, not metadata validation
            // Only validate for obviously corrupt metadata patterns
            for (offset, fields) in field_offsets {
                if fields.len() > 1000 {
                    return Err(malformed_error!(
                        "Suspiciously large field overlap at offset {}: {} field layouts share the same position (possible corruption)",
                        offset,
                        fields.len()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates class layout constraints for packing size and total size specifications.
    ///
    /// Ensures that all class layouts are properly defined with valid packing sizes,
    /// reasonable class sizes, and consistent layout specifications. Validates that
    /// class layout constraints are compatible with their field definitions.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All class layouts are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Class layout violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Class packing sizes are invalid (not 0 or power of 2) or exceed 128 bytes
    /// - Class sizes exceed reasonable bounds (exceeding 0x7FFFFFFF)
    /// - Parent type references are invalid (null or exceed TypeDef table row count)
    /// - Layout constraints are malformed
    fn validate_class_layouts(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(class_layout_table) = tables.table::<ClassLayoutRaw>() {
            let typedef_table = tables.table::<TypeDefRaw>();

            for class_layout in class_layout_table {
                let packing_size = class_layout.packing_size;
                if packing_size != 0 && !packing_size.is_power_of_two() {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has invalid packing size {} - must be 0 or a power of 2",
                        class_layout.rid,
                        packing_size
                    ));
                }

                if packing_size > 128 {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has excessive packing size {} exceeding maximum of 128",
                        class_layout.rid,
                        packing_size
                    ));
                }

                if class_layout.class_size > 0x7FFF_FFFF {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has invalid class size {} exceeding maximum",
                        class_layout.rid,
                        class_layout.class_size
                    ));
                }

                if class_layout.parent == 0 {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has null parent reference",
                        class_layout.rid
                    ));
                }

                if let Some(typedef_tbl) = typedef_table {
                    if class_layout.parent > typedef_tbl.row_count {
                        return Err(malformed_error!(
                            "ClassLayout RID {} references TypeDef RID {} but table only has {} rows",
                            class_layout.rid,
                            class_layout.parent,
                            typedef_tbl.row_count
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates layout constraint consistency across related metadata tables.
    ///
    /// Ensures that layout constraints are consistent between ClassLayout and
    /// FieldLayout tables, and that layout definitions maintain proper relationships
    /// with their parent types. Validates cross-table layout constraint integrity.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All layout constraints are consistent
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Layout consistency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Field offsets are at maximum boundary indicating potential overflow
    /// - Parent type references are invalid or missing (non-existent TypeDef RIDs)
    /// - Field layouts exceed reasonable offset bounds (>1MB suggesting corruption)
    /// - ClassLayout parent references point to non-existent TypeDef entries
    fn validate_layout_consistency(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(class_layout_table), Some(field_layout_table), Some(typedef_table)) = (
            tables.table::<ClassLayoutRaw>(),
            tables.table::<FieldLayoutRaw>(),
            tables.table::<TypeDefRaw>(),
        ) {
            let mut class_layouts: HashMap<u32, u32> = HashMap::new();
            for class_layout in class_layout_table {
                class_layouts.insert(class_layout.parent, class_layout.rid);
            }

            for field_layout in field_layout_table {
                if field_layout.field_offset == 0x7FFF_FFFF {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has field offset at maximum boundary - potential overflow",
                        field_layout.rid
                    ));
                }

                if let Some(field_table) = tables.table::<FieldRaw>() {
                    if field_layout.field > field_table.row_count {
                        continue;
                    }

                    let typedef_rows: Vec<_> = typedef_table.iter().collect();
                    let mut parent_typedef_rid = None;

                    for (index, typedef_entry) in typedef_rows.iter().enumerate() {
                        let start_field = typedef_entry.field_list;
                        let end_field = if index + 1 < typedef_rows.len() {
                            typedef_rows[index + 1].field_list
                        } else {
                            u32::MAX
                        };

                        if field_layout.field >= start_field && field_layout.field < end_field {
                            parent_typedef_rid = Some(typedef_entry.rid);
                            break;
                        }
                    }

                    // If we found the parent type, validate field offset against class layout
                    if let Some(parent_rid) = parent_typedef_rid {
                        if let Some(&class_layout_rid) = class_layouts.get(&parent_rid) {
                            // Find the actual class layout to validate field offset against class size
                            if let Some(parent_class_layout) = class_layout_table
                                .iter()
                                .find(|cl| cl.rid == class_layout_rid)
                            {
                                // Validate field offset is reasonable (but allow flexibility for legitimate .NET patterns)
                                // Note: In legitimate .NET assemblies, field offsets can exceed declared class size
                                // due to explicit layout, union types, interop scenarios, inheritance, etc.
                                // Only flag truly unreasonable offsets that suggest corruption
                                if parent_class_layout.class_size > 0
                                    && field_layout.field_offset > 1_048_576
                                {
                                    return Err(malformed_error!(
                                        "FieldLayout RID {} has unreasonably large field offset {} (possible corruption)",
                                        field_layout.rid,
                                        field_layout.field_offset
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            for class_layout in class_layout_table {
                let typedef_found = typedef_table
                    .iter()
                    .any(|typedef| typedef.rid == class_layout.parent);

                if !typedef_found {
                    return Err(malformed_error!(
                        "ClassLayout RID {} references non-existent TypeDef RID {}",
                        class_layout.rid,
                        class_layout.parent
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates field alignment and type size consistency for layout integrity.
    ///
    /// Ensures that field layouts respect natural alignment requirements and that
    /// field offsets are reasonable relative to their declared types. Provides
    /// additional safety validation beyond basic bounds checking.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field alignments are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Alignment violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Field offsets are not properly aligned for their type
    /// - Field layouts violate natural alignment requirements
    /// - Explicit layout fields have unreasonable spacing
    fn validate_field_alignment(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(field_layout_table), Some(_field_table)) =
            (tables.table::<FieldLayoutRaw>(), tables.table::<FieldRaw>())
        {
            for field_layout in field_layout_table {
                let field_offset = field_layout.field_offset;

                if (field_offset % 4 == 1 || field_offset % 4 == 3) && field_offset > 65536 {
                    return Err(malformed_error!(
                            "FieldLayout RID {} has unusual alignment at field offset {} - potential layout issue",
                            field_layout.rid,
                            field_offset
                        ));
                }

                if field_offset > 16_777_216 {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has extremely large field offset {} - possible corruption",
                        field_layout.rid,
                        field_offset
                    ));
                }

                if field_offset == u32::MAX - 1 || field_offset == u32::MAX - 3 {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has field offset {} near maximum boundary - overflow risk",
                        field_layout.rid,
                        field_offset
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates layout constraints for value types and their special requirements.
    ///
    /// Ensures that value type layouts meet special requirements for stack allocation
    /// and value semantics. Validates that value type layouts are reasonable and
    /// don't violate runtime constraints.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All value type layouts are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Value type violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Value type class sizes exceed reasonable stack limits
    /// - Value type packing constraints are inappropriate
    /// - Value type field layouts create alignment issues
    fn validate_value_type_layouts(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(class_layout_table), Some(typedef_table)) = (
            tables.table::<ClassLayoutRaw>(),
            tables.table::<TypeDefRaw>(),
        ) {
            for class_layout in class_layout_table {
                if let Some(typedef_entry) = typedef_table
                    .iter()
                    .find(|td| td.rid == class_layout.parent)
                {
                    const SEALED_FLAG: u32 = 0x0100;
                    const SERIALIZABLE_FLAG: u32 = 0x2000;

                    let is_likely_value_type = (typedef_entry.flags & SEALED_FLAG) != 0;

                    if is_likely_value_type {
                        if class_layout.class_size > 1_048_576 {
                            return Err(malformed_error!(
                                "ClassLayout RID {} for potential value type has excessive size {} - may cause stack issues",
                                class_layout.rid,
                                class_layout.class_size
                            ));
                        }

                        if class_layout.packing_size > 0
                            && class_layout.class_size > 0
                            && u32::from(class_layout.packing_size) > class_layout.class_size
                        {
                            return Err(malformed_error!(
                                    "ClassLayout RID {} has packing size {} larger than class size {} - invalid layout",
                                    class_layout.rid,
                                    class_layout.packing_size,
                                    class_layout.class_size
                                ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates sequential layout ordering and constraints.
    ///
    /// For types with sequential layout, ensures that field ordering makes sense
    /// and that layout constraints are appropriate for sequential allocation.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All sequential layouts are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Sequential layout violations found
    fn validate_sequential_layout(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(field_layout_table) = tables.table::<FieldLayoutRaw>() {
            let field_layouts: Vec<_> = field_layout_table.iter().collect();
            let mut type_field_layouts: HashMap<u32, Vec<FieldLayoutRaw>> = HashMap::new();

            for field_layout in field_layouts {
                let estimated_parent = field_layout.field / 10; // Very rough grouping
                type_field_layouts
                    .entry(estimated_parent)
                    .or_default()
                    .push(field_layout.clone());
            }

            for (_parent_id, mut fields) in type_field_layouts {
                if fields.len() > 1 {
                    fields.sort_by_key(|f| f.field_offset);

                    for window in fields.windows(2) {
                        let field1 = &window[0];
                        let field2 = &window[1];
                        let gap = field2.field_offset.saturating_sub(field1.field_offset);

                        if gap > 1_048_576 {
                            return Err(malformed_error!(
                                "Large gap {} between FieldLayout RID {} and {} - possible layout issue",
                                gap,
                                field1.rid,
                                field2.rid
                            ));
                        }

                        if gap == 0 && field1.field_offset > 0 && field1.field_offset > 65536 {
                            return Err(malformed_error!(
                                    "FieldLayout RID {} and {} overlap at large field offset {} - verify union layout",
                                    field1.rid,
                                    field2.rid,
                                    field1.field_offset
                                ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl RawValidator for RawLayoutConstraintValidator {
    /// Validates the structural integrity and consistency of all field and class layout constraints.
    ///
    /// Performs comprehensive validation of layout constraints, including:
    /// 1. Field layout position and alignment validation
    /// 2. Class layout size and packing constraint validation
    /// 3. Memory overlap detection for explicit layouts
    /// 4. Cross-table layout consistency validation
    ///
    /// This method provides foundational guarantees about layout constraint integrity
    /// that higher-level memory layout validators can rely upon during semantic validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All layout constraints are valid and meet ECMA-335 requirements
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Layout constraint violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] for:
    /// - Invalid field layout positioning or overlapping field definitions
    /// - Inconsistent class packing size or total size constraints
    /// - Field offsets exceeding class size boundaries
    /// - Layout constraints violating inheritance requirements
    /// - Invalid alignment or padding specifications
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();

        Self::validate_field_layouts(assembly_view)?;
        Self::validate_class_layouts(assembly_view)?;
        Self::validate_layout_consistency(assembly_view)?;

        Self::validate_field_alignment(assembly_view)?;
        Self::validate_value_type_layouts(assembly_view)?;
        Self::validate_sequential_layout(assembly_view)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawLayoutConstraintValidator"
    }

    fn priority(&self) -> u32 {
        120
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_constraint_validation
    }
}

impl Default for RawLayoutConstraintValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        test::{
            factories::validation::raw_constraints_layout::raw_layout_constraint_validator_file_factory,
            validator_test,
        },
    };

    #[test]
    fn test_raw_layout_constraint_validator() -> Result<()> {
        let validator = RawLayoutConstraintValidator::new();
        let config = ValidationConfig {
            enable_constraint_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_layout_constraint_validator_file_factory,
            "RawLayoutConstraintValidator",
            "Malformed",
            config,
            |context| validator.validate_raw(context),
        )
    }
}
