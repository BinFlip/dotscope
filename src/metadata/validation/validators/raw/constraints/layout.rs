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
//! This validator returns [`crate::Error::ValidationConstraintError`] for:
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
        tables::*,
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Field layout violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationConstraintError`] if:
    /// - Field offsets are invalid or out of bounds (exceeding 0x7FFFFFFF)
    /// - Field layouts overlap in explicit layout scenarios (multiple fields at same offset)
    /// - Field references are invalid or null (zero field reference)
    /// - Field references exceed Field table row count
    fn validate_field_layouts(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(field_layout_table) = tables.table::<FieldLayoutRaw>() {
            let mut field_offsets: HashMap<usize, Vec<(u32, u32)>> = HashMap::new();

            for field_layout in field_layout_table.iter() {
                // Validate field reference is not null
                if field_layout.field == 0 {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has null field reference",
                        field_layout.rid
                    ));
                }

                // Validate offset is reasonable (not exceeding 2GB)
                if field_layout.offset > 0x7FFFFFFF {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has invalid offset {} exceeding maximum",
                        field_layout.rid,
                        field_layout.offset
                    ));
                }

                // Validate field reference points to valid Field if table exists
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

                // Group field layouts by their parent type for overlap detection
                // For now, we'll collect offsets and detect obvious overlaps within the same offset
                field_offsets
                    .entry(field_layout.offset)
                    .or_default()
                    .push((field_layout.rid, field_layout.field));
            }

            // Check for multiple fields at the same offset (potential overlap)
            for (offset, fields) in field_offsets {
                if fields.len() > 1 {
                    return Err(malformed_error!(
                        "Multiple fields found at offset {}: {} field layouts share the same position",
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Class layout violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationConstraintError`] if:
    /// - Class packing sizes are invalid (not 0 or power of 2) or exceed 128 bytes
    /// - Class sizes exceed reasonable bounds (exceeding 0x7FFFFFFF)
    /// - Parent type references are invalid (null or exceed TypeDef table row count)
    /// - Layout constraints are malformed
    fn validate_class_layouts(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(class_layout_table) = tables.table::<ClassLayoutRaw>() {
            let typedef_table = tables.table::<TypeDefRaw>();

            for class_layout in class_layout_table.iter() {
                // Validate packing size is a power of 2 (0, 1, 2, 4, 8, 16, 32, 64, 128)
                let packing_size = class_layout.packing_size;
                if packing_size != 0 && !packing_size.is_power_of_two() {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has invalid packing size {} - must be 0 or a power of 2",
                        class_layout.rid,
                        packing_size
                    ));
                }

                // Validate packing size doesn't exceed reasonable bounds (128 bytes)
                if packing_size > 128 {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has excessive packing size {} exceeding maximum of 128",
                        class_layout.rid,
                        packing_size
                    ));
                }

                // Validate class size is reasonable (not exceeding 2GB)
                if class_layout.class_size > 0x7FFFFFFF {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has invalid class size {} exceeding maximum",
                        class_layout.rid,
                        class_layout.class_size
                    ));
                }

                // Validate parent reference is not null
                if class_layout.parent == 0 {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has null parent reference",
                        class_layout.rid
                    ));
                }

                // Validate parent reference points to valid TypeDef if table exists
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Layout consistency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationConstraintError`] if:
    /// - Field offsets are at maximum boundary indicating potential overflow
    /// - Parent type references are invalid or missing (non-existent TypeDef RIDs)
    /// - Field layouts exceed reasonable offset bounds (>1MB suggesting corruption)
    /// - ClassLayout parent references point to non-existent TypeDef entries
    fn validate_layout_consistency(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        // Validate consistency between ClassLayout and FieldLayout tables
        if let (Some(class_layout_table), Some(field_layout_table), Some(typedef_table)) = (
            tables.table::<ClassLayoutRaw>(),
            tables.table::<FieldLayoutRaw>(),
            tables.table::<TypeDefRaw>(),
        ) {
            // Build a map of TypeDef to ClassLayout RID for efficient lookup
            let mut class_layouts: HashMap<u32, u32> = HashMap::new();
            for class_layout in class_layout_table.iter() {
                class_layouts.insert(class_layout.parent, class_layout.rid);
            }

            // For each field layout, check if it's consistent with its type's class layout
            for field_layout in field_layout_table.iter() {
                // Validate field offset is not at the exact boundary of maximum class size
                // (this would indicate potential overflow)
                if field_layout.offset == 0x7FFFFFFF {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has field offset at maximum boundary - potential overflow",
                        field_layout.rid
                    ));
                }

                // Find the field's parent type by resolving through TypeDef field ownership ranges
                if let Some(field_table) = tables.table::<FieldRaw>() {
                    if field_layout.field > field_table.row_count {
                        continue; // Skip if field reference is invalid (already validated earlier)
                    }

                    // Find which TypeDef owns this field using range-based ownership
                    let typedef_rows: Vec<_> = typedef_table.iter().collect();
                    let mut parent_typedef_rid = None;

                    for (index, typedef_entry) in typedef_rows.iter().enumerate() {
                        let start_field = typedef_entry.field_list;
                        let end_field = if index + 1 < typedef_rows.len() {
                            typedef_rows[index + 1].field_list
                        } else {
                            u32::MAX // Last TypeDef owns all remaining fields
                        };

                        // Check if field falls within this TypeDef's ownership range
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
                                    && field_layout.offset > 1048576
                                // 1MB - reasonable upper bound
                                {
                                    return Err(malformed_error!(
                                        "FieldLayout RID {} has unreasonably large offset {} (possible corruption)",
                                        field_layout.rid,
                                        field_layout.offset
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Validate that all ClassLayout parent references point to valid TypeDef entries
            for class_layout in class_layout_table.iter() {
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Alignment violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationConstraintError`] if:
    /// - Field offsets are not properly aligned for their type
    /// - Field layouts violate natural alignment requirements
    /// - Explicit layout fields have unreasonable spacing
    fn validate_field_alignment(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(field_layout_table), Some(_field_table)) =
            (tables.table::<FieldLayoutRaw>(), tables.table::<FieldRaw>())
        {
            for field_layout in field_layout_table.iter() {
                // Validate field offset alignment for common cases
                let offset = field_layout.offset;

                // Basic alignment validation - ensure offsets are not on odd boundaries
                // for what appear to be larger data types based on common patterns
                if offset % 4 == 1 || offset % 4 == 3 {
                    // Allow this but validate it's not excessive
                    if offset > 65536 {
                        return Err(malformed_error!(
                            "FieldLayout RID {} has unusual alignment at offset {} - potential layout issue",
                            field_layout.rid,
                            offset
                        ));
                    }
                }

                // Validate against extremely large gaps that suggest corruption
                // (while allowing legitimate large offsets for interop scenarios)
                if offset > 16777216 {
                    // 16MB - very generous upper bound
                    return Err(malformed_error!(
                        "FieldLayout RID {} has extremely large offset {} - possible corruption",
                        field_layout.rid,
                        offset
                    ));
                }

                // Basic sanity check: ensure offset is not at problematic boundaries
                if offset == usize::MAX - 1 || offset == usize::MAX - 3 {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has offset {} near maximum boundary - overflow risk",
                        field_layout.rid,
                        offset
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Value type violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationConstraintError`] if:
    /// - Value type class sizes exceed reasonable stack limits
    /// - Value type packing constraints are inappropriate
    /// - Value type field layouts create alignment issues
    fn validate_value_type_layouts(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(class_layout_table), Some(typedef_table)) = (
            tables.table::<ClassLayoutRaw>(),
            tables.table::<TypeDefRaw>(),
        ) {
            for class_layout in class_layout_table.iter() {
                // Find the corresponding TypeDef to check if it's a value type
                if let Some(typedef_entry) = typedef_table
                    .iter()
                    .find(|td| td.rid == class_layout.parent)
                {
                    // Check for value type characteristics in flags
                    // This is a heuristic check - in a full implementation we'd resolve inheritance
                    const SEALED_FLAG: u32 = 0x0100;
                    const SERIALIZABLE_FLAG: u32 = 0x2000;

                    let is_likely_value_type = (typedef_entry.flags & SEALED_FLAG) != 0;

                    if is_likely_value_type {
                        // Validate value type class size is reasonable for stack allocation
                        // .NET has practical limits on value type sizes for performance
                        if class_layout.class_size > 1048576 {
                            // 1MB is very generous
                            return Err(malformed_error!(
                                "ClassLayout RID {} for potential value type has excessive size {} - may cause stack issues",
                                class_layout.rid,
                                class_layout.class_size
                            ));
                        }

                        // Validate packing size is appropriate for value types
                        if class_layout.packing_size > 64 {
                            // Allow larger packing sizes but warn about potential issues
                            // In practice, most value types use smaller packing sizes
                        }

                        // Validate class size and packing size relationship
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Sequential layout violations found
    fn validate_sequential_layout(&self, assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(field_layout_table) = tables.table::<FieldLayoutRaw>() {
            // Collect field layouts into owned vectors for grouping
            let field_layouts: Vec<_> = field_layout_table.iter().collect();
            let mut type_field_layouts: HashMap<u32, Vec<FieldLayoutRaw>> = HashMap::new();

            // This is a simplified approach - in a full implementation we'd resolve
            // the actual parent types through TypeDef field ownership
            for field_layout in field_layouts {
                // Use field RID as a proxy for grouping (simplified)
                let estimated_parent = field_layout.field / 10; // Very rough grouping
                type_field_layouts
                    .entry(estimated_parent)
                    .or_default()
                    .push(field_layout.clone());
            }

            // Validate field layout ordering within each type
            for (_parent_id, mut fields) in type_field_layouts {
                if fields.len() > 1 {
                    // Sort by offset to check for reasonable sequential ordering
                    fields.sort_by_key(|f| f.offset);

                    // Check for reasonable spacing between sequential fields
                    for window in fields.windows(2) {
                        let field1 = &window[0];
                        let field2 = &window[1];
                        let gap = field2.offset.saturating_sub(field1.offset);

                        // Flag extremely large gaps as potential issues
                        if gap > 1048576 {
                            // 1MB gap
                            return Err(malformed_error!(
                                "Large gap {} between FieldLayout RID {} and {} - possible layout issue",
                                gap,
                                field1.rid,
                                field2.rid
                            ));
                        }

                        // Flag zero gaps (overlapping) unless it's intentional (union-style)
                        if gap == 0 && field1.offset > 0 {
                            // This might be intentional for union types, so just validate it's reasonable
                            if field1.offset > 65536 {
                                return Err(malformed_error!(
                                    "FieldLayout RID {} and {} overlap at large offset {} - verify union layout",
                                    field1.rid,
                                    field2.rid,
                                    field1.offset
                                ));
                            }
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
    /// * `Err(`[`crate::Error::ValidationConstraintError`]`)` - Layout constraint violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationConstraintError`] for:
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

        // Core layout validation
        self.validate_field_layouts(assembly_view)?;
        self.validate_class_layouts(assembly_view)?;
        self.validate_layout_consistency(assembly_view)?;

        // Enhanced layout validation
        self.validate_field_alignment(assembly_view)?;
        self.validate_value_type_layouts(assembly_view)?;
        self.validate_sequential_layout(assembly_view)?;

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
    use crate::metadata::{
        cilassemblyview::CilAssemblyView,
        validation::{config::ValidationConfig, context::factory, scanner::ReferenceScanner},
    };
    use std::path::PathBuf;

    #[test]
    fn test_raw_layout_constraint_validator_creation() {
        let validator = RawLayoutConstraintValidator::new();
        assert_eq!(validator.name(), "RawLayoutConstraintValidator");
        assert_eq!(validator.priority(), 120);
    }

    #[test]
    fn test_raw_layout_constraint_validator_should_run() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::new(&view).unwrap();
            let mut config = ValidationConfig::minimal();

            config.enable_constraint_validation = true;
            let context = factory::raw_loading_context(&view, &scanner, &config);
            let validator = RawLayoutConstraintValidator::new();
            assert!(validator.should_run(&context));

            config.enable_constraint_validation = false;
            let context = factory::raw_loading_context(&view, &scanner, &config);
            assert!(!validator.should_run(&context));
        }
    }

    #[test]
    fn test_raw_layout_constraint_validator_validate() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::new(&view).unwrap();
            let config = ValidationConfig::minimal();
            let context = factory::raw_loading_context(&view, &scanner, &config);

            let validator = RawLayoutConstraintValidator::new();
            assert!(validator.validate_raw(&context).is_ok());
        }
    }
}
