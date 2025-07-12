//! Raw operation validator for assembly modification operation validation.
//!
//! This validator ensures the structural integrity of metadata modification operations,
//! validating individual insert, update, and delete operations for proper format,
//! RID bounds, and basic conflict detection. It operates on raw operation data
//! to provide foundational guarantees before higher-level semantic validation.
//! This validator runs with priority 110 and only operates during modification validation.
//!
//! # Architecture
//!
//! The operation validation system implements comprehensive operation validation strategies in sequential order:
//! 1. **Insert Operation Validation** - Ensures new rows have valid RIDs and proper data format
//! 2. **Update Operation Validation** - Validates target RIDs exist and data format is correct
//! 3. **Delete Operation Validation** - Ensures delete targets exist and are safe to remove
//! 4. **Operation Sequence Validation** - Checks for temporal ordering and basic conflicts
//!
//! The implementation validates operations according to ECMA-335 specifications,
//! ensuring proper modification structure before application to metadata tables.
//! All validation includes RID bounds checking and temporal consistency verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::modification::operation::RawOperationValidator`] - Main validator implementation providing comprehensive operation validation
//! - [`crate::metadata::validation::validators::raw::modification::operation::RawOperationValidator::validate_insert_operations`] - Insert operation validation with RID conflict detection
//! - [`crate::metadata::validation::validators::raw::modification::operation::RawOperationValidator::validate_update_operations`] - Update operation validation with target existence checking
//! - [`crate::metadata::validation::validators::raw::modification::operation::RawOperationValidator::validate_delete_operations`] - Delete operation validation with safety checking
//! - [`crate::metadata::validation::validators::raw::modification::operation::RawOperationValidator::validate_operation_sequences`] - Sequence validation with temporal ordering
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawOperationValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawOperationValidator::new();
//!
//! // Check if validation should run (only for modification contexts)
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationStructuralError`] for:
//! - Invalid RID values in operations (out of bounds, conflicts, reserved values)
//! - Malformed operation data or incorrect table data types
//! - Update operations targeting non-existent rows or deleted rows
//! - Delete operations creating referential integrity violations or targeting critical metadata
//! - Operation sequence conflicts or invalid temporal ordering
//! - Multiple operations targeting the same RID without proper sequencing
//! - Excessive update operations indicating potential loops
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable operation structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::raw::modification`] - Part of the modification validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::cilassembly::AssemblyChanges`] - Source of modification operations
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution
//!
//! # References
//!
//! - [ECMA-335 II.22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata table specifications
//! - [ECMA-335 II.24](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata physical layout

use crate::{
    cilassembly::{Operation, TableModifications},
    metadata::{
        tables::{TableDataOwned, TableId},
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Result,
};
use std::collections::{HashMap, HashSet};

/// Foundation validator for assembly modification operation integrity and consistency.
///
/// Ensures the structural integrity and consistency of modification operations
/// in assembly changes, validating proper operation format, RID bounds, and
/// basic conflict detection. This validator operates at the operation level to provide
/// essential guarantees before modification application can proceed.
///
/// The validator implements comprehensive coverage of operation validation
/// according to ECMA-335 specifications, ensuring proper operation structure and
/// preventing malformed modifications that could corrupt metadata integrity.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable operation structures.
pub struct RawOperationValidator;

impl RawOperationValidator {
    /// Creates a new operation validator.
    ///
    /// Initializes a validator instance that can be used to validate modification
    /// operations across multiple assemblies. The validator is stateless and can be
    /// reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::raw::modification::operation::RawOperationValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    pub fn new() -> Self {
        Self
    }

    /// Validates insert operations for proper RID allocation and data format.
    ///
    /// Ensures that all insert operations have valid RIDs, proper table data types,
    /// and do not conflict with existing rows or other insert operations. Validates
    /// that RID allocation follows proper sequencing and bounds checking.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications containing operations to validate via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All insert operations are valid
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Insert operation violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - Insert RIDs are invalid (zero/reserved) or out of bounds (exceeding 0xFFFFFF)
    /// - Insert operations conflict with existing rows in original table
    /// - Multiple inserts target the same RID within the same table
    /// - Table data types are incompatible with target tables
    /// - RID allocation jumps too far ahead of next available RID
    fn validate_insert_operations(
        &self,
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        for (table_id, modifications) in table_changes {
            if let TableModifications::Sparse {
                operations,
                next_rid,
                original_row_count,
                ..
            } = modifications
            {
                let mut insert_rids = HashSet::new();

                for operation in operations {
                    if let Operation::Insert(rid, table_data) = &operation.operation {
                        // Validate RID is not zero (reserved)
                        if *rid == 0 {
                            return Err(malformed_error!(
                                "Insert operation for table {:?} has invalid RID 0 - RID 0 is reserved",
                                table_id
                            ));
                        }

                        // Validate RID doesn't exceed reasonable bounds (2^24 - 1 for metadata tokens)
                        if *rid > 0xFFFFFF {
                            return Err(malformed_error!(
                                "Insert operation for table {:?} has RID {} exceeding maximum metadata token limit",
                                table_id,
                                rid
                            ));
                        }

                        // Validate RID is not conflicting with original table rows
                        if *rid <= *original_row_count {
                            return Err(malformed_error!(
                                "Insert operation for table {:?} targets RID {} which conflicts with existing row (original count: {})",
                                table_id,
                                rid,
                                original_row_count
                            ));
                        }

                        // Validate RID allocation is sequential from next_rid
                        if *rid >= *next_rid + 1000 {
                            return Err(malformed_error!(
                                "Insert operation for table {:?} has RID {} too far ahead of next available RID {} - potential RID exhaustion",
                                table_id,
                                rid,
                                next_rid
                            ));
                        }

                        // Check for duplicate insert RIDs
                        if !insert_rids.insert(*rid) {
                            return Err(malformed_error!(
                                "Multiple insert operations for table {:?} target the same RID {}",
                                table_id,
                                rid
                            ));
                        }

                        // Validate table data type matches the target table
                        if !self.validate_table_data_compatibility(*table_id, table_data) {
                            return Err(malformed_error!(
                                "Insert operation for table {:?} has incompatible table data type",
                                table_id
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates update operations for proper target validation and data format.
    ///
    /// Ensures that all update operations target existing rows, have proper table data types,
    /// and do not create invalid state transitions. Validates that update operations
    /// maintain metadata integrity and ECMA-335 compliance.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications containing operations to validate via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All update operations are valid
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Update operation violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - Update operations target non-existent rows (beyond original count and not inserted)
    /// - Update RIDs are invalid (zero/reserved) or target deleted rows
    /// - Table data types are incompatible with target tables
    /// - Excessive updates target the same RID (potential update loop detection)
    fn validate_update_operations(
        &self,
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        for (table_id, modifications) in table_changes {
            if let TableModifications::Sparse {
                operations,
                original_row_count,
                deleted_rows,
                ..
            } = modifications
            {
                let mut update_rids = HashMap::new();

                for operation in operations {
                    if let Operation::Update(rid, table_data) = &operation.operation {
                        // Validate RID is not zero (reserved)
                        if *rid == 0 {
                            return Err(malformed_error!(
                                "Update operation for table {:?} has invalid RID 0 - RID 0 is reserved",
                                table_id
                            ));
                        }

                        // Validate RID targets an existing or inserted row
                        let targets_original = *rid <= *original_row_count;
                        let targets_inserted = operations.iter().any(|op| {
                            matches!(&op.operation, Operation::Insert(insert_rid, _) if insert_rid == rid)
                        });

                        if !targets_original && !targets_inserted {
                            return Err(malformed_error!(
                                "Update operation for table {:?} targets non-existent RID {}",
                                table_id,
                                rid
                            ));
                        }

                        // Validate RID is not deleted
                        if deleted_rows.contains(rid) {
                            return Err(malformed_error!(
                                "Update operation for table {:?} targets deleted RID {}",
                                table_id,
                                rid
                            ));
                        }

                        // Track multiple updates to the same RID (allowed with timestamp ordering)
                        let update_count = update_rids.entry(*rid).or_insert(0);
                        *update_count += 1;

                        if *update_count > 10 {
                            return Err(malformed_error!(
                                "Excessive update operations ({}) for table {:?} RID {} - potential update loop",
                                update_count,
                                table_id,
                                rid
                            ));
                        }

                        // Validate table data type matches the target table
                        if !self.validate_table_data_compatibility(*table_id, table_data) {
                            return Err(malformed_error!(
                                "Update operation for table {:?} has incompatible table data type",
                                table_id
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates delete operations for safe deletion and referential integrity.
    ///
    /// Ensures that all delete operations target existing rows and do not create
    /// invalid states. Validates that delete operations maintain basic structural
    /// integrity requirements for metadata tables.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications containing operations to validate via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All delete operations are valid
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Delete operation violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - Delete operations target non-existent rows (beyond original count and not inserted)
    /// - Delete RIDs are invalid (zero/reserved)
    /// - Multiple deletes target the same RID within the same table
    /// - Critical metadata rows are being deleted (Module RID 1, Assembly RID 1)
    fn validate_delete_operations(
        &self,
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        for (table_id, modifications) in table_changes {
            if let TableModifications::Sparse {
                operations,
                original_row_count,
                ..
            } = modifications
            {
                let mut delete_rids = HashSet::new();

                for operation in operations {
                    if let Operation::Delete(rid) = &operation.operation {
                        // Validate RID is not zero (reserved)
                        if *rid == 0 {
                            return Err(malformed_error!(
                                "Delete operation for table {:?} has invalid RID 0 - RID 0 is reserved",
                                table_id
                            ));
                        }

                        // Validate RID targets an existing or inserted row
                        let targets_original = *rid <= *original_row_count;
                        let targets_inserted = operations.iter().any(|op| {
                            matches!(&op.operation, Operation::Insert(insert_rid, _) if insert_rid == rid)
                        });

                        if !targets_original && !targets_inserted {
                            return Err(malformed_error!(
                                "Delete operation for table {:?} targets non-existent RID {}",
                                table_id,
                                rid
                            ));
                        }

                        // Check for duplicate delete RIDs
                        if !delete_rids.insert(*rid) {
                            return Err(malformed_error!(
                                "Multiple delete operations for table {:?} target the same RID {}",
                                table_id,
                                rid
                            ));
                        }

                        // Validate critical tables don't have module deletion (RID 1)
                        if matches!(table_id, TableId::Module | TableId::Assembly) && *rid == 1 {
                            return Err(malformed_error!(
                                "Delete operation for critical table {:?} targets RID 1 - cannot delete primary metadata entry",
                                table_id
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates operation sequences for proper temporal ordering and consistency.
    ///
    /// Ensures that operation sequences maintain proper chronological ordering,
    /// conflict resolution through timestamps, and do not create impossible
    /// state transitions. Validates operation dependencies and sequencing.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications containing operations to validate via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All operation sequences are valid
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Sequence violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] if:
    /// - Operations have invalid timestamps or non-chronological ordering
    /// - Operation sequences create impossible state transitions (insert after delete)
    /// - Multiple insert or delete operations target the same RID
    /// - Update operations occur after delete operations for the same RID
    fn validate_operation_sequences(
        &self,
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        for (table_id, modifications) in table_changes {
            if let TableModifications::Sparse { operations, .. } = modifications {
                // Validate operations are chronologically ordered
                for window in operations.windows(2) {
                    if window[0].timestamp > window[1].timestamp {
                        return Err(malformed_error!(
                            "Operations for table {:?} are not chronologically ordered - timestamp {} > {}",
                            table_id,
                            window[0].timestamp,
                            window[1].timestamp
                        ));
                    }
                }

                // Validate operation sequences for each RID
                let mut rid_operations: HashMap<u32, Vec<&Operation>> = HashMap::new();
                for operation in operations {
                    let rid = operation.operation.get_rid();
                    rid_operations
                        .entry(rid)
                        .or_default()
                        .push(&operation.operation);
                }

                for (rid, ops) in rid_operations {
                    // Validate operation sequence logic for each RID
                    let mut has_insert = false;
                    let mut has_delete = false;

                    for op in &ops {
                        match op {
                            Operation::Insert(_, _) => {
                                if has_insert {
                                    return Err(malformed_error!(
                                        "Multiple insert operations for table {:?} RID {} - invalid sequence",
                                        table_id,
                                        rid
                                    ));
                                }
                                if has_delete {
                                    return Err(malformed_error!(
                                        "Insert operation after delete for table {:?} RID {} - invalid sequence",
                                        table_id,
                                        rid
                                    ));
                                }
                                has_insert = true;
                            }
                            Operation::Update(_, _) => {
                                if has_delete {
                                    return Err(malformed_error!(
                                        "Update operation after delete for table {:?} RID {} - invalid sequence",
                                        table_id,
                                        rid
                                    ));
                                }
                            }
                            Operation::Delete(_) => {
                                if has_delete {
                                    return Err(malformed_error!(
                                        "Multiple delete operations for table {:?} RID {} - invalid sequence",
                                        table_id,
                                        rid
                                    ));
                                }
                                has_delete = true;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates table data compatibility with target table type.
    ///
    /// Ensures that table data variants match their target tables by verifying
    /// that the [`crate::metadata::tables::TableDataOwned`] variant corresponds to the expected [`crate::metadata::tables::TableId`].
    /// This prevents type mismatches that could cause corruption during metadata generation.
    ///
    /// # Arguments
    ///
    /// * `table_id` - Target table identifier from [`crate::metadata::tables::TableId`]
    /// * `table_data` - Table data to validate against the target table via [`crate::metadata::tables::TableDataOwned`]
    ///
    /// # Returns
    ///
    /// Returns `true` if the table data variant matches the target table, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::tables::{TableDataOwned, TableId};
    ///
    /// // Compatible: TypeDef data for TypeDef table
    /// let type_def_data = TableDataOwned::TypeDef(/* ... */);
    /// assert!(validator.validate_table_data_compatibility(TableId::TypeDef, &type_def_data));
    ///
    /// // Incompatible: TypeDef data for Field table
    /// assert!(!validator.validate_table_data_compatibility(TableId::Field, &type_def_data));
    /// ```
    fn validate_table_data_compatibility(
        &self,
        table_id: TableId,
        table_data: &TableDataOwned,
    ) -> bool {
        let data_table_id = table_data.table_id();
        data_table_id == table_id
    }
}

impl RawValidator for RawOperationValidator {
    /// Validates the structural integrity and consistency of all modification operations.
    ///
    /// Performs comprehensive validation of modification operations, including:
    /// 1. Insert operation RID allocation and data format validation
    /// 2. Update operation target validation and data format validation
    /// 3. Delete operation safety and target validation
    /// 4. Operation sequence temporal ordering and consistency validation
    ///
    /// This method provides foundational guarantees about operation integrity
    /// that higher-level modification validators can rely upon during application.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly changes and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All modification operations are valid and meet structural requirements
    /// * `Err(`[`crate::Error::ValidationStructuralError`]`)` - Operation violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationStructuralError`] for:
    /// - Invalid RID values in operations (out of bounds, conflicts)
    /// - Malformed operation data or incorrect table data types
    /// - Update operations targeting non-existent rows
    /// - Delete operations creating structural violations
    /// - Operation sequence conflicts or invalid temporal ordering
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        // Get assembly changes from context
        if let Some(changes) = context.changes() {
            let table_changes = &changes.table_changes;

            self.validate_insert_operations(table_changes)?;
            self.validate_update_operations(table_changes)?;
            self.validate_delete_operations(table_changes)?;
            self.validate_operation_sequences(table_changes)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawOperationValidator"
    }

    fn priority(&self) -> u32 {
        110
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_structural_validation && context.is_modification_validation()
    }
}

impl Default for RawOperationValidator {
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
    fn test_raw_operation_validator_creation() {
        let validator = RawOperationValidator::new();
        assert_eq!(validator.name(), "RawOperationValidator");
        assert_eq!(validator.priority(), 110);
    }

    #[test]
    fn test_raw_operation_validator_should_run() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::new(&view).unwrap();
            let changes = crate::cilassembly::AssemblyChanges::new(&view);
            let mut config = ValidationConfig::minimal();

            config.enable_structural_validation = true;
            let context = factory::raw_modification_context(&view, &changes, &scanner, &config);
            let validator = RawOperationValidator::new();
            assert!(validator.should_run(&context));

            config.enable_structural_validation = false;
            let context = factory::raw_modification_context(&view, &changes, &scanner, &config);
            assert!(!validator.should_run(&context));

            // Test loading context (should not run)
            let loading_context = factory::raw_loading_context(&view, &scanner, &config);
            assert!(!validator.should_run(&loading_context));
        }
    }

    #[test]
    fn test_raw_operation_validator_validate_empty_context() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let scanner = ReferenceScanner::new(&view).unwrap();
            let config = ValidationConfig::minimal();
            let context = factory::raw_loading_context(&view, &scanner, &config);

            let validator = RawOperationValidator::new();
            assert!(validator.validate_raw(&context).is_ok());
        }
    }

    #[test]
    fn test_table_data_compatibility() {
        let validator = RawOperationValidator::new();

        // Create test table data using just the fields that work
        use crate::metadata::{tables::*, token::Token};

        let module_data = TableDataOwned::Module(ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001), // Table 0x00, RID 1
            offset: 0,
            generation: 0,
            name: 0,
            mvid: 0,
            encid: 0,
            encbaseid: 0,
        });

        let field_data = TableDataOwned::Field(FieldRaw {
            rid: 1,
            token: Token::new(0x04000001), // Table 0x04, RID 1
            offset: 0,
            flags: 0,
            name: 0,
            signature: 0,
        });

        // Test exact matches (compatible cases)
        assert!(validator.validate_table_data_compatibility(TableId::Module, &module_data));
        assert!(validator.validate_table_data_compatibility(TableId::Field, &field_data));

        // Test mismatches (incompatible cases)
        assert!(!validator.validate_table_data_compatibility(TableId::Field, &module_data));
        assert!(!validator.validate_table_data_compatibility(TableId::Module, &field_data));
        assert!(!validator.validate_table_data_compatibility(TableId::Assembly, &module_data));
        assert!(!validator.validate_table_data_compatibility(TableId::GenericParam, &field_data));

        // Test that the method correctly delegates to table_id()
        assert_eq!(module_data.table_id(), TableId::Module);
        assert_eq!(field_data.table_id(), TableId::Field);
    }
}
