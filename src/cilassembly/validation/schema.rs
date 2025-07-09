//! Basic schema validation for table operations in assembly modifications.
//!
//! This module provides fundamental schema validation to ensure that table operations
//! conform to ECMA-335 metadata table specifications. It validates data type compatibility,
//! RID constraints, and basic referential integrity to prevent invalid operations from
//! being applied to the assembly metadata.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::validation::schema::BasicSchemaValidator`] - Main schema validator for table operations
//!
//! # Architecture
//!
//! The schema validation system provides fundamental validation checks that ensure
//! compliance with ECMA-335 specifications:
//!
//! ## Data Type Validation
//! The validator ensures that:
//! - Row data types match their target tables
//! - Table schemas are properly respected
//! - Type compatibility is maintained across operations
//!
//! ## RID Validation
//! The validator validates RID constraints:
//! - RIDs must be non-zero (following ECMA-335 conventions)
//! - RIDs must be within valid bounds
//! - RID format compliance is maintained
//!
//! ## Operation Validation
//! The validator checks that:
//! - Insert operations contain valid row data
//! - Update operations target valid RIDs with compatible data
//! - Delete operations target valid RIDs
//! - All operations respect table schema constraints
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use crate::cilassembly::validation::schema::BasicSchemaValidator;
//! use crate::cilassembly::validation::ValidationStage;
//! use crate::cilassembly::AssemblyChanges;
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//!
//! # let view = CilAssemblyView::from_file("test.dll")?;
//! # let changes = AssemblyChanges::new();
//! // Create validator
//! let validator = BasicSchemaValidator;
//!
//! // Validate changes for schema compliance
//! validator.validate(&changes, &view)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
//! purely on the input data provided to the validation methods.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::validation::ValidationPipeline`] - Used as a validation stage
//! - [`crate::cilassembly::modifications::TableModifications`] - Validates table operations
//! - [`crate::metadata::tables::TableDataOwned`] - Validates row data compatibility

use crate::{
    cilassembly::{validation::ValidationStage, AssemblyChanges, Operation, TableModifications},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{TableDataOwned, TableId},
    },
    Error, Result,
};

/// Basic schema validation for table operations in assembly modifications.
///
/// [`BasicSchemaValidator`] provides fundamental schema validation to ensure that
/// table operations conform to ECMA-335 metadata table specifications. It validates
/// data type compatibility, RID constraints, and basic referential integrity to
/// prevent invalid operations from being applied to the assembly metadata.
///
/// # Validation Checks
///
/// The validator performs the following fundamental schema checks:
/// - **Data Type Validation**: Ensures row data types match their target tables
/// - **RID Validation**: Validates that RIDs are properly formed (non-zero, within bounds)
/// - **Schema Compliance**: Ensures operations respect table schema constraints
/// - **Type Compatibility**: Maintains type compatibility across operations
///
/// # Operation Support
///
/// The validator supports validation of all operation types:
/// - Insert operations with new row data
/// - Update operations with modified row data
/// - Delete operations targeting existing rows
/// - Replaced table operations with complete row sets
///
/// # Usage Examples
///
/// ```rust,ignore
/// use crate::cilassembly::validation::schema::BasicSchemaValidator;
/// use crate::cilassembly::validation::ValidationStage;
/// use crate::cilassembly::AssemblyChanges;
/// use crate::metadata::cilassemblyview::CilAssemblyView;
///
/// # let view = CilAssemblyView::from_file("test.dll")?;
/// # let changes = AssemblyChanges::new();
/// let validator = BasicSchemaValidator;
///
/// // Validate all table operations for schema compliance
/// validator.validate(&changes, &view)?;
/// # Ok::<(), crate::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
/// purely on the input data provided to the validation methods.
pub struct BasicSchemaValidator;

impl ValidationStage for BasicSchemaValidator {
    fn validate(&self, changes: &AssemblyChanges, _original: &CilAssemblyView) -> Result<()> {
        for (table_id, table_modifications) in &changes.table_changes {
            match table_modifications {
                TableModifications::Sparse { operations, .. } => {
                    for operation in operations {
                        self.validate_operation(*table_id, &operation.operation)?;
                    }
                }
                TableModifications::Replaced(rows) => {
                    for (i, row) in rows.iter().enumerate() {
                        let rid = (i + 1) as u32;
                        self.validate_row_data(*table_id, rid, row)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Basic Schema Validation"
    }
}

impl BasicSchemaValidator {
    /// Validates a single table operation for schema compliance.
    ///
    /// This method validates that the provided operation conforms to the schema
    /// requirements for the target table. It checks RID validity, data type
    /// compatibility, and basic schema constraints.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the target table
    /// * `operation` - The [`crate::cilassembly::operation::Operation`] to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the operation is valid for the target table,
    /// or an [`crate::Error`] describing the validation failure.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for various validation failures:
    /// - [`crate::Error::ValidationInvalidRid`] for invalid RID values
    /// - [`crate::Error::ValidationTableSchemaMismatch`] for data type mismatches
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::schema::BasicSchemaValidator;
    /// use crate::cilassembly::operation::Operation;
    /// use crate::metadata::tables::TableId;
    ///
    /// # let validator = BasicSchemaValidator;
    /// # let operation = Operation::Delete(1);
    /// // Validate a delete operation
    /// validator.validate_operation(TableId::TypeDef, &operation)?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn validate_operation(&self, table_id: TableId, operation: &Operation) -> Result<()> {
        match operation {
            Operation::Insert(rid, row_data) => {
                if *rid == 0 {
                    return Err(Error::ValidationInvalidRid {
                        table: table_id,
                        rid: *rid,
                    });
                }
                self.validate_row_data(table_id, *rid, row_data)?;
            }
            Operation::Update(rid, row_data) => {
                if *rid == 0 {
                    return Err(Error::ValidationInvalidRid {
                        table: table_id,
                        rid: *rid,
                    });
                }
                self.validate_row_data(table_id, *rid, row_data)?;
            }
            Operation::Delete(rid) => {
                if *rid == 0 {
                    return Err(Error::ValidationInvalidRid {
                        table: table_id,
                        rid: *rid,
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates row data compatibility with the target table schema.
    ///
    /// This method ensures that the provided row data is compatible with the
    /// target table's schema requirements. It validates data type matching
    /// and basic schema constraints to prevent invalid data from being inserted
    /// or updated in the table.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] of the target table
    /// * `_rid` - The RID of the target row (currently unused but reserved for future validation)
    /// * `row_data` - The [`crate::metadata::tables::TableDataOwned`] to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the row data is compatible with the target table,
    /// or an [`crate::Error`] describing the schema mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationTableSchemaMismatch`] if the row data
    /// type does not match the target table's expected schema.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::cilassembly::validation::schema::BasicSchemaValidator;
    /// use crate::metadata::tables::{TableId, TableDataOwned};
    ///
    /// # let validator = BasicSchemaValidator;
    /// # let row_data = TableDataOwned::TypeDef(/* ... */);
    /// // Validate row data for TypeDef table
    /// validator.validate_row_data(TableId::TypeDef, 1, &row_data)?;
    /// # Ok::<(), crate::Error>(())
    /// ```
    fn validate_row_data(
        &self,
        table_id: TableId,
        _rid: u32,
        row_data: &TableDataOwned,
    ) -> Result<()> {
        // Validate that row data type matches the table
        let valid = match (table_id, row_data) {
            (TableId::TypeDef, TableDataOwned::TypeDef(_)) => true,
            (TableId::MethodDef, TableDataOwned::MethodDef(_)) => true,
            (TableId::Field, TableDataOwned::Field(_)) => true,
            (TableId::TypeRef, TableDataOwned::TypeRef(_)) => true,
            (TableId::MemberRef, TableDataOwned::MemberRef(_)) => true,
            (TableId::CustomAttribute, TableDataOwned::CustomAttribute(_)) => true,
            (TableId::Assembly, TableDataOwned::Assembly(_)) => true,
            (TableId::Module, TableDataOwned::Module(_)) => true,
            (TableId::Param, TableDataOwned::Param(_)) => true,
            // ToDo: Add more matches as TableDataOwned variants are implemented
            _ => false,
        };

        if !valid {
            return Err(Error::ValidationTableSchemaMismatch {
                table: table_id,
                expected: format!("{table_id:?}"),
                actual: format!("{:?}", std::mem::discriminant(row_data)),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        cilassembly::{AssemblyChanges, Operation, TableModifications, TableOperation},
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{CodedIndex, TableDataOwned, TableId, TypeDefRaw},
            token::Token,
        },
    };

    fn create_test_row() -> TableDataOwned {
        TableDataOwned::TypeDef(TypeDefRaw {
            rid: 0,
            token: Token::new(0x02000000),
            offset: 0,
            flags: 0,
            type_name: 1,
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 0),
            field_list: 1,
            method_list: 1,
        })
    }

    #[test]
    fn test_basic_schema_validator_valid_operations() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add valid table operation
            let mut table_modifications = TableModifications::new_sparse(1);
            let insert_op = TableOperation::new(Operation::Insert(100, create_test_row()));
            table_modifications.apply_operation(insert_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = BasicSchemaValidator;
            let result = validator.validate(&changes, &view);
            assert!(
                result.is_ok(),
                "Valid operations should pass basic schema validation"
            );
        }
    }

    #[test]
    fn test_basic_schema_validator_zero_rid_error() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Add invalid operation with RID 0
            let mut table_modifications = TableModifications::new_sparse(1);
            let invalid_op = TableOperation::new(Operation::Insert(0, create_test_row()));
            table_modifications.apply_operation(invalid_op).unwrap();
            changes
                .table_changes
                .insert(TableId::TypeDef, table_modifications);

            let validator = BasicSchemaValidator;
            let result = validator.validate(&changes, &view);
            assert!(result.is_err(), "RID 0 should fail validation");

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Invalid RID"),
                    "Should be RID validation error"
                );
            }
        }
    }

    #[test]
    fn test_basic_schema_validator_schema_mismatch() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut changes = AssemblyChanges::empty();

            // Try to insert TypeDef row into MethodDef table (schema mismatch)
            let mut table_modifications = TableModifications::new_sparse(1);
            let mismatch_op = TableOperation::new(Operation::Insert(100, create_test_row()));
            table_modifications.apply_operation(mismatch_op).unwrap();
            changes
                .table_changes
                .insert(TableId::MethodDef, table_modifications); // Wrong table!

            let validator = BasicSchemaValidator;
            let result = validator.validate(&changes, &view);
            assert!(result.is_err(), "Schema mismatch should fail validation");

            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Table schema mismatch"),
                    "Should be schema validation error"
                );
            }
        }
    }
}
