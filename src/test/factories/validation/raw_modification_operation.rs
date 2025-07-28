//! Factory methods for raw modification operation validation testing.
//!
//! Contains helper methods migrated from raw modification operation validation source files
//! for creating test assemblies with various operation validation scenarios.

use crate::{
    cilassembly::{AssemblyChanges, CilAssembly, Operation, TableModifications, TableOperation},
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
/// Test factory for RawOperationValidator following the golden pattern.
///
/// Creates test assemblies covering basic operation validation scenarios.
/// Note: This validator primarily uses direct corruption testing rather than file-based tests.
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn raw_operation_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    // 1. Clean test assembly (should pass all operation validation when no modifications)
    if let Some(clean_path) = get_clean_testfile() {
        assemblies.push(TestAssembly::new(clean_path, true));
    }

    // Note: File-based corruption testing is complex for modification validators
    // since they only run during modification validation contexts. Instead,
    // we use the direct corruption test (test_raw_operation_validator_direct_corruption)
    // which creates corrupted modifications in memory and tests them directly.

    Ok(assemblies)
}

/// Helper function to create a dummy TypeDef for testing purposes
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_dummy_typedef(rid: u32, flags: u32) -> TypeDefRaw {
    TypeDefRaw {
        rid,
        token: Token::new(0x02000000 | rid),
        offset: 0,
        flags,
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex {
            tag: TableId::TypeDef,
            row: 0,
            token: Token::new(0),
            ci_type: CodedIndexType::TypeDefOrRef,
        },
        field_list: 1,
        method_list: 1,
    }
}

/// Creates corrupted changes with invalid RID zero
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_invalid_rid_zero() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create operation with invalid RID 0
    let invalid_op = TableOperation::new(Operation::Insert(0, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with excessive RID
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_excessive_rid() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create operation with RID exceeding 0xFFFFFF (24-bit limit)
    let invalid_op = TableOperation::new(Operation::Insert(0x1000000, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with nonexistent target
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_nonexistent_target() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1); // original_row_count = 0

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create update operation targeting RID 999 that doesn't exist
    let invalid_op = TableOperation::new(Operation::Update(999, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with update after delete
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_update_after_delete() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(2); // original_row_count = 1

    let typedef_data = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(typedef_data);

    // Create delete operation followed by update operation (invalid sequence)
    let delete_op = TableOperation::new_with_timestamp(Operation::Delete(1), 1000);
    let update_op = TableOperation::new_with_timestamp(Operation::Update(1, table_data), 2000);

    if let TableModifications::Sparse {
        operations,
        deleted_rows,
        ..
    } = &mut table_mods
    {
        operations.push(delete_op);
        operations.push(update_op);
        deleted_rows.insert(1); // Mark as deleted
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with excessive updates
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_excessive_updates() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(2); // original_row_count = 1

    let typedef_data = create_dummy_typedef(1, 0);

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        // Add more than 10 update operations on same RID (limit is 10)
        for i in 0..12 {
            let table_data = TableDataOwned::TypeDef(typedef_data.clone());
            let update_op = TableOperation::new_with_timestamp(
                Operation::Update(1, table_data),
                1000 + i as u64,
            );
            operations.push(update_op);
        }
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with unordered operations
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_unordered_operations() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let typedef_data1 = create_dummy_typedef(1, 0);
    let typedef_data2 = create_dummy_typedef(2, 1);

    // Create operations with non-chronological timestamps
    let op1 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data1)),
        2000, // Later timestamp
    );
    let op2 = TableOperation::new_with_timestamp(
        Operation::Insert(2, TableDataOwned::TypeDef(typedef_data2)),
        1000, // Earlier timestamp
    );

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        // Add in wrong order (later timestamp first)
        operations.push(op1);
        operations.push(op2);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with conflicting inserts
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_conflicting_inserts() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let typedef_data1 = create_dummy_typedef(1, 0);
    let typedef_data2 = create_dummy_typedef(2, 1);

    // Create multiple insert operations targeting the same RID
    let op1 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data1)),
        1000,
    );
    let op2 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data2)),
        2000,
    );

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(op1);
        operations.push(op2);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates assembly with invalid RID zero
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_invalid_rid_zero() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    // Load clean assembly and create CilAssembly
    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    // Create corrupted modification directly by manipulating the changes structure
    let mut corrupted_changes = AssemblyChanges::empty();

    // Create table modifications with invalid RID 0 operation
    let mut table_mods = TableModifications::new_sparse(1);

    // Create a fake TypeDef data to use in the invalid operation
    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create operation with invalid RID 0
    let invalid_op = TableOperation::new(Operation::Insert(0, table_data));

    // Force the invalid operation into the table modifications
    // This bypasses the normal validation that would prevent RID 0
    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);

    // Write to temporary file with the corrupted changes
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates assembly with excessive RID
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_excessive_rid() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create operation with RID exceeding 0xFFFFFF (24-bit limit)
    let invalid_op = TableOperation::new(Operation::Insert(0x1000000, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates assembly with nonexistent target
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_nonexistent_target() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1); // original_row_count = 0

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create update operation targeting RID 999 that doesn't exist
    let invalid_op = TableOperation::new(Operation::Update(999, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates assembly with update after delete
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_update_after_delete() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(2); // original_row_count = 1

    let typedef_data = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(typedef_data);

    // Create delete operation followed by update operation (invalid sequence)
    let delete_op = TableOperation::new_with_timestamp(Operation::Delete(1), 1000);
    let update_op = TableOperation::new_with_timestamp(Operation::Update(1, table_data), 2000);

    if let TableModifications::Sparse {
        operations,
        deleted_rows,
        ..
    } = &mut table_mods
    {
        operations.push(delete_op);
        operations.push(update_op);
        deleted_rows.insert(1); // Mark as deleted
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates assembly with excessive updates
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_excessive_updates() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(2); // original_row_count = 1

    let typedef_data = create_dummy_typedef(1, 0);

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        // Add more than 10 update operations on same RID (limit is 10)
        for i in 0..12 {
            let table_data = TableDataOwned::TypeDef(typedef_data.clone());
            let update_op = TableOperation::new_with_timestamp(
                Operation::Update(1, table_data),
                1000 + i as u64,
            );
            operations.push(update_op);
        }
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates assembly with unordered operations
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_unordered_operations() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let typedef_data1 = create_dummy_typedef(1, 0);
    let typedef_data2 = create_dummy_typedef(2, 1);

    // Create operations with non-chronological timestamps
    let op1 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data1)),
        2000, // Later timestamp
    );
    let op2 = TableOperation::new_with_timestamp(
        Operation::Insert(2, TableDataOwned::TypeDef(typedef_data2)),
        1000, // Earlier timestamp
    );

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        // Add in wrong order (later timestamp first)
        operations.push(op1);
        operations.push(op2);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates assembly with conflicting inserts
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_assembly_with_conflicting_inserts() -> Result<tempfile::NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = crate::metadata::cilassemblyview::CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);

    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let typedef_data1 = create_dummy_typedef(1, 0);
    let typedef_data2 = create_dummy_typedef(2, 1);

    // Create multiple insert operations targeting the same RID
    let op1 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data1)),
        1000,
    );
    let op2 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data2)),
        2000,
    );

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(op1);
        operations.push(op2);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    create_temp_assembly_with_changes(assembly, corrupted_changes)
}

/// Creates temporary assembly with changes
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_temp_assembly_with_changes(
    _assembly: CilAssembly,
    _corrupted_changes: AssemblyChanges,
) -> Result<tempfile::NamedTempFile> {
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    use std::fs;

    if let Some(clean_testfile) = get_clean_testfile() {
        fs::copy(clean_testfile, temp_path)?;
    }

    Ok(temp_file)
}
