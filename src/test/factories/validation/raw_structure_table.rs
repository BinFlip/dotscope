//! Factory methods for raw structure table validation testing.
//!
//! Contains helper methods migrated from raw structure table validation source files
//! for creating test assemblies with various table validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{AssemblyRaw, CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for RawTableValidator following the golden pattern.
///
/// Creates test assemblies covering basic table validation scenarios.
/// Tests required table presence, cross-table dependencies, and table structure integrity.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn raw_table_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. Multiple Assembly rows - create assembly with >1 Assembly table rows
    match create_assembly_with_multiple_assembly_rows() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with multiple Assembly rows: {e}"
            )));
        }
    }

    // 3. Cross-table dependency violation - TypeDef field list exceeding Field table bounds
    match create_assembly_with_field_list_violation() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with field list violation: {e}"
            )));
        }
    }

    // 4. Cross-table dependency violation - TypeDef method list exceeding MethodDef table bounds
    match create_assembly_with_method_list_violation() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with method list violation: {e}"
            )));
        }
    }

    // 5. Required table presence - Module table with 0 rows
    match create_assembly_with_empty_module_table() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with empty Module table: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates a modified assembly with empty Module table (0 rows).
///
/// This deletes the Module table row entirely, creating an empty Module table
/// which violates ECMA-335 requirement of exactly 1 Module row.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_empty_module_table() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;

    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Delete the Module table row entirely - this will reduce row_count to 0
    // Use remove_references=true to force removal even if referenced
    match context.table_row_remove(TableId::Module, 1, true) {
        Ok(()) => {
            // Module row deletion succeeded
        }
        Err(e) => {
            // Row deletion failed - maybe Module table is protected
            // Fall back to just returning an error to indicate this test doesn't work
            return Err(Error::Error(format!(
                "Cannot remove Module table row: {e} - this test case is not supported"
            )));
        }
    }

    let mut assembly = context.finish();

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with multiple Assembly table rows.
///
/// ECMA-335 requires at most 1 row in the Assembly table. This creates
/// a second Assembly row to violate this constraint.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_multiple_assembly_rows() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a second Assembly row which violates ECMA-335 "at most 1 row" constraint
    // Use add_table_row to actually add a second row (increasing row_count to 2)
    let duplicate_assembly = AssemblyRaw {
        rid: 2,                        // Will be set by add_table_row
        token: Token::new(0x20000002), // Assembly table token for RID 2
        offset: 0,
        hash_alg_id: 0x8004, // CALG_SHA1
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0,
        public_key: 0, // Assuming blob index 0
        name: 1,       // Assuming string index 1 exists
        culture: 0,    // Null culture
    };

    // Add the duplicate Assembly row - this will increase Assembly table row_count to 2
    context.table_row_add(
        TableId::Assembly,
        TableDataOwned::Assembly(duplicate_assembly),
    )?;

    let mut assembly = context.finish();

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with TypeDef field list exceeding Field table bounds.
///
/// This creates a TypeDef that references field list starting at a RID beyond
/// what exists in the Field table, violating cross-table dependency constraints.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_field_list_violation() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let context = BuilderContext::new(assembly);

    let mut assembly = context.finish();

    // Create a TypeDef with field_list pointing beyond Field table bounds
    let invalid_typedef = TypeDefRaw {
        rid: 1,
        token: Token::new(0x02000001),
        offset: 0,
        flags: 0x00100000, // Class, not interface
        type_name: 1,      // Assuming string index 1 exists
        type_namespace: 0, // No namespace
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 999999, // Way beyond any reasonable Field table size
        method_list: 0,
    };

    assembly.table_row_update(
        TableId::TypeDef,
        1,
        TableDataOwned::TypeDef(invalid_typedef),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with TypeDef method list exceeding MethodDef table bounds.
///
/// This creates a TypeDef that references method list starting at a RID beyond
/// what exists in the MethodDef table, violating cross-table dependency constraints.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/table.rs`
pub fn create_assembly_with_method_list_violation() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let context = BuilderContext::new(assembly);

    let mut assembly = context.finish();

    // Create a TypeDef with method_list pointing beyond MethodDef table bounds
    let invalid_typedef = TypeDefRaw {
        rid: 1,
        token: Token::new(0x02000001),
        offset: 0,
        flags: 0x00100000, // Class, not interface
        type_name: 1,      // Assuming string index 1 exists
        type_namespace: 0, // No namespace
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 0,
        method_list: 999999, // Way beyond any reasonable MethodDef table size
    };

    assembly.table_row_update(
        TableId::TypeDef,
        1,
        TableDataOwned::TypeDef(invalid_typedef),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
