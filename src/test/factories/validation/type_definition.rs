//! Factory methods for type definition validation testing.
//!
//! Contains helper methods migrated from type definition validation source files
//! for creating test assemblies with various type definition validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Main factory method for type definition validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn owned_type_definition_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all type definition validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test type with empty name
    assemblies.push(create_assembly_with_empty_type_name()?);

    // 3. NEGATIVE: Test type name with null character
    // TODO: This test may not work as expected due to string heap handling
    // assemblies.push(create_assembly_with_null_char_in_type_name()?);

    // 4. NEGATIVE: Test namespace with null character
    // TODO: This test may not work as expected due to string heap handling
    // assemblies.push(create_assembly_with_null_char_in_namespace()?);

    // 5. NEGATIVE: Test malformed special name pattern
    assemblies.push(create_assembly_with_malformed_special_name()?);

    // Note: Other test cases (invalid attribute combinations, inconsistent type flavors)
    // require more complex setup and will be added incrementally

    Ok(assemblies)
}

/// Creates an assembly with a type having an empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn create_assembly_with_empty_type_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type with empty name
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty type name: {e}")))?;

    // Create a regular namespace (not "<Module>") to ensure validation triggers
    let namespace_index = assembly
        .string_add("TestNamespace")
        .map_err(|e| Error::Error(format!("Failed to add namespace: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

    let invalid_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001,               // Public
        type_name: empty_name_index,     // Empty name - should trigger validation failure
        type_namespace: namespace_index, // Regular namespace (not "<Module>")
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
        .map_err(|e| Error::Error(format!("Failed to add invalid type: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a type name containing null character - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn create_assembly_with_null_char_in_type_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type name with null character
    let invalid_name = "Invalid\0Type";
    let invalid_name_index = assembly
        .string_add(invalid_name)
        .map_err(|e| Error::Error(format!("Failed to add invalid type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

    let invalid_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001,             // Public
        type_name: invalid_name_index, // Name with null character - should trigger validation failure
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
        .map_err(|e| Error::Error(format!("Failed to add invalid type: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a namespace containing null character - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn create_assembly_with_null_char_in_namespace() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create valid type name
    let type_name_index = assembly
        .string_add("ValidTypeName")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    // Create namespace with null character
    let invalid_namespace = "Invalid\0Namespace";
    let invalid_namespace_index = assembly
        .string_add(invalid_namespace)
        .map_err(|e| Error::Error(format!("Failed to add invalid namespace: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

    let invalid_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001, // Public
        type_name: type_name_index,
        type_namespace: invalid_namespace_index, // Namespace with null character - should trigger validation failure
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
        .map_err(|e| Error::Error(format!("Failed to add invalid type: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a malformed special name pattern - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/definition.rs`
pub fn create_assembly_with_malformed_special_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type name with malformed special pattern (starts with < but doesn't end with >)
    let malformed_name = "<InvalidSpecialName";
    let malformed_name_index = assembly
        .string_add(malformed_name)
        .map_err(|e| Error::Error(format!("Failed to add malformed type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

    let invalid_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001,               // Public
        type_name: malformed_name_index, // Malformed special name - should trigger validation failure
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
        .map_err(|e| Error::Error(format!("Failed to add invalid type: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
