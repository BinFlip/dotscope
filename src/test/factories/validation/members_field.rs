//! Factory methods for members field validation testing.
//!
//! Contains helper methods migrated from members field validation source files
//! for creating test assemblies with various field validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{FieldRaw, TableDataOwned, TableId},
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Test factory for OwnedFieldValidator following the golden pattern.
///
/// Creates test assemblies covering all field validation rules:
/// 1. Clean assembly (should pass)
/// 2. Field with null character in name
/// 3. Literal field without static flag
/// 4. RTSpecialName without SpecialName flag combination
/// 5. Field with empty name
/// 6. Backing field that's not private
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the field violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/members/field.rs`
pub fn owned_field_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all field validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test field with null character in name
    assemblies.push(create_assembly_with_null_character_field_name()?);

    // 3. NEGATIVE: Test literal field without static flag
    assemblies.push(create_assembly_with_literal_non_static_field()?);

    // 4. NEGATIVE: Test RTSpecialName without SpecialName flag combination
    assemblies.push(create_assembly_with_rtspecial_without_special()?);

    // 5. NEGATIVE: Test field with empty name
    assemblies.push(create_assembly_with_empty_field_name()?);

    // 6. NEGATIVE: Test backing field that's not private
    assemblies.push(create_assembly_with_non_private_backing_field()?);

    Ok(assemblies)
}

/// Creates an assembly with a field containing null character in name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/field.rs`
pub fn create_assembly_with_null_character_field_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    let name_index = assembly
        .string_add("Field\0WithNull")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::Field) + 1;

    let invalid_field = FieldRaw {
        rid: next_rid,
        token: Token::new(0x04000000 + next_rid),
        offset: 0,
        flags: 0x0002,
        name: name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(invalid_field))
        .map_err(|e| Error::Error(format!("Failed to add invalid field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a literal field that's not static - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/field.rs`
pub fn create_assembly_with_literal_non_static_field() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    let name_index = assembly
        .string_add("InvalidLiteralField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::Field) + 1;

    // LITERAL flag without STATIC flag - invalid per ECMA-335
    let invalid_field = FieldRaw {
        rid: next_rid,
        token: Token::new(0x04000000 + next_rid),
        offset: 0,
        flags: 0x0040, // LITERAL without STATIC
        name: name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(invalid_field))
        .map_err(|e| Error::Error(format!("Failed to add invalid field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a field having RTSpecialName but not SpecialName - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/field.rs`
pub fn create_assembly_with_rtspecial_without_special() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    let name_index = assembly
        .string_add("RTSpecialField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::Field) + 1;

    // RTSpecialName without SpecialName - invalid per ECMA-335
    let invalid_field = FieldRaw {
        rid: next_rid,
        token: Token::new(0x04000000 + next_rid),
        offset: 0,
        flags: 0x0402, // Private + RTSpecialName without SpecialName
        name: name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(invalid_field))
        .map_err(|e| Error::Error(format!("Failed to add invalid field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a field having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/field.rs`
pub fn create_assembly_with_empty_field_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    let name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::Field) + 1;

    let invalid_field = FieldRaw {
        rid: next_rid,
        token: Token::new(0x04000000 + next_rid),
        offset: 0,
        flags: 0x0002,
        name: name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(invalid_field))
        .map_err(|e| Error::Error(format!("Failed to add invalid field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a backing field that's not private - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/field.rs`
pub fn create_assembly_with_non_private_backing_field() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    let name_index = assembly
        .string_add("<MyProperty>k__BackingField")
        .map_err(|e| Error::Error(format!("Failed to add backing field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::Field) + 1;

    // Backing field with public access - should be private
    let invalid_field = FieldRaw {
        rid: next_rid,
        token: Token::new(0x04000000 + next_rid),
        offset: 0,
        flags: 0x0007, // Public - backing fields should be private
        name: name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(invalid_field))
        .map_err(|e| Error::Error(format!("Failed to add invalid field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
