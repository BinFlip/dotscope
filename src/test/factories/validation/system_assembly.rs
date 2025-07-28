//! Factory methods for system assembly validation testing.
//!
//! Contains helper methods migrated from system assembly validation source files
//! for creating test assemblies with various assembly validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{AssemblyRaw, TableDataOwned, TableId},
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Test factory for OwnedAssemblyValidator following the golden pattern.
///
/// Creates test assemblies covering all assembly validation rules:
/// 1. Clean assembly (should pass)
/// 2. Assembly with empty name
/// 3. Assembly with invalid name format (invalid characters)
/// 4. Assembly with maximum valid version numbers (should pass)
/// 5. Assembly with invalid culture format
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the assembly violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn owned_assembly_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all assembly validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test assembly with empty name
    assemblies.push(create_assembly_with_empty_name()?);

    // 3. NEGATIVE: Test assembly with invalid name format (invalid characters)
    assemblies.push(create_assembly_with_invalid_name_format()?);

    // 4. BOUNDARY: Test assembly with maximum valid version numbers (should pass)
    assemblies.push(create_assembly_with_maximum_version_numbers()?);

    // 5. NEGATIVE: Test assembly with invalid culture format
    assemblies.push(create_assembly_with_invalid_culture_format()?);

    // Note: Other test cases (cross-assembly references, module file consistency)
    // require more complex assembly manipulation and will be added incrementally

    Ok(assemblies)
}

/// Creates an assembly with empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn create_assembly_with_empty_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create assembly with empty name
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty assembly name: {e}")))?;

    let assembly_rid = 1; // Assembly table always has RID 1

    let invalid_assembly = AssemblyRaw {
        rid: assembly_rid,
        token: Token::new(0x20000000 + assembly_rid),
        offset: 0,
        hash_alg_id: 0x8004, // SHA1
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0,
        public_key: 0,
        name: empty_name_index, // Empty name - should trigger validation failure
        culture: 0,
    };

    assembly
        .table_row_update(
            TableId::Assembly,
            1,
            TableDataOwned::Assembly(invalid_assembly),
        )
        .map_err(|e| Error::Error(format!("Failed to update invalid assembly: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with invalid name format (invalid characters) - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn create_assembly_with_invalid_name_format() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create assembly name with invalid characters (contains /)
    let invalid_name = "Invalid/Assembly*Name";
    let invalid_name_index = assembly
        .string_add(invalid_name)
        .map_err(|e| Error::Error(format!("Failed to add invalid assembly name: {e}")))?;

    let assembly_rid = 1;

    let invalid_assembly = AssemblyRaw {
        rid: assembly_rid,
        token: Token::new(0x20000000 + assembly_rid),
        offset: 0,
        hash_alg_id: 0x8004, // SHA1
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0,
        public_key: 0,
        name: invalid_name_index, // Invalid name format - should trigger validation failure
        culture: 0,
    };

    assembly
        .table_row_update(
            TableId::Assembly,
            1,
            TableDataOwned::Assembly(invalid_assembly),
        )
        .map_err(|e| Error::Error(format!("Failed to update invalid assembly: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with maximum valid version numbers - validation should pass
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn create_assembly_with_maximum_version_numbers() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create valid assembly name
    let assembly_name_index = assembly
        .string_add("ValidAssemblyName")
        .map_err(|e| Error::Error(format!("Failed to add assembly name: {e}")))?;

    let assembly_rid = 1;

    let invalid_assembly = AssemblyRaw {
        rid: assembly_rid,
        token: Token::new(0x20000000 + assembly_rid),
        offset: 0,
        hash_alg_id: 0x8004, // SHA1
        major_version: 999,  // Max before suspicious threshold - should be valid
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0,
        public_key: 0,
        name: assembly_name_index,
        culture: 0,
    };

    assembly
        .table_row_update(
            TableId::Assembly,
            1,
            TableDataOwned::Assembly(invalid_assembly),
        )
        .map_err(|e| Error::Error(format!("Failed to update invalid assembly: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, true))
}

/// Creates an assembly with invalid culture format - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn create_assembly_with_invalid_culture_format() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create valid assembly name
    let assembly_name_index = assembly
        .string_add("ValidAssemblyName")
        .map_err(|e| Error::Error(format!("Failed to add assembly name: {e}")))?;

    // Create invalid culture format (too many parts)
    let invalid_culture = "en-US-extra-invalid";
    let invalid_culture_index = assembly
        .string_add(invalid_culture)
        .map_err(|e| Error::Error(format!("Failed to add invalid culture: {e}")))?;

    let assembly_rid = 1;

    let invalid_assembly = AssemblyRaw {
        rid: assembly_rid,
        token: Token::new(0x20000000 + assembly_rid),
        offset: 0,
        hash_alg_id: 0x8004, // SHA1
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0,
        public_key: 0,
        name: assembly_name_index,
        culture: invalid_culture_index, // Invalid culture format - should trigger validation failure
    };

    assembly
        .table_row_update(
            TableId::Assembly,
            1,
            TableDataOwned::Assembly(invalid_assembly),
        )
        .map_err(|e| Error::Error(format!("Failed to update invalid assembly: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
