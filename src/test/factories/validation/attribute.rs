//! Factory methods for attribute validation testing.
//!
//! Contains helper methods migrated from attribute validation source files
//! for creating test assemblies with various custom attribute validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, CustomAttributeRaw, TableDataOwned, TableId},
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Test factory for OwnedAttributeValidator following the golden pattern.
///
/// Creates test assemblies covering all attribute validation rules:
/// 1. Clean assembly (should pass)
/// 2. Excessive fixed arguments (>20)
/// 3. Excessive named arguments (>50)
/// 4. Duplicate named argument names
/// 5. Empty named argument name
/// 6. Null character in string argument
/// 7. Excessively long string (>10000 chars)
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the attribute violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn owned_attribute_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all attribute validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test excessive fixed arguments (>20)
    assemblies.push(create_assembly_with_excessive_fixed_args()?);

    // 3. NEGATIVE: Test excessive named arguments (>50)
    assemblies.push(create_assembly_with_excessive_named_args()?);

    // 4. NEGATIVE: Test duplicate named argument names
    assemblies.push(create_assembly_with_duplicate_named_args()?);

    // 5. NEGATIVE: Test empty named argument name
    assemblies.push(create_assembly_with_empty_named_arg_name()?);

    // 6. NEGATIVE: Test null character in string argument
    assemblies.push(create_assembly_with_null_character_string()?);

    // 7. NEGATIVE: Test excessively long string (>10000 chars)
    assemblies.push(create_assembly_with_excessive_string_length()?);

    Ok(assemblies)
}

/// Create assembly with excessive fixed arguments (>20) - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn create_assembly_with_excessive_fixed_args() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create a custom attribute value with 25 fixed arguments (exceeds limit of 20)
    let mut fixed_args = Vec::new();
    for i in 0..25 {
        fixed_args.push(crate::metadata::customattributes::CustomAttributeArgument::I4(i));
    }

    let custom_attr_value = crate::metadata::customattributes::CustomAttributeValue {
        fixed_args,
        named_args: vec![],
    };

    // Encode the custom attribute value to blob
    let blob_data =
        crate::metadata::customattributes::encode_custom_attribute_value(&custom_attr_value)
            .map_err(|e| Error::Error(format!("Failed to encode custom attribute: {e}")))?;

    let blob_index = assembly
        .blob_add(&blob_data)
        .map_err(|e| Error::Error(format!("Failed to add blob: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

    // Create CustomAttributeRaw with excessive fixed arguments
    let invalid_custom_attr = CustomAttributeRaw {
        rid: next_rid,
        token: Token::new(0x0C000000 + next_rid),
        offset: 0,
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType),
        value: blob_index,
    };

    assembly
        .table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(invalid_custom_attr),
        )
        .map_err(|e| Error::Error(format!("Failed to add custom attribute: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Create assembly with excessive named arguments (>50) - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn create_assembly_with_excessive_named_args() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create 55 named arguments (exceeds limit of 50)
    let mut named_args = Vec::new();
    for i in 0..55 {
        named_args.push(
            crate::metadata::customattributes::CustomAttributeNamedArgument {
                is_field: false,
                name: format!("Property{i}"),
                arg_type: "String".to_string(),
                value: crate::metadata::customattributes::CustomAttributeArgument::String(format!(
                    "Value{i}"
                )),
            },
        );
    }

    let custom_attr_value = crate::metadata::customattributes::CustomAttributeValue {
        fixed_args: vec![],
        named_args,
    };

    let blob_data =
        crate::metadata::customattributes::encode_custom_attribute_value(&custom_attr_value)
            .map_err(|e| Error::Error(format!("Failed to encode custom attribute: {e}")))?;

    let blob_index = assembly
        .blob_add(&blob_data)
        .map_err(|e| Error::Error(format!("Failed to add blob: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

    let invalid_custom_attr = CustomAttributeRaw {
        rid: next_rid,
        token: Token::new(0x0C000000 + next_rid),
        offset: 0,
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType),
        value: blob_index,
    };

    assembly
        .table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(invalid_custom_attr),
        )
        .map_err(|e| Error::Error(format!("Failed to add custom attribute: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Create assembly with duplicate named argument names - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn create_assembly_with_duplicate_named_args() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create named arguments with duplicate names
    let named_args = vec![
        crate::metadata::customattributes::CustomAttributeNamedArgument {
            is_field: false,
            name: "DuplicateName".to_string(),
            arg_type: "String".to_string(),
            value: crate::metadata::customattributes::CustomAttributeArgument::String(
                "Value1".to_string(),
            ),
        },
        crate::metadata::customattributes::CustomAttributeNamedArgument {
            is_field: false,
            name: "DuplicateName".to_string(), // Same name as above - invalid
            arg_type: "String".to_string(),
            value: crate::metadata::customattributes::CustomAttributeArgument::String(
                "Value2".to_string(),
            ),
        },
    ];

    let custom_attr_value = crate::metadata::customattributes::CustomAttributeValue {
        fixed_args: vec![],
        named_args,
    };

    let blob_data =
        crate::metadata::customattributes::encode_custom_attribute_value(&custom_attr_value)
            .map_err(|e| Error::Error(format!("Failed to encode custom attribute: {e}")))?;

    let blob_index = assembly
        .blob_add(&blob_data)
        .map_err(|e| Error::Error(format!("Failed to add blob: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

    let invalid_custom_attr = CustomAttributeRaw {
        rid: next_rid,
        token: Token::new(0x0C000000 + next_rid),
        offset: 0,
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType),
        value: blob_index,
    };

    assembly
        .table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(invalid_custom_attr),
        )
        .map_err(|e| Error::Error(format!("Failed to add custom attribute: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Create assembly with empty named argument name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn create_assembly_with_empty_named_arg_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create named argument with empty name
    let named_args = vec![
        crate::metadata::customattributes::CustomAttributeNamedArgument {
            is_field: false,
            name: "".to_string(), // Empty name - invalid
            arg_type: "String".to_string(),
            value: crate::metadata::customattributes::CustomAttributeArgument::String(
                "Value".to_string(),
            ),
        },
    ];

    let custom_attr_value = crate::metadata::customattributes::CustomAttributeValue {
        fixed_args: vec![],
        named_args,
    };

    let blob_data =
        crate::metadata::customattributes::encode_custom_attribute_value(&custom_attr_value)
            .map_err(|e| Error::Error(format!("Failed to encode custom attribute: {e}")))?;

    let blob_index = assembly
        .blob_add(&blob_data)
        .map_err(|e| Error::Error(format!("Failed to add blob: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

    let invalid_custom_attr = CustomAttributeRaw {
        rid: next_rid,
        token: Token::new(0x0C000000 + next_rid),
        offset: 0,
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType),
        value: blob_index,
    };

    assembly
        .table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(invalid_custom_attr),
        )
        .map_err(|e| Error::Error(format!("Failed to add custom attribute: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Create assembly with null character in string - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn create_assembly_with_null_character_string() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create string argument with null character
    let fixed_args = vec![
        crate::metadata::customattributes::CustomAttributeArgument::String(
            "String\0WithNull".to_string(),
        ),
    ];

    let custom_attr_value = crate::metadata::customattributes::CustomAttributeValue {
        fixed_args,
        named_args: vec![],
    };

    let blob_data =
        crate::metadata::customattributes::encode_custom_attribute_value(&custom_attr_value)
            .map_err(|e| Error::Error(format!("Failed to encode custom attribute: {e}")))?;

    let blob_index = assembly
        .blob_add(&blob_data)
        .map_err(|e| Error::Error(format!("Failed to add blob: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

    let invalid_custom_attr = CustomAttributeRaw {
        rid: next_rid,
        token: Token::new(0x0C000000 + next_rid),
        offset: 0,
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType),
        value: blob_index,
    };

    assembly
        .table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(invalid_custom_attr),
        )
        .map_err(|e| Error::Error(format!("Failed to add custom attribute: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Create assembly with excessively long string (>10000) - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/attribute.rs`
pub fn create_assembly_with_excessive_string_length() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create string with 15,000 characters (exceeds limit of 10,000)
    let long_string = "A".repeat(15_000);
    let fixed_args =
        vec![crate::metadata::customattributes::CustomAttributeArgument::String(long_string)];

    let custom_attr_value = crate::metadata::customattributes::CustomAttributeValue {
        fixed_args,
        named_args: vec![],
    };

    let blob_data =
        crate::metadata::customattributes::encode_custom_attribute_value(&custom_attr_value)
            .map_err(|e| Error::Error(format!("Failed to encode custom attribute: {e}")))?;

    let blob_index = assembly
        .blob_add(&blob_data)
        .map_err(|e| Error::Error(format!("Failed to add blob: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

    let invalid_custom_attr = CustomAttributeRaw {
        rid: next_rid,
        token: Token::new(0x0C000000 + next_rid),
        offset: 0,
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute),
        constructor: CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType),
        value: blob_index,
    };

    assembly
        .table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(invalid_custom_attr),
        )
        .map_err(|e| Error::Error(format!("Failed to add custom attribute: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
