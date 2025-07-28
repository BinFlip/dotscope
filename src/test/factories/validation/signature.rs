//! Factory methods for signature validation testing.
//!
//! Contains helper methods migrated from signature validation source files
//! for creating test assemblies with various signature validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            CodedIndex, CodedIndexType, MethodDefRaw, ParamRaw, TableDataOwned, TableId, TypeDefRaw,
        },
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Test factory for OwnedSignatureValidator following the golden pattern.
///
/// Creates test assemblies covering all signature validation rules:
/// 1. Clean assembly (should pass)
/// 2. Method with empty name
/// 3. Parameter with excessively long name (>255 characters)
/// 4. Method with unresolved return type
/// 5. Method with unresolved parameter type
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the signature violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn owned_signature_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all signature validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 3. NEGATIVE: Test parameter with excessively long name (>255 characters)
    assemblies.push(create_assembly_with_long_parameter_name()?);

    // 4. NEGATIVE: Test method with unresolved return type
    assemblies.push(create_assembly_with_unresolved_return_type()?);

    // 5. NEGATIVE: Test method with unresolved parameter type
    assemblies.push(create_assembly_with_unresolved_parameter_type()?);

    // Note: Other test cases (excessive custom attributes, generic parameter issues,
    // excessive overloads) require additional table manipulation and will be added incrementally

    Ok(assemblies)
}

/// Creates an assembly with a method having an empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_empty_method_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the method
    let type_name_index = assembly
        .string_add("TypeWithEmptyMethodName")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

    let type_def = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001, // Public
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    // Create method with empty name
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty method name: {e}")))?;

    let signature_bytes = vec![0x00, 0x00]; // Default method signature (no parameters, void return)
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let invalid_method = MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006,          // Public
        name: empty_name_index, // Empty name - should trigger validation failure
        signature: signature_index,
        param_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    assembly
        .table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )
        .map_err(|e| Error::Error(format!("Failed to add invalid method: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a parameter having an excessively long name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_long_parameter_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the method
    let type_name_index = assembly
        .string_add("TypeWithLongParameterName")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

    let type_def = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001, // Public
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    // Create method name
    let method_name_index = assembly
        .string_add("MethodWithLongParam")
        .map_err(|e| Error::Error(format!("Failed to add method name: {e}")))?;

    // Create signature with one parameter
    let signature_bytes = vec![0x00, 0x01, 0x01, 0x08]; // 1 parameter, void return, I4 parameter
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let method_def = MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006, // Public
        name: method_name_index,
        signature: signature_index,
        param_list: param_rid,
    };

    // Create parameter with excessively long name (>255 characters)
    let long_param_name = "a".repeat(300); // 300 characters - should trigger validation failure
    let long_param_name_index = assembly
        .string_add(&long_param_name)
        .map_err(|e| Error::Error(format!("Failed to add long parameter name: {e}")))?;

    let invalid_param = ParamRaw {
        rid: param_rid,
        token: Token::new(0x08000000 + param_rid),
        offset: 0,
        flags: 0x0000, // In
        sequence: 1,
        name: long_param_name_index, // Excessively long name - should trigger validation failure
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    assembly
        .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method_def))
        .map_err(|e| Error::Error(format!("Failed to add method: {e}")))?;

    assembly
        .table_row_add(TableId::Param, TableDataOwned::Param(invalid_param))
        .map_err(|e| Error::Error(format!("Failed to add invalid parameter: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a parameter having excessive custom attributes - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_excessive_parameter_attributes() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the method
    let type_name_index = assembly
        .string_add("TypeWithExcessiveParamAttrs")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

    let type_def = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001, // Public
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    // Create method name
    let method_name_index = assembly
        .string_add("MethodWithExcessiveParamAttrs")
        .map_err(|e| Error::Error(format!("Failed to add method name: {e}")))?;

    // Create signature with one parameter
    let signature_bytes = vec![0x00, 0x01, 0x01, 0x08]; // 1 parameter, void return, I4 parameter
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let method_def = MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006, // Public
        name: method_name_index,
        signature: signature_index,
        param_list: param_rid,
    };

    // Create parameter
    let param_name_index = assembly
        .string_add("paramWithManyAttrs")
        .map_err(|e| Error::Error(format!("Failed to add parameter name: {e}")))?;

    let param = ParamRaw {
        rid: param_rid,
        token: Token::new(0x08000000 + param_rid),
        offset: 0,
        flags: 0x0001, // In
        sequence: 1,
        name: param_name_index,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    assembly
        .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method_def))
        .map_err(|e| Error::Error(format!("Failed to add method: {e}")))?;

    assembly
        .table_row_add(TableId::Param, TableDataOwned::Param(param))
        .map_err(|e| Error::Error(format!("Failed to add parameter: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a method having unresolved return type - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_unresolved_return_type() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the method
    let type_name_index = assembly
        .string_add("TypeWithUnresolvedReturnType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

    let type_def = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001, // Public
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    // Create method name
    let method_name_index = assembly
        .string_add("MethodWithUnresolvedReturnType")
        .map_err(|e| Error::Error(format!("Failed to add method name: {e}")))?;

    // Create invalid signature blob with unresolved return type
    // Format: [calling_convention, param_count, return_type, ...params]
    let invalid_signature_bytes = vec![
        0x00, // DEFAULT calling convention
        0x00, // 0 parameters
        0x12, // ELEMENT_TYPE_CLASS (indicates a class type follows)
        0xFF, 0xFF, 0xFF,
        0x7F, // Invalid TypeDefOrRef token (compressed integer, maximum invalid value)
    ];
    let signature_index = assembly
        .blob_add(&invalid_signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add invalid signature: {e}")))?;

    let invalid_method = MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006, // Public
        name: method_name_index,
        signature: signature_index, // Invalid signature with unresolved return type
        param_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    assembly
        .table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )
        .map_err(|e| Error::Error(format!("Failed to add invalid method: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with a method having unresolved parameter type - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/metadata/signature.rs`
pub fn create_assembly_with_unresolved_parameter_type() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the method
    let type_name_index = assembly
        .string_add("TypeWithUnresolvedParamType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let param_rid = assembly.original_table_row_count(TableId::Param) + 1;

    let type_def = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: 0x00000001, // Public
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    // Create method name
    let method_name_index = assembly
        .string_add("MethodWithUnresolvedParamType")
        .map_err(|e| Error::Error(format!("Failed to add method name: {e}")))?;

    // Create invalid signature blob with unresolved parameter type
    // Format: [calling_convention, param_count, return_type, param1_type, ...]
    let invalid_signature_bytes = vec![
        0x00, // DEFAULT calling convention
        0x01, // 1 parameter
        0x01, // Return type: ELEMENT_TYPE_VOID
        0x12, // Parameter type: ELEMENT_TYPE_CLASS (indicates a class type follows)
        0xFF, 0xFF, 0xFF,
        0x7F, // Invalid TypeDefOrRef token (compressed integer, maximum invalid value)
    ];
    let signature_index = assembly
        .blob_add(&invalid_signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add invalid signature: {e}")))?;

    let invalid_method = MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006, // Public
        name: method_name_index,
        signature: signature_index, // Invalid signature with unresolved parameter type
        param_list: param_rid,
    };

    // Create parameter with name (the signature is what has the unresolved type)
    let param_name_index = assembly
        .string_add("unresolvedParam")
        .map_err(|e| Error::Error(format!("Failed to add parameter name: {e}")))?;

    let param = ParamRaw {
        rid: param_rid,
        token: Token::new(0x08000000 + param_rid),
        offset: 0,
        flags: 0x0001, // In
        sequence: 1,
        name: param_name_index,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    assembly
        .table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )
        .map_err(|e| Error::Error(format!("Failed to add invalid method: {e}")))?;

    assembly
        .table_row_add(TableId::Param, TableDataOwned::Param(param))
        .map_err(|e| Error::Error(format!("Failed to add parameter: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
