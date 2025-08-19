//! Factory methods for ownership validation testing.
//!
//! Contains helper methods migrated from ownership validation source files
//! for creating test assemblies with various ownership validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeAttributes, TypeDefRaw},
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Main factory method for creating ownership validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn owned_ownership_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all ownership validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test broken method ownership reference
    assemblies.push(create_assembly_with_broken_method_ownership()?);

    // 3. NEGATIVE: Test invalid method accessibility
    assemblies.push(create_assembly_with_invalid_method_accessibility()?);

    // 4. NEGATIVE: Test invalid static constructor
    assemblies.push(create_assembly_with_invalid_static_constructor()?);

    // 5. NEGATIVE: Test nested accessibility violation
    assemblies.push(create_assembly_with_nested_accessibility_violation()?);

    Ok(assemblies)
}

/// Creates an assembly with broken method ownership reference
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_broken_method_ownership() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create method with empty name to trigger validation failure
    let empty_method_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty method name: {e}")))?;

    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let invalid_method = crate::metadata::tables::MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006,                 // Public
        name: empty_method_name_index, // Empty name - should trigger validation failure
        signature: 1,
        param_list: 1,
    };

    assembly
        .table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )
        .map_err(|e| Error::Error(format!("Failed to add method: {e}")))?;

    // Create type that owns the method with empty name
    let type_name_index = assembly
        .string_add("TestType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let invalid_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid, // Reference to method with empty name - should trigger validation failure
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with invalid method accessibility
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_invalid_method_accessibility() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create method with invalid visibility flags
    let method_name_index = assembly
        .string_add("TestMethod")
        .map_err(|e| Error::Error(format!("Failed to add method name: {e}")))?;

    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let invalid_method = crate::metadata::tables::MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0008, // Invalid visibility value (8 is beyond valid range 0-6)
        name: method_name_index,
        signature: 1,
        param_list: 1,
    };

    assembly
        .table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )
        .map_err(|e| Error::Error(format!("Failed to add method: {e}")))?;

    let type_name_index = assembly
        .string_add("TestType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let test_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(test_type))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with invalid static constructor flags
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_invalid_static_constructor() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create static constructor (.cctor) without static flag
    let cctor_name_index = assembly
        .string_add(".cctor")
        .map_err(|e| Error::Error(format!("Failed to add .cctor name: {e}")))?;

    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let invalid_cctor = crate::metadata::tables::MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x0006, // Public (0x0006) but missing static flag (0x0010) - should trigger validation failure
        name: cctor_name_index,
        signature: 1,
        param_list: 1,
    };

    assembly
        .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(invalid_cctor))
        .map_err(|e| Error::Error(format!("Failed to add .cctor method: {e}")))?;

    let type_name_index = assembly
        .string_add("TestType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let test_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: method_rid,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(test_type))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with nested type accessibility violation
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_nested_accessibility_violation() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create non-public container type
    let container_name_index = assembly
        .string_add("InternalContainer")
        .map_err(|e| Error::Error(format!("Failed to add container name: {e}")))?;

    let container_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let container_type = TypeDefRaw {
        rid: container_rid,
        token: Token::new(0x02000000 + container_rid),
        offset: 0,
        flags: TypeAttributes::NOT_PUBLIC, // Not public container
        type_name: container_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(container_type))
        .map_err(|e| Error::Error(format!("Failed to add container type: {e}")))?;

    // Create nested type with top-level visibility instead of nested visibility - should trigger validation failure
    let nested_name_index = assembly
        .string_add("InternalContainer+InvalidNested")
        .map_err(|e| Error::Error(format!("Failed to add nested name: {e}")))?;

    let nested_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let nested_type = TypeDefRaw {
        rid: nested_rid,
        token: Token::new(0x02000000 + nested_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC, // Using top-level PUBLIC instead of NESTED_PUBLIC - should trigger validation failure
        type_name: nested_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(nested_type))
        .map_err(|e| Error::Error(format!("Failed to add nested type: {e}")))?;

    // Create NestedClass entry to establish the ownership relationship
    let nested_class_rid = assembly.original_table_row_count(TableId::NestedClass) + 1;
    let nested_class = crate::metadata::tables::NestedClassRaw {
        rid: nested_class_rid,
        token: Token::new(0x29000000 + nested_class_rid),
        offset: 0,
        nested_class: nested_rid,
        enclosing_class: container_rid,
    };

    assembly
        .table_row_add(
            TableId::NestedClass,
            TableDataOwned::NestedClass(nested_class),
        )
        .map_err(|e| Error::Error(format!("Failed to add nested class relationship: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
