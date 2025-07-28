//! Factory methods for type ownership validation testing.
//!
//! Contains helper methods migrated from type ownership validation source files
//! for creating test assemblies with various type ownership validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            CodedIndex, CodedIndexType, FieldRaw, MethodDefRaw, NestedClassRaw, TableDataOwned,
            TableId, TypeAttributes, TypeDefRaw,
        },
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Main factory method for type ownership validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn owned_type_ownership_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all ownership validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 3. NEGATIVE: Test field with empty name
    assemblies.push(create_assembly_with_empty_field_name()?);

    // 4. NEGATIVE: Test field with invalid visibility flags
    assemblies.push(create_assembly_with_invalid_field_visibility()?);

    Ok(assemblies)
}

/// Creates an assembly with nested type having invalid visibility for nesting
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_invalid_nested_visibility() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create container type
    let container_name_index = assembly
        .string_add("ContainerType")
        .map_err(|e| Error::Error(format!("Failed to add container name: {e}")))?;

    let container_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let container_type = TypeDefRaw {
        rid: container_rid,
        token: Token::new(0x02000000 + container_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC, // Public container
        type_name: container_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(container_type))
        .map_err(|e| Error::Error(format!("Failed to add container type: {e}")))?;

    // Create nested type with invalid visibility (value beyond valid range)
    let nested_name_index = assembly
        .string_add("ContainerType+NestedType")
        .map_err(|e| Error::Error(format!("Failed to add nested name: {e}")))?;

    let nested_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let nested_type = TypeDefRaw {
        rid: nested_rid,
        token: Token::new(0x02000000 + nested_rid),
        offset: 0,
        flags: 0x00000008, // Invalid visibility value (8 is beyond valid range 0-7)
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
    let nested_class = NestedClassRaw {
        rid: nested_class_rid,
        token: Token::new(0x29000000 + nested_class_rid),
        offset: 0,
        nested_class: nested_rid,       // Raw index into TypeDef table
        enclosing_class: container_rid, // Raw index into TypeDef table
    };

    assembly
        .table_row_add(
            TableId::NestedClass,
            TableDataOwned::NestedClass(nested_class),
        )
        .map_err(|e| Error::Error(format!("Failed to add nested class relationship: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with nested type having empty name
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_empty_nested_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create container type
    let container_name_index = assembly
        .string_add("ContainerType")
        .map_err(|e| Error::Error(format!("Failed to add container name: {e}")))?;

    let container_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let container_type = TypeDefRaw {
        rid: container_rid,
        token: Token::new(0x02000000 + container_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: container_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(container_type))
        .map_err(|e| Error::Error(format!("Failed to add container type: {e}")))?;

    // Create nested type with empty name (should trigger validation failure)
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty name: {e}")))?;

    let nested_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let nested_type = TypeDefRaw {
        rid: nested_rid,
        token: Token::new(0x02000000 + nested_rid),
        offset: 0,
        flags: TypeAttributes::NESTED_PUBLIC,
        type_name: empty_name_index, // Empty name - this should trigger validation failure
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
    let nested_class = NestedClassRaw {
        rid: nested_class_rid,
        token: Token::new(0x29000000 + nested_class_rid),
        offset: 0,
        nested_class: nested_rid,       // Raw index into TypeDef table
        enclosing_class: container_rid, // Raw index into TypeDef table
    };

    assembly
        .table_row_add(
            TableId::NestedClass,
            TableDataOwned::NestedClass(nested_class),
        )
        .map_err(|e| Error::Error(format!("Failed to add nested class relationship: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with method having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_empty_method_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the method
    let type_name_index = assembly
        .string_add("TestType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let typedef = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    // Create method with empty name
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty method name: {e}")))?;

    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
    let method = MethodDefRaw {
        rid: method_rid,
        token: Token::new(0x06000000 + method_rid),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0x00000006,      // Public
        name: empty_name_index, // Empty name - should trigger validation failure
        signature: 1,           // Minimal signature blob index
        param_list: 1,
    };

    assembly
        .table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method))
        .map_err(|e| Error::Error(format!("Failed to add method: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with field having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_empty_field_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the field
    let type_name_index = assembly
        .string_add("TestType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let typedef = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    // Create field with empty name
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty field name: {e}")))?;

    let field_rid = assembly.original_table_row_count(TableId::Field) + 1;
    let field = FieldRaw {
        rid: field_rid,
        token: Token::new(0x04000000 + field_rid),
        offset: 0,
        flags: 0x00000006,      // Public
        name: empty_name_index, // Empty name - should trigger validation failure
        signature: 1,           // Minimal signature blob index
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(field))
        .map_err(|e| Error::Error(format!("Failed to add field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with field having invalid visibility flags - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/types/ownership.rs`
pub fn create_assembly_with_invalid_field_visibility() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type to contain the field
    let type_name_index = assembly
        .string_add("TestType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let typedef = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

    // Create field with invalid visibility flags
    let field_name_index = assembly
        .string_add("InvalidField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let field_rid = assembly.original_table_row_count(TableId::Field) + 1;
    let field = FieldRaw {
        rid: field_rid,
        token: Token::new(0x04000000 + field_rid),
        offset: 0,
        flags: 0x00000008, // Invalid visibility (8 is beyond valid range 0-7)
        name: field_name_index,
        signature: 1, // Minimal signature blob index
    };

    assembly
        .table_row_add(TableId::Field, TableDataOwned::Field(field))
        .map_err(|e| Error::Error(format!("Failed to add field: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
