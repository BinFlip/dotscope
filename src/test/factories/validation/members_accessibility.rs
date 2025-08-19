//! Factory methods for members accessibility validation testing.
//!
//! Contains helper methods migrated from members accessibility validation source files
//! for creating test assemblies with various accessibility validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            CodedIndex, CodedIndexType, FieldAttributes, FieldRaw, MethodDefRaw, TableDataOwned,
            TableId, TypeAttributes, TypeDefRaw,
        },
        token::Token,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};

/// Main factory method for members accessibility validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn owned_accessibility_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all accessibility validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test sealed interface (interfaces can't be sealed)
    assemblies.push(create_assembly_with_sealed_interface()?);

    // 3. NEGATIVE: Test interface with non-static field
    assemblies.push(create_assembly_with_interface_instance_field()?);

    // 4. NEGATIVE: Test interface with non-constant field
    assemblies.push(create_assembly_with_interface_non_constant_field()?);

    // 5. NEGATIVE: Test method with empty name
    assemblies.push(create_assembly_with_empty_method_name()?);

    // 6. NEGATIVE: Test literal field that's not static
    assemblies.push(create_assembly_with_literal_non_static_field()?);

    Ok(assemblies)
}

/// Creates an assembly with a sealed interface - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_sealed_interface() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    let name_index = assembly
        .string_add("InvalidSealedInterface")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let next_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

    // Create interface with SEALED flag (0x0100) - this should be invalid
    let invalid_interface = TypeDefRaw {
        rid: next_rid,
        token: Token::new(0x02000000 + next_rid),
        offset: 0,
        flags: TypeAttributes::INTERFACE | 0x0100, // Interface + Sealed - invalid combination
        type_name: name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_interface))
        .map_err(|e| Error::Error(format!("Failed to add invalid interface: {e}")))?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with interface containing non-static field - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_interface_instance_field() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create interface type
    let interface_name_index = assembly
        .string_add("InterfaceWithInstanceField")
        .map_err(|e| Error::Error(format!("Failed to add interface name: {e}")))?;

    let interface_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let field_rid = assembly.original_table_row_count(TableId::Field) + 1;

    let interface_type = TypeDefRaw {
        rid: interface_rid,
        token: Token::new(0x02000000 + interface_rid),
        offset: 0,
        flags: TypeAttributes::INTERFACE | TypeAttributes::PUBLIC,
        type_name: interface_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: field_rid, // Points to the field we'll create
        method_list: 1,
    };

    // Create field with instance (non-static) flag - invalid in interface
    let field_name_index = assembly
        .string_add("InstanceField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let invalid_field = FieldRaw {
        rid: field_rid,
        token: Token::new(0x04000000 + field_rid),
        offset: 0,
        flags: FieldAttributes::PUBLIC, // Missing STATIC flag - invalid in interface
        name: field_name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_type))
        .map_err(|e| Error::Error(format!("Failed to add interface: {e}")))?;

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

/// Creates an assembly with interface containing non-constant field - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_interface_non_constant_field() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create interface type
    let interface_name_index = assembly
        .string_add("InterfaceWithNonConstantField")
        .map_err(|e| Error::Error(format!("Failed to add interface name: {e}")))?;

    let interface_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let field_rid = assembly.original_table_row_count(TableId::Field) + 1;

    let interface_type = TypeDefRaw {
        rid: interface_rid,
        token: Token::new(0x02000000 + interface_rid),
        offset: 0,
        flags: TypeAttributes::INTERFACE | TypeAttributes::PUBLIC,
        type_name: interface_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: field_rid,
        method_list: 1,
    };

    // Create static field without LITERAL flag - invalid in interface
    let field_name_index = assembly
        .string_add("NonConstantField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let invalid_field = FieldRaw {
        rid: field_rid,
        token: Token::new(0x04000000 + field_rid),
        offset: 0,
        flags: FieldAttributes::PUBLIC | FieldAttributes::STATIC, // Static but missing LITERAL (0x0040) - invalid in interface
        name: field_name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_type))
        .map_err(|e| Error::Error(format!("Failed to add interface: {e}")))?;

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

/// Creates an assembly with method having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_empty_method_name() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type
    let type_name_index = assembly
        .string_add("TypeWithEmptyMethodName")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;

    let type_def = TypeDefRaw {
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

    // Create method with empty name - invalid
    let empty_name_index = assembly
        .string_add("")
        .map_err(|e| Error::Error(format!("Failed to add empty name: {e}")))?;

    let signature_bytes = vec![0x00, 0x00, 0x01]; // No args, void return
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
        name: empty_name_index, // Empty name - invalid
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

/// Creates an assembly with literal field that's not static - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_literal_non_static_field() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type
    let type_name_index = assembly
        .string_add("TypeWithLiteralInstanceField")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let field_rid = assembly.original_table_row_count(TableId::Field) + 1;

    let type_def = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: field_rid,
        method_list: 1,
    };

    // Create literal field without static flag - invalid per ECMA-335
    let field_name_index = assembly
        .string_add("LiteralInstanceField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    let invalid_field = FieldRaw {
        rid: field_rid,
        token: Token::new(0x04000000 + field_rid),
        offset: 0,
        flags: FieldAttributes::PUBLIC | 0x0040, // LITERAL without STATIC - invalid
        name: field_name_index,
        signature: signature_index,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_def))
        .map_err(|e| Error::Error(format!("Failed to add type: {e}")))?;

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
