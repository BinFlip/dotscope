//! Factory methods for members accessibility validation testing.
//!
//! Contains helper methods migrated from members accessibility validation source files
//! for creating test assemblies with various accessibility validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            CodedIndex, CodedIndexType, FieldAttributes, FieldBuilder, FieldRaw, MethodDefRaw,
            NestedClassRaw, TableDataOwned, TableId, TypeAttributes, TypeDefBuilder, TypeDefRaw,
        },
        token::Token,
        validation::ValidationConfig,
    },
    test::{get_testfile_crafted2, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Main factory method for members accessibility validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn owned_accessibility_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error(
            "crafted_2.exe not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all accessibility validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test sealed interface (interfaces can't be sealed)
    let temp_file = create_assembly_with_sealed_interface()?;
    assemblies.push(TestAssembly::from_temp_file_with_error(
        temp_file,
        "cannot be sealed",
    ));

    // 3. NEGATIVE: Test interface with non-static field
    let temp_file = create_assembly_with_interface_instance_field()?;
    assemblies.push(TestAssembly::from_temp_file_with_error(
        temp_file,
        "non-static field",
    ));

    // 4. NEGATIVE: Test interface with non-constant field
    let temp_file = create_assembly_with_interface_non_constant_field()?;
    assemblies.push(TestAssembly::from_temp_file_with_error(
        temp_file,
        "non-constant field",
    ));

    // 5. NEGATIVE: Test method with empty name
    let temp_file = create_assembly_with_empty_method_name()?;
    assemblies.push(TestAssembly::from_temp_file_with_error(
        temp_file,
        "empty name",
    ));

    // 6. NEGATIVE: Test literal field that's not static
    let temp_file = create_assembly_with_literal_non_static_field()?;
    assemblies.push(TestAssembly::from_temp_file_with_error(
        temp_file,
        "must be static",
    ));

    // 7. NEGATIVE: Test nested type with top-level visibility instead of nested visibility
    let temp_file = create_assembly_with_nested_accessibility_violation()?;
    assemblies.push(TestAssembly::from_temp_file_with_error(
        temp_file,
        "invalid visibility flags",
    ));

    Ok(assemblies)
}

/// Creates an assembly with a sealed interface - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_sealed_interface() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error("crafted_2.exe not available".to_string()));
    };
    let view = CilAssemblyView::from_path(&clean_testfile)
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

    Ok(temp_file)
}

/// Creates an assembly with interface containing non-static field - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_interface_instance_field() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error("crafted_2.exe not available".to_string()));
    };
    let view = CilAssemblyView::from_path(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Get the next RIDs for TypeDef and Field
    let interface_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let field_rid = assembly.original_table_row_count(TableId::Field) + 1;

    // Create interface type name
    let interface_name_index = assembly
        .string_add("InterfaceWithInstanceField")
        .map_err(|e| Error::Error(format!("Failed to add interface name: {e}")))?;

    // Create field name and signature
    let field_name_index = assembly
        .string_add("InstanceField")
        .map_err(|e| Error::Error(format!("Failed to add field name: {e}")))?;

    let signature_bytes = vec![0x06, 0x08]; // FIELD signature marker + ELEMENT_TYPE_I4
    let signature_index = assembly
        .blob_add(&signature_bytes)
        .map_err(|e| Error::Error(format!("Failed to add signature: {e}")))?;

    // Create the interface type first, with field_list pointing to our field
    let interface_type = TypeDefRaw {
        rid: interface_rid,
        token: Token::new(0x02000000 + interface_rid),
        offset: 0,
        flags: TypeAttributes::INTERFACE | TypeAttributes::PUBLIC,
        type_name: interface_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: field_rid, // Point to the field we'll create
        method_list: 1,
    };

    // Create the field with non-static flag (invalid in interface)
    let invalid_field = FieldRaw {
        rid: field_rid,
        token: Token::new(0x04000000 + field_rid),
        offset: 0,
        flags: FieldAttributes::PUBLIC, // Missing STATIC flag - invalid in interface
        name: field_name_index,
        signature: signature_index,
    };

    // Add both to the assembly
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

    Ok(temp_file)
}

/// Creates an assembly with interface containing non-constant field - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_interface_non_constant_field() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error("crafted_2.exe not available".to_string()));
    };
    let view = CilAssemblyView::from_path(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create static field without LITERAL flag - invalid in interface
    let signature_bytes = vec![0x06, 0x08]; // FIELD signature marker + ELEMENT_TYPE_I4
    let field_token = FieldBuilder::new()
        .name("NonConstantField")
        .flags(FieldAttributes::PUBLIC | FieldAttributes::STATIC) // Static but missing LITERAL (0x0040) - invalid in interface
        .signature(&signature_bytes)
        .build(&mut context)?;

    // Create interface type and explicitly associate the field with it
    let _interface_token = TypeDefBuilder::new()
        .name("InterfaceWithNonConstantField")
        .namespace("")
        .flags(TypeAttributes::INTERFACE | TypeAttributes::PUBLIC)
        .field_list(field_token.row()) // Explicitly associate field with this type
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(temp_file)
}

/// Creates an assembly with method having empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_empty_method_name() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error("crafted_2.exe not available".to_string()));
    };
    let view = CilAssemblyView::from_path(&clean_testfile)
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

    let signature_bytes = vec![0x00, 0x00, 0x01]; // Method signature: DEFAULT calling convention, 0 args, void return
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

    Ok(temp_file)
}

/// Creates an assembly with literal field that's not static - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/members/accessibility.rs`
pub fn create_assembly_with_literal_non_static_field() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error("crafted_2.exe not available".to_string()));
    };
    let view = CilAssemblyView::from_path(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create literal field without static flag - invalid per ECMA-335
    let signature_bytes = vec![0x06, 0x08]; // FIELD signature marker + ELEMENT_TYPE_I4
    let field_token = FieldBuilder::new()
        .name("LiteralInstanceField")
        .flags(FieldAttributes::PUBLIC | 0x0040) // LITERAL without STATIC - invalid
        .signature(&signature_bytes)
        .build(&mut context)?;

    // Create type and explicitly associate the field with it
    let _type_token = TypeDefBuilder::new()
        .name("TypeWithLiteralInstanceField")
        .namespace("")
        .flags(TypeAttributes::PUBLIC)
        .field_list(field_token.row()) // Explicitly associate field with this type
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(temp_file)
}

/// Creates an assembly with nested type accessibility violation
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
/// Moved to accessibility validator as it tests accessibility, not ownership.
pub fn create_assembly_with_nested_accessibility_violation() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_testfile_crafted2() else {
        return Err(Error::Error("crafted_2.exe not available".to_string()));
    };
    let view = CilAssemblyView::from_path(&clean_testfile)
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
    let nested_class = NestedClassRaw {
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

    Ok(temp_file)
}
