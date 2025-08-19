//! Factory methods for circularity validation testing.
//!
//! Contains helper methods migrated from circularity validation source files
//! for creating test assemblies with various circularity validation scenarios.

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

/// Main factory method for creating circularity validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn owned_circularity_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all circularity validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Test circular inheritance chain (A->B->A)
    assemblies.push(create_assembly_with_circular_inheritance()?);

    // 3. NEGATIVE: Test self-referential type definition
    assemblies.push(create_assembly_with_self_referential_type()?);

    // 4. NEGATIVE: Test circular interface implementation
    assemblies.push(create_assembly_with_circular_interface_implementation()?);

    Ok(assemblies)
}

/// Creates an assembly with circular inheritance (A->B->A)
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn create_assembly_with_circular_inheritance() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create type A name
    let type_a_name_index = assembly
        .string_add("TypeA")
        .map_err(|e| Error::Error(format!("Failed to add TypeA name: {e}")))?;

    // Create type B name
    let type_b_name_index = assembly
        .string_add("TypeB")
        .map_err(|e| Error::Error(format!("Failed to add TypeB name: {e}")))?;

    let type_a_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let type_b_rid = type_a_rid + 1;

    // Create TypeA that extends TypeB
    let type_a = TypeDefRaw {
        rid: type_a_rid,
        token: Token::new(0x02000000 + type_a_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_a_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, type_b_rid, CodedIndexType::TypeDefOrRef), // A extends B
        field_list: 1,
        method_list: 1,
    };

    // Create TypeB that extends TypeA - creates circular inheritance
    let type_b = TypeDefRaw {
        rid: type_b_rid,
        token: Token::new(0x02000000 + type_b_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_b_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, type_a_rid, CodedIndexType::TypeDefOrRef), // B extends A - circular!
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_a))
        .map_err(|e| Error::Error(format!("Failed to add TypeA: {e}")))?;

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(type_b))
        .map_err(|e| Error::Error(format!("Failed to add TypeB: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with self-referential type definition
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn create_assembly_with_self_referential_type() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create self-referential type name
    let type_name_index = assembly
        .string_add("SelfReferentialType")
        .map_err(|e| Error::Error(format!("Failed to add type name: {e}")))?;

    let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;

    // Create type that extends itself - direct circular inheritance
    let self_ref_type = TypeDefRaw {
        rid: type_rid,
        token: Token::new(0x02000000 + type_rid),
        offset: 0,
        flags: TypeAttributes::PUBLIC,
        type_name: type_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, type_rid, CodedIndexType::TypeDefOrRef), // Extends itself!
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(self_ref_type))
        .map_err(|e| Error::Error(format!("Failed to add self-referential type: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}

/// Creates an assembly with circular interface implementation
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/circularity.rs`
pub fn create_assembly_with_circular_interface_implementation() -> Result<TestAssembly> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    let view = CilAssemblyView::from_file(&clean_testfile)
        .map_err(|e| Error::Error(format!("Failed to load test assembly: {e}")))?;

    let mut assembly = CilAssembly::new(view);

    // Create interface I1 name
    let interface_i1_name_index = assembly
        .string_add("IInterface1")
        .map_err(|e| Error::Error(format!("Failed to add IInterface1 name: {e}")))?;

    // Create interface I2 name
    let interface_i2_name_index = assembly
        .string_add("IInterface2")
        .map_err(|e| Error::Error(format!("Failed to add IInterface2 name: {e}")))?;

    let interface_i1_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
    let interface_i2_rid = interface_i1_rid + 1;

    // Create IInterface1 that extends IInterface2
    let interface_i1 = TypeDefRaw {
        rid: interface_i1_rid,
        token: Token::new(0x02000000 + interface_i1_rid),
        offset: 0,
        flags: TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
        type_name: interface_i1_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(
            TableId::TypeDef,
            interface_i2_rid,
            CodedIndexType::TypeDefOrRef,
        ), // I1 extends I2
        field_list: 1,
        method_list: 1,
    };

    // Create IInterface2 that extends IInterface1 - creates circular interface implementation
    let interface_i2 = TypeDefRaw {
        rid: interface_i2_rid,
        token: Token::new(0x02000000 + interface_i2_rid),
        offset: 0,
        flags: TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT | TypeAttributes::PUBLIC,
        type_name: interface_i2_name_index,
        type_namespace: 0,
        extends: CodedIndex::new(
            TableId::TypeDef,
            interface_i1_rid,
            CodedIndexType::TypeDefOrRef,
        ), // I2 extends I1 - circular!
        field_list: 1,
        method_list: 1,
    };

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_i1))
        .map_err(|e| Error::Error(format!("Failed to add IInterface1: {e}")))?;

    assembly
        .table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(interface_i2))
        .map_err(|e| Error::Error(format!("Failed to add IInterface2: {e}")))?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;

    assembly
        .write_to_file(temp_file.path())
        .map_err(|e| Error::Error(format!("Failed to write assembly: {e}")))?;

    Ok(TestAssembly::from_temp_file(temp_file, false))
}
