//! Factory methods for dependency validation testing.
//!
//! Contains helper methods migrated from dependency validation source files
//! for creating test assemblies with various dependency validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
    },
    test::{get_clean_testfile, TestAssembly},
    CilAssemblyView, Error, Result,
};
use tempfile::NamedTempFile;

/// Main factory method for creating dependency validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/dependency.rs`
pub fn owned_dependency_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all dependency validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE TEST: Assembly with broken dependency chain in type hierarchy
    assemblies.push(TestAssembly::new(
        create_assembly_with_broken_dependency_chain()?.path(),
        false,
    ));

    // 3. NEGATIVE TEST: Assembly with unsatisfied transitive dependencies
    assemblies.push(TestAssembly::new(
        create_assembly_with_unsatisfied_transitive_dependencies()?.path(),
        false,
    ));

    // 4. NEGATIVE TEST: Assembly with invalid dependency ordering
    assemblies.push(TestAssembly::new(
        create_assembly_with_invalid_dependency_ordering()?.path(),
        false,
    ));

    // 5. NEGATIVE TEST: Assembly with self-referential dependencies
    assemblies.push(TestAssembly::new(
        create_assembly_with_self_referential_dependencies()?.path(),
        false,
    ));

    Ok(assemblies)
}

/// Creates an assembly with a broken dependency chain in type hierarchy.
///
/// This test creates a TypeDef that references a non-existent base type,
/// causing dependency validation to fail when trying to resolve the inheritance chain.
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/dependency.rs`
pub fn create_assembly_with_broken_dependency_chain() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // Create a TypeDef that extends a non-existent TypeRef (RID 9999)
    let broken_typedef = TypeDefRaw {
        rid: 1,
        token: Token::new(0x02000001),
        offset: 0,
        flags: 0x00100000, // Class, not interface
        type_name: 1,      // Assuming string index 1 exists
        type_namespace: 0, // No namespace
        extends: CodedIndex::new(TableId::TypeRef, 9999, CodedIndexType::TypeDefOrRef), // Non-existent TypeRef
        field_list: 1,
        method_list: 1,
    };

    assembly.table_row_update(TableId::TypeDef, 1, TableDataOwned::TypeDef(broken_typedef))?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with unsatisfied transitive dependencies.
///
/// This test creates circular dependencies where TypeDef A depends on TypeDef B,
/// which depends on a non-existent external type, breaking the transitive chain.
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/dependency.rs`
pub fn create_assembly_with_unsatisfied_transitive_dependencies() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // Create TypeDef A that extends TypeDef B
    let typedef_a = TypeDefRaw {
        rid: 1,
        token: Token::new(0x02000001),
        offset: 0,
        flags: 0x00100000, // Class
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef), // Extends TypeDef B
        field_list: 1,
        method_list: 1,
    };

    // Create TypeDef B that extends a non-existent TypeRef
    let typedef_b = TypeDefRaw {
        rid: 2,
        token: Token::new(0x02000002),
        offset: 0,
        flags: 0x00100000, // Class
        type_name: 2,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 8888, CodedIndexType::TypeDefOrRef), // Non-existent TypeRef
        field_list: 1,
        method_list: 1,
    };

    assembly.table_row_update(TableId::TypeDef, 1, TableDataOwned::TypeDef(typedef_a))?;

    assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef_b))?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with invalid dependency ordering.
///
/// This test creates a circular inheritance where TypeDef A extends TypeDef B,
/// and TypeDef B extends TypeDef A, creating an invalid dependency loop.
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/dependency.rs`
pub fn create_assembly_with_invalid_dependency_ordering() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // Create TypeDef A that extends TypeDef B
    let typedef_a = TypeDefRaw {
        rid: 1,
        token: Token::new(0x02000001),
        offset: 0,
        flags: 0x00100000, // Class
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeDefOrRef), // Extends TypeDef B
        field_list: 1,
        method_list: 1,
    };

    // Create TypeDef B that extends TypeDef A (circular dependency)
    let typedef_b = TypeDefRaw {
        rid: 2,
        token: Token::new(0x02000002),
        offset: 0,
        flags: 0x00100000, // Class
        type_name: 2,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef), // Extends TypeDef A
        field_list: 1,
        method_list: 1,
    };

    assembly.table_row_update(TableId::TypeDef, 1, TableDataOwned::TypeDef(typedef_a))?;

    assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef_b))?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with self-referential dependencies.
///
/// This test creates a TypeDef that extends itself, creating an immediate
/// self-referential dependency that should be detected and rejected.
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/dependency.rs`
pub fn create_assembly_with_self_referential_dependencies() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // Create a TypeDef that extends itself
    let self_referential_typedef = TypeDefRaw {
        rid: 1,
        token: Token::new(0x02000001),
        offset: 0,
        flags: 0x00100000, // Class
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef), // Extends itself
        field_list: 1,
        method_list: 1,
    };

    assembly.table_row_update(
        TableId::TypeDef,
        1,
        TableDataOwned::TypeDef(self_referential_typedef),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
