//! Factory methods for raw structure token validation testing.
//!
//! Contains helper methods migrated from raw structure token validation source files
//! for creating test assemblies with various token validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, TableId},
        validation::ValidationConfig,
    },
    prelude::*,
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for RawTokenValidator following the golden pattern.
///
/// Creates test assemblies covering basic token validation scenarios.
/// Tests token references, RID bounds, coded indexes, and cross-table references.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn raw_token_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    assemblies.push(TestAssembly::new(&clean_testfile, true));

    match create_assembly_with_invalid_typedef_extends() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationInvalidRid",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid TypeDef.extends: {e}"
            )));
        }
    }

    match create_assembly_with_invalid_memberref() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationInvalidRid",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid MemberRef: {e}"
            )));
        }
    }

    match create_assembly_with_invalid_genericparam() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationInvalidRid",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid GenericParam: {e}"
            )));
        }
    }

    match create_assembly_with_invalid_interfaceimpl() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationInvalidRid",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid InterfaceImpl: {e}"
            )));
        }
    }

    match create_assembly_with_invalid_methodspec() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationInvalidRid",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid MethodSpec: {e}"
            )));
        }
    }

    match create_assembly_for_cross_table_validation() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file(temp_file, true));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly for cross-table validation: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates a modified assembly with invalid TypeDef.extends coded index (out-of-bounds RID).
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_typedef_extends() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let invalid_extends = CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::TypeDefOrRef);

    TypeDefBuilder::new()
        .name("InvalidType")
        .namespace("Test")
        .flags(0x00100000)
        .extends(invalid_extends)
        .build(&mut context)?;

    let mut assembly = context.finish();

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with a table that would exceed RID bounds.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_oversized_table() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    for i in 0..1000 {
        TypeDefBuilder::new()
            .name(format!("TestType{i}"))
            .namespace("Overflow")
            .flags(0x00100001)
            .build(&mut context)?;
    }

    let mut assembly = context.finish();

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with invalid coded index to test coded index validation.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_coded_index() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let invalid_extends = CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::TypeDefOrRef);

    TypeDefBuilder::new()
        .name("InvalidCodedIndexType")
        .namespace("Test")
        .flags(0x00100000)
        .extends(invalid_extends) // This should point to non-existent TypeRef
        .build(&mut context)?;

    let mut assembly = context.finish();

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with missing cross-table references.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_missing_reference() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let field_signature = vec![0x06, 0x08];

    FieldBuilder::new()
        .name("InvalidField")
        .flags(0x0001)
        .signature(&field_signature)
        .build(&mut context)?;

    TypeDefBuilder::new()
        .name("InvalidFieldList")
        .namespace("Test")
        .flags(0x00100000)
        .build(&mut context)?;

    let mut assembly = context.finish();

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with invalid MemberRef token reference for validate_token_references testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_memberref() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let invalid_class = CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::MemberRefParent);
    let signature = vec![0x00];

    MemberRefBuilder::new()
        .name("InvalidMember")
        .class(invalid_class)
        .signature(&signature)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with table exceeding RID bounds for validate_rid_bounds testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_rid_bounds_violation() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    for i in 0..100 {
        TypeDefBuilder::new()
            .name(format!("TestType{i}"))
            .namespace("RidBoundsTest")
            .flags(0x00100001)
            .build(&mut context)?;
    }

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with invalid CustomAttribute for coded index testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_customattribute() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let typedef_token = TypeDefBuilder::new()
        .name("TestType")
        .namespace("Test")
        .flags(0x00100000)
        .build(&mut context)?;

    let invalid_constructor = CodedIndex::new(
        TableId::MemberRef,
        999999,
        CodedIndexType::CustomAttributeType,
    );
    let parent = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::HasCustomAttribute,
    );

    CustomAttributeBuilder::new()
        .parent(parent)
        .constructor(invalid_constructor)
        .value(&[])
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with invalid GenericParam for token reference testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_genericparam() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let invalid_owner = CodedIndex::new(TableId::TypeDef, 999999, CodedIndexType::TypeOrMethodDef);

    GenericParamBuilder::new()
        .number(0)
        .flags(0)
        .owner(invalid_owner)
        .name("T")
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with invalid InterfaceImpl for coded index testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_interfaceimpl() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let typedef_token = TypeDefBuilder::new()
        .name("TestInterface")
        .namespace("Test")
        .flags(0x000000A0)
        .build(&mut context)?;

    let invalid_interface = CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::TypeDefOrRef);

    InterfaceImplBuilder::new()
        .class(typedef_token.row())
        .interface(invalid_interface)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a modified assembly with invalid MethodSpec for testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_methodspec() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let invalid_method =
        CodedIndex::new(TableId::MethodDef, 999999, CodedIndexType::MethodDefOrRef);
    let instantiation = vec![0x01, 0x1C];

    MethodSpecBuilder::new()
        .method(invalid_method)
        .instantiation(&instantiation)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test specifically for cross-table reference validation.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_for_cross_table_validation() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let base_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

    let derived_type = TypeDefBuilder::new()
        .name("DerivedType")
        .namespace("CrossTableTest")
        .flags(0x00100000)
        .extends(base_type)
        .build(&mut context)?;

    let nested_type = TypeDefBuilder::new()
        .name("NestedType")
        .namespace("CrossTableTest")
        .flags(0x00100002)
        .build(&mut context)?;

    NestedClassBuilder::new()
        .nested_class(nested_type)
        .enclosing_class(derived_type)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
