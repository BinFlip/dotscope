//! Factory methods for raw structure token validation testing.
//!
//! Contains helper methods migrated from raw structure token validation source files
//! for creating test assemblies with various token validation scenarios.

use crate::{
    metadata::tables::{
        CodedIndex, CodedIndexType, GenericParamAttributes, GenericParamBuilder,
        InterfaceImplBuilder, MemberRefBuilder, MethodSpecBuilder, NestedClassBuilder, TableId,
        TypeAttributes, TypeDefBuilder,
    },
    test::{
        create_passing_test_assembly, create_test_assembly_with_error, get_testfile_wb,
        TestAssembly,
    },
    Error, Result,
};

/// Test factory for RawTokenValidator following the golden pattern.
///
/// Creates test assemblies covering basic token validation scenarios.
/// Tests token references, RID bounds, coded indexes, and cross-table references.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn raw_token_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_testfile_wb() else {
        return Err(Error::Other(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    assemblies.push(TestAssembly::new(&clean_testfile, true));

    assemblies.push(create_assembly_with_invalid_typedef_extends()?);
    assemblies.push(create_assembly_with_invalid_memberref()?);
    assemblies.push(create_assembly_with_invalid_genericparam()?);
    assemblies.push(create_assembly_with_invalid_interfaceimpl()?);
    assemblies.push(create_assembly_with_invalid_methodspec()?);
    assemblies.push(create_assembly_for_cross_table_validation()?);

    Ok(assemblies)
}

/// Creates a modified assembly with invalid TypeDef.extends coded index (out-of-bounds RID).
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_typedef_extends() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let invalid_extends =
            CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::TypeDefOrRef);

        TypeDefBuilder::new()
            .name("InvalidType")
            .namespace("Test")
            .flags(TypeAttributes::BEFORE_FIELD_INIT)
            .extends(invalid_extends)
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a modified assembly with invalid MemberRef token reference for validate_token_references testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_memberref() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let invalid_class =
            CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::MemberRefParent);
        let signature = vec![0x00];

        MemberRefBuilder::new()
            .name("InvalidMember")
            .class(invalid_class)
            .signature(&signature)
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a modified assembly with invalid GenericParam for token reference testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_genericparam() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let invalid_owner =
            CodedIndex::new(TableId::TypeDef, 999999, CodedIndexType::TypeOrMethodDef);

        GenericParamBuilder::new()
            .number(0)
            .flags(GenericParamAttributes::ZERO)
            .owner(invalid_owner)
            .name("T")
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a modified assembly with invalid InterfaceImpl for coded index testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_interfaceimpl() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let typedef_token = TypeDefBuilder::new()
            .name("TestInterface")
            .namespace("Test")
            .flags(TypeAttributes::ABSTRACT | TypeAttributes::INTERFACE)
            .build(assembly)?;

        let invalid_interface =
            CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::TypeDefOrRef);

        InterfaceImplBuilder::new()
            .class(typedef_token.placeholder())
            .interface(invalid_interface)
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a modified assembly with invalid MethodSpec for testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_methodspec() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let invalid_method =
            CodedIndex::new(TableId::MethodDef, 999999, CodedIndexType::MethodDefOrRef);
        let instantiation = vec![0x01, 0x1C];

        MethodSpecBuilder::new()
            .method(invalid_method)
            .instantiation(&instantiation)
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a test specifically for cross-table reference validation.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_for_cross_table_validation() -> Result<TestAssembly> {
    create_passing_test_assembly(get_testfile_wb, |assembly| {
        // Create an interface type (no extends required, avoids TypeRef dependency)
        let interface_type = TypeDefBuilder::new()
            .name("ICrossTableInterface")
            .namespace("CrossTableTest")
            .flags(TypeAttributes::ABSTRACT | TypeAttributes::INTERFACE | TypeAttributes::PUBLIC) // Interface | Abstract | Public
            .build(assembly)?;

        let nested_type = TypeDefBuilder::new()
            .name("NestedType")
            .namespace("CrossTableTest")
            .flags(TypeAttributes::BEFORE_FIELD_INIT | TypeAttributes::NESTED_PUBLIC) // NestedPublic
            .build(assembly)?;

        NestedClassBuilder::new()
            .nested_class(nested_type.placeholder())
            .enclosing_class(interface_type.placeholder())
            .build(assembly)?;

        Ok(())
    })
}
