//! Factory methods for raw structure token validation testing.
//!
//! Contains helper methods migrated from raw structure token validation source files
//! for creating test assemblies with various token validation scenarios.

use crate::{
    metadata::tables::{
        CodedIndex, CodedIndexType, CustomAttributeBuilder, FieldBuilder, GenericParamBuilder,
        InterfaceImplBuilder, MemberRefBuilder, MethodSpecBuilder, NestedClassBuilder, TableId,
        TypeDefBuilder,
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
            .flags(0x00100000)
            .extends(invalid_extends)
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a modified assembly with a table that would exceed RID bounds.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_oversized_table() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        for i in 0..1000 {
            TypeDefBuilder::new()
                .name(format!("TestType{i}"))
                .namespace("Overflow")
                .flags(0x00100001)
                .build(assembly)?;
        }

        Ok(())
    })
}

/// Creates a modified assembly with invalid coded index to test coded index validation.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_coded_index() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let invalid_extends =
            CodedIndex::new(TableId::TypeRef, 999999, CodedIndexType::TypeDefOrRef);

        TypeDefBuilder::new()
            .name("InvalidCodedIndexType")
            .namespace("Test")
            .flags(0x00100000)
            .extends(invalid_extends) // This should point to non-existent TypeRef
            .build(assembly)?;

        Ok(())
    })
}

/// Creates a modified assembly with missing cross-table references.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_missing_reference() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let field_signature = vec![0x06, 0x08];

        FieldBuilder::new()
            .name("InvalidField")
            .flags(0x0001)
            .signature(&field_signature)
            .build(assembly)?;

        TypeDefBuilder::new()
            .name("InvalidFieldList")
            .namespace("Test")
            .flags(0x00100000)
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

/// Creates a modified assembly with table exceeding RID bounds for validate_rid_bounds testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_rid_bounds_violation() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        for i in 0..100 {
            TypeDefBuilder::new()
                .name(format!("TestType{i}"))
                .namespace("RidBoundsTest")
                .flags(0x00100001)
                .build(assembly)?;
        }

        Ok(())
    })
}

/// Creates a modified assembly with invalid CustomAttribute for coded index testing.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/token.rs`
pub fn create_assembly_with_invalid_customattribute() -> Result<TestAssembly> {
    create_test_assembly_with_error(get_testfile_wb, "InvalidRid", |assembly| {
        let typedef_token = TypeDefBuilder::new()
            .name("TestType")
            .namespace("Test")
            .flags(0x00100000)
            .build(assembly)?;

        let invalid_constructor = CodedIndex::new(
            TableId::MemberRef,
            999999,
            CodedIndexType::CustomAttributeType,
        );
        let parent = CodedIndex::new(
            TableId::TypeDef,
            typedef_token.placeholder(),
            CodedIndexType::HasCustomAttribute,
        );

        CustomAttributeBuilder::new()
            .parent(parent)
            .constructor(invalid_constructor)
            .value(&[])
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
            .flags(0)
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
            .flags(0x000000A0)
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
            .flags(0x000000A1) // Interface | Abstract | Public
            .build(assembly)?;

        let nested_type = TypeDefBuilder::new()
            .name("NestedType")
            .namespace("CrossTableTest")
            .flags(0x00100002) // NestedPublic
            .build(assembly)?;

        NestedClassBuilder::new()
            .nested_class(nested_type.placeholder())
            .enclosing_class(interface_type.placeholder())
            .build(assembly)?;

        Ok(())
    })
}
