//! Factory methods for ownership validation testing.
//!
//! Contains helper methods migrated from ownership validation source files
//! for creating test assemblies with various ownership validation scenarios.

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, MethodDefRaw, TableDataOwned, TableId, TypeAttributes,
            TypeDefRaw,
        },
        token::Token,
    },
    test::{create_test_assembly, get_testfile_mscorlib, TestAssembly},
    Error, Result,
};

/// Main factory method for creating ownership validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn owned_ownership_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_testfile_mscorlib() else {
        return Err(Error::Other(
            "mscorlib.dll not available - test cannot run".to_string(),
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

    Ok(assemblies)
}

/// Creates an assembly with broken method ownership reference
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_broken_method_ownership() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
        // Create method with empty name to trigger validation failure
        let empty_method_name_index = assembly.string_add("")?;

        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006,                               // Public
            name: empty_method_name_index.placeholder(), // Empty name - should trigger validation failure
            signature: 1,
            param_list: 1,
        };

        assembly.table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )?;

        // Create type that owns the method with empty name
        let type_name_index = assembly.string_add("TestType")?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let invalid_type = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: TypeAttributes::PUBLIC,
            type_name: type_name_index.placeholder(),
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid, // Reference to method with empty name - should trigger validation failure
        };

        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(invalid_type))?;

        Ok(())
    })
}

/// Creates an assembly with invalid method accessibility
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_invalid_method_accessibility() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
        // Create method with invalid visibility flags
        let method_name_index = assembly.string_add("TestMethod")?;

        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let invalid_method = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0008, // Invalid visibility value (8 is beyond valid range 0-6)
            name: method_name_index.placeholder(),
            signature: 1,
            param_list: 1,
        };

        assembly.table_row_add(
            TableId::MethodDef,
            TableDataOwned::MethodDef(invalid_method),
        )?;

        let type_name_index = assembly.string_add("TestType")?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let test_type = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: TypeAttributes::PUBLIC,
            type_name: type_name_index.placeholder(),
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(test_type))?;

        Ok(())
    })
}

/// Creates an assembly with invalid static constructor flags
///
/// Originally from: `src/metadata/validation/validators/owned/relationships/ownership.rs`
pub fn create_assembly_with_invalid_static_constructor() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
        // Create static constructor (.cctor) without static flag
        let cctor_name_index = assembly.string_add(".cctor")?;

        let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
        let invalid_cctor = MethodDefRaw {
            rid: method_rid,
            token: Token::new(0x06000000 + method_rid),
            offset: 0,
            rva: 0,
            impl_flags: 0,
            flags: 0x0006, // Public (0x0006) but missing static flag (0x0010) - should trigger validation failure
            name: cctor_name_index.placeholder(),
            signature: 1,
            param_list: 1,
        };

        assembly.table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(invalid_cctor))?;

        let type_name_index = assembly.string_add("TestType")?;

        let type_rid = assembly.original_table_row_count(TableId::TypeDef) + 1;
        let test_type = TypeDefRaw {
            rid: type_rid,
            token: Token::new(0x02000000 + type_rid),
            offset: 0,
            flags: TypeAttributes::PUBLIC,
            type_name: type_name_index.placeholder(),
            type_namespace: 0,
            extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
            field_list: 1,
            method_list: method_rid,
        };

        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(test_type))?;

        Ok(())
    })
}
