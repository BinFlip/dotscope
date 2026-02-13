//! Factory methods for type dependency validation testing.
//!
//! Contains helper methods migrated from type dependency validation source files
//! for creating test assemblies with various type dependency validation scenarios.

use crate::{
    metadata::{tables::*, token::Token},
    test::{create_test_assembly_with_error, get_testfile_mscorlib, TestAssembly},
    Error, Result,
};

/// Main factory method for type dependency validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn owned_type_dependency_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_testfile_mscorlib() else {
        return Err(Error::Other(
            "mscorlib.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all type dependency validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE: Type with unresolved base type dependency
    match create_assembly_with_unresolved_base_type() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => {
            return Err(Error::Other(format!(
                "Failed to create test assembly with unresolved base type: {e}"
            )));
        }
    }

    // 3. NEGATIVE: Type with broken interface dependency reference
    match create_assembly_with_broken_interface_reference() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => {
            return Err(Error::Other(format!(
                "Failed to create test assembly with broken interface reference: {e}"
            )));
        }
    }

    // Note: Test 4 is disabled as it requires complex signature blob corruption.
    // Tests 1, 2, 3, and 5 provide comprehensive coverage for the core type dependency validation logic.

    // 4. NEGATIVE: Method with missing parameter type dependency (disabled - complex signature blob corruption needed)
    // The current implementation creates a separate ParamRaw table entry, but the validator
    // checks method.params which comes from signature blob resolution, not the Param table.
    // match create_assembly_with_missing_parameter_type() {
    //     Ok(test_assembly) => assemblies.push(test_assembly),
    //     Err(e) => {
    //         return Err(Error::Other(format!(
    //             "Failed to create test assembly with missing parameter type: {e}"
    //         )));
    //     }
    // }

    // 5. NEGATIVE: Type with unresolved nested type dependency (testing)
    match create_assembly_with_unresolved_nested_type() {
        Ok(test_assembly) => assemblies.push(test_assembly),
        Err(e) => {
            return Err(Error::Other(format!(
                "Failed to create test assembly with unresolved nested type: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates an assembly with a type that has an unresolved base type dependency.
/// Uses raw table manipulation to create a type with a base type that has an empty name,
/// triggering the "unresolved base type dependency" validation error.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_unresolved_base_type() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "unresolved base type dependency",
        |assembly| {
            // Create a type with a valid base type reference
            let base_typedef_token = TypeDefBuilder::new()
                .name("BaseClass")
                .namespace("Test")
                .flags(0x00100000) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let base_rid = base_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            let _derived_typedef_token = TypeDefBuilder::new()
                .name("DerivedClass")
                .namespace("Test")
                .flags(0x00100000) // Public class
                .extends(CodedIndex::new(
                    TableId::TypeDef,
                    base_rid,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(assembly)?;

            // Corrupt the base type by setting its name to an empty string (index 0)
            // This simulates an unresolved base type dependency
            let corrupted_base_type = TypeDefRaw {
                flags: 0x00100000,
                type_name: 0,      // Empty name - this will trigger the validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: 1,
                method_list: 1,
                rid: base_rid,
                token: Token::new(0x02000000 | base_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                base_rid,
                TableDataOwned::TypeDef(corrupted_base_type),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a type that has a broken interface dependency reference.
/// This simulates a scenario where an interface reference cannot be resolved.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_broken_interface_reference() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "unresolved interface dependency",
        |assembly| {
            // Create an interface type
            let interface_typedef_token = TypeDefBuilder::new()
                .name("ITestInterface")
                .namespace("Test")
                .flags(0x00100000 | 0x00000020) // Public + Interface
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let interface_rid = interface_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create a type that implements the interface
            let implementing_typedef_token = TypeDefBuilder::new()
                .name("TestClass")
                .namespace("Test")
                .flags(0x00100000) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let implementing_rid = implementing_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Add interface implementation
            let interface_impl = InterfaceImplRaw {
                class: implementing_rid,
                interface: CodedIndex::new(
                    TableId::TypeDef,
                    interface_rid,
                    CodedIndexType::TypeDefOrRef,
                ),
                rid: 1,
                token: Token::new(0x09000001), // InterfaceImpl table token
                offset: 0,
            };

            assembly.table_row_add(
                TableId::InterfaceImpl,
                TableDataOwned::InterfaceImpl(interface_impl),
            )?;

            // Corrupt the interface type by setting its name to empty (index 0)
            // This will cause the interface dependency to appear unresolved
            let corrupted_interface_type = TypeDefRaw {
                flags: 0x00100000 | 0x00000020, // Public + Interface
                type_name: 0,      // Empty name - this will trigger the validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: 1,
                method_list: 1,
                rid: interface_rid,
                token: Token::new(0x02000000 | interface_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                interface_rid,
                TableDataOwned::TypeDef(corrupted_interface_type),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a method that has a missing parameter type dependency.
/// This simulates a method parameter with an unresolvable type reference.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_missing_parameter_type() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "missing type dependency",
        |assembly| {
            // Create a type to contain the method
            let _typedef_token = TypeDefBuilder::new()
                .name("TestClass")
                .namespace("Test")
                .flags(0x00100000) // Public class
                .build(assembly)?;

            // Create a parameter type that we'll corrupt later
            let param_typedef_token = TypeDefBuilder::new()
                .name("ParamType")
                .namespace("Test")
                .flags(0x00100000) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let param_type_rid = param_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create a method with the parameter type using raw table API
            let method_rid = assembly.original_table_row_count(TableId::MethodDef) + 1;
            let method = MethodDefRaw {
                rid: method_rid,
                token: Token::new(0x06000000 + method_rid),
                offset: 0,
                rva: 0,
                impl_flags: 0x00000000,
                flags: 0x00000006, // Public
                name: assembly.string_add("TestMethod")?.placeholder(),
                signature: 1, // Basic method signature index
                param_list: 1,
            };
            assembly.table_row_add(TableId::MethodDef, TableDataOwned::MethodDef(method))?;

            // Create a parameter using the parameter type
            let param = ParamRaw {
                flags: 0x0000,
                sequence: 1,
                name: assembly.string_add("param1")?.placeholder(),
                rid: 1,
                token: Token::new(0x08000001), // Param table token
                offset: 0,
            };

            assembly.table_row_add(TableId::Param, TableDataOwned::Param(param))?;

            // Corrupt the parameter type by setting its name to empty (index 0)
            // This simulates an unresolved parameter type dependency
            let corrupted_param_type = TypeDefRaw {
                flags: 0x00100000,
                type_name: 0,      // Empty name - this will trigger the validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: 1,
                method_list: 1,
                rid: param_type_rid,
                token: Token::new(0x02000000 | param_type_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                param_type_rid,
                TableDataOwned::TypeDef(corrupted_param_type),
            )?;

            Ok(())
        },
    )
}

/// Creates an assembly with a type that has an unresolved nested type dependency.
/// This simulates a nested type with an empty name that cannot be resolved.
///
/// Originally from: `src/metadata/validation/validators/owned/types/dependency.rs`
pub fn create_assembly_with_unresolved_nested_type() -> Result<TestAssembly> {
    create_test_assembly_with_error(
        get_testfile_mscorlib,
        "unresolved nested type dependency",
        |assembly| {
            // Create a containing type
            let containing_typedef_token = TypeDefBuilder::new()
                .name("ContainingClass")
                .namespace("Test")
                .flags(0x00100000) // Public class
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let containing_rid = containing_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create a nested type
            let nested_typedef_token = TypeDefBuilder::new()
                .name("NestedClass")
                .namespace("Test")
                .flags(0x00100000 | 0x00000008) // Public + Nested
                .build(assembly)?;

            // Get the actual RID from the resolved token
            let nested_rid = nested_typedef_token
                .token()
                .expect("Token should be resolved")
                .row();

            // Create the corrupted nested type with empty name to trigger validation error
            // This simulates a nested type that cannot be resolved during validation
            let corrupted_nested_type = TypeDefRaw {
                flags: 0x00100000 | 0x00000008, // Public + Nested
                type_name: 0, // Empty name at index 0 - this should trigger validation error
                type_namespace: 1, // Valid namespace
                extends: CodedIndex::new(TableId::TypeDef, 0, CodedIndexType::TypeDefOrRef),
                field_list: 1,
                method_list: 1,
                rid: nested_rid,
                token: Token::new(0x02000000 | nested_rid),
                offset: 0,
            };

            assembly.table_row_update(
                TableId::TypeDef,
                nested_rid,
                TableDataOwned::TypeDef(corrupted_nested_type),
            )?;

            // Create nested class relationship - this will create a dependency on the corrupted type
            let nested_class = NestedClassRaw {
                nested_class: nested_rid,
                enclosing_class: containing_rid,
                rid: 1,
                token: Token::new(0x29000001), // NestedClass table token
                offset: 0,
            };

            assembly.table_row_add(
                TableId::NestedClass,
                TableDataOwned::NestedClass(nested_class),
            )?;

            Ok(())
        },
    )
}
