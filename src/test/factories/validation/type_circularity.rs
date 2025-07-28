//! Factory methods for type circularity validation testing.
//!
//! Contains helper methods migrated from type circularity validation source files
//! for creating test assemblies with various type circularity validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeAttributes, TypeDefRaw},
        token::Token,
        validation::ValidationConfig,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

// Note: Some builder types are imported through prelude in the original file
// We'll include what we need explicitly or use the prelude
use crate::prelude::*;

/// File factory function for OwnedTypeCircularityValidator testing.
///
/// Creates test assemblies with different types of circular dependencies.
/// Each assembly tests a specific circularity detection scenario.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn owned_type_circularity_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    match create_assembly_with_inheritance_circularity() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Circular inheritance",
            ));
        }
        Err(e) => eprintln!("Warning: Could not create inheritance test assembly: {e}"),
    }

    match create_assembly_with_nested_type_circularity() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Circular nested type relationship detected",
            ));
        }
        Err(e) => eprintln!("Warning: Could not create nested type test assembly: {e}"),
    }

    match create_assembly_with_interface_circularity() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Circular inheritance detected",
            ));
        }
        Err(e) => eprintln!("Warning: Could not create interface test assembly: {e}"),
    }

    match create_assembly_with_depth_limit_violation() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Inheritance chain depth exceeds maximum nesting depth limit",
            ));
        }
        Err(e) => eprintln!("Warning: Could not create depth limit violation test: {e}"),
    }

    Ok(assemblies)
}

/// Creates an assembly with inheritance circularity.
///
/// Creates types that inherit from each other in a circular pattern:
/// ClassA -> ClassB -> ClassA
///
/// The approach is to create the circular inheritance directly in the TypeDef table
/// in a way that will be detected by the validator when the assembly is reloaded.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_inheritance_circularity() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let class_a_name_index = context.string_add("CircularClassA")?;
    let class_b_name_index = context.string_add("CircularClassB")?;
    let test_namespace_index = context.string_add("Test")?;

    let mut assembly = context.finish();
    let current_typedef_count = assembly.original_table_row_count(TableId::TypeDef);

    let class_a_row = current_typedef_count + 1;
    let class_b_row = current_typedef_count + 2;
    let class_a_token = Token::new(0x02000000 | class_a_row);
    let class_b_token = Token::new(0x02000000 | class_b_row);

    let class_a_raw = TypeDefRaw {
        rid: class_a_token.row(),
        token: class_a_token,
        offset: 0,
        flags: TypeAttributes::PUBLIC | TypeAttributes::CLASS,
        type_name: class_a_name_index,
        type_namespace: test_namespace_index,
        extends: CodedIndex::new(
            TableId::TypeDef,
            class_b_token.row(),
            CodedIndexType::TypeDefOrRef,
        ),
        field_list: 1,
        method_list: 1,
    };

    let class_b_raw = TypeDefRaw {
        rid: class_b_token.row(),
        token: class_b_token,
        offset: 0,
        flags: TypeAttributes::PUBLIC | TypeAttributes::CLASS,
        type_name: class_b_name_index,
        type_namespace: test_namespace_index,
        extends: CodedIndex::new(
            TableId::TypeDef,
            class_a_token.row(),
            CodedIndexType::TypeDefOrRef,
        ),
        field_list: 1,
        method_list: 1,
    };

    let _actual_class_a_row =
        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(class_a_raw))?;
    let _actual_class_b_row =
        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(class_b_raw))?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with nested type circularity.
///
/// Creates types that contain each other as nested types through the NestedClass table.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_nested_type_circularity() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let outer_token = TypeDefBuilder::new()
        .name("CircularOuter")
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS)
        .build(&mut context)?;

    let inner_token = TypeDefBuilder::new()
        .name("CircularInner")
        .namespace("Test")
        .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
        .build(&mut context)?;

    NestedClassBuilder::new()
        .nested_class(inner_token)
        .enclosing_class(outer_token)
        .build(&mut context)?;

    NestedClassBuilder::new()
        .nested_class(outer_token)
        .enclosing_class(inner_token)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with interface implementation circularity.
///
/// Creates interfaces that implement each other through InterfaceImpl entries.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_interface_circularity() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let interface_a_token = TypeDefBuilder::new()
        .name("ICircularA")
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT)
        .build(&mut context)?;

    let interface_b_token = TypeDefBuilder::new()
        .name("ICircularB")
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT)
        .build(&mut context)?;

    InterfaceImplBuilder::new()
        .class(interface_a_token.0)
        .interface(CodedIndex::new(
            TableId::TypeDef,
            interface_b_token.row(),
            CodedIndexType::TypeDefOrRef,
        ))
        .build(&mut context)?;

    InterfaceImplBuilder::new()
        .class(interface_b_token.0)
        .interface(CodedIndex::new(
            TableId::TypeDef,
            interface_a_token.row(),
            CodedIndexType::TypeDefOrRef,
        ))
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with inheritance chain that exceeds max depth.
///
/// Creates a long inheritance chain that should trigger depth limit validation.
///
/// Originally from: `src/metadata/validation/validators/owned/types/circularity.rs`
pub fn create_assembly_with_depth_limit_violation() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let mut previous_token: Option<Token> = None;
    let chain_length = 120; // Should exceed max depth limit of 100

    for i in 0..chain_length {
        let mut builder = TypeDefBuilder::new()
            .name(format!("DeepClass{i}"))
            .namespace("Test")
            .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS);

        if let Some(parent_token) = previous_token {
            builder = builder.extends(CodedIndex::new(
                TableId::TypeDef,
                parent_token.row(),
                CodedIndexType::TypeDefOrRef,
            ));
        }

        let current_token = builder.build(&mut context)?;
        previous_token = Some(current_token);
    }

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
