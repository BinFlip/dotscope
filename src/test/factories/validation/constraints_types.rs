//! Factory methods for constraints types validation testing.
//!
//! Contains helper methods migrated from constraints types validation source files
//! for creating test assemblies with various type constraint validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            CodedIndex, CodedIndexType, GenericParamAttributes, GenericParamBuilder,
            GenericParamConstraintBuilder, InterfaceImplBuilder, TableId, TypeDefBuilder,
        },
        token::Token,
        validation::ValidationConfig,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for OwnedTypeConstraintValidator following the golden pattern.
///
/// Creates test assemblies covering all validation rules:
/// 1. Clean assembly (should pass)
/// 2. Assembly with conflicting generic parameter attributes (covariant + contravariant)
/// 3. Assembly with conflicting constraint types (reference type + value type)
/// 4. Assembly with unresolved constraint references (broken constraint reference)
/// 5. Assembly with empty constraint type names (unresolved constraint)
/// 6. Assembly with non-interface implemented as interface
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the constraint violations that the owned
/// validator should detect in the resolved metadata structures.
pub fn owned_type_constraint_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    // 1. Clean assembly - should pass all constraint validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. Assembly with conflicting variance attributes (covariant + contravariant)
    match create_assembly_with_conflicting_variance() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "cannot be both covariant and contravariant",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with conflicting variance: {e}"
            )));
        }
    }

    // 3. Assembly with conflicting constraint types (reference + value type)
    match create_assembly_with_conflicting_constraints() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "cannot have both reference type and value type constraints",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with conflicting constraints: {e}"
            )));
        }
    }

    // 4. Assembly with broken constraint references (invalid RID)
    match create_assembly_with_broken_constraint_reference() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Failed to resolve constraint type token",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with broken constraint reference: {e}"
            )));
        }
    }

    // 5. Assembly with empty constraint type name (unresolved constraint)
    match create_assembly_with_empty_constraint_name() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "has unresolved constraint",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with empty constraint name: {e}"
            )));
        }
    }

    // 6. Assembly with non-interface implemented as interface
    match create_assembly_with_fake_interface_implementation() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "implements non-interface type",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with fake interface implementation: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates an assembly with conflicting generic parameter variance attributes.
///
/// This creates a raw assembly containing a generic type with a parameter that has
/// both COVARIANT and CONTRAVARIANT flags set, which violates ECMA-335 constraints.
/// When loaded by CilObject, this should trigger validation failure in the owned validator.
fn create_assembly_with_conflicting_variance() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a generic type definition
    let typedef_token = TypeDefBuilder::new()
        .name("ConflictingVarianceType`1")
        .namespace("Test")
        .flags(0x00000000) // Class, NotPublic
        .build(&mut context)?;

    // Create GenericParam with conflicting variance flags (COVARIANT | CONTRAVARIANT)
    let conflicting_flags =
        GenericParamAttributes::COVARIANT | GenericParamAttributes::CONTRAVARIANT;

    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    GenericParamBuilder::new()
        .number(0)
        .flags(conflicting_flags)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with conflicting constraint type attributes.
///
/// This creates a raw assembly containing a generic type with a parameter that has
/// both REFERENCE_TYPE_CONSTRAINT and NOT_NULLABLE_VALUE_TYPE_CONSTRAINT flags set,
/// which is invalid according to ECMA-335. When loaded by CilObject, this should
/// trigger validation failure in the owned validator.
fn create_assembly_with_conflicting_constraints() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a generic type definition
    let typedef_token = TypeDefBuilder::new()
        .name("ConflictingConstraintsType`1")
        .namespace("Test")
        .flags(0x00000000) // Class, NotPublic
        .build(&mut context)?;

    // Create GenericParam with conflicting constraint flags (class + struct)
    let conflicting_flags = GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT
        | GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT;

    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    GenericParamBuilder::new()
        .number(0)
        .flags(conflicting_flags)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with broken constraint references.
///
/// This creates a raw assembly containing a generic type with a parameter that has
/// a constraint reference pointing to an invalid/non-existent type RID. When the
/// metadata is resolved by CilObject, this should result in broken constraint references
/// that trigger validation failure in the owned validator.
fn create_assembly_with_broken_constraint_reference() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a generic type definition
    let typedef_token = TypeDefBuilder::new()
        .name("BrokenConstraintType`1")
        .namespace("Test")
        .flags(0x00000000) // Class, NotPublic
        .build(&mut context)?;

    // Create a GenericParam
    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    let generic_param_token = GenericParamBuilder::new()
        .number(0)
        .flags(0)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    // Create a GenericParamConstraint with invalid constraint reference (out-of-bounds TypeRef RID)
    let invalid_constraint = CodedIndex::new(
        TableId::TypeRef,
        999999, // Invalid RID that doesn't exist
        CodedIndexType::TypeDefOrRef,
    );

    GenericParamConstraintBuilder::new()
        .owner(Token::new(generic_param_token.0))
        .constraint(invalid_constraint)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with empty constraint type names.
///
/// This creates a raw assembly where constraint types have empty names,
/// simulating unresolved constraints that should trigger validation failure.
fn create_assembly_with_empty_constraint_name() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a generic type definition
    let typedef_token = TypeDefBuilder::new()
        .name("EmptyConstraintType`1")
        .namespace("Test")
        .flags(0x00000000) // Class, NotPublic
        .build(&mut context)?;

    // Create a constraint type with empty name (simulating unresolved type)
    let constraint_typedef_token = TypeDefBuilder::new()
        .name("") // Empty name - this should trigger the validation error
        .namespace("Test")
        .flags(0x00000000)
        .build(&mut context)?;

    // Create a GenericParam
    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    let generic_param_token = GenericParamBuilder::new()
        .number(0)
        .flags(0)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    // Create a GenericParamConstraint referencing the empty-named type
    let constraint_ref = CodedIndex::new(
        TableId::TypeDef,
        constraint_typedef_token.row(),
        CodedIndexType::TypeDefOrRef,
    );

    GenericParamConstraintBuilder::new()
        .owner(Token::new(generic_param_token.0))
        .constraint(constraint_ref)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with a class implementing a non-interface as an interface.
///
/// This creates a raw assembly containing a class that implements another class
/// (not an interface) as if it were an interface, which should trigger validation
/// failure when the owned validator checks interface implementation constraints.
fn create_assembly_with_fake_interface_implementation() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a regular class (NOT an interface) that will be "implemented" as an interface
    let fake_interface_token = TypeDefBuilder::new()
        .name("NotAnInterface") // Name doesn't suggest interface
        .namespace("Test")
        .flags(0x00000000) // Class, NotPublic - NOT an interface (missing INTERFACE flag)
        .build(&mut context)?;

    // Create a class that "implements" the non-interface
    let implementing_class_token = TypeDefBuilder::new()
        .name("ImplementingClass")
        .namespace("Test")
        .flags(0x00000000) // Class, NotPublic
        .build(&mut context)?;

    // Create InterfaceImpl that makes the class "implement" the non-interface
    let fake_interface_ref = CodedIndex::new(
        TableId::TypeDef,
        fake_interface_token.row(),
        CodedIndexType::TypeDefOrRef,
    );

    InterfaceImplBuilder::new()
        .class(implementing_class_token.row())
        .interface(fake_interface_ref)
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()
        .map_err(|e| Error::Error(format!("Failed to create temp file: {e}")))?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
