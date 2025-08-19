//! Factory methods for raw constraints generic validation testing.
//!
//! Contains helper methods migrated from raw constraints generic validation source files
//! for creating test assemblies with various generic constraint validation scenarios.

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, GenericParamConstraintRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    prelude::*,
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for RawGenericConstraintValidator following the golden pattern.
///
/// Creates test assemblies covering all generic constraint validation rules:
/// 1. Clean assembly (should pass)
/// 2. Generic parameter with invalid flags (both covariant and contravariant)
/// 3. Generic parameter constraint with null owner reference
/// 4. Generic parameter constraint with owner exceeding table bounds
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that should trigger validation failures in the raw validation stage.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn raw_generic_constraint_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    if let Some(clean_path) = get_clean_testfile() {
        assemblies.push(TestAssembly::new(clean_path, true));
    }

    // 3. NEGATIVE: Generic parameter with invalid flags (both covariant and contravariant)
    match create_assembly_with_invalid_parameter_flags() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid parameter flags: {e}"
            )));
        }
    }

    // 4. NEGATIVE: Generic parameter constraint with null owner reference
    match create_assembly_with_null_constraint_owner() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with null constraint owner: {e}"
            )));
        }
    }

    // 5. NEGATIVE: Generic parameter constraint with owner exceeding table bounds
    match create_assembly_with_constraint_owner_exceeding_bounds() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with constraint owner exceeding bounds: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates an assembly with a generic parameter constraint with null owner reference.
/// Uses raw table manipulation to create an invalid constraint with owner = 0.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn create_assembly_with_null_constraint_owner() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a valid generic parameter first
    let typedef_token = TypeDefBuilder::new()
        .name("GenericType")
        .namespace("Test")
        .flags(0x00100000)
        .build(&mut context)?;

    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    let _generic_param_token = GenericParamBuilder::new()
        .number(0)
        .flags(0x0000)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create GenericParamConstraint with null owner using raw table manipulation
    let invalid_constraint = GenericParamConstraintRaw {
        owner: 0, // Invalid: null owner reference
        constraint: CodedIndex::new(
            TableId::TypeDef,
            typedef_token.row(),
            CodedIndexType::TypeDefOrRef,
        ),
        rid: 1,
        token: Token::new(0x2C000001), // GenericParamConstraint table token
        offset: 0,
    };

    assembly.table_row_add(
        TableId::GenericParamConstraint,
        TableDataOwned::GenericParamConstraint(invalid_constraint),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with a generic parameter constraint where owner exceeds table bounds.
/// Uses raw table manipulation to create an invalid constraint reference.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn create_assembly_with_constraint_owner_exceeding_bounds() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a valid generic parameter first
    let typedef_token = TypeDefBuilder::new()
        .name("GenericType")
        .namespace("Test")
        .flags(0x00100000)
        .build(&mut context)?;

    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    let _generic_param_token = GenericParamBuilder::new()
        .number(0)
        .flags(0x0000)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create GenericParamConstraint with owner exceeding GenericParam table bounds
    let invalid_constraint = GenericParamConstraintRaw {
        owner: 0xFFFF, // Invalid: far exceeds any realistic GenericParam table size
        constraint: CodedIndex::new(
            TableId::TypeDef,
            typedef_token.row(),
            CodedIndexType::TypeDefOrRef,
        ),
        rid: 1,
        token: Token::new(0x2C000001), // GenericParamConstraint table token
        offset: 0,
    };

    assembly.table_row_add(
        TableId::GenericParamConstraint,
        TableDataOwned::GenericParamConstraint(invalid_constraint),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with generic parameter having conflicting variance flags.
/// This tests whether the validator catches flag combinations the builder allows.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/generic.rs`
pub fn create_assembly_with_invalid_parameter_flags() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let typedef_builder = TypeDefBuilder::new()
        .name("GenericType")
        .namespace("Test")
        .flags(0x00100000);

    let typedef_token = typedef_builder.build(&mut context)?;

    let owner = CodedIndex::new(
        TableId::TypeDef,
        typedef_token.row(),
        CodedIndexType::TypeOrMethodDef,
    );

    GenericParamBuilder::new()
        .number(0)
        .flags(0x0003)
        .owner(owner)
        .name("T")
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
