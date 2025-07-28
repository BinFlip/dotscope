//! Factory methods for raw constraints layout validation testing.
//!
//! Contains helper methods migrated from raw constraints layout validation source files
//! for creating test assemblies with various layout constraint validation scenarios.

use crate::{
    metadata::{
        tables::{ClassLayoutRaw, FieldLayoutRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    prelude::*,
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for RawLayoutConstraintValidator following the golden pattern.
///
/// Creates test assemblies covering all layout constraint validation rules:
/// 1. Clean assembly (should pass)
/// 2. Null field reference in FieldLayout
/// 3. Invalid field offset - exceeding 0x7FFFFFFF
/// 4. Invalid packing size - not power of 2
/// 5. Excessive class size - exceeding 0x7FFFFFFF
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that should trigger validation failures in the raw validation stage.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn raw_layout_constraint_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. Null field reference in FieldLayout - should definitely fail
    match create_assembly_with_null_field_reference() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with null field reference: {e}"
            )));
        }
    }

    // 3. Invalid field offset - exceeding 0x7FFFFFFF
    match create_assembly_with_invalid_field_offset() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with invalid field offset: {e}"
            )));
        }
    }

    // 4. Invalid packing size - not power of 2
    match create_assembly_with_invalid_packing_size() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with invalid packing size: {e}"
            )));
        }
    }

    // 5. Excessive class size - exceeding 0x7FFFFFFF
    match create_assembly_with_excessive_class_size() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create assembly with excessive class size: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates an assembly with overlapping fields at the same offset to test field layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_overlapping_fields() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a basic type first
    let _typedef_token = TypeDefBuilder::new()
        .name("OverlappingFieldsType")
        .namespace("Test")
        .flags(0x00100108) // Explicit layout
        .build(&mut context)?;

    // Create a single field
    let field_token = FieldBuilder::new()
        .name("TestField")
        .flags(0x0001)
        .signature(&[0x06, 0x08])
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create suspiciously large number of field layouts at same offset (>1000 to trigger corruption detection)
    for i in 1..=1001 {
        let field_layout = FieldLayoutRaw {
            field_offset: 4, // All fields at same position
            field: field_token.row(),
            rid: i,
            token: Token::new(0x10000000 + i),
            offset: ((i - 1) * 8) as usize, // Different metadata stream offsets
        };

        assembly.table_row_update(
            TableId::FieldLayout,
            i,
            TableDataOwned::FieldLayout(field_layout),
        )?;
    }

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    Ok(temp_file)
}

/// Creates an assembly with invalid packing size (not power of 2) to test class layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_invalid_packing_size() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let typedef_token = TypeDefBuilder::new()
        .name("InvalidPackingType")
        .namespace("Test")
        .flags(0x00100000)
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create class layout with invalid packing size directly
    let class_layout = ClassLayoutRaw {
        packing_size: 3, // Invalid - not power of 2
        class_size: 16,
        parent: typedef_token.row(),
        rid: 1,
        token: Token::new(0x0F000001), // ClassLayout table token
        offset: 0,
    };

    assembly.table_row_update(
        TableId::ClassLayout,
        1,
        TableDataOwned::ClassLayout(class_layout),
    )?;
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    Ok(temp_file)
}

/// Creates an assembly with excessive class size to test class layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_excessive_class_size() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let typedef_token = TypeDefBuilder::new()
        .name("ExcessiveSizeType")
        .namespace("Test")
        .flags(0x00100000)
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create class layout with excessive size directly
    let class_layout = ClassLayoutRaw {
        packing_size: 1,
        class_size: 0x80000000, // Exceeds maximum allowed (0x7FFFFFFF)
        parent: typedef_token.row(),
        rid: 1,
        token: Token::new(0x0F000001), // ClassLayout table token
        offset: 0,
    };

    assembly.table_row_update(
        TableId::ClassLayout,
        1,
        TableDataOwned::ClassLayout(class_layout),
    )?;
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    Ok(temp_file)
}

/// Creates an assembly with invalid field offset to test field layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_invalid_field_offset() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let _typedef_token = TypeDefBuilder::new()
        .name("InvalidOffsetType")
        .namespace("Test")
        .flags(0x00100108) // Explicit layout
        .build(&mut context)?;

    let field_token = FieldBuilder::new()
        .name("InvalidField")
        .flags(0x0001)
        .signature(&[0x06, 0x08])
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create field layout with invalid field offset directly
    let field_layout = FieldLayoutRaw {
        field_offset: 0x80000000, // Exceeds maximum allowed (0x7FFFFFFF)
        field: field_token.row(),
        rid: 1,
        token: Token::new(0x10000001), // FieldLayout table token
        offset: 0,                     // Metadata stream offset
    };

    assembly.table_row_update(
        TableId::FieldLayout,
        1,
        TableDataOwned::FieldLayout(field_layout),
    )?;
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    Ok(temp_file)
}

/// Creates an assembly with null field reference to test field layout validation.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_null_field_reference() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let _typedef_token = TypeDefBuilder::new()
        .name("NullFieldRefType")
        .namespace("Test")
        .flags(0x00100108) // Explicit layout
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create field layout with null field reference directly
    let field_layout = FieldLayoutRaw {
        field_offset: 0,
        field: 0, // Null field reference - should cause error
        rid: 1,
        token: Token::new(0x10000001), // FieldLayout table token
        offset: 0,
    };

    assembly.table_row_update(
        TableId::FieldLayout,
        1,
        TableDataOwned::FieldLayout(field_layout),
    )?;
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    Ok(temp_file)
}

/// Creates an assembly with field offset at maximum boundary to test overflow detection.
///
/// Originally from: `src/metadata/validation/validators/raw/constraints/layout.rs`
pub fn create_assembly_with_boundary_field_offset() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let _typedef_token = TypeDefBuilder::new()
        .name("BoundaryOffsetType")
        .namespace("Test")
        .flags(0x00100108) // Explicit layout
        .build(&mut context)?;

    let field_token = FieldBuilder::new()
        .name("BoundaryField")
        .flags(0x0001)
        .signature(&[0x06, 0x08])
        .build(&mut context)?;

    let mut assembly = context.finish();

    // Create field layout with field offset at maximum boundary directly
    let field_layout = FieldLayoutRaw {
        field_offset: 0x7FFFFFFF, // At maximum boundary - should trigger overflow warning
        field: field_token.row(),
        rid: 1,
        token: Token::new(0x10000001), // FieldLayout table token
        offset: 0,                     // Metadata stream offset
    };

    assembly.table_row_update(
        TableId::FieldLayout,
        1,
        TableDataOwned::FieldLayout(field_layout),
    )?;
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    Ok(temp_file)
}
