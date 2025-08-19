//! Basic write pipeline integration tests.
//!
//! Tests for basic assembly writing functionality, including unmodified assemblies
//! and simple modifications to verify the core write pipeline works correctly.

use dotscope::prelude::*;
use std::path::Path;
use tempfile::NamedTempFile;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/crafted_2.exe";

#[test]
fn test_write_unmodified_assembly() -> Result<()> {
    // Load assembly without modifications
    let view = CilAssemblyView::from_file(Path::new(TEST_ASSEMBLY_PATH))?;
    let mut assembly = CilAssembly::new(view);

    // Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Verify the written file can be loaded
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Basic integrity checks
    assert!(
        written_view.strings().is_some(),
        "Written assembly should have strings heap"
    );
    assert!(
        written_view.blobs().is_some(),
        "Written assembly should have blobs heap"
    );
    assert!(
        written_view.tables().is_some(),
        "Written assembly should have metadata tables"
    );

    // Verify basic metadata structure is preserved
    let tables = written_view.tables().unwrap();
    assert!(
        tables.table_row_count(TableId::Module) > 0,
        "Should have module table entries"
    );
    assert!(
        tables.table_row_count(TableId::TypeDef) > 0,
        "Should have type definition entries"
    );

    Ok(())
}

#[test]
fn test_write_with_minimal_modification() -> Result<()> {
    // Load assembly and make a minimal modification
    let view = CilAssemblyView::from_file(Path::new(TEST_ASSEMBLY_PATH))?;
    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Add a single string - minimal modification to trigger write pipeline
    let test_string = "MinimalTestString";
    let string_index = context.string_add(test_string)?;
    assert!(string_index > 0, "String index should be positive");

    let mut assembly = context.finish();

    // Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Verify the written file can be loaded and contains our modification
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    let strings = written_view
        .strings()
        .ok_or_else(|| Error::Error("Written assembly should have strings heap".to_string()))?;

    // Verify our modification is present
    let found = strings.iter().any(|(_, s)| s == test_string);
    assert!(
        found,
        "Added string '{test_string}' should be present in written assembly"
    );

    // Verify basic structure is still intact
    assert!(
        written_view.tables().is_some(),
        "Written assembly should have metadata tables"
    );

    Ok(())
}

#[test]
fn test_write_preserves_existing_data() -> Result<()> {
    // Test that writing preserves existing assembly data
    let view = CilAssemblyView::from_file(Path::new(TEST_ASSEMBLY_PATH))?;

    // Capture some original data
    let original_strings_count = view.strings().map(|s| s.iter().count()).unwrap_or(0);
    let original_method_count = view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Make a modification
    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);
    let _string_idx = context.string_add("PreservationTestString")?;
    let mut assembly = context.finish();

    // Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Write and reload
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Verify existing data is preserved
    let new_strings_count = written_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let new_method_count = written_view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Strings should increase by 1, methods should stay the same
    assert_eq!(
        new_method_count, original_method_count,
        "Method count should be preserved"
    );
    assert!(
        new_strings_count >= original_strings_count,
        "String count should increase or stay the same"
    );

    // Verify some known existing data is still there
    let strings = written_view.strings().unwrap();
    assert!(
        strings.iter().any(|(_, s)| s == "Task`1"),
        "Standard type 'Task`1' should be preserved"
    );

    Ok(())
}

#[test]
fn test_multiple_write_operations() -> Result<()> {
    // Test that an assembly can be written multiple times
    let view = CilAssemblyView::from_file(Path::new(TEST_ASSEMBLY_PATH))?;
    let mut assembly = CilAssembly::new(view);

    // Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Write first time
    let temp_file1 = NamedTempFile::new()?;
    assembly.write_to_file(temp_file1.path())?;

    // Write second time (should work without issues)
    let temp_file2 = NamedTempFile::new()?;
    assembly.write_to_file(temp_file2.path())?;

    // Both files should be valid and loadable
    let written_view1 = CilAssemblyView::from_file(temp_file1.path())?;
    let written_view2 = CilAssemblyView::from_file(temp_file2.path())?;

    // Both should have the same basic structure
    assert_eq!(
        written_view1
            .tables()
            .map(|t| t.table_row_count(TableId::Module)),
        written_view2
            .tables()
            .map(|t| t.table_row_count(TableId::Module)),
        "Both written files should have the same module count"
    );

    Ok(())
}
