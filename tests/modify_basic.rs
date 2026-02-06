//! Basic write pipeline integration tests.
//!
//! Tests for basic assembly writing functionality, including unmodified assemblies
//! and simple modifications to verify the core write pipeline works correctly.

use dotscope::prelude::*;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/crafted_2.exe";

#[test]
fn test_write_unmodified_assembly() -> Result<()> {
    // Load assembly without modifications
    let mut assembly = CilAssembly::from_path(TEST_ASSEMBLY_PATH)?;

    // Write to memory
    let bytes = assembly.to_memory()?;

    // Verify the written bytes can be loaded
    let written_view = CilAssemblyView::from_mem(bytes)?;

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
    let mut assembly = CilAssembly::from_path(TEST_ASSEMBLY_PATH)?;

    // Add a single string - minimal modification to trigger write pipeline
    let test_string = "MinimalTestString";
    let _string_ref = assembly.string_add(test_string)?;
    // ChangeRef is valid if we got here without error

    // Write to memory
    let bytes = assembly.to_memory()?;

    // Verify the written bytes can be loaded and contains our modification
    let written_view = CilAssemblyView::from_mem(bytes)?;

    let strings = written_view
        .strings()
        .ok_or_else(|| Error::Other("Written assembly should have strings heap".to_string()))?;

    // Verify our modification is present
    assert!(
        strings.contains(test_string),
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
    let mut assembly = CilAssembly::from_path(TEST_ASSEMBLY_PATH)?;

    // Capture some original data
    let original_strings_count = assembly
        .view()
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let original_method_count = assembly
        .view()
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Make a modification
    let string_idx = assembly.string_add("PreservationTestString")?;

    // Write to memory and reload
    let bytes = assembly.to_memory()?;
    let written_view = CilAssemblyView::from_mem(bytes)?;

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

    // Verify the added string can be retrieved
    let strings = written_view.strings().unwrap();
    let retrieved_string = strings.get(string_idx.offset().unwrap() as usize)?;
    assert_eq!(
        retrieved_string, "PreservationTestString",
        "Added string should be retrievable after write"
    );

    Ok(())
}

#[test]
fn test_multiple_write_operations() -> Result<()> {
    // Test that an assembly can be written multiple times
    let mut assembly = CilAssembly::from_path(TEST_ASSEMBLY_PATH)?;

    // Write first time
    let bytes1 = assembly.to_memory()?;

    // Write second time (should work without issues)
    let bytes2 = assembly.to_memory()?;

    // Both should be valid and loadable
    let written_view1 = CilAssemblyView::from_mem(bytes1)?;
    let written_view2 = CilAssemblyView::from_mem(bytes2)?;

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
