//! Heap modification integration tests.
//!
//! Tests for modifying metadata heaps (strings, blobs, GUIDs, userstrings) and verifying
//! that changes are correctly persisted through the write pipeline.

use dotscope::prelude::*;
use std::path::Path;
use tempfile::NamedTempFile;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/crafted_2.exe";

/// Helper function to perform a round-trip test with specific verification
fn perform_round_trip_test<F, V>(modify_fn: F, verify_fn: V) -> Result<()>
where
    F: FnOnce(&mut BuilderContext) -> Result<()>,
    V: FnOnce(&CilAssemblyView) -> Result<()>,
{
    // Load original assembly and create context
    let view = CilAssemblyView::from_file(Path::new(TEST_ASSEMBLY_PATH))?;
    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Apply modifications
    modify_fn(&mut context)?;
    let mut assembly = context.finish();

    // Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Load written file and verify
    let written_view = CilAssemblyView::from_file(temp_file.path())?;
    verify_fn(&written_view)?;

    Ok(())
}

#[test]
fn test_string_heap_add_and_verify() -> Result<()> {
    let test_string = "TestAddedString";

    perform_round_trip_test(
        |context| {
            let _index = context.string_add(test_string)?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Error("No strings heap found".to_string()))?;

            // Verify the specific string was added
            let found = strings.iter().any(|(_, s)| s == test_string);
            assert!(
                found,
                "Added string '{test_string}' should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_blob_heap_add_and_verify() -> Result<()> {
    let test_blob = vec![0x06, 0x08, 0xFF, 0xAA]; // Test blob data

    perform_round_trip_test(
        |context| {
            let _index = context.blob_add(&test_blob)?;
            Ok(())
        },
        |written_view| {
            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Error("No blobs heap found".to_string()))?;

            // Verify the specific blob was added
            let found = blobs.iter().any(|(_, blob)| blob == test_blob);
            assert!(
                found,
                "Added blob {test_blob:?} should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_guid_heap_add_and_verify() -> Result<()> {
    let test_guid = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];

    perform_round_trip_test(
        |context| {
            let _index = context.guid_add(&test_guid)?;
            Ok(())
        },
        |written_view| {
            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Error("No GUIDs heap found".to_string()))?;

            // Verify the specific GUID was added
            let found = guids.iter().any(|(_, guid)| guid.to_bytes() == test_guid);
            assert!(
                found,
                "Added GUID {test_guid:?} should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_userstring_heap_add_and_verify() -> Result<()> {
    let test_userstring = "TestAddedUserString";

    perform_round_trip_test(
        |context| {
            let _index = context.userstring_add(test_userstring)?;
            Ok(())
        },
        |written_view| {
            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Error("No userstrings heap found".to_string()))?;

            // Verify the specific userstring was added
            let found = userstrings
                .iter()
                .any(|(_, us)| us.to_string().unwrap_or_default() == test_userstring);
            assert!(
                found,
                "Added userstring '{test_userstring}' should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_mixed_heap_additions() -> Result<()> {
    let test_string = "MixedTestString";
    let test_blob = vec![0x01, 0x02, 0x03];
    let test_guid = [0xFF; 16];
    let test_userstring = "MixedTestUserString";

    perform_round_trip_test(
        |context| {
            let _str_idx = context.string_add(test_string)?;
            let _blob_idx = context.blob_add(&test_blob)?;
            let _guid_idx = context.guid_add(&test_guid)?;
            let _us_idx = context.userstring_add(test_userstring)?;
            Ok(())
        },
        |written_view| {
            // Verify all additions are present
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Error("No strings heap found".to_string()))?;
            assert!(
                strings.iter().any(|(_, s)| s == test_string),
                "String should be present"
            );

            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Error("No blobs heap found".to_string()))?;
            assert!(
                blobs.iter().any(|(_, b)| b == test_blob),
                "Blob should be present"
            );

            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Error("No GUIDs heap found".to_string()))?;
            assert!(
                guids.iter().any(|(_, g)| g.to_bytes() == test_guid),
                "GUID should be present"
            );

            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Error("No userstrings heap found".to_string()))?;
            assert!(
                userstrings
                    .iter()
                    .any(|(_, us)| us.to_string().unwrap_or_default() == test_userstring),
                "Userstring should be present"
            );

            Ok(())
        },
    )
}

#[test]
fn test_string_modification_and_verify() -> Result<()> {
    let original_string = "Task`1"; // Should exist in crafted_2.exe
    let modified_string = "System.Object.Modified";

    perform_round_trip_test(
        |context| {
            // Get the original view to find the string index
            let view = CilAssemblyView::from_file(Path::new(TEST_ASSEMBLY_PATH))?;
            let strings = view
                .strings()
                .ok_or_else(|| Error::Error("No strings heap found".to_string()))?;

            let original_index = strings
                .iter()
                .find(|(_, s)| *s == original_string)
                .map(|(i, _)| i) // Use the actual index from the iterator
                .ok_or_else(|| Error::Error(format!("String '{original_string}' not found")))?;

            context.string_update(original_index as u32, modified_string)?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Error("No strings heap found".to_string()))?;

            // Verify the modification was applied
            let found_modified = strings.iter().any(|(_, s)| s == modified_string);
            assert!(
                found_modified,
                "Modified string '{modified_string}' should be present"
            );

            // Verify original string is no longer present
            let found_original = strings.iter().any(|(_, s)| s == original_string);
            assert!(
                !found_original,
                "Original string '{original_string}' should be replaced"
            );

            Ok(())
        },
    )
}

#[test]
fn test_heap_data_persistence() -> Result<()> {
    // Test that heap modifications don't corrupt existing data
    let test_string = "PersistenceTestString";

    perform_round_trip_test(
        |context| {
            let _index = context.string_add(test_string)?;
            Ok(())
        },
        |written_view| {
            // Verify basic metadata structures are intact
            assert!(
                written_view.strings().is_some(),
                "Strings heap should exist"
            );
            assert!(written_view.blobs().is_some(), "Blobs heap should exist");
            assert!(written_view.tables().is_some(), "Tables should exist");

            // Verify our addition is there
            let strings = written_view.strings().unwrap();
            assert!(
                strings.iter().any(|(_, s)| s == test_string),
                "Added string should be present"
            );

            // Verify some existing data is preserved (Task`1 should exist)
            assert!(
                strings.iter().any(|(_, s)| s == "Task`1"),
                "Existing string 'Task`1' should be preserved"
            );

            Ok(())
        },
    )
}
