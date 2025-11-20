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

#[test]
fn test_string_heap_replacement() -> Result<()> {
    // Create a custom string heap with null byte at index 0 followed by two null-terminated strings
    let mut custom_heap = vec![0]; // Index 0 must always be null
    custom_heap.extend_from_slice(b"CustomString1\0AnotherString\0");

    perform_round_trip_test(
        |context| {
            context.string_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Error("No strings heap found".to_string()))?;

            // Verify the custom strings are present
            let found_custom1 = strings.iter().any(|(_, s)| s == "CustomString1");
            let found_custom2 = strings.iter().any(|(_, s)| s == "AnotherString");

            assert!(
                found_custom1,
                "Custom string 'CustomString1' should be present in replaced heap"
            );
            assert!(
                found_custom2,
                "Custom string 'AnotherString' should be present in replaced heap"
            );

            // Verify that original strings are no longer present (heap was replaced)
            let found_original = strings.iter().any(|(_, s)| s == "Task`1");
            assert!(
                !found_original,
                "Original strings should not be present after heap replacement"
            );

            Ok(())
        },
    )
}

#[test]
fn test_blob_heap_replacement() -> Result<()> {
    // Create a custom blob heap with null byte at index 0 followed by length-prefixed blobs
    // Index 0: null byte (required)
    // First blob: length=3, data=[0x01, 0x02, 0x03]
    // Second blob: length=2, data=[0xFF, 0xFE]
    let mut custom_heap = vec![0]; // Index 0 must always be null
    custom_heap.extend_from_slice(&[0x03, 0x01, 0x02, 0x03, 0x02, 0xFF, 0xFE]);

    perform_round_trip_test(
        |context| {
            context.blob_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Error("No blobs heap found".to_string()))?;

            // Verify the custom blobs are present
            let found_blob1 = blobs.iter().any(|(_, blob)| blob == [0x01, 0x02, 0x03]);
            let found_blob2 = blobs.iter().any(|(_, blob)| blob == [0xFF, 0xFE]);

            assert!(
                found_blob1,
                "Custom blob [0x01, 0x02, 0x03] should be present in replaced heap"
            );
            assert!(
                found_blob2,
                "Custom blob [0xFF, 0xFE] should be present in replaced heap"
            );

            // Since we replaced the entire heap, original blobs should not be present
            let blob_count = blobs.iter().count();
            assert!(
                blob_count <= 3, // Empty blob at index 0 + our 2 blobs
                "Replaced heap should only contain our custom blobs (found {blob_count} blobs)",
            );

            Ok(())
        },
    )
}

#[test]
fn test_guid_heap_replacement() -> Result<()> {
    // Create a custom GUID heap with two GUIDs (32 bytes total)
    let guid1 = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];
    let guid2 = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];

    let mut custom_heap = Vec::new();
    custom_heap.extend_from_slice(&guid1);
    custom_heap.extend_from_slice(&guid2);

    perform_round_trip_test(
        |context| {
            context.guid_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Error("No GUIDs heap found".to_string()))?;

            // Verify the custom GUIDs are present
            let found_guid1 = guids.iter().any(|(_, guid)| guid.to_bytes() == guid1);
            let found_guid2 = guids.iter().any(|(_, guid)| guid.to_bytes() == guid2);

            assert!(
                found_guid1,
                "Custom GUID 1 should be present in replaced heap"
            );
            assert!(
                found_guid2,
                "Custom GUID 2 should be present in replaced heap"
            );

            // Since we replaced the entire heap, only our GUIDs should be present
            let guid_count = guids.iter().count();
            assert_eq!(
                guid_count, 2,
                "Replaced heap should only contain our 2 custom GUIDs (found {guid_count} GUIDs)",
            );

            Ok(())
        },
    )
}

#[test]
fn test_userstring_heap_replacement() -> Result<()> {
    // Create a custom user string heap with null byte at index 0 followed by length-prefixed UTF-16 strings
    // Index 0: null byte (required)
    // String "Hi": length=5 (4 bytes UTF-16 + 1 terminator), UTF-16 data: 0x48,0x00,0x69,0x00, terminator: 0x01
    let mut custom_heap = vec![0]; // Index 0 must always be null
    custom_heap.extend_from_slice(&[0x05, 0x48, 0x00, 0x69, 0x00, 0x01]);

    perform_round_trip_test(
        |context| {
            context.userstring_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Error("No userstrings heap found".to_string()))?;

            // Verify the custom user string is present
            let found_custom = userstrings
                .iter()
                .any(|(_, us)| us.to_string().unwrap_or_default() == "Hi");

            assert!(
                found_custom,
                "Custom user string 'Hi' should be present in replaced heap"
            );

            // Since we replaced the entire heap, original user strings should not be present
            let userstring_count = userstrings.iter().count();
            assert!(
                userstring_count <= 2, // Empty userstring at index 0 + our 1 userstring
                "Replaced heap should only contain our custom user string (found {userstring_count} userstrings)",
            );

            Ok(())
        },
    )
}

#[test]
fn test_heap_replacement_with_subsequent_additions() -> Result<()> {
    // Test that subsequent additions work with replaced heaps
    let mut custom_string_heap = vec![0]; // Index 0 must always be null
    custom_string_heap.extend_from_slice(b"ReplacedString\0");

    perform_round_trip_test(
        |context| {
            // Replace string heap
            context.string_add_heap(custom_string_heap.clone())?;

            // Add a new string after replacement
            let _new_index = context.string_add("AddedAfterReplacement")?;

            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Error("No strings heap found".to_string()))?;

            // Verify both the replaced string and the newly added string are present
            let found_replaced = strings.iter().any(|(_, s)| s == "ReplacedString");
            let found_added = strings.iter().any(|(_, s)| s == "AddedAfterReplacement");

            assert!(found_replaced, "Replaced string should be present");
            assert!(
                found_added,
                "String added after replacement should be present"
            );

            // Verify original strings are not present
            let found_original = strings.iter().any(|(_, s)| s == "Task`1");
            assert!(
                !found_original,
                "Original strings should not be present after heap replacement"
            );

            Ok(())
        },
    )
}
