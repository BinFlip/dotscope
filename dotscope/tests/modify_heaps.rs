//! Heap modification integration tests.
//!
//! Tests for modifying metadata heaps (strings, blobs, GUIDs, userstrings) and verifying
//! that changes are correctly persisted through the write pipeline.

use dotscope::prelude::*;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/crafted_2.exe";

/// Helper function to perform a round-trip test with specific verification
fn perform_round_trip_test<F, V>(modify_fn: F, verify_fn: V) -> Result<()>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
    V: FnOnce(&CilAssemblyView) -> Result<()>,
{
    // Load original assembly
    let mut assembly = CilAssembly::from_path(TEST_ASSEMBLY_PATH)?;

    // Apply modifications
    modify_fn(&mut assembly)?;

    // Write to memory
    let bytes = assembly.to_memory()?;

    // Load written bytes and verify
    let written_view = CilAssemblyView::from_mem(bytes)?;
    verify_fn(&written_view)?;

    Ok(())
}

#[test]
fn test_string_heap_add_and_verify() -> Result<()> {
    let test_string = "TestAddedString";

    perform_round_trip_test(
        |assembly| {
            let _index = assembly.string_add(test_string)?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify the specific string was added
            assert!(
                strings.contains(test_string),
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
        |assembly| {
            let _index = assembly.blob_add(&test_blob)?;
            Ok(())
        },
        |written_view| {
            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Other("No blobs heap found".to_string()))?;

            // Verify the specific blob was added
            assert!(
                blobs.contains(&test_blob),
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
        |assembly| {
            let _index = assembly.guid_add(&test_guid)?;
            Ok(())
        },
        |written_view| {
            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Other("No GUIDs heap found".to_string()))?;

            // Verify the specific GUID was added
            assert!(
                guids.contains(&uguid::Guid::from_bytes(test_guid)),
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
        |assembly| {
            let _index = assembly.userstring_add(test_userstring)?;
            Ok(())
        },
        |written_view| {
            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Other("No userstrings heap found".to_string()))?;

            // Verify the specific userstring was added
            assert!(
                userstrings.contains(test_userstring),
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
        |assembly| {
            let _str_idx = assembly.string_add(test_string)?;
            let _blob_idx = assembly.blob_add(&test_blob)?;
            let _guid_idx = assembly.guid_add(&test_guid)?;
            let _us_idx = assembly.userstring_add(test_userstring)?;
            Ok(())
        },
        |written_view| {
            // Verify all additions are present
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;
            assert!(strings.contains(test_string), "String should be present");

            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Other("No blobs heap found".to_string()))?;
            assert!(blobs.contains(&test_blob), "Blob should be present");

            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Other("No GUIDs heap found".to_string()))?;
            assert!(
                guids.contains(&uguid::Guid::from_bytes(test_guid)),
                "GUID should be present"
            );

            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Other("No userstrings heap found".to_string()))?;
            assert!(
                userstrings.contains(test_userstring),
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
        |assembly| {
            // Get the original view to find the string index
            let strings = assembly
                .view()
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            let original_index = strings
                .find(original_string)
                .ok_or_else(|| Error::Other(format!("String '{original_string}' not found")))?;

            assembly.string_update(original_index, modified_string)?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify the modification was applied
            assert!(
                strings.contains(modified_string),
                "Modified string '{modified_string}' should be present"
            );

            // Verify original string is no longer present
            assert!(
                !strings.contains(original_string),
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
        |assembly| {
            let _index = assembly.string_add(test_string)?;
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
                strings.contains(test_string),
                "Added string should be present"
            );

            // Verify some existing data is preserved (Task`1 should exist)
            assert!(
                strings.contains("Task`1"),
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
        |assembly| {
            assembly.string_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify the custom strings are present
            assert!(
                strings.contains("CustomString1"),
                "Custom string 'CustomString1' should be present in replaced heap"
            );
            assert!(
                strings.contains("AnotherString"),
                "Custom string 'AnotherString' should be present in replaced heap"
            );

            // Verify that original strings are no longer present (heap was replaced)
            assert!(
                !strings.contains("Task`1"),
                "Original strings should not be present after heap replacement"
            );

            Ok(())
        },
    )
}

#[test]
fn test_blob_heap_replacement() -> Result<()> {
    // When replacing a blob heap, we must preserve the original blob data to maintain
    // existing references (method signatures, custom attributes, etc.) that point into
    // the blob heap. This test replaces the heap while preserving original content.

    // Load the assembly first to get the original blob heap
    let assembly = CilAssembly::from_path(TEST_ASSEMBLY_PATH)?;
    let original_blob_data = assembly
        .view()
        .blobs()
        .map(|blobs| blobs.data().to_vec())
        .unwrap_or_else(|| vec![0]); // Ensure at least null byte at index 0
    let original_blob_count = assembly
        .view()
        .blobs()
        .map(|b| b.iter().count())
        .unwrap_or(0);
    drop(assembly);

    // Create replacement heap: original data + our custom blobs appended
    // Custom blobs: length=3, data=[0x01, 0x02, 0x03] and length=2, data=[0xAA, 0xBB]
    let mut custom_heap = original_blob_data.clone();
    custom_heap.extend_from_slice(&[0x03, 0x01, 0x02, 0x03, 0x02, 0xAA, 0xBB]);

    perform_round_trip_test(
        |assembly| {
            assembly.blob_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Other("No blobs heap found".to_string()))?;

            // Verify our custom blobs are present
            assert!(
                blobs.contains(&[0x01, 0x02, 0x03]),
                "Custom blob [0x01, 0x02, 0x03] should be present in replaced heap"
            );
            assert!(
                blobs.contains(&[0xAA, 0xBB]),
                "Custom blob [0xAA, 0xBB] should be present in replaced heap"
            );

            // Verify we have at least the original blobs plus our 2 custom ones
            let blob_count = blobs.iter().count();
            assert!(
                blob_count >= original_blob_count + 2,
                "Replaced heap should contain at least original ({}) + 2 custom blobs (found {})",
                original_blob_count,
                blob_count
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
        |assembly| {
            assembly.guid_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Other("No GUIDs heap found".to_string()))?;

            // Verify the custom GUIDs are present
            assert!(
                guids.contains(&uguid::Guid::from_bytes(guid1)),
                "Custom GUID 1 should be present in replaced heap"
            );
            assert!(
                guids.contains(&uguid::Guid::from_bytes(guid2)),
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
        |assembly| {
            assembly.userstring_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Other("No userstrings heap found".to_string()))?;

            // Verify the custom user string is present
            assert!(
                userstrings.contains("Hi"),
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
        |assembly| {
            // Replace string heap
            assembly.string_add_heap(custom_string_heap.clone())?;

            // Add a new string after replacement
            let _new_index = assembly.string_add("AddedAfterReplacement")?;

            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify both the replaced string and the newly added string are present
            assert!(
                strings.contains("ReplacedString"),
                "Replaced string should be present"
            );
            assert!(
                strings.contains("AddedAfterReplacement"),
                "String added after replacement should be present"
            );

            // Verify original strings are not present
            assert!(
                !strings.contains("Task`1"),
                "Original strings should not be present after heap replacement"
            );

            Ok(())
        },
    )
}
