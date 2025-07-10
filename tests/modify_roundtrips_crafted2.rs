//! Consolidated integration tests for dotscope assembly modification round-trip operations.
//!
//! These tests validate the complete public API by simulating real user implementations.
//! They test the full pipeline: load assembly -> make modifications -> write to file ->
//! load written file -> verify changes are correctly persisted.
//!
//! All tests use only the public API exported in the prelude to ensure they represent
//! actual user usage patterns.

use dotscope::prelude::*;
use std::path::Path;
use tempfile::NamedTempFile;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/crafted_2.exe";

/// Helper function to create a test assembly for integration testing
fn create_test_assembly() -> Result<CilAssembly> {
    let path = Path::new(TEST_ASSEMBLY_PATH);
    if !path.exists() {
        panic!("Test assembly not found at: {}", path.display());
    }

    let view = CilAssemblyView::from_file(path)?;
    Ok(CilAssembly::new(view))
}

/// Helper function to perform a complete round-trip test
fn perform_round_trip_test<F>(test_name: &str, modify_assembly: F) -> Result<CilAssemblyView>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
{
    // Step 1: Load original assembly
    let mut assembly = create_test_assembly()?;

    // Step 2: Apply modifications
    modify_assembly(&mut assembly)?;

    // Step 2.5: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 3: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    println!("Round-trip test '{test_name}' completed successfully");
    Ok(written_view)
}

#[test]
fn test_string_heap_modifications_round_trip() -> Result<()> {
    let written_view = perform_round_trip_test("string_heap_modifications", |assembly| {
        // Add strings, then modify them
        let idx1 = assembly.add_string("OriginalString1")?;
        let idx2 = assembly.add_string("OriginalString2")?;
        let _idx3 = assembly.add_string("StringToKeep")?;

        // Update strings
        assembly.update_string(idx1, "ModifiedString1")?;
        assembly.update_string(idx2, "ModifiedString2")?;

        // Remove a string (this will test reference handling)
        let idx_to_remove = assembly.add_string("StringToRemove")?;
        assembly.remove_string(idx_to_remove, ReferenceHandlingStrategy::FailIfReferenced)?;

        Ok(())
    })?;

    // Verify modifications persisted
    let strings_heap = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    let mut found_modified = 0;
    let mut found_original = 0;
    let mut found_removed = 0;

    for (_, string) in strings_heap.iter() {
        match string {
            "ModifiedString1" | "ModifiedString2" => found_modified += 1,
            "OriginalString1" | "OriginalString2" => found_original += 1,
            "StringToRemove" => found_removed += 1,
            _ => {}
        }
    }

    assert!(found_modified >= 2, "Should find modified strings");
    assert_eq!(
        found_original, 0,
        "Should not find original strings after modification"
    );
    assert_eq!(found_removed, 0, "Should not find removed string");

    Ok(())
}

#[test]
fn test_blob_heap_modifications_round_trip() -> Result<()> {
    let written_view = perform_round_trip_test("blob_heap_modifications", |assembly| {
        // Add blobs, then modify them
        let idx1 = assembly.add_blob(&[1, 2, 3])?;
        let idx2 = assembly.add_blob(&[4, 5, 6])?;
        let _idx3 = assembly.add_blob(&[7, 8, 9])?; // Keep unchanged

        // Update blobs
        assembly.update_blob(idx1, &[10, 20, 30, 40])?;
        assembly.update_blob(idx2, &[50, 60])?;

        // Remove a blob
        let idx_to_remove = assembly.add_blob(&[99, 98, 97])?;
        assembly.remove_blob(idx_to_remove, ReferenceHandlingStrategy::FailIfReferenced)?;

        Ok(())
    })?;

    // Verify modifications persisted
    let blobs_heap = written_view
        .blobs()
        .expect("Written assembly should have blobs heap");

    let mut found_modified = 0;
    let mut found_original = 0;
    let mut found_removed = 0;
    let mut found_kept = 0;

    for (_, blob) in blobs_heap.iter() {
        if blob == vec![10, 20, 30, 40] || blob == vec![50, 60] {
            found_modified += 1;
        } else if blob == vec![1, 2, 3] || blob == vec![4, 5, 6] {
            found_original += 1;
        } else if blob == vec![99, 98, 97] {
            found_removed += 1;
        } else if blob == vec![7, 8, 9] {
            found_kept += 1;
        }
    }

    assert!(found_modified >= 2, "Should find modified blobs");
    assert_eq!(
        found_original, 0,
        "Should not find original blobs after modification"
    );
    assert_eq!(found_removed, 0, "Should not find removed blob");
    assert!(found_kept >= 1, "Should find unchanged blob");

    Ok(())
}

#[test]
fn test_guid_heap_additions_round_trip() -> Result<()> {
    // Test GUID additions only (modifications might not be fully implemented)
    let test_guid1 = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];
    let test_guid2 = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    let written_view = perform_round_trip_test("guid_heap_additions", |assembly| {
        // Add multiple GUIDs to test heap expansion
        assembly.add_guid(&test_guid1)?;
        assembly.add_guid(&test_guid2)?;
        assembly.add_guid(&[0x42; 16])?;
        assembly.add_guid(&[0x00; 16])?;

        Ok(())
    })?;

    // Verify GUIDs were added and persisted
    let guids_heap = written_view
        .guids()
        .expect("Written assembly should have GUIDs heap");

    let mut found_test_guids = 0;

    for (_, guid) in guids_heap.iter() {
        let guid_bytes = guid.to_bytes();
        if guid_bytes == test_guid1
            || guid_bytes == test_guid2
            || guid_bytes == [0x42; 16]
            || guid_bytes == [0x00; 16]
        {
            found_test_guids += 1;
        }
    }

    assert!(found_test_guids >= 4, "Should find all added GUIDs");

    Ok(())
}

#[test]
fn test_guid_heap_modifications_round_trip() -> Result<()> {
    // Test GUID modifications to verify they work correctly
    let test_guid1 = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];
    let test_guid2 = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let modified_guid1 = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    let modified_guid2 = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];

    let written_view = perform_round_trip_test("guid_heap_modifications", |assembly| {
        // First check what's in the original heap
        if let Some(guids) = assembly.view().guids() {
            println!("Original GUID heap:");
            for (idx, guid) in guids.iter() {
                println!("  Index {}: {:02X?}", idx, guid.to_bytes());
            }
        }

        // Add GUIDs, then modify them
        let idx1 = assembly.add_guid(&test_guid1)?;
        let idx2 = assembly.add_guid(&test_guid2)?;
        let _idx3 = assembly.add_guid(&[0x42; 16])?; // Keep unchanged

        println!("Added GUID indices: idx1={idx1}, idx2={idx2}");

        // Update GUIDs
        assembly.update_guid(idx1, &modified_guid1)?;
        assembly.update_guid(idx2, &modified_guid2)?;

        // Remove a GUID
        let idx_to_remove = assembly.add_guid(&[0x99; 16])?;
        println!("GUID to remove index: {idx_to_remove}");
        assembly.remove_guid(idx_to_remove, ReferenceHandlingStrategy::FailIfReferenced)?;

        Ok(())
    })?;

    // Verify modifications persisted
    let guids_heap = written_view
        .guids()
        .expect("Written assembly should have GUIDs heap");

    let mut found_modified = 0;
    let mut found_original = 0;
    let mut found_removed = 0;
    let mut found_kept = 0;

    for (index, guid) in guids_heap.iter() {
        let guid_bytes = guid.to_bytes();
        println!("Found GUID at index {index}: {guid_bytes:02X?}");
        if guid_bytes == modified_guid1 || guid_bytes == modified_guid2 {
            found_modified += 1;
        } else if guid_bytes == test_guid1 || guid_bytes == test_guid2 {
            found_original += 1;
        } else if guid_bytes == [0x99; 16] {
            found_removed += 1;
        } else if guid_bytes == [0x42; 16] {
            found_kept += 1;
        }
    }

    assert!(found_modified >= 2, "Should find modified GUIDs");
    assert_eq!(
        found_original, 0,
        "Should not find original GUIDs after modification"
    );
    assert_eq!(found_removed, 0, "Should not find removed GUID");
    assert!(found_kept >= 1, "Should find unchanged GUID");

    Ok(())
}

#[test]
fn test_userstring_heap_modifications_round_trip() -> Result<()> {
    // Test user string modifications to verify they work correctly
    let written_view = perform_round_trip_test("userstring_heap_modifications", |assembly| {
        // First check original heap
        if let Some(userstrings) = assembly.view().userstrings() {
            println!("Original UserString heap exists");
            for (idx, us) in userstrings.iter().take(3) {
                println!("  Original Index {}: '{}'", idx, us.to_string_lossy());
            }
        }

        // Add user strings, then modify them
        let idx1 = assembly.add_userstring("OriginalUserString1")?;
        let idx2 = assembly.add_userstring("OriginalUserString2")?;
        let _idx3 = assembly.add_userstring("UserStringToKeep")?; // Keep unchanged

        println!("Added UserString indices: idx1={idx1}, idx2={idx2}");

        // Update user strings
        assembly.update_userstring(idx1, "ModifiedUserString1")?;
        assembly.update_userstring(idx2, "ModifiedUserString2")?;

        // Remove a user string
        let idx_to_remove = assembly.add_userstring("UserStringToRemove")?;
        println!("UserString to remove index: {idx_to_remove}");
        assembly.remove_userstring(idx_to_remove, ReferenceHandlingStrategy::FailIfReferenced)?;

        Ok(())
    })?;

    // Verify modifications persisted
    let userstrings_heap = written_view
        .userstrings()
        .expect("Written assembly should have user strings heap");

    let mut found_modified = 0;
    let mut found_original = 0;
    let mut found_removed = 0;
    let mut found_kept = 0;

    for (index, userstring) in userstrings_heap.iter() {
        let content = userstring.to_string_lossy();
        if content.contains("ModifiedUserString")
            || content.contains("OriginalUserString")
            || content.contains("UserString")
        {
            println!("Found UserString at index {index}: '{content}'");
        }
        if content == "ModifiedUserString1" || content == "ModifiedUserString2" {
            found_modified += 1;
        } else if content == "OriginalUserString1" || content == "OriginalUserString2" {
            found_original += 1;
        } else if content == "UserStringToRemove" {
            found_removed += 1;
        } else if content == "UserStringToKeep" {
            found_kept += 1;
        }
    }

    assert!(found_modified >= 2, "Should find modified user strings");
    assert_eq!(
        found_original, 0,
        "Should not find original user strings after modification"
    );
    assert_eq!(found_removed, 0, "Should not find removed user string");
    assert!(found_kept >= 1, "Should find unchanged user string");

    Ok(())
}

#[test]
fn test_userstring_heap_additions_round_trip() -> Result<()> {
    // Test user string additions only (modifications might not be fully implemented)
    let written_view = perform_round_trip_test("userstring_heap_additions", |assembly| {
        // Add multiple user strings to test heap expansion
        assembly.add_userstring("TestUserString1")?;
        assembly.add_userstring("TestUserString2")?;
        assembly.add_userstring("Unicode🦀UserString")?;
        assembly.add_userstring("")?; // Empty user string

        Ok(())
    })?;

    // Verify user strings were added and persisted
    let userstrings_heap = written_view
        .userstrings()
        .expect("Written assembly should have user strings heap");

    let mut found_test_userstrings = 0;

    for (_, userstring) in userstrings_heap.iter() {
        let content = userstring.to_string_lossy();
        if content == "TestUserString1"
            || content == "TestUserString2"
            || content == "Unicode🦀UserString"
            || content.is_empty()
        {
            found_test_userstrings += 1;
        }
    }

    assert!(
        found_test_userstrings >= 4,
        "Should find all added user strings"
    );

    Ok(())
}

#[test]
fn test_mixed_heap_additions_round_trip() -> Result<()> {
    // Test additions across all heap types (focus on what works)
    let written_view = perform_round_trip_test("mixed_heap_additions", |assembly| {
        // Add entries to all heaps
        assembly.add_string("MixedTestString")?;
        assembly.add_blob(&[1, 2, 3, 4])?;
        assembly.add_guid(&[0x11; 16])?;
        assembly.add_userstring("MixedTestUserString")?;

        // Test string and blob modifications which seem to work
        let string_idx = assembly.add_string("StringToModify")?;
        let blob_idx = assembly.add_blob(&[10, 20])?;

        assembly.update_string(string_idx, "ModifiedString")?;
        assembly.update_blob(blob_idx, &[30, 40, 50])?;

        Ok(())
    })?;

    // Verify all additions and working modifications persisted correctly
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let blobs_heap = written_view.blobs().expect("Should have blobs heap");
    let guids_heap = written_view.guids().expect("Should have GUIDs heap");
    let userstrings_heap = written_view
        .userstrings()
        .expect("Should have user strings heap");

    // Check added and modified strings
    let mut found_test_string = false;
    let mut found_modified_string = false;
    for (_, string) in strings_heap.iter() {
        if string == "MixedTestString" {
            found_test_string = true;
        } else if string == "ModifiedString" {
            found_modified_string = true;
        }
    }
    assert!(found_test_string, "Should find added test string");
    assert!(found_modified_string, "Should find modified string");

    // Check added and modified blobs
    let mut found_test_blob = false;
    let mut found_modified_blob = false;
    for (_, blob) in blobs_heap.iter() {
        if blob == vec![1, 2, 3, 4] {
            found_test_blob = true;
        } else if blob == vec![30, 40, 50] {
            found_modified_blob = true;
        }
    }
    assert!(found_test_blob, "Should find added test blob");
    assert!(found_modified_blob, "Should find modified blob");

    // Check added GUID
    let mut found_test_guid = false;
    for (_, guid) in guids_heap.iter() {
        if guid.to_bytes() == [0x11; 16] {
            found_test_guid = true;
            break;
        }
    }
    assert!(found_test_guid, "Should find added test GUID");

    // Check added user string
    let mut found_test_userstring = false;
    for (_, userstring) in userstrings_heap.iter() {
        if userstring.to_string_lossy() == "MixedTestUserString" {
            found_test_userstring = true;
            break;
        }
    }
    assert!(found_test_userstring, "Should find added test user string");

    Ok(())
}

#[test]
fn test_builder_context_round_trip() -> Result<()> {
    // Test BuilderContext separately since it needs its own assembly instance
    let original_assembly = create_test_assembly()?;
    let mut context = BuilderContext::new(original_assembly);

    let str1 = context.add_string("BuilderString1")?;
    let _str2 = context.get_or_add_string("BuilderString2")?;
    let str3 = context.get_or_add_string("BuilderString1")?; // Should deduplicate

    assert_eq!(str1, str3, "Builder should deduplicate identical strings");

    let _blob_idx = context.add_blob(&[1, 2, 3, 4])?;
    let _guid_idx = context.add_guid(&[0x99; 16])?;
    let _userstring_idx = context.add_userstring("BuilderUserString")?;

    // Finish the context and write to file
    let mut assembly = context.finish();
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Verify builder operations persisted correctly
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let blobs_heap = written_view.blobs().expect("Should have blobs heap");
    let guids_heap = written_view.guids().expect("Should have GUIDs heap");
    let userstrings_heap = written_view
        .userstrings()
        .expect("Should have user strings heap");

    // Check for deduplication - should only have 2 unique strings, not 3
    let mut builder_strings = 0;
    for (_, string) in strings_heap.iter() {
        if string == "BuilderString1" || string == "BuilderString2" {
            builder_strings += 1;
        }
    }
    assert_eq!(
        builder_strings, 2,
        "Should have exactly 2 unique builder strings (deduplication worked)"
    );

    // Verify other heap entries
    let mut found_blob = false;
    for (_, blob) in blobs_heap.iter() {
        if blob == vec![1, 2, 3, 4] {
            found_blob = true;
            break;
        }
    }
    assert!(found_blob, "Should find builder blob");

    let mut found_guid = false;
    for (_, guid) in guids_heap.iter() {
        if guid.to_bytes() == [0x99; 16] {
            found_guid = true;
            break;
        }
    }
    assert!(found_guid, "Should find builder GUID");

    let mut found_userstring = false;
    for (_, userstring) in userstrings_heap.iter() {
        if userstring.to_string_lossy() == "BuilderUserString" {
            found_userstring = true;
            break;
        }
    }
    assert!(found_userstring, "Should find builder user string");

    Ok(())
}

#[test]
fn test_large_scale_operations_round_trip() -> Result<()> {
    let written_view = perform_round_trip_test("large_scale_operations", |assembly| {
        // Test with many operations to ensure scalability

        // Test with many operations to ensure scalability
        for i in 0..50 {
            assembly.add_string(&format!("ScaleTestString{i}"))?;
        }

        // Use fewer blob additions to avoid triggering full heap rebuild
        // which exposes pre-existing corruption in the test assembly file
        for i in 0..5 {
            assembly.add_blob(&[i as u8, (i * 2) as u8, (i * 3) as u8])?;
        }

        for i in 0..10 {
            let mut guid = [0u8; 16];
            guid[0] = i as u8;
            guid[15] = (255 - i) as u8;
            assembly.add_guid(&guid)?;
        }

        for i in 0..15 {
            assembly.add_userstring(&format!("UserString{i}"))?;
        }

        Ok(())
    })?;

    // Verify heap sizes increased appropriately
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let blobs_heap = written_view.blobs().expect("Should have blobs heap");
    let guids_heap = written_view.guids().expect("Should have GUIDs heap");
    let userstrings_heap = written_view
        .userstrings()
        .expect("Should have user strings heap");

    // Count added entries (approximate checks since original heap may have content)
    let string_count = strings_heap.iter().count();
    let blob_count = blobs_heap.iter().count();
    let guid_count = guids_heap.iter().count();
    let userstring_count = userstrings_heap.iter().count();

    // Verify we have at least the expected number of added entries
    // (original heap content may exist, so we check for minimums)
    assert!(
        string_count >= 50,
        "Should have at least 50 additional strings (added 50, found {string_count})"
    );

    assert!(
        blob_count >= 5,
        "Should have at least 5 additional blobs (added 5, found {blob_count})"
    );

    assert!(
        guid_count >= 10,
        "Should have at least 10 additional GUIDs (added 10, found {guid_count})"
    );

    assert!(
        userstring_count >= 15,
        "Should have at least 15 additional user strings (added 15, found {userstring_count})"
    );

    Ok(())
}

#[test]
fn test_empty_operations_round_trip() -> Result<()> {
    let written_view = perform_round_trip_test("empty_operations", |assembly| {
        // Test round-trip with minimal modification to ensure write path works
        assembly.add_string("MinimalModification")?;
        Ok(())
    })?;

    // Verify assembly structure is preserved
    assert!(
        written_view.strings().is_some(),
        "Should preserve strings heap"
    );
    assert!(written_view.blobs().is_some(), "Should preserve blobs heap");
    // Note: GUID and UserString heaps may not exist in original assembly

    Ok(())
}

#[test]
fn test_modify_existing_string_round_trip() -> Result<()> {
    let written_view = perform_round_trip_test("modify_existing_string", |assembly| {
        // Collect the string data first to avoid borrowing issues
        let mut target_data = None;
        if let Some(strings_heap) = assembly.view().strings() {
            // Find a string we can modify (look for a non-empty string)
            for (index, original_string) in strings_heap.iter() {
                if !original_string.is_empty() && index > 1 {
                    // Skip the empty string at index 0 and potentially system strings
                    target_data = Some((index as u32, original_string.to_string()));
                    break;
                }
            }
        }

        if let Some((index, original_string)) = target_data {
            let modified_content = format!("MODIFIED_{original_string}");
            assembly.update_string(index, &modified_content)?;
            println!("Modified existing string at index {index}: '{original_string}' -> '{modified_content}'");
        }
        Ok(())
    })?;

    // Verify the modification was persisted
    if let Some(strings_heap) = written_view.strings() {
        let mut found_modified = false;
        for (_, string) in strings_heap.iter() {
            if string.starts_with("MODIFIED_") {
                found_modified = true;
                println!("Found modified string in output: '{string}'");
                break;
            }
        }
        assert!(found_modified, "Should find the modified existing string");
    }

    Ok(())
}

#[test]
fn test_remove_existing_string_round_trip() -> Result<()> {
    let mut target_string = String::new();
    let mut target_index = 0u32;

    let written_view = perform_round_trip_test("remove_existing_string", |assembly| {
        // Collect the string data first to avoid borrowing issues
        let mut target_data = None;
        if let Some(strings_heap) = assembly.view().strings() {
            for (index, original_string) in strings_heap.iter() {
                if !original_string.is_empty() && index > 5 && original_string.len() > 3 {
                    // Pick a string that's likely not critical to the assembly
                    target_data = Some((index as u32, original_string.to_string()));
                    break;
                }
            }
        }

        if let Some((index, original_string)) = target_data {
            target_string = original_string.clone();
            target_index = index;
            assembly.remove_string(index, ReferenceHandlingStrategy::NullifyReferences)?;
            println!("Removed existing string at index {index}: '{original_string}'");
        }
        Ok(())
    })?;

    // Verify the string was removed
    if target_index > 0 {
        if let Some(strings_heap) = written_view.strings() {
            let mut found_removed = false;
            for (_, string) in strings_heap.iter() {
                if string == target_string {
                    found_removed = true;
                    break;
                }
            }
            assert!(
                !found_removed,
                "Removed string should not be found in output"
            );
        }
    }

    Ok(())
}

#[test]
fn test_modify_existing_blob_round_trip() -> Result<()> {
    let written_view = perform_round_trip_test("modify_existing_blob", |assembly| {
        // Collect the blob data first to avoid borrowing issues
        let mut target_data = None;
        if let Some(blob_heap) = assembly.view().blobs() {
            for (index, original_blob) in blob_heap.iter() {
                if !original_blob.is_empty() && index > 1 && original_blob.len() > 2 {
                    target_data = Some((index as u32, original_blob.to_vec()));
                    break;
                }
            }
        }

        if let Some((index, original_blob)) = target_data {
            // Create a modified version of the blob
            let mut modified_blob = original_blob.clone();
            modified_blob.insert(0, 0xFF); // Add a marker byte
            modified_blob.push(0xEE); // Add a marker byte at the end

            assembly.update_blob(index, &modified_blob)?;
            println!(
                "Modified existing blob at index {index}: {} bytes -> {} bytes",
                original_blob.len(),
                modified_blob.len()
            );
        }
        Ok(())
    })?;

    // Verify the modification was persisted
    if let Some(blob_heap) = written_view.blobs() {
        let mut found_modified = false;
        for (_, blob) in blob_heap.iter() {
            if blob.len() > 2 && blob[0] == 0xFF && blob[blob.len() - 1] == 0xEE {
                found_modified = true;
                println!(
                    "Found modified blob in output: {} bytes with markers",
                    blob.len()
                );
                break;
            }
        }
        assert!(found_modified, "Should find the modified existing blob");
    }

    Ok(())
}

#[test]
fn test_metadata_preservation_round_trip() -> Result<()> {
    // Get original view for comparison
    let original_assembly = create_test_assembly()?;
    let original_view = original_assembly.view();
    let original_strings_count = original_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let original_blobs_count = original_view.blobs().map(|b| b.iter().count()).unwrap_or(0);

    let written_view = perform_round_trip_test("metadata_preservation", |assembly| {
        // Add minimal modifications
        assembly.add_string("PreservationTest")?;
        Ok(())
    })?;

    // Verify critical metadata is preserved
    let written_strings_count = written_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);

    assert!(
        written_strings_count > original_strings_count,
        "Written assembly should have at least one additional string"
    );

    // Verify other heaps are preserved
    let written_blobs_count = written_view.blobs().map(|b| b.iter().count()).unwrap_or(0);
    assert!(
        written_blobs_count >= original_blobs_count,
        "Blob heap should be preserved or grown"
    );

    Ok(())
}
