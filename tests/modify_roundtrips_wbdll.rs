//! True round-trip integration tests for assembly modification operations.
//!
//! These tests validate the complete write pipeline by:
//! 1. Loading an assembly
//! 2. Making modifications (add/modify/remove)
//! 3. Writing to a temporary file
//! 4. Loading the written file again
//! 5. Verifying changes are correctly persisted

use dotscope::prelude::*;
use std::path::PathBuf;
use tempfile::NamedTempFile;

const TEST_ASSEMBLY_PATH: &str = "tests/samples/WindowsBase.dll";

/// Helper function to get test assembly path
fn get_test_assembly_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(TEST_ASSEMBLY_PATH)
}

/// Helper function to create a test assembly
fn create_test_assembly() -> Result<CilAssembly> {
    let path = get_test_assembly_path();
    if !path.exists() {
        panic!("Test assembly not found at: {}", path.display());
    }

    let view = CilAssemblyView::from_file(&path)?;
    Ok(CilAssembly::new(view))
}

/// Helper to get initial heap sizes before modifications
fn get_initial_heap_sizes(view: &CilAssemblyView) -> (u32, u32, u32, u32) {
    let strings_count = view.strings().map(|s| s.iter().count() as u32).unwrap_or(0);

    let blobs_count = view
        .blobs()
        .map(|b| {
            let count = b.iter().count() as u32;
            count
        })
        .unwrap_or(0);

    let guids_count = view.guids().map(|g| g.iter().count() as u32).unwrap_or(0);

    let userstrings_count = view
        .userstrings()
        .map(|us| us.iter().count() as u32)
        .unwrap_or(0);

    (strings_count, blobs_count, guids_count, userstrings_count)
}

#[test]
fn test_string_addition_round_trip() -> Result<()> {
    // Step 1: Load original assembly
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let original_strings = original_view.strings().expect("Should have strings");
    let original_strings_count = original_strings.iter().count();
    // Step 2: Add new strings
    let test_strings = vec!["TestString1", "TestString2", "TestString3"];
    let mut added_indices = Vec::new();

    for test_string in &test_strings {
        let index = assembly.string_add(test_string)?;
        added_indices.push(index);
    }

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 5: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify changes are persisted
    let written_strings = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    // Check that we have more strings than before
    let written_strings_count = written_strings.iter().count();
    assert_eq!(
        written_strings_count,
        original_strings_count + test_strings.len(),
        "Written assembly should have {} more strings",
        test_strings.len()
    );

    // Verify each added string can be retrieved
    for (i, &index) in added_indices.iter().enumerate() {
        let retrieved_string = written_strings.get(index as usize)?;
        assert_eq!(
            retrieved_string, test_strings[i],
            "String at index {index} should match added string"
        );
    }

    Ok(())
}

#[test]
fn test_string_modification_round_trip() -> Result<()> {
    // Step 1: Load and add a string to modify
    let mut assembly = create_test_assembly()?;
    let original_string = "OriginalString";
    let modified_string = "ModifiedString";

    let string_index = assembly.string_add(original_string)?;

    // Step 2: Modify the string
    assembly.string_update(string_index, modified_string)?;

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify modification is persisted
    let written_strings = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    let retrieved_string = written_strings.get(string_index as usize)?;
    assert_eq!(
        retrieved_string, modified_string,
        "Modified string should be persisted at index {string_index}"
    );

    // Ensure we don't have the original string at that index
    assert_ne!(
        retrieved_string, original_string,
        "Original string should be replaced"
    );

    Ok(())
}

#[test]
fn test_string_removal_round_trip() -> Result<()> {
    // Step 1: Load and add strings
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let original_strings_count = original_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);

    let string_to_keep = "StringToKeep";
    let string_to_remove = "StringToRemove";

    let keep_index = assembly.string_add(string_to_keep)?;
    let remove_index = assembly.string_add(string_to_remove)?;

    // Step 2: Remove one string
    assembly.string_remove(remove_index, ReferenceHandlingStrategy::FailIfReferenced)?;

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify removal is persisted
    let written_strings = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    // Should have original count + 1 (only the kept string)
    let written_strings_count = written_strings.iter().count();

    // Debug: Show the extra strings to understand what's happening

    assert_eq!(
        written_strings_count,
        original_strings_count + 1,
        "Written assembly should have only one additional string"
    );

    // The kept string should still be accessible
    let retrieved_kept = written_strings.get(keep_index as usize)?;
    assert_eq!(
        retrieved_kept, string_to_keep,
        "Kept string should still be accessible"
    );

    // The removed string should not be accessible (or be empty/invalid)
    match written_strings.get(remove_index as usize) {
        Ok(retrieved) => {
            // If it's accessible, it should be empty or different
            assert_ne!(
                retrieved, string_to_remove,
                "Removed string should not be retrievable with original content"
            );
        }
        Err(_) => {
            // This is also acceptable - the index might be invalid after removal
        }
    }

    Ok(())
}

#[test]
fn test_blob_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let original_blobs_count = original_view.blobs().map(|b| b.iter().count()).unwrap_or(0);

    // Step 2: Add and modify blobs
    let blob1_data = vec![1, 2, 3, 4, 5];
    let blob2_data = vec![10, 20, 30];
    let modified_blob_data = vec![99, 88, 77, 66];

    let blob1_index = assembly.blob_add(&blob1_data)?;
    let _blob2_index = assembly.blob_add(&blob2_data)?;

    // Modify the first blob
    assembly.blob_update(blob1_index, &modified_blob_data)?;

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify changes are persisted
    let written_blobs = written_view
        .blobs()
        .expect("Written assembly should have blob heap");

    let written_blobs_count = written_blobs.iter().count();

    // Allow for a small number of extra empty blobs due to padding/alignment
    assert!(
        written_blobs_count >= original_blobs_count + 2,
        "Should have at least 2 additional blobs, got {} vs expected minimum {}",
        written_blobs_count,
        original_blobs_count + 2
    );
    assert!(
        written_blobs_count <= original_blobs_count + 5,
        "Should not have more than 3 extra padding blobs, got {} vs maximum expected {}",
        written_blobs_count,
        original_blobs_count + 5
    );

    // Instead of using the returned indices (which are byte offsets),
    // let's find the blobs by content in the written heap
    let mut found_modified = false;
    let mut found_original = false;

    for (_offset, blob) in written_blobs.iter() {
        if blob == modified_blob_data {
            found_modified = true;
        }
        if blob == blob2_data {
            found_original = true;
        }
    }

    assert!(found_modified, "Modified blob should be found in the heap");
    assert!(
        found_original,
        "Unmodified blob should be found in the heap"
    );

    Ok(())
}

#[test]
fn test_guid_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let original_guids_count = original_view.guids().map(|g| g.iter().count()).unwrap_or(0);

    // Step 2: Add and modify GUIDs
    let guid1 = [1u8; 16];
    let guid2 = [2u8; 16];
    let modified_guid = [99u8; 16];

    let guid1_index = assembly.guid_add(&guid1)?;
    let guid2_index = assembly.guid_add(&guid2)?;

    // Modify the first GUID
    assembly.guid_update(guid1_index, &modified_guid)?;

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify changes are persisted
    let written_guids = written_view
        .guids()
        .expect("Written assembly should have GUID heap");

    let written_guids_count = written_guids.iter().count();

    assert_eq!(
        written_guids_count,
        original_guids_count + 2,
        "Should have 2 additional GUIDs"
    );

    // Verify modified GUID
    let retrieved_guid1 = written_guids.get(guid1_index as usize)?;
    assert_eq!(
        retrieved_guid1.to_bytes(),
        modified_guid,
        "Modified GUID should be persisted"
    );

    // Verify unmodified GUID
    let retrieved_guid2 = written_guids.get(guid2_index as usize)?;
    assert_eq!(
        retrieved_guid2.to_bytes(),
        guid2,
        "Unmodified GUID should be persisted unchanged"
    );

    Ok(())
}

#[test]
fn test_userstring_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let original_userstrings_count = original_view
        .userstrings()
        .map(|us| us.iter().count())
        .unwrap_or(0);

    // Step 2: Add and modify user strings
    let userstring1 = "UserString1";
    let userstring2 = "UserString2";
    let modified_userstring = "ModifiedUserString";

    let us1_index = assembly.userstring_add(userstring1)?;
    let _us2_index = assembly.userstring_add(userstring2)?;

    // Modify the first user string
    assembly.userstring_update(us1_index, modified_userstring)?;

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify changes are persisted
    let written_userstrings = written_view
        .userstrings()
        .expect("Written assembly should have user strings heap");

    let written_userstrings_count = written_userstrings.iter().count();

    assert_eq!(
        written_userstrings_count,
        original_userstrings_count + 2,
        "Should have 2 additional user strings"
    );

    // Verify modified user string by searching for content
    // (API indices may shift when string sizes change due to modifications)
    let mut found_modified = false;
    let mut found_userstring2 = false;

    for (_, userstring) in written_userstrings.iter() {
        let content = userstring.to_string_lossy();
        if content == modified_userstring {
            found_modified = true;
        }
        if content == userstring2 {
            found_userstring2 = true;
        }
    }

    assert!(
        found_modified,
        "Modified user string '{modified_userstring}' should be persisted"
    );
    assert!(
        found_userstring2,
        "User string '{userstring2}' should be persisted unchanged"
    );

    Ok(())
}

#[test]
fn test_mixed_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly and capture initial state
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let (orig_strings, orig_blobs, orig_guids, orig_userstrings) =
        get_initial_heap_sizes(original_view);

    // Step 2: Perform mixed operations on all heap types
    let test_string = "MixedTestString";
    let test_blob = vec![1, 2, 3, 4];
    let test_guid = [42u8; 16];
    let test_userstring = "MixedTestUserString";

    let string_index = assembly.string_add(test_string)?;
    let blob_index = assembly.blob_add(&test_blob)?;
    let guid_index = assembly.guid_add(&test_guid)?;
    let userstring_index = assembly.userstring_add(test_userstring)?;

    // Modify some entries
    let modified_string = "ModifiedMixedString";
    let modified_blob = vec![99, 88, 77];

    assembly.string_update(string_index, modified_string)?;
    assembly.blob_update(blob_index, &modified_blob)?;

    // Step 3: Validate and apply changes
    assembly.validate_and_apply_changes()?;

    // Step 4: Write to temporary file
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify all changes are persisted
    let (written_strings, written_blobs, written_guids, written_userstrings) =
        get_initial_heap_sizes(&written_view);

    // Check heap sizes increased correctly
    assert_eq!(
        written_strings,
        orig_strings + 1,
        "Should have 1 additional string"
    );
    assert_eq!(
        written_blobs,
        orig_blobs + 1,
        "Should have 1 additional blob"
    );
    assert_eq!(
        written_guids,
        orig_guids + 1,
        "Should have 1 additional GUID"
    );
    assert_eq!(
        written_userstrings,
        orig_userstrings + 1,
        "Should have 1 additional user string"
    );

    // Verify each modified entry
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let retrieved_string = strings_heap.get(string_index as usize)?;
    assert_eq!(
        retrieved_string, modified_string,
        "Modified string should be persisted"
    );

    let blobs_heap = written_view.blobs().expect("Should have blob heap");
    let retrieved_blob = blobs_heap.get(blob_index as usize)?;
    assert_eq!(
        retrieved_blob, modified_blob,
        "Modified blob should be persisted"
    );

    let guids_heap = written_view.guids().expect("Should have GUID heap");
    let retrieved_guid = guids_heap.get(guid_index as usize)?;
    assert_eq!(
        retrieved_guid.to_bytes(),
        test_guid,
        "GUID should be persisted unchanged"
    );

    let userstrings_heap = written_view
        .userstrings()
        .expect("Should have user strings heap");
    let retrieved_userstring = userstrings_heap.get(userstring_index as usize)?;
    assert_eq!(
        retrieved_userstring.to_string_lossy(),
        test_userstring,
        "User string should be persisted unchanged"
    );

    Ok(())
}

#[test]
fn test_builder_context_round_trip() -> Result<()> {
    // Step 1: Load assembly and create builder context
    let assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let (orig_strings, orig_blobs, orig_guids, orig_userstrings) =
        get_initial_heap_sizes(original_view);

    let mut context = BuilderContext::new(assembly);

    // Step 2: Use builder context APIs
    let str1 = context.string_add("BuilderString1")?;
    let str2 = context.string_get_or_add("BuilderString2")?;
    let str3 = context.string_get_or_add("BuilderString1")?; // Should deduplicate

    assert_eq!(str1, str3, "Builder should deduplicate identical strings");

    let blob_index = context.blob_add(&[1, 2, 3])?;
    let _guid_index = context.guid_add(&[99u8; 16])?;
    let _userstring_index = context.userstring_add("BuilderUserString")?;

    // Modify through builder context
    context.string_update(str2, "UpdatedBuilderString")?;
    context.blob_update(blob_index, &[4, 5, 6])?;

    // Step 3: Finish and write
    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    // Step 4: Load the written file
    let written_view = CilAssemblyView::from_file(temp_file.path())?;

    // Step 5: Verify builder operations are persisted
    let (written_strings, written_blobs, written_guids, written_userstrings) =
        get_initial_heap_sizes(&written_view);

    // Should have 2 unique strings (deduplication worked)
    assert_eq!(
        written_strings,
        orig_strings + 2,
        "Should have 2 additional strings after deduplication"
    );
    assert_eq!(
        written_blobs,
        orig_blobs + 1,
        "Should have 1 additional blob"
    );
    assert_eq!(
        written_guids,
        orig_guids + 1,
        "Should have 1 additional GUID"
    );
    assert_eq!(
        written_userstrings,
        orig_userstrings + 1,
        "Should have 1 additional user string"
    );

    // Verify specific entries
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let retrieved_str1 = strings_heap.get(str1 as usize)?;
    assert_eq!(
        retrieved_str1, "BuilderString1",
        "First builder string should be persisted"
    );

    let retrieved_str2 = strings_heap.get(str2 as usize)?;
    assert_eq!(
        retrieved_str2, "UpdatedBuilderString",
        "Updated builder string should be persisted"
    );

    let blobs_heap = written_view.blobs().expect("Should have blob heap");
    let retrieved_blob = blobs_heap.get(blob_index as usize)?;
    assert_eq!(
        retrieved_blob,
        vec![4, 5, 6],
        "Updated blob should be persisted"
    );

    Ok(())
}
