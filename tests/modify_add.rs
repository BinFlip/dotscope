//! Integration tests for the write module.
//!
//! These tests verify the complete end-to-end functionality of writing
//! modified assemblies to disk and ensuring they can be loaded back correctly.

use dotscope::prelude::*;
use std::path::Path;

#[test]
fn extend_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let view = CilAssemblyView::from_file(Path::new("tests/samples/crafted_2.exe"))?;

    let original_string_count = view.strings().map(|s| s.iter().count()).unwrap_or(0);
    let original_blob_count = view.blobs().map(|b| b.iter().count()).unwrap_or(0);
    let original_userstring_count = view.userstrings().map(|u| u.iter().count()).unwrap_or(0);
    let original_field_count = view
        .tables()
        .map(|t| t.table_row_count(TableId::Field))
        .unwrap_or(0);
    let original_method_count = view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);
    let original_param_count = view
        .tables()
        .map(|t| t.table_row_count(TableId::Param))
        .unwrap_or(0);

    let assembly = view.to_owned();
    let mut context = BuilderContext::new(assembly);

    // Step 2: Add new heap entries

    // Define strings and blobs that will be used by builders
    let test_string = "TestAddedString";
    let test_blob = vec![0x06, 0x08]; // FIELD signature for System.Int32
    let test_userstring = "TestAddedUserString";

    // Add user string directly (not used by builders)
    let userstring_index = context.userstring_add(test_userstring)?;
    assert!(userstring_index > 0, "UserString index should be positive");

    // Step 3: Add new table rows that reference the new heap entries

    // Add a new Field using the FieldBuilder
    let field_token = FieldBuilder::new()
        .name(test_string)
        .flags(0x0001) // Private field
        .signature(&test_blob)
        .build(&mut context)?;

    assert!(field_token.value() > 0, "Field token should be positive");
    assert!(
        field_token.value() > original_field_count,
        "Field token should be higher than original field count"
    );

    // Add a new MethodDef using the MethodDefBuilder
    let method_name_string = "TestAddedMethod";
    let method_signature_blob = vec![0x00, 0x00, 0x01]; // DEFAULT, 0 params, VOID

    let method_token = MethodDefBuilder::new()
        .name(method_name_string)
        .flags(0x0001) // Private method
        .impl_flags(0) // No special implementation flags
        .signature(&method_signature_blob)
        .rva(0) // No implementation
        .build(&mut context)?;

    assert!(method_token.value() > 0, "Method token should be positive");
    assert!(
        method_token.value() > original_method_count,
        "Method token should be higher than original method count"
    );

    // Add a new Param using the ParamBuilder
    let param_name_string = "TestAddedParam";

    let param_token = ParamBuilder::new()
        .name(param_name_string)
        .flags(0x0000) // No special flags
        .sequence(1) // First parameter
        .build(&mut context)?;

    assert!(param_token.value() > 0, "Param token should be positive");
    assert!(
        param_token.value() > original_param_count,
        "Param token should be higher than original param count"
    );

    // Step 4: Write to a temporary file
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path();

    // Get the assembly back from context and write to file
    let mut assembly = context.finish();

    // Use the new validation system
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(temp_path)?;

    // Verify the file was actually created
    assert!(temp_path.exists(), "Output file should exist after writing");

    // Verify the file is not empty
    let file_size = std::fs::metadata(temp_path)?.len();
    assert!(file_size > 0, "Output file should not be empty");

    // Step 5: Load the new file and verify our additions
    let modified_view =
        CilAssemblyView::from_file(temp_path).expect("Modified assembly should load successfully");

    // Verify heap additions
    // Check strings
    let strings = modified_view
        .strings()
        .expect("Modified assembly should have strings heap");

    let new_string_count = strings.iter().count();
    assert!(
        new_string_count > original_string_count,
        "String heap should have grown from {} to at least {}",
        original_string_count,
        original_string_count + 1
    );
    assert!(
        new_string_count >= original_string_count + 3,
        "String heap should have at least 3 more entries, got {} (expected at least {})",
        new_string_count,
        original_string_count + 3
    );

    // Verify our added strings exist by searching for them in the heap
    let mut found_test_string = false;
    let mut found_method_name = false;
    let mut found_param_name = false;

    for (_offset, string) in strings.iter() {
        if string == test_string {
            found_test_string = true;
        }
        if string == method_name_string {
            found_method_name = true;
        }
        if string == param_name_string {
            found_param_name = true;
        }
    }

    assert!(
        found_test_string,
        "Should find test string '{test_string}' in heap"
    );
    assert!(
        found_method_name,
        "Should find method name '{method_name_string}' in heap"
    );
    assert!(
        found_param_name,
        "Should find param name '{param_name_string}' in heap"
    );

    // Check blobs
    let blobs = modified_view
        .blobs()
        .expect("Modified assembly should have blob heap");

    let new_blob_count = blobs.iter().count();
    assert!(
        new_blob_count > original_blob_count,
        "Blob heap should have grown from {} to at least {}",
        original_blob_count,
        original_blob_count + 1
    );
    assert!(
        new_blob_count >= original_blob_count + 2,
        "Blob heap should have at least 2 more entries, got {} (expected at least {})",
        new_blob_count,
        original_blob_count + 2
    );

    // Verify our added blobs exist by searching for them in the heap
    let mut found_test_blob = false;
    let mut found_method_signature = false;

    for (_offset, blob) in blobs.iter() {
        if blob == test_blob {
            found_test_blob = true;
        }
        if blob == method_signature_blob {
            found_method_signature = true;
        }
    }

    assert!(found_test_blob, "Should find test blob in heap");
    assert!(
        found_method_signature,
        "Should find method signature blob in heap"
    );

    // Check user strings
    let userstrings = modified_view
        .userstrings()
        .expect("Modified assembly should have userstring heap");

    let new_userstring_count = userstrings.iter().count();

    assert!(
        new_userstring_count > original_userstring_count,
        "UserString heap should have grown from {} to at least {} but got {}",
        original_userstring_count,
        original_userstring_count + 1,
        new_userstring_count
    );
    assert_eq!(
        new_userstring_count,
        original_userstring_count + 1,
        "UserString heap should have exactly 1 more entry"
    );

    // Retrieve and verify the added userstring by finding it in the heap
    // Since the userstring_index might not match the actual offset due to alignment adjustments,
    // we'll find the userstring by content instead
    let mut found_our_userstring = false;
    for (_offset, userstring) in userstrings.iter() {
        let content = userstring.to_string_lossy();
        if content == test_userstring {
            found_our_userstring = true;
            break;
        }
    }
    assert!(
        found_our_userstring,
        "Should find our added userstring '{test_userstring}' in the heap"
    );

    // Verify table additions
    let tables = modified_view
        .tables()
        .expect("Modified assembly should have metadata tables");

    // Check Field table
    let new_field_count = tables.table_row_count(TableId::Field);
    assert!(
        new_field_count > original_field_count,
        "Field table should have grown from {} to at least {}",
        original_field_count,
        original_field_count + 1
    );
    assert_eq!(
        new_field_count,
        original_field_count + 1,
        "Field table should have exactly 1 more row"
    );

    // Check MethodDef table
    let new_method_count = tables.table_row_count(TableId::MethodDef);
    assert!(
        new_method_count > original_method_count,
        "MethodDef table should have grown from {} to at least {}",
        original_method_count,
        original_method_count + 1
    );
    assert_eq!(
        new_method_count,
        original_method_count + 1,
        "MethodDef table should have exactly 1 more row"
    );

    // Check Param table
    let new_param_count = tables.table_row_count(TableId::Param);
    assert!(
        new_param_count > original_param_count,
        "Param table should have grown from {} to at least {}",
        original_param_count,
        original_param_count + 1
    );
    assert_eq!(
        new_param_count,
        original_param_count + 1,
        "Param table should have exactly 1 more row"
    );
    Ok(())
}
