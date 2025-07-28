//! Factory methods for raw structure heap validation testing.
//!
//! Contains helper methods migrated from raw structure heap validation source files
//! for creating test assemblies with various heap validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{cilassemblyview::CilAssemblyView, validation::ValidationConfig},
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for RawHeapValidator following the golden pattern.
///
/// Creates test assemblies covering basic heap validation scenarios.
/// Tests UTF-8, UTF-16, GUID alignment, and other heap integrity validations.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn raw_heap_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. UserString heap with invalid UTF-16
    match create_assembly_with_invalid_utf16_userstring() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid UTF-16 userstring: {e}"
            )));
        }
    }

    // 3. String heap with invalid UTF-8 (temporarily disabled - heap replacement approach fails)
    // The current heap replacement approach doesn't work because the strings iterator
    // cannot parse heavily corrupted heaps, so the validation never runs.
    // This would require a different approach, such as:
    // - Direct raw table manipulation to reference corrupted string indices
    // - Lower-level heap corruption that maintains parseable structure
    // - Alternative assembly creation method that bypasses heap validation
    // TODO: Investigate alternative approaches for creating invalid UTF-8 in parseable string heaps

    // 4. GUID heap with invalid size alignment
    match create_assembly_with_invalid_guid_alignment() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "Malformed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid GUID alignment: {e}"
            )));
        }
    }

    // 5. GUID heap with valid content (tests our new validation logic)
    match create_assembly_with_valid_guid_content() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file(temp_file, true));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with GUID content: {e}"
            )));
        }
    }

    // Note: Additional heap corruption tests for String heap (UTF-8) and Blob heap
    // require more sophisticated corruption techniques. The heap replacement approach
    // works well for GUID alignment and UserString UTF-16 validation, demonstrating
    // the effectiveness of direct heap manipulation for validation testing.

    Ok(assemblies)
}

/// Creates a test assembly with invalid UTF-16 in the userstring heap.
///
/// Creates a userstring heap with invalid UTF-16 sequences using heap replacement.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_invalid_utf16_userstring() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a userstring heap with invalid UTF-16 sequences
    // Structure: null byte + length prefix + invalid UTF-16 data + terminator
    let mut userstring_heap = vec![0]; // Required null byte at index 0

    // Create a userstring entry with unpaired surrogate
    // Length: 5 bytes (2 bytes high surrogate + 2 bytes regular char + 1 terminator)
    userstring_heap.push(0x05); // Length prefix
    userstring_heap.extend_from_slice(&[0x00, 0xD8]); // Unpaired high surrogate (invalid UTF-16)
    userstring_heap.extend_from_slice(&[0x41, 0x00]); // Valid 'A' character
    userstring_heap.push(0x01); // Terminator byte

    context.userstring_add_heap(userstring_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with invalid GUID heap size alignment.
///
/// Creates a GUID heap that is not a multiple of 16 bytes using heap replacement.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_invalid_guid_alignment() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a GUID heap with invalid size (not multiple of 16 bytes)
    let mut guid_heap = Vec::new();
    // Add one complete GUID (16 bytes)
    guid_heap.extend_from_slice(&[0x12; 16]);
    // Add incomplete GUID (only 10 bytes) - violates 16-byte alignment requirement
    guid_heap.extend_from_slice(&[0x34; 10]);

    context.guid_add_heap(guid_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with valid GUID heap content to test
/// the new GUID content validation logic.
///
/// Creates a minimal test to validate the new GUID content validation logic
/// works correctly with valid GUID data.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_valid_guid_content() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a very simple GUID heap with just one GUID that should pass basic validation
    // The real test is to ensure our new validation code runs without errors
    // on a valid GUID heap, demonstrating the implementation is working
    let mut guid_heap = Vec::new();

    // Add exactly 1 complete GUID (16 bytes)
    guid_heap.extend_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ]);

    context.guid_add_heap(guid_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with userstring heap size not 4-byte aligned.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_unaligned_userstring_heap() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a userstring heap that is not 4-byte aligned (5 bytes)
    let userstring_heap = vec![0, 0x03, 0x41, 0x00, 0x01]; // 5 bytes - not 4-byte aligned
    context.userstring_add_heap(userstring_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with individual userstring exceeding character limit.
///
/// Creates a userstring heap with a userstring that simulates exceeding the 0x1FFFFFFF character limit.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_oversized_individual_userstring() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a userstring heap with a userstring that would report excessive character count
    let mut userstring_heap = vec![0]; // Required null byte at index 0

    // Create a userstring with size that appears to exceed 0x1FFFFFFF characters when parsed
    // Using compressed integer encoding for length prefix
    userstring_heap.extend_from_slice(&[
        0xFF, 0xFF, 0xFF,
        0xFF, // Length prefix indicating very long userstring (compressed integer)
        0x41, 0x00, // 'A' character in UTF-16
        0x42, 0x00, // 'B' character in UTF-16
        0x01, // Terminator byte
    ]);

    // Pad to 4-byte alignment
    while userstring_heap.len() % 4 != 0 {
        userstring_heap.push(0);
    }

    context.userstring_add_heap(userstring_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
