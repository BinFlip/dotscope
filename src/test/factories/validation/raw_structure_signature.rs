//! Factory methods for raw structure signature validation testing.
//!
//! Contains helper methods migrated from raw structure signature validation source files
//! for creating test assemblies with various signature validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{cilassemblyview::CilAssemblyView, validation::ValidationConfig},
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Test factory for RawSignatureValidator following the golden pattern.
///
/// Creates test assemblies covering basic signature validation scenarios.
/// Tests calling convention validation, compressed integer format, and blob bounds.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/signature.rs`
pub fn raw_signature_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    if let Some(clean_path) = get_clean_testfile() {
        assemblies.push(TestAssembly::new(clean_path, true));
    }

    // Enhanced comprehensive negative testing using direct blob heap manipulation
    // to create specific signature corruption scenarios that target validation rules

    // 1. NEGATIVE: Method signature with invalid calling convention
    match create_assembly_with_invalid_method_calling_convention() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationRawValidatorFailed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid method calling convention: {e}"
            )));
        }
    }

    // 2. NEGATIVE: Field signature with invalid calling convention (not 0x06)
    match create_assembly_with_invalid_field_calling_convention() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationRawValidatorFailed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with invalid field calling convention: {e}"
            )));
        }
    }

    // 3. NEGATIVE: Malformed compressed integer in signature blob
    match create_assembly_with_malformed_compressed_integer() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationRawValidatorFailed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with malformed compressed integer: {e}"
            )));
        }
    }

    // 4. NEGATIVE: Signature blob exceeding maximum size limit
    match create_assembly_with_oversized_signature_blob() {
        Ok(temp_file) => {
            assemblies.push(TestAssembly::from_temp_file_with_error(
                temp_file,
                "ValidationRawValidatorFailed",
            ));
        }
        Err(e) => {
            return Err(Error::Error(format!(
                "Failed to create test assembly with oversized signature blob: {e}"
            )));
        }
    }

    Ok(assemblies)
}

/// Creates a test assembly with invalid method calling convention (> 0x05).
///
/// Creates a signature blob with an invalid method calling convention that exceeds
/// the valid range (0x00-0x05) defined by ECMA-335, triggering RawSignatureValidator
/// validation failure.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/signature.rs`
pub fn create_assembly_with_invalid_method_calling_convention() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a proper blob heap with corrupted signature
    // Blob heap format: [null_byte, size_prefix, blob_data, size_prefix, blob_data, ...]
    let blob_heap = vec![
        0,    // Required null byte at offset 0
        0x04, // Size prefix (4 bytes of signature data)
        0x06, // Invalid method calling convention (> 0x05)
        0x01, // Parameter count (1)
        0x01, // Return type: void (ELEMENT_TYPE_VOID)
        0x08, // Parameter type: I4 (ELEMENT_TYPE_I4)
    ];

    // Add the corrupted blob heap
    context.blob_add_heap(blob_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = tempfile::NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with invalid field calling convention (not 0x06).
///
/// Creates a signature blob with an invalid field calling convention that doesn't
/// match the required 0x06 value defined by ECMA-335, triggering RawSignatureValidator
/// validation failure.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/signature.rs`
pub fn create_assembly_with_invalid_field_calling_convention() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a proper blob heap with corrupted field signature
    let blob_heap = vec![
        0,    // Required null byte at offset 0
        0x02, // Size prefix (2 bytes of signature data)
        0x07, // Invalid field calling convention (should be 0x06)
        0x08, // Field type: I4 (ELEMENT_TYPE_I4)
    ];

    // Add the corrupted blob heap
    context.blob_add_heap(blob_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = tempfile::NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with malformed compressed integer encoding.
///
/// Creates a signature blob with invalid compressed integer encoding that violates
/// ECMA-335 format requirements, triggering RawSignatureValidator validation failure.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/signature.rs`
pub fn create_assembly_with_malformed_compressed_integer() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a proper blob heap with malformed compressed integer
    let blob_heap = vec![
        0,    // Required null byte at offset 0
        0x02, // Size prefix (2 bytes of signature data)
        0x00, // Valid method calling convention (DEFAULT)
        0xE0, // Invalid compressed integer pattern (11100000)
              // Missing continuation bytes for 4-byte encoding - creates malformed structure
    ];

    // Add the corrupted blob heap
    context.blob_add_heap(blob_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = tempfile::NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates a test assembly with oversized signature blob (> 64KB).
///
/// Creates a signature blob that exceeds the maximum reasonable size limit,
/// triggering RawSignatureValidator blob bounds validation failure.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/signature.rs`
pub fn create_assembly_with_oversized_signature_blob() -> Result<NamedTempFile> {
    let clean_testfile = get_clean_testfile()
        .ok_or_else(|| Error::Error("WindowsBase.dll not available".to_string()))?;
    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create a proper blob heap with oversized signature blob
    let mut blob_heap = vec![
        0, // Required null byte at offset 0
        0xC0, 0x01, 0x00, 0x01, // Size prefix for 65537 bytes (4-byte encoding)
        0x00, // Valid method calling convention
        0x00, // Parameter count (0)
        0x01, // Return type: void
    ];

    // Fill remaining to reach 65537 bytes total
    blob_heap.resize(blob_heap.len() + 65534, 0xFF);

    // Add the oversized blob heap
    context.blob_add_heap(blob_heap)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = tempfile::NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
