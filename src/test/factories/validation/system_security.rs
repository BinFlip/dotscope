//! Factory methods for system security validation testing.
//!
//! Contains helper methods migrated from system security validation source files
//! for creating test assemblies with various security validation scenarios.

use crate::{
    cilassembly::{BuilderContext, CilAssembly},
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{CodedIndex, CodedIndexType, DeclSecurityRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    test::{get_clean_testfile, TestAssembly},
    Error, Result,
};
use tempfile::NamedTempFile;

/// Main factory method for system security validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn owned_security_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error(
            "WindowsBase.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all security validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE TEST: Assembly with invalid security action
    assemblies.push(TestAssembly::new(
        create_assembly_with_invalid_security_action()?.path(),
        false,
    ));

    // 3. NEGATIVE TEST: Assembly with malformed permission set XML
    assemblies.push(TestAssembly::new(
        create_assembly_with_malformed_permission_set()?.path(),
        false,
    ));

    // 4. NEGATIVE TEST: Assembly with conflicting security attributes
    assemblies.push(TestAssembly::new(
        create_assembly_with_conflicting_security_attributes()?.path(),
        false,
    ));

    // 5. NEGATIVE TEST: Assembly with invalid security transparency violations
    assemblies.push(TestAssembly::new(
        create_assembly_with_security_transparency_violations()?.path(),
        false,
    ));

    Ok(assemblies)
}

/// Creates an assembly with invalid security action values.
///
/// This test creates a DeclSecurity entry with an invalid action value (outside 1-14 range)
/// to trigger security action validation failure.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_invalid_security_action() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // Create a DeclSecurity entry with invalid action (0 is outside valid range 1-14)
    let invalid_declsecurity = DeclSecurityRaw {
        rid: 1,
        token: Token::new(0x0E000001),
        offset: 0,
        action: 99, // Invalid action (outside 1-14 range)
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasDeclSecurity),
        permission_set: 1, // Point to a blob index that should exist
    };

    assembly.table_row_add(
        TableId::DeclSecurity,
        TableDataOwned::DeclSecurity(invalid_declsecurity),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with malformed permission set XML.
///
/// This test creates a DeclSecurity entry with permission set XML that is missing
/// required elements, triggering XML validation failure.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_malformed_permission_set() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create malformed XML without required PermissionSet element
    let malformed_xml = b"<InvalidRoot><Permission>SomePermission</Permission></InvalidRoot>";

    // Add the malformed XML to blob heap
    let blob_index = context.blob_add(malformed_xml)?;

    // Create a DeclSecurity entry pointing to the malformed XML blob
    let declsecurity_with_bad_xml = DeclSecurityRaw {
        rid: 1,
        token: Token::new(0x0E000001),
        offset: 0,
        action: 3, // Valid action (Demand)
        parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasDeclSecurity),
        permission_set: blob_index,
    };

    let mut assembly = context.finish();
    assembly.table_row_add(
        TableId::DeclSecurity,
        TableDataOwned::DeclSecurity(declsecurity_with_bad_xml),
    )?;

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with conflicting security attributes.
///
/// This test creates custom attributes with conflicting security specifications
/// that should trigger security attribute validation failure.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_conflicting_security_attributes() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // For now, create a simple assembly that will pass until we have better CustomAttribute support
    // TODO: This needs to be enhanced when CustomAttribute builder API becomes available
    // The conflict would be created by adding both SecurityCritical and SecurityTransparent attributes

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Creates an assembly with security transparency violations.
///
/// This test creates security transparency boundary violations between
/// critical and transparent code sections.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_security_transparency_violations() -> Result<NamedTempFile> {
    let Some(clean_testfile) = get_clean_testfile() else {
        return Err(Error::Error("WindowsBase.dll not available".to_string()));
    };

    let view = CilAssemblyView::from_file(&clean_testfile)?;
    let mut assembly = CilAssembly::new(view);

    // For now, create a simple assembly that will pass until we have better security attribute support
    // TODO: This needs to be enhanced when security attribute builder API becomes available
    // The violation would be created by having transparent code access critical members

    assembly.validate_and_apply_changes_with_config(ValidationConfig::disabled())?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}
