//! Factory methods for system security validation testing.
//!
//! Contains helper methods migrated from system security validation source files
//! for creating test assemblies with various security validation scenarios.

use crate::{
    metadata::{
        customattributes::{
            encode_custom_attribute_value, CustomAttributeArgument, CustomAttributeValue,
        },
        tables::{
            CodedIndex, CodedIndexType, CustomAttributeRaw, DeclSecurityRaw, TableDataOwned,
            TableId,
        },
        token::Token,
    },
    test::{create_test_assembly, get_testfile_mscorlib, TestAssembly},
    Error, Result,
};

/// Main factory method for system security validation test assemblies
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn owned_security_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let Some(clean_testfile) = get_testfile_mscorlib() else {
        return Err(Error::Other(
            "mscorlib.dll not available - test cannot run".to_string(),
        ));
    };

    // 1. REQUIRED: Clean assembly - should pass all security validation
    assemblies.push(TestAssembly::new(&clean_testfile, true));

    // 2. NEGATIVE TEST: Assembly with invalid security action
    assemblies.push(create_assembly_with_invalid_security_action()?);

    // 3. NEGATIVE TEST: Assembly with malformed permission set XML
    assemblies.push(create_assembly_with_malformed_permission_set()?);

    // 4. NEGATIVE TEST: Assembly with conflicting security attributes
    assemblies.push(create_assembly_with_conflicting_security_attributes()?);

    // 5. NEGATIVE TEST: Assembly with security transparency violations
    assemblies.push(create_assembly_with_security_transparency_violations()?);

    Ok(assemblies)
}

/// Creates an assembly with invalid security action values.
///
/// This test creates a DeclSecurity entry with an invalid action value (outside 1-14 range)
/// to trigger security action validation failure.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_invalid_security_action() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
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

        Ok(())
    })
}

/// Creates an assembly with malformed permission set XML.
///
/// This test creates a DeclSecurity entry with permission set XML that is missing
/// required elements, triggering XML validation failure.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_malformed_permission_set() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
        // Create malformed XML without required PermissionSet element
        let malformed_xml = b"<InvalidRoot><Permission>SomePermission</Permission></InvalidRoot>";

        // Add the malformed XML to blob heap
        let blob_index = assembly.blob_add(malformed_xml)?;

        // Create a DeclSecurity entry pointing to the malformed XML blob
        let declsecurity_with_bad_xml = DeclSecurityRaw {
            rid: 1,
            token: Token::new(0x0E000001),
            offset: 0,
            action: 3, // Valid action (Demand)
            parent: CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasDeclSecurity),
            permission_set: blob_index.placeholder(),
        };

        assembly.table_row_add(
            TableId::DeclSecurity,
            TableDataOwned::DeclSecurity(declsecurity_with_bad_xml),
        )?;

        Ok(())
    })
}

/// Creates an assembly with conflicting security attributes.
///
/// This test creates custom attributes with conflicting security specifications
/// (SecurityCritical AND SecurityTransparent on the same type) that should trigger
/// security attribute validation failure.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_conflicting_security_attributes() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
        // Add SecurityCritical attribute to TypeDef 1
        let critical_attr_value = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String(
                "SecurityCritical".to_string(),
            )],
            named_args: vec![],
        };

        let critical_blob = encode_custom_attribute_value(&critical_attr_value).map_err(|e| {
            Error::Other(format!("Failed to encode SecurityCritical attribute: {e}"))
        })?;

        let critical_blob_index = assembly.blob_add(&critical_blob)?;

        let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

        let critical_custom_attr = CustomAttributeRaw {
            rid: next_rid,
            token: Token::new(0x0C000000 + next_rid),
            offset: 0,
            parent: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::HasCustomAttribute),
            constructor: CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::CustomAttributeType,
            ),
            value: critical_blob_index.placeholder(),
        };

        assembly.table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(critical_custom_attr),
        )?;

        // Add SecurityTransparent attribute to the same TypeDef
        let transparent_attr_value = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String(
                "SecurityTransparent".to_string(),
            )],
            named_args: vec![],
        };

        let transparent_blob =
            encode_custom_attribute_value(&transparent_attr_value).map_err(|e| {
                Error::Other(format!(
                    "Failed to encode SecurityTransparent attribute: {e}"
                ))
            })?;

        let transparent_blob_index = assembly.blob_add(&transparent_blob)?;

        let next_rid2 = assembly.original_table_row_count(TableId::CustomAttribute) + 2;

        let transparent_custom_attr = CustomAttributeRaw {
            rid: next_rid2,
            token: Token::new(0x0C000000 + next_rid2),
            offset: 0,
            parent: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::HasCustomAttribute),
            constructor: CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::CustomAttributeType,
            ),
            value: transparent_blob_index.placeholder(),
        };

        assembly.table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(transparent_custom_attr),
        )?;

        Ok(())
    })
}

/// Creates an assembly with security transparency violations.
///
/// This test creates security transparency boundary violations where a transparent
/// type inherits from a critical type, which violates security transparency rules.
///
/// In mscorlib, TypeDef 2 is typically System.Object and TypeDef 3 inherits from it.
/// We mark the base type as SecurityCritical and the derived type as SecurityTransparent
/// to trigger a transparency violation.
///
/// Originally from: `src/metadata/validation/validators/owned/system/security.rs`
pub fn create_assembly_with_security_transparency_violations() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, |assembly| {
        // Mark TypeDef 2 (base type, typically System.Object) as SecurityCritical
        let critical_attr_value = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String(
                "SecurityCritical".to_string(),
            )],
            named_args: vec![],
        };

        let critical_blob = encode_custom_attribute_value(&critical_attr_value).map_err(|e| {
            Error::Other(format!("Failed to encode SecurityCritical attribute: {e}"))
        })?;

        let critical_blob_index = assembly.blob_add(&critical_blob)?;

        let next_rid = assembly.original_table_row_count(TableId::CustomAttribute) + 1;

        let critical_custom_attr = CustomAttributeRaw {
            rid: next_rid,
            token: Token::new(0x0C000000 + next_rid),
            offset: 0,
            parent: CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::HasCustomAttribute),
            constructor: CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::CustomAttributeType,
            ),
            value: critical_blob_index.placeholder(),
        };

        assembly.table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(critical_custom_attr),
        )?;

        // Mark TypeDef 3 (derived type that inherits from TypeDef 2) as SecurityTransparent
        let transparent_attr_value = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String(
                "SecurityTransparent".to_string(),
            )],
            named_args: vec![],
        };

        let transparent_blob =
            encode_custom_attribute_value(&transparent_attr_value).map_err(|e| {
                Error::Other(format!(
                    "Failed to encode SecurityTransparent attribute: {e}"
                ))
            })?;

        let transparent_blob_index = assembly.blob_add(&transparent_blob)?;

        let next_rid2 = assembly.original_table_row_count(TableId::CustomAttribute) + 2;

        let transparent_custom_attr = CustomAttributeRaw {
            rid: next_rid2,
            token: Token::new(0x0C000000 + next_rid2),
            offset: 0,
            parent: CodedIndex::new(TableId::TypeDef, 3, CodedIndexType::HasCustomAttribute),
            constructor: CodedIndex::new(
                TableId::MethodDef,
                1,
                CodedIndexType::CustomAttributeType,
            ),
            value: transparent_blob_index.placeholder(),
        };

        assembly.table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(transparent_custom_attr),
        )?;

        Ok(())
    })
}
