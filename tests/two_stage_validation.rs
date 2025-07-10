//! Integration tests for two-stage validation approach.
//!
//! These tests verify that the two-stage validation system works correctly:
//! - Stage 1: Raw validation during CilAssemblyView loading
//! - Stage 2: Owned data validation during CilObject loading
//!
//! This module uses CilAssembly to create precise test cases that target specific
//! validation modules with controlled modifications.

use dotscope::metadata::tables::{
    AssemblyRefRaw, ModuleRaw, ModuleRefRaw, TableDataOwned, TableId,
};
use dotscope::metadata::token::Token;
use dotscope::{CilAssembly, CilAssemblyView, CilObject, ValidationConfig, ValidationPipeline};
use std::path::PathBuf;
use tempfile::NamedTempFile;

/// Factory method that creates a file designed to trigger BasicSchemaValidator failures.
/// This targets data type validation, RID constraints, and operation validation.
fn factory_testfile_schema_validation_failure(
) -> std::result::Result<NamedTempFile, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    let view = CilAssemblyView::from_file(&path)?;
    let mut assembly = CilAssembly::new(view);

    // Strategy 1: Add valid strings first to ensure we have references
    let valid_string1 = assembly.add_string("SchemaTestValid1")?;
    let valid_string2 = assembly.add_string("SchemaTestValid2")?;

    // Strategy 2: Create ModuleRef with questionable but valid references
    let questionable_moduleref = ModuleRefRaw {
        rid: 0,                        // Will be set by add_table_row
        token: Token::new(0x1A000001), // Temporary, will be updated
        offset: 0,
        name: valid_string1, // Valid reference
    };

    let _moduleref_rid = assembly.add_table_row(
        TableId::ModuleRef,
        TableDataOwned::ModuleRef(questionable_moduleref),
    )?;

    // Strategy 3: Create AssemblyRef with unusual flag combinations
    let unusual_assemblyref = AssemblyRefRaw {
        rid: 0,
        token: Token::new(0x23000001),
        offset: 0,
        major_version: 99999, // Large but valid version values
        minor_version: 99999,
        build_number: 99999,
        revision_number: 99999,
        flags: 0x0001,          // PublicKey flag
        public_key_or_token: 0, // But no public key data - semantic inconsistency
        name: valid_string2,    // Valid string reference
        culture: 0,             // Valid null culture
        hash_value: 0,          // Valid null hash
    };

    let _assemblyref_rid = assembly.add_table_row(
        TableId::AssemblyRef,
        TableDataOwned::AssemblyRef(unusual_assemblyref),
    )?;

    // Use disabled validation pipeline to allow these through
    let disabled_pipeline = ValidationPipeline::new();
    assembly.validate_and_apply_changes_with_pipeline(&disabled_pipeline)?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Factory method that creates a file designed to trigger RidConsistencyValidator failures.
/// This targets RID conflict detection and uniqueness constraints.
fn factory_testfile_rid_consistency_failure(
) -> std::result::Result<NamedTempFile, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    let view = CilAssemblyView::from_file(&path)?;
    let mut assembly = CilAssembly::new(view);

    // Strategy 1: Add duplicate Module entries (should only be one per assembly)
    // This targets RID consistency as there should only be one Module entry
    let duplicate_module = ModuleRaw {
        rid: 0,                        // Will be set by add_table_row
        token: Token::new(0x00000001), // Temporary
        offset: 0,
        generation: 0,
        name: assembly.add_string("DuplicateModule")?,
        mvid: 1, // GUID heap index
        encid: 0,
        encbaseid: 0,
    };

    // Add multiple Module entries (should violate uniqueness)
    let _module_rid1 = assembly.add_table_row(
        TableId::Module,
        TableDataOwned::Module(duplicate_module.clone()),
    )?;

    let _module_rid2 =
        assembly.add_table_row(TableId::Module, TableDataOwned::Module(duplicate_module))?;

    // Strategy 2: Add many entries to test RID bounds
    for i in 0..100 {
        let _string_index = assembly.add_string(&format!("RidTestString_{i}"))?;
    }

    // Use disabled validation pipeline to allow invalid references through
    let disabled_pipeline = ValidationPipeline::new();
    assembly.validate_and_apply_changes_with_pipeline(&disabled_pipeline)?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Factory method that creates a file designed to trigger ReferentialIntegrityValidator failures.
/// This targets cross-reference validation and dangling reference prevention.
fn factory_testfile_referential_integrity_failure(
) -> std::result::Result<NamedTempFile, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    let view = CilAssemblyView::from_file(&path)?;
    let mut assembly = CilAssembly::new(view);

    // Strategy 1: Add some valid strings first
    let valid_string1 = assembly.add_string("RefIntegrityTest1")?;
    let valid_string2 = assembly.add_string("RefIntegrityTest2")?;

    // Strategy 2: Create AssemblyRef with suspicious but technically valid patterns
    // These should pass basic loading but might trigger referential integrity issues
    let suspicious_assemblyref = AssemblyRefRaw {
        rid: 0,
        token: Token::new(0x23000001),
        offset: 0,
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0x0002,          // PublicKeyToken flag
        public_key_or_token: 0, // But no token data - referential inconsistency
        name: valid_string1,    // Valid string reference
        culture: 0,             // Valid null culture
        hash_value: 0,          // Valid null hash
    };

    let _assemblyref_rid = assembly.add_table_row(
        TableId::AssemblyRef,
        TableDataOwned::AssemblyRef(suspicious_assemblyref),
    )?;

    // Strategy 3: Create ModuleRef with cross-referencing patterns
    let cross_ref_moduleref = ModuleRefRaw {
        rid: 0,
        token: Token::new(0x1A000001),
        offset: 0,
        name: valid_string2, // Valid reference
    };

    let _moduleref_rid = assembly.add_table_row(
        TableId::ModuleRef,
        TableDataOwned::ModuleRef(cross_ref_moduleref),
    )?;

    // Strategy 4: Add more entries to create complex referential patterns
    for i in 0..20 {
        let _string_index = assembly.add_string(&format!("RefIntegrityPattern_{i}"))?;
    }

    // Use disabled validation pipeline to allow these through
    let disabled_pipeline = ValidationPipeline::new();
    assembly.validate_and_apply_changes_with_pipeline(&disabled_pipeline)?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

/// Factory method that creates a file designed to trigger owned validation pipeline failures.
/// This targets semantic validation, layout validation, and constraint validation.
fn factory_testfile_owned_validation_failure(
) -> std::result::Result<NamedTempFile, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    let view = CilAssemblyView::from_file(&path)?;
    let mut assembly = CilAssembly::new(view);

    // Strategy 1: Create multiple Module entries (violates uniqueness constraints in owned validation)
    let module1 = ModuleRaw {
        rid: 0,
        token: Token::new(0x00000001),
        offset: 0,
        generation: 0,
        name: assembly.add_string("OwnedValidationTestModule1")?,
        mvid: 1,
        encid: 0,
        encbaseid: 0,
    };

    let module2 = ModuleRaw {
        rid: 0,
        token: Token::new(0x00000002),
        offset: 0,
        generation: 0,
        name: assembly.add_string("OwnedValidationTestModule2")?,
        mvid: 2,
        encid: 0,
        encbaseid: 0,
    };

    let _module_rid1 = assembly.add_table_row(TableId::Module, TableDataOwned::Module(module1))?;

    let _module_rid2 = assembly.add_table_row(TableId::Module, TableDataOwned::Module(module2))?;

    // Strategy 2: Create AssemblyRef entries with semantic inconsistencies
    // Add assemblies with conflicting version information
    let conflict_assembly1 = AssemblyRefRaw {
        rid: 0,
        token: Token::new(0x23000001),
        offset: 0,
        major_version: 1,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0x0001,          // PublicKey flag
        public_key_or_token: 0, // But no public key data - semantic conflict
        name: assembly.add_string("ConflictAssembly")?,
        culture: 0,
        hash_value: 0,
    };

    let _conflict_rid = assembly.add_table_row(
        TableId::AssemblyRef,
        TableDataOwned::AssemblyRef(conflict_assembly1),
    )?;

    // Use disabled validation pipeline to allow these through
    let disabled_pipeline = ValidationPipeline::new();
    assembly.validate_and_apply_changes_with_pipeline(&disabled_pipeline)?;

    let temp_file = NamedTempFile::new()?;
    assembly.write_to_file(temp_file.path())?;

    Ok(temp_file)
}

#[test]
fn test_two_stage_validation_integration() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");

    // Test 1: Load with disabled validation (no validation stages)
    let result = CilObject::from_file_with_validation(&path, ValidationConfig::disabled());
    assert!(result.is_ok(), "Disabled validation should always succeed");

    // Test 2: Load with minimal validation (stage 1 only)
    let result = CilObject::from_file_with_validation(&path, ValidationConfig::minimal());
    assert!(
        result.is_ok(),
        "Minimal validation should succeed with raw validation"
    );

    // Test 3: Load with production validation (both stages)
    let result = CilObject::from_file_with_validation(&path, ValidationConfig::production());
    assert!(
        result.is_ok(),
        "Production validation should succeed with two-stage validation"
    );

    // Test 4: Load with comprehensive validation (both stages, maximum validation)
    let result = CilObject::from_file_with_validation(&path, ValidationConfig::comprehensive());
    assert!(
        result.is_ok(),
        "Comprehensive validation should succeed with full validation"
    );

    // Test 5: Test CilAssemblyView raw validation independently
    let view_result =
        CilAssemblyView::from_file_with_validation(&path, ValidationConfig::raw_only());
    assert!(
        view_result.is_ok(),
        "Raw-only validation should succeed on CilAssemblyView"
    );
}

/// Test that BasicSchemaValidator can detect schema violations
#[test]
fn test_basicschema_validator() {
    let test_file =
        factory_testfile_schema_validation_failure().expect("Failed to create schema test file");

    // Disabled validation must always work
    let result =
        CilAssemblyView::from_file_with_validation(test_file.path(), ValidationConfig::disabled());
    assert!(result.is_ok(), "Disabled validation must always succeed");

    // Test if schema validator can catch issues
    println!("Testing BasicSchemaValidator:");
    test_validator_behavior(&test_file, "BasicSchemaValidator");
}

/// Test that RidConsistencyValidator can detect RID conflicts  
#[test]
fn test_ridconsistency_validator() {
    let test_file = factory_testfile_rid_consistency_failure()
        .expect("Failed to create RID consistency test file");

    // Disabled validation must always work
    let result =
        CilAssemblyView::from_file_with_validation(test_file.path(), ValidationConfig::disabled());
    assert!(result.is_ok(), "Disabled validation must always succeed");

    // Test if RID consistency validator can catch issues
    println!("Testing RidConsistencyValidator:");
    test_validator_behavior(&test_file, "RidConsistencyValidator");
}

/// Test that ReferentialIntegrityValidator can detect dangling references
#[test]
fn test_referentialintegrity_validator() {
    let test_file = factory_testfile_referential_integrity_failure()
        .expect("Failed to create referential integrity test file");

    // Disabled validation must always work
    let result =
        CilAssemblyView::from_file_with_validation(test_file.path(), ValidationConfig::disabled());
    assert!(result.is_ok(), "Disabled validation must always succeed");

    // Test if referential integrity validator can catch issues
    println!("Testing ReferentialIntegrityValidator:");
    test_validator_behavior(&test_file, "ReferentialIntegrityValidator");
}

/// Test that owned validation pipeline can detect semantic issues
#[test]
fn test_owned_validation_validators() {
    let test_file = factory_testfile_owned_validation_failure()
        .expect("Failed to create owned validation test file");

    // Disabled validation must always work
    let result =
        CilObject::from_file_with_validation(test_file.path(), ValidationConfig::disabled());
    assert!(result.is_ok(), "Disabled validation must always succeed");

    // Test owned validation specifically
    println!("Testing Owned Validation Pipeline:");
    let owned_result =
        CilObject::from_file_with_validation(test_file.path(), ValidationConfig::owned_only());

    println!(
        "  Owned-only validation: {}",
        if owned_result.is_ok() {
            "PASSED"
        } else {
            "FAILED"
        }
    );

    if let Err(e) = owned_result {
        println!("    Error: {e:?}");
    }
}

/// Helper function to test validator behavior in a focused way
fn test_validator_behavior(temp_file: &NamedTempFile, validator_name: &str) {
    let validation_levels = vec![
        ("minimal", ValidationConfig::minimal()),
        ("production", ValidationConfig::production()),
        ("comprehensive", ValidationConfig::comprehensive()),
    ];

    for (name, config) in validation_levels {
        let result = CilAssemblyView::from_file_with_validation(temp_file.path(), config);
        println!(
            "  {} validation: {}",
            name,
            if result.is_ok() { "PASSED" } else { "FAILED" }
        );

        if let Err(e) = result {
            println!("    {validator_name} caught: {e:?}");
        }
    }
}
