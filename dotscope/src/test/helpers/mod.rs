//! Helper functions and utilities for testing
//!
//! This module contains helper functions for creating test data structures
//! and mock objects. It includes both legacy helpers for backward compatibility
//! and new specialized helpers for different testing scenarios.
//!
//! # Assembly Loading Helpers
//!
//! Two primary helpers simplify test assembly creation:
//!
//! - [`load_test_assembly`] - Loads a `CilAssembly` from a test file path function
//! - [`create_test_assembly`] - Creates a `TestAssembly` with modifications applied
//! - [`test_assembly_arc`] - Returns a cached `Arc<CilObject>` for pass tests
//!
//! These helpers eliminate boilerplate in validation factory functions and integration tests.

use std::{path::PathBuf, sync::Arc};

use crate::{
    cilassembly::CilAssembly,
    metadata::{
        method::MethodRc,
        tables::{AssemblyRefRc, FileRc, ModuleRefRc},
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
    },
    CilObject, Error, Result,
};

use super::{
    builders::{AssemblyRefBuilder, CilTypeBuilder, FileBuilder, MethodBuilder, ModuleRefBuilder},
    validator::TestAssembly,
};

pub mod dependencies;

// Helper function to create a ModuleRef
pub fn create_module_ref(rid: u32, name: &str) -> ModuleRefRc {
    ModuleRefBuilder::new()
        .with_rid(rid)
        .with_name(name)
        .build()
}

// Helper function to create an AssemblyRef
pub fn create_assembly_ref(rid: u32, name: &str) -> AssemblyRefRc {
    AssemblyRefBuilder::new()
        .with_rid(rid)
        .with_name(name)
        .build()
}

// Helper function to create a File
pub fn create_file(rid: u32, name: &str) -> FileRc {
    FileBuilder::new().with_rid(rid).with_name(name).build()
}

// Helper function to create a Method
pub fn create_method(name: &str) -> MethodRc {
    MethodBuilder::simple_void_method(name).build()
}

// Helper function to create a CilType
pub fn create_cil_type(
    token: Token,
    namespace: &str,
    name: &str,
    external: Option<CilTypeReference>,
) -> CilTypeRc {
    CilTypeBuilder::new()
        .with_token(token)
        .with_namespace(namespace)
        .with_name(name)
        .with_external(external.unwrap_or_else(|| CilTypeReference::File(create_file(1, "test"))))
        .build()
}

/// Loads a [`CilAssembly`] from a test file path function.
///
/// This helper simplifies assembly loading in tests by wrapping the common pattern
/// of calling a test file function and loading the assembly from the resulting path.
///
/// # Arguments
///
/// * `testfile_fn` - A function that returns an optional path to a test file
///
/// # Returns
///
/// A `Result` containing the loaded `CilAssembly` or an error if:
/// - The test file function returns `None`
/// - The assembly fails to load
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::test::{load_test_assembly, get_testfile_mscorlib};
///
/// let assembly = load_test_assembly(get_testfile_mscorlib)?;
/// // Now you can work with the assembly
/// ```
pub fn load_test_assembly(testfile_fn: fn() -> Option<PathBuf>) -> Result<CilAssembly> {
    let testfile =
        testfile_fn().ok_or_else(|| Error::Other("Test file not available".to_string()))?;
    CilAssembly::from_path(&testfile)
}

/// Creates a failing [`TestAssembly`] from any test file.
///
/// Loads an assembly from `testfile_fn`, applies modifications via `f`,
/// generates to memory, and returns a `TestAssembly` marked as should fail.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::test::{create_test_assembly, get_testfile_mscorlib, get_testfile_wb};
///
/// // Using mscorlib
/// let test = create_test_assembly(get_testfile_mscorlib, |asm| Ok(()))?;
///
/// // Using WindowsBase
/// let test = create_test_assembly(get_testfile_wb, |asm| Ok(()))?;
/// ```
pub fn create_test_assembly<F>(testfile_fn: fn() -> Option<PathBuf>, f: F) -> Result<TestAssembly>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
{
    let mut assembly = load_test_assembly(testfile_fn)?;
    f(&mut assembly)?;
    let bytes = assembly.to_memory()?;
    Ok(TestAssembly::from_bytes(bytes, false))
}

/// Creates a passing [`TestAssembly`] from any test file.
///
/// Same as [`create_test_assembly`] but marked as should pass validation.
pub fn create_passing_test_assembly<F>(
    testfile_fn: fn() -> Option<PathBuf>,
    f: F,
) -> Result<TestAssembly>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
{
    let mut assembly = load_test_assembly(testfile_fn)?;
    f(&mut assembly)?;
    let bytes = assembly.to_memory()?;
    Ok(TestAssembly::from_bytes(bytes, true))
}

/// Creates a failing [`TestAssembly`] with expected error pattern.
///
/// Same as [`create_test_assembly`] but with a specific expected error pattern.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::test::{create_test_assembly_with_error, get_testfile_wb};
///
/// let test = create_test_assembly_with_error(get_testfile_wb, "GUID heap", |asm| {
///     // Create invalid GUID heap
///     Ok(())
/// })?;
/// ```
pub fn create_test_assembly_with_error<F>(
    testfile_fn: fn() -> Option<PathBuf>,
    error_pattern: &str,
    f: F,
) -> Result<TestAssembly>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
{
    let mut assembly = load_test_assembly(testfile_fn)?;
    f(&mut assembly)?;
    let bytes = assembly.to_memory()?;
    Ok(TestAssembly::from_bytes_with_error(bytes, error_pattern))
}

/// Returns a cached `Arc<CilObject>` for use in pass tests.
///
/// This helper loads a test assembly once and caches it for reuse across tests.
/// Useful for pass tests that need an assembly parameter but don't actually use it.
///
/// # Panics
///
/// Panics if the test assembly cannot be loaded.
pub fn test_assembly_arc() -> Arc<CilObject> {
    use std::sync::LazyLock;

    static TEST_ASSEMBLY: LazyLock<Arc<CilObject>> = LazyLock::new(|| {
        Arc::new(
            CilObject::from_path(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/samples/crafted_2.exe"),
            )
            .expect("Failed to load test assembly"),
        )
    });

    Arc::clone(&TEST_ASSEMBLY)
}
