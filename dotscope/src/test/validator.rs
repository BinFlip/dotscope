//! Centralized validator testing harness for comprehensive validation testing.
//!
//! This module provides a unified testing framework for all validators in the dotscope project.
//! It implements a factory pattern with function pointers to separate test assembly creation
//! from validation result verification, making it easy to create comprehensive tests for all
//! 25 validators in the system.
//!
//! # Architecture
//!
//! The testing harness uses two function pointers:
//! - `file_factory`: Creates test assemblies with specific validation issues
//! - `file_verify`: Verifies that validation results match expectations
//!
//! This separation allows for:
//! - Uniform test execution across all validators
//! - Reusable assembly creation patterns
//! - Centralized cleanup and error handling
//! - Clear separation of concerns

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        validation::{
            OwnedValidationContext, RawValidationContext, ReferenceScanner, ValidationConfig,
        },
    },
    Error, Result,
};
use rayon::ThreadPoolBuilder;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Test assembly specification for validator testing.
///
/// Source of assembly data for testing - either a file path or in-memory bytes.
#[derive(Debug)]
pub enum TestAssemblySource {
    /// File-backed assembly with path and optional temp file for cleanup
    File {
        path: PathBuf,
        _temp_file: Option<NamedTempFile>,
    },
    /// In-memory assembly data (zero-copy from generation)
    Memory(Vec<u8>),
}

/// Each test assembly represents a specific validation scenario, either a clean
/// assembly that should pass validation or a modified assembly designed to trigger
/// specific validation failures.
#[derive(Debug)]
pub struct TestAssembly {
    /// Source of the assembly data
    pub source: TestAssemblySource,
    /// Whether this assembly should pass (true) or fail (false) validation
    pub should_pass: bool,
    /// Optional specific error message or pattern expected for failing assemblies
    pub expected_error_pattern: Option<String>,
}

impl TestAssembly {
    /// Creates a new test assembly specification from a file path.
    pub fn new<P: Into<PathBuf>>(path: P, should_pass: bool) -> Self {
        Self {
            source: TestAssemblySource::File {
                path: path.into(),
                _temp_file: None,
            },
            should_pass,
            expected_error_pattern: None,
        }
    }

    /// Creates a test assembly that should fail with a specific error pattern.
    pub fn failing_with_error<P: Into<PathBuf>>(path: P, error_pattern: &str) -> Self {
        Self {
            source: TestAssemblySource::File {
                path: path.into(),
                _temp_file: None,
            },
            should_pass: false,
            expected_error_pattern: Some(error_pattern.to_string()),
        }
    }

    /// Creates a test assembly from a temporary file with automatic cleanup.
    pub fn from_temp_file(temp_file: NamedTempFile, should_pass: bool) -> Self {
        let path = temp_file.path().to_path_buf();
        Self {
            source: TestAssemblySource::File {
                path,
                _temp_file: Some(temp_file),
            },
            should_pass,
            expected_error_pattern: None,
        }
    }

    /// Creates a failing test assembly from a temporary file with specific error pattern.
    pub fn from_temp_file_with_error(temp_file: NamedTempFile, error_pattern: &str) -> Self {
        let path = temp_file.path().to_path_buf();
        Self {
            source: TestAssemblySource::File {
                path,
                _temp_file: Some(temp_file),
            },
            should_pass: false,
            expected_error_pattern: Some(error_pattern.to_string()),
        }
    }

    /// Creates a test assembly from in-memory bytes.
    ///
    /// This is the preferred method for test assembly creation as it avoids
    /// file I/O overhead.
    pub fn from_bytes(data: Vec<u8>, should_pass: bool) -> Self {
        Self {
            source: TestAssemblySource::Memory(data),
            should_pass,
            expected_error_pattern: None,
        }
    }

    /// Creates a failing test assembly from in-memory bytes with specific error pattern.
    pub fn from_bytes_with_error(data: Vec<u8>, error_pattern: &str) -> Self {
        Self {
            source: TestAssemblySource::Memory(data),
            should_pass: false,
            expected_error_pattern: Some(error_pattern.to_string()),
        }
    }

    /// Returns the path if this is a file-backed assembly.
    pub fn path(&self) -> Option<&Path> {
        match &self.source {
            TestAssemblySource::File { path, .. } => Some(path),
            TestAssemblySource::Memory(_) => None,
        }
    }

    /// Returns the bytes if this is a memory-backed assembly.
    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.source {
            TestAssemblySource::File { .. } => None,
            TestAssemblySource::Memory(data) => Some(data),
        }
    }

    /// Returns true if this is a memory-backed assembly.
    pub fn is_memory_backed(&self) -> bool {
        matches!(self.source, TestAssemblySource::Memory(_))
    }

    /// Returns a description of this assembly for error messages.
    pub fn description(&self) -> String {
        match &self.source {
            TestAssemblySource::File { path, .. } => path.display().to_string(),
            TestAssemblySource::Memory(data) => format!("<in-memory {} bytes>", data.len()),
        }
    }

    /// Loads this assembly as a `CilAssemblyView` with validation disabled.
    ///
    /// Used by the test harness to load assemblies for validator testing.
    pub fn load(&self) -> Result<CilAssemblyView> {
        match &self.source {
            TestAssemblySource::File { path, .. } => {
                CilAssemblyView::from_path_with_validation(path, ValidationConfig::disabled())
            }
            TestAssemblySource::Memory(data) => CilAssemblyView::from_mem_with_validation(
                data.clone(),
                ValidationConfig::disabled(),
            ),
        }
    }
}

/// Validation test result containing the outcome and any error information.
#[derive(Debug)]
pub struct ValidationTestResult {
    /// The assembly that was tested
    pub assembly: TestAssembly,
    /// Whether validation succeeded
    pub validation_succeeded: bool,
    /// Error message if validation failed
    pub error_message: Option<String>,
    /// Whether the test passed (validation result matched expectation)
    pub test_passed: bool,
}

/// File factory function type for creating test assemblies.
///
/// This function creates one or more test assemblies with specific validation issues.
/// Each assembly should target exactly one validation rule to ensure test isolation.
pub type FileFactory = fn() -> Result<Vec<TestAssembly>>;

/// Default comprehensive file verification implementation for validator testing.
///
/// This verification function performs comprehensive validation of test results:
/// - Ensures all positive tests pass (clean assemblies)
/// - Ensures all negative tests fail with expected error patterns
/// - Validates error message specificity for diagnostic quality
/// - Confirms test coverage across all validation rules
///
/// # Error Validation Strategy
///
/// For failing tests, this function checks:
/// - Specific error types are returned as expected
/// - Error messages contain expected patterns for diagnostic clarity
/// - Error information is preserved in error details for debugging
///
/// # Arguments
///
/// * `results` - Test results from validator execution
/// * `validator_name` - Name of the validator being tested (for error messages)
/// * `expected_error_type` - Expected error type for negative tests (e.g., "InvalidToken")
///
/// # Returns
///
/// Ok(()) if all tests passed as expected, error otherwise
fn file_verify(
    results: &[ValidationTestResult],
    validator_name: &str,
    expected_error_type: &str,
) -> Result<()> {
    if results.is_empty() {
        return Err(Error::Other(
            "No test assemblies were processed".to_string(),
        ));
    }

    let mut positive_tests = 0;
    let mut negative_tests = 0;

    for result in results {
        if result.assembly.should_pass {
            positive_tests += 1;
            if !result.test_passed {
                return Err(Error::Other(format!(
                    "Positive test failed for {}: validation should have passed but got error: {:?}",
                    result.assembly.description(),
                    result.error_message
                )));
            }
            if !result.validation_succeeded {
                return Err(Error::Other(format!(
                    "Clean assembly {} failed {} validation unexpectedly",
                    result.assembly.description(),
                    validator_name
                )));
            }
        } else {
            negative_tests += 1;
            if !result.test_passed {
                return Err(Error::Other(format!(
                    "Negative test failed for {}: expected validation failure with pattern '{:?}' but got: validation_succeeded={}, error={:?}",
                    result.assembly.description(),
                    result.assembly.expected_error_pattern,
                    result.validation_succeeded,
                    result.error_message
                )));
            }
            if result.validation_succeeded {
                return Err(Error::Other(format!(
                    "Modified assembly {} passed validation but should have failed",
                    result.assembly.description()
                )));
            }

            // Verify error message contains expected pattern for negative tests
            if let Some(expected_pattern) = &result.assembly.expected_error_pattern {
                if let Some(error_msg) = &result.error_message {
                    if !error_msg.contains(expected_pattern) {
                        return Err(Error::Other(format!(
                            "Error message '{error_msg}' does not contain expected pattern '{expected_pattern}'"
                        )));
                    }
                    // Verify it's the expected error type
                    if !expected_error_type.is_empty() && !error_msg.contains(expected_error_type) {
                        return Err(Error::Other(format!(
                            "Expected {expected_error_type} but got: {error_msg}"
                        )));
                    }
                }
            }
        }
    }

    // Ensure we have at least one positive test (clean assembly)
    if positive_tests < 1 {
        return Err(Error::Other("No positive test cases found".to_string()));
    }

    // Verify comprehensive coverage - we should have negative tests for validation rules
    if results.len() > 1 && negative_tests < 1 {
        return Err(Error::Other(format!(
            "Expected negative tests for validation rules, got {negative_tests}"
        )));
    }

    Ok(())
}

/// Runs comprehensive validator tests using the centralized test harness.
///
/// This function orchestrates the complete validator testing process:
/// 1. Creates test assemblies using the provided file factory
/// 2. Runs validation tests on each assembly
/// 3. Collects and analyzes results
/// 4. Performs comprehensive verification using the default verification logic
///
/// The test harness automatically handles:
/// - Positive and negative test case validation
/// - Error message pattern matching
/// - Test coverage verification
/// - Assembly cleanup and error handling
///
/// # Arguments
///
/// * `file_factory` - Function that creates test assemblies with specific validation issues
/// * `validator_name` - Name of the validator being tested (for error messages)
/// * `expected_error_type` - Expected error type for negative tests (e.g., "InvalidToken")
/// * `validation_config` - Configuration for the validation run
/// * `run_validator` - Function that executes the validator on a given context
///
/// # Returns
///
/// Ok(()) if all tests pass as expected, error otherwise
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::test::{validator_test, TestAssembly};
/// use dotscope::metadata::validation::ValidationConfig;
///
/// fn my_file_factory() -> Result<Vec<TestAssembly>> {
///     // Create test assemblies
///     Ok(vec![])
/// }
///
/// validator_test(
///     my_file_factory,
///     "MyValidator",
///     "ValidationError",
///     ValidationConfig::default(),
///     |context| my_validator.validate(context),
/// )?;
/// ```
pub fn validator_test<F>(
    file_factory: FileFactory,
    validator_name: &str,
    expected_error_type: &str,
    validation_config: ValidationConfig,
    run_validator: F,
) -> Result<()>
where
    F: Fn(&RawValidationContext) -> Result<()>,
{
    let test_assemblies = file_factory()?;
    if test_assemblies.is_empty() {
        return Err(Error::Other("No test-assembly found!".to_string()));
    }

    let mut test_results = Vec::new();

    for assembly in test_assemblies {
        let validation_result = run_validation_test(&assembly, &validation_config, &run_validator);

        let test_result = match validation_result {
            Ok(()) => ValidationTestResult {
                test_passed: assembly.should_pass,
                validation_succeeded: true,
                error_message: None,
                assembly,
            },
            Err(error) => {
                let error_msg = format!("{error:?}");
                let test_passed = if assembly.should_pass {
                    false
                } else if let Some(expected_pattern) = &assembly.expected_error_pattern {
                    error_msg.contains(expected_pattern)
                } else {
                    true
                };

                ValidationTestResult {
                    test_passed,
                    validation_succeeded: false,
                    error_message: Some(error_msg),
                    assembly,
                }
            }
        };

        test_results.push(test_result);
    }

    file_verify(&test_results, validator_name, expected_error_type)
}

/// Runs comprehensive owned validator tests using the centralized test harness.
///
/// This function provides the same functionality as `validator_test` but for owned validators
/// that operate on resolved metadata structures through `CilObject`. It orchestrates:
/// 1. Creates test assemblies using the provided file factory
/// 2. Creates both CilAssemblyView (for ReferenceScanner) and CilObject (for resolved metadata)
/// 3. Runs owned validation tests on each assembly
/// 4. Collects and analyzes results using the same verification logic
///
/// # Arguments
///
/// * `file_factory` - Function that creates test assemblies with specific validation issues
/// * `validator_name` - Name of the validator being tested (for error messages)
/// * `expected_error_type` - Expected error type for negative tests (e.g., "ValidationOwnedFailed")
/// * `validation_config` - Configuration for the validation run
/// * `run_validator` - Function that executes the owned validator on a given context
///
/// # Returns
///
/// Ok(()) if all tests pass as expected, error otherwise
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::test::{owned_validator_test, TestAssembly};
/// use dotscope::metadata::validation::ValidationConfig;
///
/// fn my_file_factory() -> Result<Vec<TestAssembly>> {
///     // Create test assemblies
///     Ok(vec![])
/// }
///
/// owned_validator_test(
///     my_file_factory,
///     "MyOwnedValidator",
///     "ValidationOwnedFailed",
///     ValidationConfig::default(),
///     |context| my_owned_validator.validate_owned(context),
/// )?;
/// ```
pub fn owned_validator_test<F>(
    file_factory: FileFactory,
    validator_name: &str,
    expected_error_type: &str,
    validation_config: ValidationConfig,
    run_validator: F,
) -> Result<()>
where
    F: Fn(&OwnedValidationContext) -> Result<()>,
{
    let test_assemblies = file_factory()?;
    if test_assemblies.is_empty() {
        return Err(Error::Other("No test-assembly found!".to_string()));
    }

    let mut test_results = Vec::new();

    for assembly in test_assemblies {
        let validation_result =
            run_owned_validation_test(&assembly, &validation_config, &run_validator);

        let test_result = match validation_result {
            Ok(()) => ValidationTestResult {
                test_passed: assembly.should_pass,
                validation_succeeded: true,
                error_message: None,
                assembly,
            },
            Err(error) => {
                let error_msg = format!("{error:?}");
                let test_passed = if assembly.should_pass {
                    false
                } else if let Some(expected_pattern) = &assembly.expected_error_pattern {
                    error_msg.contains(expected_pattern)
                } else {
                    true
                };

                ValidationTestResult {
                    test_passed,
                    validation_succeeded: false,
                    error_message: Some(error_msg),
                    assembly,
                }
            }
        };

        test_results.push(test_result);
    }

    file_verify(&test_results, validator_name, expected_error_type)
}

fn run_validation_test<F>(
    assembly: &TestAssembly,
    config: &ValidationConfig,
    run_validator: &F,
) -> Result<()>
where
    F: Fn(&RawValidationContext) -> Result<()>,
{
    // Disable validation during loading to test individual validators in isolation.
    // The test harness controls which validators run via the run_validator callback.
    let assembly_view = assembly.load()?;
    let scanner = ReferenceScanner::from_view(&assembly_view)?;
    let thread_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();
    let context =
        RawValidationContext::new_for_loading(&assembly_view, &scanner, config, &thread_pool);
    run_validator(&context)
}

fn run_owned_validation_test<F>(
    assembly: &TestAssembly,
    config: &ValidationConfig,
    run_validator: &F,
) -> Result<()>
where
    F: Fn(&OwnedValidationContext) -> Result<()>,
{
    use std::io::Write;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mono_deps_path = Path::new(&manifest_dir).join("tests/samples/mono_4.8");

    // Disable validation during loading to test individual validators in isolation.
    let assembly_view = assembly.load()?;

    // For ProjectLoader, we need a file path. For memory-backed assemblies,
    // create a temporary file.
    let _temp_file: Option<NamedTempFile>;
    let primary_path: PathBuf = match &assembly.source {
        TestAssemblySource::File { path, .. } => path.clone(),
        TestAssemblySource::Memory(data) => {
            let mut temp = NamedTempFile::new().map_err(|e| {
                Error::Other(format!(
                    "Failed to create temp file for owned validation: {e}"
                ))
            })?;
            temp.write_all(data).map_err(|e| {
                Error::Other(format!(
                    "Failed to write temp file for owned validation: {e}"
                ))
            })?;
            let path = temp.path().to_path_buf();
            _temp_file = Some(temp);
            path
        }
    };

    // Load CilObject with dependencies using ProjectLoader
    // Enable strict mode for validator tests so loading failures cause immediate errors
    // Disable validation during loading to test raw validator logic
    let project_result = crate::project::ProjectLoader::new()
        .primary_file(&primary_path)?
        .with_search_path(&mono_deps_path)?
        .auto_discover(true)
        .strict_mode(true)
        .with_validation(ValidationConfig::disabled())
        .build()?;

    let object = project_result
        .project
        .get_primary()
        .ok_or_else(|| Error::Other("Failed to get primary assembly from project".to_string()))?;

    let scanner = ReferenceScanner::from_view(&assembly_view)?;
    let thread_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();
    let context = OwnedValidationContext::new(object.as_ref(), &scanner, config, &thread_pool);
    run_validator(&context)
}

/// Gets the path to the clean test file (WindowsBase.dll) for validator testing.
///
/// This function provides a centralized way to locate the clean assembly file
/// used across all validator tests. It uses the cargo manifest directory to
/// construct the correct path regardless of where tests are run from.
///
/// # Returns
///
/// - `Some(PathBuf)` - Path to WindowsBase.dll if it exists
/// - `None` - If WindowsBase.dll is not available
pub fn get_testfile_wb() -> Option<PathBuf> {
    let windowsbase_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    if windowsbase_path.exists() {
        Some(windowsbase_path)
    } else {
        None
    }
}

/// Returns path to crafted_2.exe for use as a clean test assembly with proper identity.
///
/// This is preferred over WindowsBase.dll for validation tests that create new types,
/// since crafted_2.exe has its own identity and created types will be recognized
/// as target assembly types.
pub fn get_testfile_crafted2() -> Option<PathBuf> {
    let crafted_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/crafted_2.exe");
    if crafted_path.exists() {
        Some(crafted_path)
    } else {
        None
    }
}

/// Returns path to mscorlib.dll for use as a completely self-contained test assembly.
///
/// This is the best choice for modification tests that don't need to test cross-assembly
/// dependencies, since mscorlib.dll has zero external dependencies and is completely
/// self-contained. This makes tests faster and more reliable than using assemblies
/// with many dependencies.
///
/// # Returns
///
/// - `Some(PathBuf)` - Path to mscorlib.dll if it exists
/// - `None` - If mscorlib.dll is not available
pub fn get_testfile_mscorlib() -> Option<PathBuf> {
    let mscorlib_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/mono_4.8/mscorlib.dll");
    if mscorlib_path.exists() {
        Some(mscorlib_path)
    } else {
        None
    }
}
