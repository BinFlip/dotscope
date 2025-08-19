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
        cilobject::CilObject,
        validation::{
            OwnedValidationContext, RawValidationContext, ReferenceScanner, ValidationConfig,
        },
    },
    Error, Result,
};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Test assembly specification for validator testing.
///
/// Each test assembly represents a specific validation scenario, either a clean
/// assembly that should pass validation or a modified assembly designed to trigger
/// specific validation failures.
#[derive(Debug)]
pub struct TestAssembly {
    /// Path to the test assembly file
    pub path: PathBuf,
    /// Whether this assembly should pass (true) or fail (false) validation
    pub should_pass: bool,
    /// Optional specific error message or pattern expected for failing assemblies
    pub expected_error_pattern: Option<String>,
    /// Temp file handle for automatic cleanup
    _temp_file: Option<NamedTempFile>,
}

impl TestAssembly {
    /// Creates a new test assembly specification.
    pub fn new<P: Into<PathBuf>>(path: P, should_pass: bool) -> Self {
        Self {
            path: path.into(),
            should_pass,
            expected_error_pattern: None,
            _temp_file: None,
        }
    }

    /// Creates a test assembly that should fail with a specific error pattern.
    pub fn failing_with_error<P: Into<PathBuf>>(path: P, error_pattern: &str) -> Self {
        Self {
            path: path.into(),
            should_pass: false,
            expected_error_pattern: Some(error_pattern.to_string()),
            _temp_file: None,
        }
    }

    /// Creates a test assembly from a temporary file with automatic cleanup.
    pub fn from_temp_file(temp_file: NamedTempFile, should_pass: bool) -> Self {
        let path = temp_file.path().to_path_buf();
        Self {
            path,
            should_pass,
            expected_error_pattern: None,
            _temp_file: Some(temp_file),
        }
    }

    /// Creates a failing test assembly from a temporary file with specific error pattern.
    pub fn from_temp_file_with_error(temp_file: NamedTempFile, error_pattern: &str) -> Self {
        let path = temp_file.path().to_path_buf();
        Self {
            path,
            should_pass: false,
            expected_error_pattern: Some(error_pattern.to_string()),
            _temp_file: Some(temp_file),
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
/// * `expected_error_type` - Expected error type for negative tests (e.g., "ValidationTokenError")
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
        return Err(Error::Error(
            "No test assemblies were processed".to_string(),
        ));
    }

    let mut positive_tests = 0;
    let mut negative_tests = 0;

    for result in results {
        if result.assembly.should_pass {
            positive_tests += 1;
            if !result.test_passed {
                return Err(Error::Error(format!(
                    "Positive test failed for {}: validation should have passed but got error: {:?}",
                    result.assembly.path.display(),
                    result.error_message
                )));
            }
            if !result.validation_succeeded {
                return Err(Error::Error(format!(
                    "Clean assembly {} failed {} validation unexpectedly",
                    result.assembly.path.display(),
                    validator_name
                )));
            }
        } else {
            negative_tests += 1;
            if !result.test_passed {
                return Err(Error::Error(format!(
                    "Negative test failed for {}: expected validation failure with pattern '{:?}' but got: validation_succeeded={}, error={:?}",
                    result.assembly.path.display(),
                    result.assembly.expected_error_pattern,
                    result.validation_succeeded,
                    result.error_message
                )));
            }
            if result.validation_succeeded {
                return Err(Error::Error(format!(
                    "Modified assembly {} passed validation but should have failed",
                    result.assembly.path.display()
                )));
            }

            // Verify error message contains expected pattern for negative tests
            if let Some(expected_pattern) = &result.assembly.expected_error_pattern {
                if let Some(error_msg) = &result.error_message {
                    if !error_msg.contains(expected_pattern) {
                        return Err(Error::Error(format!(
                            "Error message '{error_msg}' does not contain expected pattern '{expected_pattern}'"
                        )));
                    }
                    // Verify it's the expected error type
                    if !expected_error_type.is_empty() && !error_msg.contains(expected_error_type) {
                        return Err(Error::Error(format!(
                            "Expected {expected_error_type} but got: {error_msg}"
                        )));
                    }
                }
            }
        }
    }

    // Ensure we have at least one positive test (clean assembly)
    if positive_tests < 1 {
        return Err(Error::Error("No positive test cases found".to_string()));
    }

    // Verify comprehensive coverage - we should have negative tests for validation rules
    if results.len() > 1 && negative_tests < 1 {
        return Err(Error::Error(format!(
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
/// * `expected_error_type` - Expected error type for negative tests (e.g., "ValidationTokenError")
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
        return Err(Error::Error("No test-assembly found!".to_string()));
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
/// * `expected_error_type` - Expected error type for negative tests (e.g., "ValidationOwnedValidatorFailed")
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
///     "ValidationOwnedValidatorFailed",
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
        return Err(Error::Error("No test-assembly found!".to_string()));
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
    let assembly_view = CilAssemblyView::from_file(&assembly.path)?;
    let scanner = ReferenceScanner::from_view(&assembly_view)?;
    let context = RawValidationContext::new_for_loading(&assembly_view, &scanner, config);
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
    // Create both CilAssemblyView (for ReferenceScanner) and CilObject (for resolved metadata)
    let assembly_view = CilAssemblyView::from_file(&assembly.path)?;
    let object = CilObject::from_file(&assembly.path)?;
    let scanner = ReferenceScanner::from_view(&assembly_view)?;
    let context = OwnedValidationContext::new(&object, &scanner, config);
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
pub fn get_clean_testfile() -> Option<PathBuf> {
    let windowsbase_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    if windowsbase_path.exists() {
        Some(windowsbase_path)
    } else {
        None
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_validator_harness_example() -> Result<()> {
//         fn example_file_factory() -> Result<Vec<TestAssembly>> {
//             let Some(clean_testfile) = get_clean_testfile() else {
//                 return Err(Error::Error("WindowsBase.dll not available".to_string()));
//             };
//             Ok(vec![TestAssembly::new(clean_testfile, true)])
//         }

//         let example_validator = |_context: &RawValidationContext| -> Result<()> { Ok(()) };

//         validator_test(
//             example_file_factory,
//             "ExampleValidator",
//             "ValidationError",
//             ValidationConfig {
//                 enable_structural_validation: true,
//                 ..Default::default()
//             },
//             example_validator,
//         )
//     }
// }
