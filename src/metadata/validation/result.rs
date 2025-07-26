//! Validation result types for collecting and aggregating validation outcomes.
//!
//! This module provides types for representing validation results from individual validators
//! and aggregating them across multiple validators and validation stages. The result system
//! supports both fail-fast (Stage 1) and collect-all-errors (Stage 2) execution models.
//!
//! # Architecture
//!
//! The result system has three main components:
//! 1. **Individual Outcomes**: [`crate::metadata::validation::result::ValidationOutcome`] represents single validator results
//! 2. **Stage Results**: [`crate::metadata::validation::result::ValidationResult`] aggregates outcomes within a validation stage
//! 3. **Two-Stage Results**: [`crate::metadata::validation::result::TwoStageValidationResult`] combines both raw and owned validation stages
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::result::ValidationResult`] - Aggregated results from multiple validators
//! - [`crate::metadata::validation::result::ValidationOutcome`] - Result from a single validator
//! - [`crate::metadata::validation::result::TwoStageValidationResult`] - Combined results from both validation stages
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{ValidationResult, ValidationOutcome};
//! use dotscope::{Result, Error};
//! use std::time::Duration;
//!
//! // Create result from individual validator outcomes
//! let validator_results = vec![
//!     ("Validator1", Ok(()) as Result<()>),
//!     ("Validator2", Err(Error::NotSupported)),
//! ];
//!
//! let result = ValidationResult::from_named_results(
//!     validator_results,
//!     Duration::from_millis(100)
//! );
//!
//! if result.is_failure() {
//!     println!("Validation failed: {} errors", result.failure_count());
//!     for failure in result.failures() {
//!         println!("  {}: {:?}", failure.validator_name(), failure.error());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`], allowing results to be safely
//! passed between threads and aggregated in parallel validation scenarios.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Produces validation results
//! - [`crate::metadata::validation::traits`] - Validators return [`crate::Result`] converted to outcomes
//! - [`crate::Error`] - Error types used in failed validation outcomes

use crate::{Error, Result};
use std::{fmt, time::Duration};

/// Represents the outcome of a validation operation.
///
/// This type is used to collect validation results from multiple validators
/// and provide detailed information about validation success or failure.
/// It aggregates [`crate::metadata::validation::result::ValidationOutcome`] instances
/// from individual validators.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ValidationResult;
/// use dotscope::{Result, Error};
/// use std::time::Duration;
///
/// let results = vec![
///     Ok(()),
///     Err(Error::NotSupported),
///     Ok(()),
/// ];
///
/// let validation_result = ValidationResult::from_results(results, Duration::from_millis(100));
///
/// if validation_result.is_failure() {
///     println!("Failed validators: {}", validation_result.failure_count());
///     for error in validation_result.errors() {
///         println!("Error: {}", error);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`], making it safe to use in concurrent validation scenarios.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Individual validation outcomes from each validator
    outcomes: Vec<ValidationOutcome>,
    /// Total number of validators that ran
    validator_count: usize,
    /// Total time spent on validation
    duration: Duration,
    /// Whether validation was successful overall
    success: bool,
}

impl ValidationResult {
    /// Creates a new successful validation result.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::result::ValidationResult`] representing successful validation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationResult;
    ///
    /// let result = ValidationResult::success();
    /// assert!(result.is_success());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn success() -> Self {
        Self {
            outcomes: Vec::new(),
            validator_count: 0,
            duration: Duration::ZERO,
            success: true,
        }
    }

    /// Creates a validation result from a collection of individual results.
    ///
    /// This method aggregates results from multiple validators, collecting all
    /// errors and computing overall success status.
    ///
    /// # Arguments
    ///
    /// * `results` - Individual validation results from validators as [`Vec<Result<()>>`]
    /// * `duration` - Total time spent on validation as [`std::time::Duration`]
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::result::ValidationResult`] aggregating all individual results.
    #[must_use]
    pub fn from_results(results: Vec<Result<()>>, duration: Duration) -> Self {
        let mut outcomes = Vec::with_capacity(results.len());
        let mut success = true;

        for (index, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => {
                    outcomes.push(ValidationOutcome::success(format!("Validator {index}")));
                }
                Err(error) => {
                    success = false;
                    outcomes.push(ValidationOutcome::failure(
                        format!("Validator {index}"),
                        error,
                    ));
                }
            }
        }

        Self {
            validator_count: outcomes.len(),
            outcomes,
            duration,
            success,
        }
    }

    /// Creates a validation result from named validator results.
    ///
    /// This variant allows associating validator names with their results for
    /// better error reporting and debugging.
    ///
    /// # Arguments
    ///
    /// * `named_results` - Pairs of (validator_name, result)
    /// * `duration` - Total time spent on validation
    #[must_use]
    pub fn from_named_results(named_results: Vec<(&str, Result<()>)>, duration: Duration) -> Self {
        let mut outcomes = Vec::with_capacity(named_results.len());
        let mut success = true;

        for (name, result) in named_results {
            match result {
                Ok(()) => {
                    outcomes.push(ValidationOutcome::success(name.to_string()));
                }
                Err(error) => {
                    success = false;
                    outcomes.push(ValidationOutcome::failure(name.to_string(), error));
                }
            }
        }

        Self {
            validator_count: outcomes.len(),
            outcomes,
            duration,
            success,
        }
    }

    /// Combines multiple validation results into a single result.
    ///
    /// This is useful for combining results from different validation stages
    /// or groups of validators.
    ///
    /// # Arguments
    ///
    /// * `results` - Collection of validation results to combine
    #[must_use]
    pub fn combine(results: Vec<ValidationResult>) -> Self {
        let mut combined_outcomes = Vec::new();
        let mut total_validator_count = 0;
        let mut total_duration = Duration::ZERO;
        let mut overall_success = true;

        for result in results {
            combined_outcomes.extend(result.outcomes);
            total_validator_count += result.validator_count;
            total_duration += result.duration;
            overall_success = overall_success && result.success;
        }

        Self {
            outcomes: combined_outcomes,
            validator_count: total_validator_count,
            duration: total_duration,
            success: overall_success,
        }
    }

    /// Returns whether the validation was successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Returns whether the validation failed.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !self.success
    }

    /// Returns the number of validators that ran.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.validator_count
    }

    /// Returns the total validation duration.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns all validation outcomes.
    #[must_use]
    pub fn outcomes(&self) -> &[ValidationOutcome] {
        &self.outcomes
    }

    /// Returns only the failed validation outcomes.
    #[must_use]
    pub fn failures(&self) -> Vec<&ValidationOutcome> {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.is_failure())
            .collect()
    }

    /// Returns the number of failed validators.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.is_failure())
            .count()
    }

    /// Returns all errors from failed validations.
    #[must_use]
    pub fn errors(&self) -> Vec<&Error> {
        self.outcomes
            .iter()
            .filter_map(|outcome| outcome.error())
            .collect()
    }

    /// Converts this result into a standard `Result<(), Error>`.
    ///
    /// If validation was successful, returns `Ok(())`. If validation failed,
    /// returns an appropriate error containing details about the failures.
    ///
    /// # Errors
    ///
    /// Returns an error if validation failed, containing details about all validation failures.
    pub fn into_result(self) -> Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            let errors = self.errors().into_iter().cloned().collect::<Vec<_>>();
            let error_count = errors.len();
            let summary = format!(
                "{} of {} validators failed",
                error_count, self.validator_count
            );

            Err(Error::ValidationStage2Failed {
                errors,
                error_count,
                summary,
            })
        }
    }

    /// Returns the first error if validation failed.
    #[must_use]
    pub fn first_error(&self) -> Option<&Error> {
        self.failures().first().and_then(|outcome| outcome.error())
    }
}

impl fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_success() {
            write!(
                f,
                "Validation successful: {} validators passed in {:?}",
                self.validator_count, self.duration
            )
        } else {
            write!(
                f,
                "Validation failed: {} of {} validators failed in {:?}",
                self.failure_count(),
                self.validator_count,
                self.duration
            )
        }
    }
}

/// Represents the outcome of a single validator.
///
/// This type captures the result of running a single validator, including
/// success/failure status, any errors, and timing information.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ValidationOutcome;
/// use dotscope::Error;
/// use std::time::Duration;
///
/// // Create a successful outcome
/// let success = ValidationOutcome::success("MyValidator".to_string());
/// assert!(success.is_success());
///
/// // Create a failed outcome
/// let failure = ValidationOutcome::failure("MyValidator".to_string(), Error::NotSupported);
/// assert!(failure.is_failure());
/// assert!(failure.error().is_some());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`], allowing outcomes to be safely shared between threads.
#[derive(Debug, Clone)]
pub struct ValidationOutcome {
    /// Name of the validator
    validator_name: String,
    /// Whether the validation succeeded
    success: bool,
    /// Error if validation failed
    error: Option<Error>,
    /// Time spent on this validator
    duration: Duration,
}

impl ValidationOutcome {
    /// Creates a successful validation outcome.
    ///
    /// # Arguments
    ///
    /// * `validator_name` - Name of the validator that succeeded
    #[must_use]
    pub fn success(validator_name: String) -> Self {
        Self {
            validator_name,
            success: true,
            error: None,
            duration: Duration::ZERO,
        }
    }

    /// Creates a successful validation outcome with duration.
    ///
    /// # Arguments
    ///
    /// * `validator_name` - Name of the validator that succeeded
    /// * `duration` - Time spent on validation
    #[must_use]
    pub fn success_with_duration(validator_name: String, duration: Duration) -> Self {
        Self {
            validator_name,
            success: true,
            error: None,
            duration,
        }
    }

    /// Creates a failed validation outcome.
    ///
    /// # Arguments
    ///
    /// * `validator_name` - Name of the validator that failed
    /// * `error` - The validation error
    #[must_use]
    pub fn failure(validator_name: String, error: Error) -> Self {
        Self {
            validator_name,
            success: false,
            error: Some(error),
            duration: Duration::ZERO,
        }
    }

    /// Creates a failed validation outcome with duration.
    ///
    /// # Arguments
    ///
    /// * `validator_name` - Name of the validator that failed
    /// * `error` - The validation error
    /// * `duration` - Time spent on validation
    #[must_use]
    pub fn failure_with_duration(validator_name: String, error: Error, duration: Duration) -> Self {
        Self {
            validator_name,
            success: false,
            error: Some(error),
            duration,
        }
    }

    /// Returns the validator name.
    #[must_use]
    pub fn validator_name(&self) -> &str {
        &self.validator_name
    }

    /// Returns whether the validation succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Returns whether the validation failed.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !self.success
    }

    /// Returns the error if validation failed.
    #[must_use]
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// Returns the validation duration.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.duration
    }
}

impl fmt::Display for ValidationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_success() {
            write!(f, "{}: SUCCESS ({:?})", self.validator_name, self.duration)
        } else {
            write!(
                f,
                "{}: FAILED ({:?}) - {}",
                self.validator_name,
                self.duration,
                self.error
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref()
                    .unwrap_or("Unknown error")
            )
        }
    }
}

/// Result type for two-stage validation operations.
///
/// This type tracks the results of both Stage 1 (raw) and Stage 2 (owned)
/// validation, allowing for detailed reporting of which stage failed and why.
/// It combines results from [`crate::metadata::validation::traits::RawValidator`]
/// and [`crate::metadata::validation::traits::OwnedValidator`] implementations.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{TwoStageValidationResult, ValidationResult};
/// use std::time::Duration;
///
/// let mut two_stage = TwoStageValidationResult::new();
///
/// // Set Stage 1 result
/// let stage1_result = ValidationResult::success();
/// two_stage.set_stage1_result(stage1_result);
///
/// // Check results
/// assert!(two_stage.stage1_passed());
/// assert!(two_stage.is_success());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`], allowing two-stage results to be safely used in concurrent scenarios.
#[derive(Debug, Clone)]
pub struct TwoStageValidationResult {
    /// Result from Stage 1 (raw validation)
    stage1_result: Option<ValidationResult>,
    /// Result from Stage 2 (owned validation)
    stage2_result: Option<ValidationResult>,
    /// Overall duration
    total_duration: Duration,
}

impl TwoStageValidationResult {
    /// Creates a new two-stage validation result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stage1_result: None,
            stage2_result: None,
            total_duration: Duration::ZERO,
        }
    }

    /// Sets the Stage 1 validation result.
    pub fn set_stage1_result(&mut self, result: ValidationResult) {
        self.total_duration += result.duration();
        self.stage1_result = Some(result);
    }

    /// Sets the Stage 2 validation result.
    pub fn set_stage2_result(&mut self, result: ValidationResult) {
        self.total_duration += result.duration();
        self.stage2_result = Some(result);
    }

    /// Returns the Stage 1 result if available.
    #[must_use]
    pub fn stage1_result(&self) -> Option<&ValidationResult> {
        self.stage1_result.as_ref()
    }

    /// Returns the Stage 2 result if available.
    #[must_use]
    pub fn stage2_result(&self) -> Option<&ValidationResult> {
        self.stage2_result.as_ref()
    }

    /// Returns whether Stage 1 passed.
    #[must_use]
    pub fn stage1_passed(&self) -> bool {
        self.stage1_result
            .as_ref()
            .is_none_or(ValidationResult::is_success)
    }

    /// Returns whether Stage 2 passed.
    #[must_use]
    pub fn stage2_passed(&self) -> bool {
        self.stage2_result
            .as_ref()
            .is_none_or(ValidationResult::is_success)
    }

    /// Returns whether both stages passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.stage1_passed() && self.stage2_passed()
    }

    /// Returns the total validation duration.
    #[must_use]
    pub fn total_duration(&self) -> Duration {
        self.total_duration
    }

    /// Converts this result into a standard `Result<(), Error>`.
    ///
    /// # Errors
    ///
    /// Returns an error if validation failed in either stage, containing details about the failure.
    pub fn into_result(self) -> Result<()> {
        if let Some(stage1) = &self.stage1_result {
            if stage1.is_failure() {
                if let Some(first_error) = stage1.first_error() {
                    return Err(Error::ValidationStage1Failed {
                        source: Box::new((*first_error).clone()),
                        message: format!(
                            "Stage 1 (raw) validation failed with {} errors",
                            stage1.failure_count()
                        ),
                    });
                }
            }
        }

        if let Some(stage2) = &self.stage2_result {
            if stage2.is_failure() {
                return stage2.clone().into_result();
            }
        }

        Ok(())
    }
}

impl Default for TwoStageValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TwoStageValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Two-stage validation ")?;

        if self.is_success() {
            write!(f, "successful")?;
        } else {
            write!(f, "failed")?;
        }

        write!(f, " (total duration: {:?})", self.total_duration)?;

        if let Some(stage1) = &self.stage1_result {
            write!(f, "\n  Stage 1: {stage1}")?;
        }

        if let Some(stage2) = &self.stage2_result {
            write!(f, "\n  Stage 2: {stage2}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::time::Duration;

    #[test]
    fn test_validation_result_success() {
        let result = ValidationResult::success();
        assert!(result.is_success());
        assert!(!result.is_failure());
        assert_eq!(result.validator_count(), 0);
        assert_eq!(result.failure_count(), 0);
    }

    #[test]
    fn test_validation_result_from_results() {
        let results = vec![Ok(()), Err(Error::NotSupported), Ok(())];

        let validation_result = ValidationResult::from_results(results, Duration::from_millis(100));

        assert!(!validation_result.is_success());
        assert_eq!(validation_result.validator_count(), 3);
        assert_eq!(validation_result.failure_count(), 1);
        assert_eq!(validation_result.duration(), Duration::from_millis(100));
    }

    #[test]
    fn test_validation_result_from_named_results() {
        let results = vec![("Validator1", Ok(())), ("Validator2", Err(Error::Empty))];

        let validation_result =
            ValidationResult::from_named_results(results, Duration::from_millis(50));

        assert!(!validation_result.is_success());
        assert_eq!(validation_result.validator_count(), 2);
        assert_eq!(validation_result.failure_count(), 1);

        let failures = validation_result.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].validator_name(), "Validator2");
    }

    #[test]
    fn test_validation_result_combine() {
        let result1 = ValidationResult::from_results(vec![Ok(())], Duration::from_millis(10));
        let result2 = ValidationResult::from_results(
            vec![Err(Error::NotSupported)],
            Duration::from_millis(20),
        );

        let combined = ValidationResult::combine(vec![result1, result2]);

        assert!(!combined.is_success());
        assert_eq!(combined.validator_count(), 2);
        assert_eq!(combined.failure_count(), 1);
        assert_eq!(combined.duration(), Duration::from_millis(30));
    }

    #[test]
    fn test_validation_outcome() {
        let success_outcome = ValidationOutcome::success("TestValidator".to_string());
        assert!(success_outcome.is_success());
        assert!(!success_outcome.is_failure());
        assert_eq!(success_outcome.validator_name(), "TestValidator");
        assert!(success_outcome.error().is_none());

        let failure_outcome = ValidationOutcome::failure("FailValidator".to_string(), Error::Empty);
        assert!(!failure_outcome.is_success());
        assert!(failure_outcome.is_failure());
        assert_eq!(failure_outcome.validator_name(), "FailValidator");
        assert!(failure_outcome.error().is_some());
    }

    #[test]
    fn test_two_stage_validation_result() {
        let mut two_stage = TwoStageValidationResult::new();

        let stage1_result = ValidationResult::from_results(vec![Ok(())], Duration::from_millis(10));
        let stage2_result = ValidationResult::from_results(
            vec![Err(Error::NotSupported)],
            Duration::from_millis(20),
        );

        two_stage.set_stage1_result(stage1_result);
        two_stage.set_stage2_result(stage2_result);

        assert!(two_stage.stage1_passed());
        assert!(!two_stage.stage2_passed());
        assert!(!two_stage.is_success());
        assert_eq!(two_stage.total_duration(), Duration::from_millis(30));
    }

    #[test]
    fn test_validation_result_into_result() {
        let success_result = ValidationResult::success();
        assert!(success_result.into_result().is_ok());

        let failure_result = ValidationResult::from_results(
            vec![Err(Error::NotSupported)],
            Duration::from_millis(10),
        );
        assert!(failure_result.into_result().is_err());
    }
}
