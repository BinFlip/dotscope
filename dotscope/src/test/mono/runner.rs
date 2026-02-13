//! Test orchestration and temporary directory management
//!
//! This module provides the test runner infrastructure that coordinates compilation,
//! execution, and verification of .NET assemblies across supported architectures.

use crate::prelude::*;
use crate::test::mono::capabilities::{Architecture, TestCapabilities};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Test runner that manages the test environment and coordinates test execution
pub struct TestRunner {
    /// Temporary directory for test artifacts
    temp_dir: TempDir,
    /// Detected system capabilities
    capabilities: TestCapabilities,
}

impl TestRunner {
    /// Create a new test runner with auto-detected capabilities
    pub fn new() -> Result<Self> {
        let capabilities = TestCapabilities::detect();

        if !capabilities.can_test() {
            return Err(Error::Other(format!(
                "Cannot run tests: no compiler/runtime available. {}",
                capabilities.summary()
            )));
        }

        Ok(Self {
            temp_dir: TempDir::new()?,
            capabilities,
        })
    }

    /// Get the detected capabilities
    pub fn capabilities(&self) -> &TestCapabilities {
        &self.capabilities
    }

    /// Get the temporary directory path
    pub fn temp_path(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Get the supported architectures
    pub fn architectures(&self) -> &[Architecture] {
        &self.capabilities.supported_architectures
    }

    /// Create a file path for an architecture-specific artifact
    pub fn artifact_path(&self, base_name: &str, arch: &Architecture, extension: &str) -> PathBuf {
        self.temp_dir.path().join(format!(
            "{}_{}{}",
            base_name,
            arch.filename_suffix(),
            extension
        ))
    }

    /// Create a subdirectory for an architecture
    pub fn arch_dir(&self, arch: &Architecture) -> Result<PathBuf> {
        let dir = self.temp_dir.path().join(arch.filename_suffix());
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Run a test function for all supported architectures
    pub fn for_each_architecture<F, T>(&self, mut test_fn: F) -> Vec<ArchTestResult<T>>
    where
        F: FnMut(&Architecture, &Path, &TestCapabilities) -> Result<T>,
    {
        let mut results = Vec::new();

        for arch in &self.capabilities.supported_architectures {
            let arch_dir = match self.arch_dir(arch) {
                Ok(dir) => dir,
                Err(e) => {
                    results.push(ArchTestResult {
                        architecture: arch.clone(),
                        success: false,
                        result: None,
                        error: Some(format!("Failed to create arch directory: {}", e)),
                    });
                    continue;
                }
            };

            match test_fn(arch, &arch_dir, &self.capabilities) {
                Ok(result) => {
                    results.push(ArchTestResult {
                        architecture: arch.clone(),
                        success: true,
                        result: Some(result),
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(ArchTestResult {
                        architecture: arch.clone(),
                        success: false,
                        result: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        results
    }

    /// Check if all architecture tests passed
    pub fn all_passed<T>(results: &[ArchTestResult<T>]) -> bool {
        results.iter().all(|r| r.success)
    }

    /// Get failed results with their error messages
    pub fn failed_results<T>(results: &[ArchTestResult<T>]) -> Vec<(&Architecture, &str)> {
        results
            .iter()
            .filter(|r| !r.success)
            .map(|r| {
                (
                    &r.architecture,
                    r.error.as_deref().unwrap_or("Unknown error"),
                )
            })
            .collect()
    }
}

/// Result of running a test for a specific architecture
#[derive(Debug)]
pub struct ArchTestResult<T> {
    pub architecture: Architecture,
    pub success: bool,
    pub result: Option<T>,
    pub error: Option<String>,
}

impl<T> ArchTestResult<T> {
    /// Check if this result was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get the result value if successful
    pub fn value(&self) -> Option<&T> {
        self.result.as_ref()
    }

    /// Get the error message if failed
    pub fn error_message(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_creation() -> Result<()> {
        let runner = TestRunner::new()?;
        println!("Capabilities: {}", runner.capabilities().summary());
        assert!(!runner.architectures().is_empty());
        assert!(runner.temp_path().exists());
        Ok(())
    }

    #[test]
    fn test_artifact_path() -> Result<()> {
        let runner = TestRunner::new()?;
        if let Some(arch) = runner.architectures().first() {
            let path = runner.artifact_path("test", arch, ".exe");
            assert!(path.to_string_lossy().contains(arch.filename_suffix()));
            assert!(path.to_string_lossy().ends_with(".exe"));
        }
        Ok(())
    }

    #[test]
    fn test_arch_dir_creation() -> Result<()> {
        let runner = TestRunner::new()?;
        if let Some(arch) = runner.architectures().first() {
            let dir = runner.arch_dir(arch)?;
            assert!(dir.exists());
            assert!(dir.is_dir());
        }
        Ok(())
    }

    #[test]
    fn test_for_each_architecture() -> Result<()> {
        let runner = TestRunner::new()?;

        let results =
            runner.for_each_architecture(|arch, _dir, _caps| Ok(format!("Tested {}", arch.name)));

        assert!(!results.is_empty());
        assert!(TestRunner::all_passed(&results));

        for result in &results {
            assert!(result.is_success());
            assert!(result.value().is_some());
        }

        Ok(())
    }
}
