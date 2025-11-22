//! Test orchestration and temporary folder management for mono testing
//!
//! This module provides the core test runner infrastructure for mono-based
//! verification tests, handling temporary directory management and dual
//! architecture testing coordination.

use crate::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Architecture configuration for compilation and testing
#[derive(Clone, Debug)]
pub struct ArchConfig {
    pub name: String,
    pub platform_flags: Vec<String>,
}

impl ArchConfig {
    /// Create x86 (32-bit) architecture configuration
    pub fn x86() -> Self {
        Self {
            name: "x86".to_string(),
            platform_flags: vec!["/platform:x86".to_string()],
        }
    }

    /// Create x64 (64-bit) architecture configuration
    pub fn x64() -> Self {
        Self {
            name: "x64".to_string(),
            platform_flags: vec!["/platform:x64".to_string()],
        }
    }

    /// Create both standard architectures
    pub fn standard_architectures() -> Vec<Self> {
        vec![Self::x86(), Self::x64()]
    }

    /// Create architectures available on the current platform
    ///
    /// On Windows, both x86 and x64 are available.
    /// On Linux/macOS, we use AnyCPU plus the native architecture.
    /// x64 assemblies cannot run on ARM64 hardware without emulation.
    pub fn platform_available_architectures() -> Vec<Self> {
        #[cfg(target_os = "windows")]
        {
            vec![Self::x86(), Self::x64()]
        }
        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        {
            // On x86_64 Unix platforms, we can run AnyCPU and x64
            vec![Self::anycpu(), Self::x64()]
        }
        #[cfg(all(not(target_os = "windows"), not(target_arch = "x86_64")))]
        {
            // On ARM64 and other architectures, only use AnyCPU
            // x64-specific assemblies won't run without emulation
            vec![Self::anycpu()]
        }
    }

    /// Create AnyCPU (platform-agnostic) configuration
    pub fn anycpu() -> Self {
        Self {
            name: "anycpu".to_string(),
            platform_flags: vec![],
        }
    }

    /// Get safe filename component for this architecture
    pub fn filename_component(&self) -> String {
        self.name.replace("-", "").to_lowercase()
    }
}

/// Main test runner for mono-based verification
pub struct MonoTestRunner {
    temp_dir: TempDir,
    architectures: Vec<ArchConfig>,
}

impl MonoTestRunner {
    /// Create new test runner with platform-available architectures
    ///
    /// Uses `platform_available_architectures()` to select architectures
    /// that work on the current platform (x86+x64 on Windows, anycpu+x64 elsewhere).
    pub fn new() -> Result<Self> {
        Ok(Self {
            temp_dir: TempDir::new()?,
            architectures: ArchConfig::platform_available_architectures(),
        })
    }

    /// Create test runner with custom architectures
    pub fn with_architectures(architectures: Vec<ArchConfig>) -> Result<Self> {
        Ok(Self {
            temp_dir: TempDir::new()?,
            architectures,
        })
    }

    /// Get path to temporary directory
    pub fn temp_path(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Get configured architectures
    pub fn architectures(&self) -> &[ArchConfig] {
        &self.architectures
    }

    /// Run test for all configured architectures
    pub fn run_for_all_architectures<F, R>(&self, mut test_fn: F) -> Result<Vec<ArchTestResult<R>>>
    where
        F: FnMut(&ArchConfig, &Path) -> Result<R>,
    {
        let mut results = Vec::new();

        for arch in &self.architectures {
            match test_fn(arch, self.temp_path()) {
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
                        error: Some(e),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Create unique file path for architecture-specific files
    pub fn create_arch_file_path(
        &self,
        base_name: &str,
        arch: &ArchConfig,
        extension: &str,
    ) -> PathBuf {
        self.temp_path().join(format!(
            "{}_{}{}",
            base_name,
            arch.filename_component(),
            extension
        ))
    }

    /// Check if all tests passed
    pub fn all_tests_passed<R>(results: &[ArchTestResult<R>]) -> bool {
        results.iter().all(|r| r.success)
    }
}

/// Result of running a test for a specific architecture
#[derive(Debug)]
pub struct ArchTestResult<R> {
    pub architecture: ArchConfig,
    pub success: bool,
    pub result: Option<R>,
    pub error: Option<Error>,
}

impl<R> ArchTestResult<R> {
    /// Check if all results in a collection succeeded
    pub fn all_succeeded(results: &[Self]) -> bool {
        results.iter().all(|r| r.success)
    }

    /// Get first error from a collection of results
    pub fn first_error(results: &[Self]) -> Option<&Error> {
        results.iter().find_map(|r| r.error.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::test::mono::runner::{ArchConfig, MonoTestRunner};

    #[test]
    fn test_arch_config_creation() {
        let x86 = ArchConfig::x86();
        assert_eq!(x86.name, "x86");
        assert_eq!(x86.platform_flags, vec!["/platform:x86"]);
        assert_eq!(x86.filename_component(), "x86");

        let x64 = ArchConfig::x64();
        assert_eq!(x64.name, "x64");
        assert_eq!(x64.platform_flags, vec!["/platform:x64"]);
        assert_eq!(x64.filename_component(), "x64");

        let anycpu = ArchConfig::anycpu();
        assert_eq!(anycpu.name, "anycpu");
        assert!(anycpu.platform_flags.is_empty());
        assert_eq!(anycpu.filename_component(), "anycpu");
    }

    #[test]
    fn test_standard_architectures() {
        let archs = ArchConfig::standard_architectures();
        assert_eq!(archs.len(), 2);
        assert_eq!(archs[0].name, "x86");
        assert_eq!(archs[1].name, "x64");
    }

    #[test]
    fn test_platform_available_architectures() {
        let archs = ArchConfig::platform_available_architectures();
        // On Windows: x86 + x64 (2 archs)
        // On x86_64 Unix: anycpu + x64 (2 archs)
        // On ARM64 Unix: anycpu only (1 arch)
        #[cfg(target_os = "windows")]
        {
            assert_eq!(archs.len(), 2);
            assert_eq!(archs[0].name, "x86");
            assert_eq!(archs[1].name, "x64");
        }
        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        {
            assert_eq!(archs.len(), 2);
            assert_eq!(archs[0].name, "anycpu");
            assert_eq!(archs[1].name, "x64");
        }
        #[cfg(all(not(target_os = "windows"), not(target_arch = "x86_64")))]
        {
            assert_eq!(archs.len(), 1);
            assert_eq!(archs[0].name, "anycpu");
        }
    }

    #[test]
    fn test_runner_creation() -> Result<()> {
        let runner = MonoTestRunner::new()?;
        // Number of architectures depends on platform
        #[cfg(target_os = "windows")]
        assert_eq!(runner.architectures().len(), 2);
        #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
        assert_eq!(runner.architectures().len(), 2);
        #[cfg(all(not(target_os = "windows"), not(target_arch = "x86_64")))]
        assert_eq!(runner.architectures().len(), 1);
        assert!(runner.temp_path().exists());
        Ok(())
    }

    #[test]
    fn test_arch_file_path_creation() -> Result<()> {
        let runner = MonoTestRunner::new()?;
        let arch = ArchConfig::x86();
        let path = runner.create_arch_file_path("test", &arch, ".exe");

        assert!(path.to_string_lossy().contains("test_x86.exe"));
        Ok(())
    }
}
