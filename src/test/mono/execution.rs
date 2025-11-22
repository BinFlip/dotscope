//! .NET runtime testing utilities
//!
//! This module provides utilities for testing .NET assemblies against various runtimes
//! (Mono or modern .NET), including version detection, execution testing, and output validation.

use crate::prelude::*;
use crate::test::mono::compilation::CompilerType;
use std::path::Path;
use std::process::Command;

/// Runtime type for executing .NET assemblies
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeType {
    /// Mono runtime (for .NET Framework assemblies)
    Mono,
    /// Modern .NET runtime (for .NET 8.0+ assemblies)
    DotNet,
}

impl RuntimeType {
    /// Determine the appropriate runtime based on compiler type
    pub fn for_compiler(compiler: &CompilerType) -> Self {
        match compiler {
            CompilerType::DotNet => RuntimeType::DotNet,
            CompilerType::Csc | CompilerType::Mcs => RuntimeType::Mono,
        }
    }
}

/// Mono runtime environment and execution utilities
pub struct MonoRuntime {
    version_info: Option<MonoVersionInfo>,
    /// Override runtime type (if None, will auto-detect based on availability)
    runtime_override: Option<RuntimeType>,
}

impl MonoRuntime {
    /// Create new Mono runtime instance
    pub fn new() -> Self {
        Self {
            version_info: None,
            runtime_override: None,
        }
    }

    /// Create a runtime instance configured for a specific runtime type
    pub fn with_runtime(runtime_type: RuntimeType) -> Self {
        Self {
            version_info: None,
            runtime_override: Some(runtime_type),
        }
    }

    /// Set the runtime type to use for execution
    pub fn set_runtime(&mut self, runtime_type: RuntimeType) {
        self.runtime_override = Some(runtime_type);
    }

    /// Check if Mono is available on the system
    pub fn is_available(&self) -> bool {
        self.is_mono_available() || self.is_dotnet_available()
    }

    /// Check if Mono runtime is available
    pub fn is_mono_available(&self) -> bool {
        Command::new("mono").arg("--version").output().is_ok()
    }

    /// Check if modern .NET runtime is available
    pub fn is_dotnet_available(&self) -> bool {
        Command::new("dotnet").arg("--version").output().is_ok()
    }

    /// Get the runtime type that will be used for execution
    pub fn active_runtime(&self) -> Option<RuntimeType> {
        if let Some(ref override_type) = self.runtime_override {
            return Some(override_type.clone());
        }
        // Default preference: mono first, then dotnet
        if self.is_mono_available() {
            Some(RuntimeType::Mono)
        } else if self.is_dotnet_available() {
            Some(RuntimeType::DotNet)
        } else {
            None
        }
    }

    /// Get Mono version information (cached after first call)
    pub fn version_info(&mut self) -> Result<&MonoVersionInfo> {
        if self.version_info.is_none() {
            self.version_info = Some(self.detect_version()?);
        }
        Ok(self.version_info.as_ref().unwrap())
    }

    /// Detect Mono version from system
    fn detect_version(&self) -> Result<MonoVersionInfo> {
        let output = Command::new("mono")
            .arg("--version")
            .output()
            .map_err(|_| Error::Error("mono not available".to_string()))?;

        if !output.status.success() {
            return Err(Error::Error("mono --version failed".to_string()));
        }

        let version_output = String::from_utf8_lossy(&output.stdout);
        let version_line = version_output
            .lines()
            .next()
            .unwrap_or("unknown")
            .to_string();

        Ok(MonoVersionInfo {
            available: true,
            version_string: version_line,
            full_output: version_output.to_string(),
        })
    }

    /// Execute a .NET assembly using the appropriate runtime (Mono or .NET)
    pub fn execute_assembly(&mut self, assembly_path: &Path) -> Result<ExecutionResult> {
        let runtime = match self.active_runtime() {
            Some(rt) => rt,
            None => {
                return Ok(ExecutionResult {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some("No .NET runtime available (neither mono nor dotnet)".to_string()),
                });
            }
        };

        match runtime {
            RuntimeType::Mono => self.execute_with_mono(assembly_path),
            RuntimeType::DotNet => self.execute_with_dotnet(assembly_path),
        }
    }

    /// Execute assembly using Mono runtime
    fn execute_with_mono(&self, assembly_path: &Path) -> Result<ExecutionResult> {
        let output = Command::new("mono")
            .arg(assembly_path)
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute mono: {}", e)))?;

        Ok(ExecutionResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            error: None,
        })
    }

    /// Execute assembly using modern .NET runtime
    fn execute_with_dotnet(&self, assembly_path: &Path) -> Result<ExecutionResult> {
        let mut cmd = Command::new("dotnet");

        // Set working directory to the assembly's directory so .NET can find
        // the runtimeconfig.json and deps.json files for dependency resolution
        if let Some(parent) = assembly_path.parent() {
            cmd.current_dir(parent);
            if let Some(filename) = assembly_path.file_name() {
                cmd.arg(filename);
            } else {
                cmd.arg(assembly_path);
            }
        } else {
            cmd.arg(assembly_path);
        }

        let output = cmd
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute dotnet: {}", e)))?;

        Ok(ExecutionResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            error: None,
        })
    }

    /// Test original executable execution with detailed logging
    pub fn test_original_executable(&mut self, exe_path: &Path) -> Result<ExecutionResult> {
        let result = self.execute_assembly(exe_path)?;
        Ok(result)
    }

    /// Comprehensive runtime compatibility test
    pub fn test_compatibility(
        &mut self,
        file_path: &Path,
        _arch_name: &str,
    ) -> Result<CompatibilityResult> {
        let mut result = CompatibilityResult::new();

        // Check runtime availability and get version info
        let runtime = self.active_runtime();
        result.mono_available = runtime.is_some();

        if let Some(ref rt) = runtime {
            // Get version info based on runtime type
            match rt {
                RuntimeType::Mono => {
                    if let Ok(version) = self.version_info() {
                        result.mono_version = Some(version.version_string.clone());
                    }
                }
                RuntimeType::DotNet => {
                    // Get dotnet version
                    if let Ok(output) = Command::new("dotnet").arg("--version").output() {
                        if output.status.success() {
                            result.mono_version = Some(format!(
                                "dotnet {}",
                                String::from_utf8_lossy(&output.stdout).trim()
                            ));
                        }
                    }
                }
            }
        } else {
            return Ok(result);
        }

        // Test execution
        match self.execute_assembly(file_path) {
            Ok(exec_result) => {
                result.execution_result = Some(exec_result.clone());
                if exec_result.success {
                    result.execution_success = true;
                } else {
                    result.execution_success = false;
                    result.execution_error =
                        exec_result.stderr.lines().next().map(|s| s.to_string());
                }
            }
            Err(e) => {
                result.execution_success = false;
                result.execution_error = Some(e.to_string());
            }
        }

        Ok(result)
    }

    /// Execute assembly with custom arguments
    pub fn execute_with_args(
        &self,
        assembly_path: &Path,
        args: &[&str],
    ) -> Result<ExecutionResult> {
        let runtime = match self.active_runtime() {
            Some(rt) => rt,
            None => {
                return Ok(ExecutionResult {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some("No .NET runtime available".to_string()),
                });
            }
        };

        let (cmd_name, cmd_error) = match runtime {
            RuntimeType::Mono => ("mono", "Failed to execute mono"),
            RuntimeType::DotNet => ("dotnet", "Failed to execute dotnet"),
        };

        let mut cmd = Command::new(cmd_name);
        cmd.arg(assembly_path);
        for arg in args {
            cmd.arg(arg);
        }

        let output = cmd
            .output()
            .map_err(|e| Error::Error(format!("{}: {}", cmd_error, e)))?;

        Ok(ExecutionResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            error: None,
        })
    }

    /// Execute with timeout (requires external timeout utility)
    pub fn execute_with_timeout(
        &mut self,
        assembly_path: &Path,
        timeout_seconds: u32,
    ) -> Result<ExecutionResult> {
        let runtime = match self.active_runtime() {
            Some(rt) => rt,
            None => {
                return Ok(ExecutionResult {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some("No .NET runtime available".to_string()),
                });
            }
        };

        let cmd_name = match runtime {
            RuntimeType::Mono => "mono",
            RuntimeType::DotNet => "dotnet",
        };

        // Use timeout command if available (Unix systems)
        let output = Command::new("timeout")
            .arg(format!("{}s", timeout_seconds))
            .arg(cmd_name)
            .arg(assembly_path)
            .output();

        match output {
            Ok(output) => Ok(ExecutionResult {
                success: output.status.success(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                error: None,
            }),
            Err(_) => {
                // Fallback to regular execution if timeout command not available
                self.execute_assembly(assembly_path)
            }
        }
    }
}

/// Information about Mono runtime version
#[derive(Debug, Clone)]
pub struct MonoVersionInfo {
    pub available: bool,
    pub version_string: String,
    pub full_output: String,
}

/// Result of executing a .NET assembly
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

impl ExecutionResult {
    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get trimmed stdout output
    pub fn output(&self) -> &str {
        self.stdout.trim()
    }

    /// Get first line of stderr if any
    pub fn first_error_line(&self) -> Option<&str> {
        self.stderr.lines().next()
    }

    /// Check if output contains specific text
    pub fn output_contains(&self, text: &str) -> bool {
        self.stdout.contains(text) || self.stderr.contains(text)
    }
}

/// Comprehensive compatibility test result
#[derive(Debug, Clone)]
pub struct CompatibilityResult {
    pub mono_available: bool,
    pub mono_version: Option<String>,
    pub execution_success: bool,
    pub execution_result: Option<ExecutionResult>,
    pub execution_error: Option<String>,
}

impl CompatibilityResult {
    pub fn new() -> Self {
        Self {
            mono_available: true,
            mono_version: None,
            execution_success: false,
            execution_result: None,
            execution_error: None,
        }
    }

    /// Check if all compatibility tests passed
    pub fn is_fully_compatible(&self) -> bool {
        self.mono_available && self.execution_success
    }

    /// Get human-readable status summary
    pub fn status_summary(&self) -> String {
        if !self.mono_available {
            "Mono not available".to_string()
        } else if self.execution_success {
            "Fully compatible".to_string()
        } else {
            format!(
                "Execution failed: {}",
                self.execution_error.as_deref().unwrap_or("Unknown error")
            )
        }
    }
}

/// Utility functions for common execution patterns
pub mod utils {
    use crate::prelude::*;
    use crate::test::mono::execution::MonoRuntime;
    use std::path::Path;

    /// Execute and expect specific output
    pub fn execute_expecting_output(
        runtime: &mut MonoRuntime,
        assembly_path: &Path,
        expected_output: &str,
    ) -> Result<bool> {
        let result = runtime.execute_assembly(assembly_path)?;
        Ok(result.success && result.stdout.trim() == expected_output)
    }

    /// Execute and expect successful exit
    pub fn execute_expecting_success(
        runtime: &mut MonoRuntime,
        assembly_path: &Path,
    ) -> Result<bool> {
        let result = runtime.execute_assembly(assembly_path)?;
        Ok(result.success)
    }

    /// Execute and capture any output
    pub fn execute_and_capture(
        runtime: &mut MonoRuntime,
        assembly_path: &Path,
    ) -> Result<(bool, String)> {
        let result = runtime.execute_assembly(assembly_path)?;
        let output = if !result.stdout.is_empty() {
            result.stdout
        } else {
            result.stderr
        };
        Ok((result.success, output))
    }

    /// Check if assembly runs without crashing (ignores output)
    pub fn check_assembly_stability(
        runtime: &mut MonoRuntime,
        assembly_path: &Path,
    ) -> Result<bool> {
        let result = runtime.execute_assembly(assembly_path)?;
        // Consider it stable if it doesn't crash (exit code 0 or specific error codes are ok)
        Ok(result.exit_code != Some(-1) && result.error.is_none())
    }
}

#[cfg(test)]
mod tests {
    use crate::test::mono::execution::{CompatibilityResult, ExecutionResult, MonoRuntime};

    #[test]
    fn test_mono_runtime_creation() {
        let runtime = MonoRuntime::new();
        // New runtime should have no cached version info and no runtime override
        assert!(runtime.version_info.is_none());
        assert!(runtime.runtime_override.is_none());
    }

    #[test]
    fn test_execution_result() {
        let result = ExecutionResult {
            success: true,
            exit_code: Some(0),
            stdout: "Hello World\n".to_string(),
            stderr: String::new(),
            error: None,
        };

        assert!(result.is_success());
        assert_eq!(result.output(), "Hello World");
        assert!(result.first_error_line().is_none());
        assert!(result.output_contains("Hello"));
    }

    #[test]
    fn test_compatibility_result() {
        let result = CompatibilityResult::new();
        assert!(result.mono_available);
        assert!(!result.execution_success);
        assert!(!result.is_fully_compatible());
    }

    #[test]
    fn test_mono_availability() {
        let runtime = MonoRuntime::new();
        // This test will vary by system, but should not panic
        let _ = runtime.is_available();
    }
}
