//! .NET assembly execution utilities
//!
//! This module handles execution of .NET assemblies using the detected runtime
//! from TestCapabilities.

use crate::prelude::*;
use crate::test::mono::capabilities::{Runtime, TestCapabilities};
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

/// Result of executing an assembly
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Whether execution succeeded (exit code 0)
    pub success: bool,
    /// Exit code from the process
    pub exit_code: Option<i32>,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Which runtime was used
    pub runtime: Option<Runtime>,
}

impl ExecutionResult {
    /// Create a successful execution result
    pub fn success(stdout: String, runtime: Runtime) -> Self {
        Self {
            success: true,
            exit_code: Some(0),
            stdout,
            stderr: String::new(),
            runtime: Some(runtime),
        }
    }

    /// Create a failed execution result
    pub fn failure(exit_code: Option<i32>, stdout: String, stderr: String) -> Self {
        Self {
            success: false,
            exit_code,
            stdout,
            stderr,
            runtime: None,
        }
    }

    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get combined output (stdout + stderr)
    pub fn combined_output(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }

    /// Get error summary for display
    pub fn error_summary(&self) -> String {
        if self.success {
            "Success".to_string()
        } else if !self.stderr.is_empty() {
            // Include all stderr for error diagnosis
            self.stderr.clone()
        } else if !self.stdout.is_empty() {
            // Look for ERROR lines first, otherwise show all output
            let error_lines: Vec<&str> = self
                .stdout
                .lines()
                .filter(|line| line.contains("ERROR"))
                .collect();
            if !error_lines.is_empty() {
                error_lines.join("\n")
            } else {
                self.stdout.clone()
            }
        } else {
            format!("Failed with exit code {:?}", self.exit_code)
        }
    }
}

/// Execute an assembly using the detected runtime
pub fn execute(capabilities: &TestCapabilities, assembly_path: &Path) -> Result<ExecutionResult> {
    let runtime = match capabilities.runtime {
        Some(r) => r,
        None => {
            return Ok(ExecutionResult::failure(
                None,
                String::new(),
                "No .NET runtime available".to_string(),
            ))
        }
    };

    execute_with_runtime(runtime, assembly_path)
}

/// Execute an assembly with a specific runtime
pub fn execute_with_runtime(runtime: Runtime, assembly_path: &Path) -> Result<ExecutionResult> {
    let output = match runtime {
        Runtime::Mono => execute_with_mono(assembly_path)?,
        Runtime::DotNet => execute_with_dotnet(assembly_path)?,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code();

    if output.status.success() {
        let mut result = ExecutionResult::success(stdout, runtime);
        result.stderr = stderr;
        result.exit_code = exit_code;
        Ok(result)
    } else {
        Ok(ExecutionResult::failure(exit_code, stdout, stderr))
    }
}

/// Execute using Mono runtime
fn execute_with_mono(assembly_path: &Path) -> Result<Output> {
    Command::new("mono")
        .arg(assembly_path)
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute mono: {}", e)))
}

/// Execute using dotnet runtime
fn execute_with_dotnet(assembly_path: &Path) -> Result<Output> {
    // For dotnet, we need to run from the assembly's directory
    // so it can find the runtimeconfig.json
    let mut cmd = Command::new("dotnet");

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

    cmd.output()
        .map_err(|e| Error::Other(format!("Failed to execute dotnet: {}", e)))
}

/// Execute an assembly and verify it produces expected output
pub fn execute_and_verify(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
    expected_output: &str,
) -> Result<ExecutionResult> {
    let result = execute(capabilities, assembly_path)?;

    if result.is_success() {
        if result.stdout.contains(expected_output) {
            Ok(result)
        } else {
            let output = result.stdout.trim().to_string();
            Ok(ExecutionResult::failure(
                result.exit_code,
                result.stdout,
                format!(
                    "Output mismatch: expected '{}', got '{}'",
                    expected_output, output
                ),
            ))
        }
    } else {
        Ok(result)
    }
}

/// Execute an assembly with a timeout
pub fn execute_with_timeout(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
    timeout: Duration,
) -> Result<ExecutionResult> {
    let runtime = match capabilities.runtime {
        Some(r) => r,
        None => {
            return Ok(ExecutionResult::failure(
                None,
                String::new(),
                "No .NET runtime available".to_string(),
            ))
        }
    };

    let mut cmd = match runtime {
        Runtime::Mono => {
            let mut c = Command::new("mono");
            c.arg(assembly_path);
            c
        }
        Runtime::DotNet => {
            let mut c = Command::new("dotnet");
            if let Some(parent) = assembly_path.parent() {
                c.current_dir(parent);
                if let Some(filename) = assembly_path.file_name() {
                    c.arg(filename);
                } else {
                    c.arg(assembly_path);
                }
            } else {
                c.arg(assembly_path);
            }
            c
        }
    };

    // Spawn and wait with timeout
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("Failed to spawn process: {}", e)))?;

    match child.wait_timeout(timeout) {
        Ok(Some(status)) => {
            let stdout = child
                .stdout
                .take()
                .map(|mut s| {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut s, &mut buf).ok();
                    buf
                })
                .unwrap_or_default();

            let stderr = child
                .stderr
                .take()
                .map(|mut s| {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut s, &mut buf).ok();
                    buf
                })
                .unwrap_or_default();

            if status.success() {
                let mut result = ExecutionResult::success(stdout, runtime);
                result.stderr = stderr;
                result.exit_code = status.code();
                Ok(result)
            } else {
                Ok(ExecutionResult::failure(status.code(), stdout, stderr))
            }
        }
        Ok(None) => {
            // Timeout - kill the process
            child.kill().ok();
            Ok(ExecutionResult::failure(
                None,
                String::new(),
                format!("Execution timed out after {:?}", timeout),
            ))
        }
        Err(e) => Err(Error::Other(format!("Failed to wait for process: {}", e))),
    }
}

/// Extension trait for Child to add wait_timeout
trait ChildExt {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildExt for std::process::Child {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(10);

        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    std::thread::sleep(poll_interval);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::mono::compilation::{compile, templates};
    use tempfile::TempDir;

    #[test]
    fn test_execution_result() {
        let success = ExecutionResult::success("Hello".to_string(), Runtime::Mono);
        assert!(success.is_success());
        assert_eq!(success.stdout, "Hello");

        let failure = ExecutionResult::failure(Some(1), String::new(), "Error".to_string());
        assert!(!failure.is_success());
        assert_eq!(failure.exit_code, Some(1));
    }

    #[test]
    fn test_execute_hello_world() -> Result<()> {
        let caps = TestCapabilities::detect();
        if !caps.can_test() {
            println!("Skipping: no compiler/runtime available");
            return Ok(());
        }

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();

        // Compile
        let compile_result = compile(
            &caps,
            templates::HELLO_WORLD,
            temp_dir.path(),
            "hello",
            arch,
        )?;
        assert!(compile_result.is_success(), "Compilation failed");

        // Execute
        let exec_result = execute(&caps, compile_result.assembly_path())?;
        assert!(
            exec_result.is_success(),
            "Execution failed: {}",
            exec_result.error_summary()
        );
        assert!(exec_result.stdout.contains("Hello from dotscope test!"));

        Ok(())
    }
}
