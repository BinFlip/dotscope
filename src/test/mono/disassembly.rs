//! IL disassembly utilities
//!
//! This module handles disassembly of .NET assemblies using the detected
//! disassembler from TestCapabilities.

use crate::prelude::*;
use crate::test::mono::capabilities::{Disassembler, TestCapabilities};
use std::path::Path;
use std::process::Command;

/// Result of a disassembly operation
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    /// Whether disassembly succeeded
    pub success: bool,
    /// The disassembled IL output
    pub il_output: String,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Which disassembler was used
    pub disassembler: Option<Disassembler>,
}

impl DisassemblyResult {
    /// Create a successful result
    pub fn success(il_output: String, disassembler: Disassembler) -> Self {
        Self {
            success: true,
            il_output,
            error: None,
            disassembler: Some(disassembler),
        }
    }

    /// Create a failed result
    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            il_output: String::new(),
            error: Some(error),
            disassembler: None,
        }
    }

    /// Check if disassembly was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Check if the failure is due to a missing/broken .NET framework
    ///
    /// This detects cases where a tool like dotnet-ildasm is installed but requires
    /// a .NET framework version that isn't available on the system.
    pub fn is_framework_error(&self) -> bool {
        if let Some(ref error) = self.error {
            // Common patterns for .NET framework version errors
            error.contains("You must install or update .NET to run this application")
                || error.contains("Framework:")
                    && error.contains("version")
                    && error.contains("was not found")
                || error.contains("The framework 'Microsoft.NETCore.App'")
        } else {
            false
        }
    }

    /// Check if the IL output contains a specific method
    pub fn contains_method(&self, method_name: &str) -> bool {
        // Look for method definition pattern: .method ... methodname (
        self.il_output.contains(&format!(" {} ", method_name))
            || self.il_output.contains(&format!(" {}(", method_name))
            || self.il_output.contains(".method") && self.il_output.contains(method_name)
    }

    /// Check if the IL output contains a specific class
    pub fn contains_class(&self, class_name: &str) -> bool {
        self.il_output.contains(".class") && self.il_output.contains(class_name)
    }

    /// Check if the IL output contains a specific instruction
    pub fn contains_instruction(&self, instruction: &str) -> bool {
        self.il_output.lines().any(|line| {
            let trimmed = line.trim();
            trimmed.starts_with(instruction) || trimmed.contains(&format!(" {} ", instruction))
        })
    }

    /// Get all method names found in the disassembly
    pub fn method_names(&self) -> Vec<String> {
        self.il_output
            .lines()
            .filter(|line| line.contains(".method"))
            .filter_map(|line| {
                // Extract method name from lines like:
                // .method public static void Main() cil managed
                // Find the last word before the parenthesis
                if let Some(paren_pos) = line.find('(') {
                    let before_paren = &line[..paren_pos];
                    before_paren
                        .split_whitespace()
                        .last()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Disassemble an assembly using the detected disassembler
pub fn disassemble(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
) -> Result<DisassemblyResult> {
    let disassembler = match capabilities.disassembler {
        Some(d) => d,
        None => {
            return Ok(DisassemblyResult::failure(
                "No IL disassembler available".to_string(),
            ))
        }
    };

    disassemble_with_caps(
        disassembler,
        assembly_path,
        capabilities.ildasm_path.as_deref(),
    )
}

/// Disassemble with a specific disassembler
pub fn disassemble_with(
    disassembler: Disassembler,
    assembly_path: &Path,
) -> Result<DisassemblyResult> {
    disassemble_with_caps(disassembler, assembly_path, None)
}

/// Disassemble with a specific disassembler, using capabilities for path resolution
fn disassemble_with_caps(
    disassembler: Disassembler,
    assembly_path: &Path,
    ildasm_path: Option<&Path>,
) -> Result<DisassemblyResult> {
    let output = match disassembler {
        Disassembler::Monodis => disassemble_with_monodis(assembly_path)?,
        Disassembler::Ildasm => disassemble_with_ildasm(assembly_path, ildasm_path)?,
        Disassembler::DotNetIldasm => disassemble_with_dotnet_ildasm(assembly_path)?,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(DisassemblyResult::success(stdout, disassembler))
    } else {
        let error = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            "Disassembly failed with unknown error".to_string()
        };
        Ok(DisassemblyResult::failure(error))
    }
}

/// Disassemble using monodis
fn disassemble_with_monodis(assembly_path: &Path) -> Result<std::process::Output> {
    Command::new("monodis")
        .arg(assembly_path)
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute monodis: {}", e)))
}

/// Disassemble using ildasm
fn disassemble_with_ildasm(
    assembly_path: &Path,
    ildasm_path: Option<&Path>,
) -> Result<std::process::Output> {
    let cmd = ildasm_path
        .map(|p| p.as_os_str().to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("ildasm"));

    Command::new(cmd)
        .arg("/text")
        .arg("/nobar")
        .arg(assembly_path)
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute ildasm: {}", e)))
}

/// Disassemble using dotnet-ildasm
fn disassemble_with_dotnet_ildasm(assembly_path: &Path) -> Result<std::process::Output> {
    Command::new("dotnet-ildasm")
        .arg(assembly_path)
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute dotnet-ildasm: {}", e)))
}

/// Verification result for checking specific elements in an assembly
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether all checks passed
    pub success: bool,
    /// Individual check results
    pub checks: Vec<(String, bool)>,
    /// The disassembly result
    pub disassembly: DisassemblyResult,
}

impl VerificationResult {
    /// Check if all verifications passed
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get failed checks
    pub fn failed_checks(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|(_, passed)| !passed)
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

/// Verify that an assembly contains expected elements
pub fn verify(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
    expected_methods: &[&str],
    expected_classes: &[&str],
) -> Result<VerificationResult> {
    let disassembly = disassemble(capabilities, assembly_path)?;

    if !disassembly.is_success() {
        return Ok(VerificationResult {
            success: false,
            checks: vec![("disassembly".to_string(), false)],
            disassembly,
        });
    }

    let mut checks = Vec::new();
    let mut all_passed = true;

    // Check for expected methods
    for method in expected_methods {
        let found = disassembly.contains_method(method);
        checks.push((format!("method:{}", method), found));
        if !found {
            all_passed = false;
        }
    }

    // Check for expected classes
    for class in expected_classes {
        let found = disassembly.contains_class(class);
        checks.push((format!("class:{}", class), found));
        if !found {
            all_passed = false;
        }
    }

    Ok(VerificationResult {
        success: all_passed,
        checks,
        disassembly,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::mono::compilation::{compile, templates};
    use tempfile::TempDir;

    #[test]
    fn test_disassembly_result() {
        let success = DisassemblyResult::success(
            ".method public static void Main()".to_string(),
            Disassembler::Monodis,
        );
        assert!(success.is_success());
        assert!(success.contains_method("Main"));

        let failure = DisassemblyResult::failure("Error".to_string());
        assert!(!failure.is_success());
    }

    #[test]
    fn test_disassemble_assembly() -> Result<()> {
        let caps = TestCapabilities::detect();
        if !caps.can_test() || !caps.can_disassemble() {
            println!("Skipping: no compiler/disassembler available");
            return Ok(());
        }

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();

        // Compile
        let compile_result = compile(
            &caps,
            templates::SIMPLE_CLASS,
            temp_dir.path(),
            "test",
            arch,
        )?;
        assert!(compile_result.is_success(), "Compilation failed");

        // Disassemble
        let disasm_result = disassemble(&caps, compile_result.assembly_path())?;
        assert!(
            disasm_result.is_success(),
            "Disassembly failed: {:?}",
            disasm_result.error
        );
        assert!(disasm_result.contains_method("Main"));
        assert!(disasm_result.contains_method("Add"));
        assert!(disasm_result.contains_class("TestClass"));

        Ok(())
    }
}
