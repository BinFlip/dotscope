//! IL disassembly verification using monodis
//!
//! This module uses the Mono disassembler (monodis) to verify that dotscope-generated
//! assemblies have valid IL metadata and can be properly disassembled. This catches
//! structural issues that might not surface during execution.

use crate::prelude::*;
use std::path::Path;
use std::process::Command;

/// Disassembler tool wrapper for monodis
#[derive(Default)]
pub struct MonoDisassembler {
    available: Option<bool>,
}

impl MonoDisassembler {
    /// Create new disassembler instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if monodis is available
    pub fn is_available(&mut self) -> bool {
        if let Some(available) = self.available {
            return available;
        }

        let available = Command::new("monodis").arg("--help").output().is_ok();
        self.available = Some(available);
        available
    }

    /// Perform basic disassembly of an assembly
    pub fn disassemble(&mut self, assembly_path: &Path) -> Result<DisassemblyResult> {
        if !self.is_available() {
            return Ok(DisassemblyResult {
                success: false,
                output: String::new(),
                error: Some("monodis not available".to_string()),
                available: false,
            });
        }

        let output = Command::new("monodis")
            .arg(assembly_path)
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute monodis: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
        })
    }

    /// Get specific information using monodis flags
    pub fn get_info(&mut self, assembly_path: &Path, flags: &[&str]) -> Result<DisassemblyResult> {
        if !self.is_available() {
            return Ok(DisassemblyResult {
                success: false,
                output: String::new(),
                error: Some("monodis not available".to_string()),
                available: false,
            });
        }

        let mut cmd = Command::new("monodis");
        for flag in flags {
            cmd.arg(flag);
        }
        cmd.arg(assembly_path);

        let output = cmd
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute monodis: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
        })
    }

    /// Test comprehensive disassembly verification
    pub fn test_verification(
        &mut self,
        file_path: &Path,
        arch_name: &str,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::new();

        if !self.is_available() {
            result.monodis_available = false;
            return Ok(result);
        }

        result.monodis_available = true;

        // Test different disassembly options
        let test_options = [
            ("basic disassembly", vec![]),
            ("method listing", vec!["--method"]),
            ("type listing", vec!["--typedef"]),
            ("assembly info", vec!["--assembly"]),
        ];

        for (test_name, args) in test_options {
            match self.get_info(file_path, &args) {
                Ok(disasm_result) if disasm_result.success => {
                    let output_len = disasm_result.output.len();

                    // Basic validation
                    if output_len < 50 {
                        let warning = format!(
                            "monodis {} output unusually short ({} chars) for {} assembly - indicates corruption",
                            test_name, output_len, arch_name
                        );
                        result.warnings.push(warning);
                    }

                    // Check for error indicators
                    if disasm_result.output.to_lowercase().contains("error")
                        || disasm_result.output.to_lowercase().contains("invalid")
                    {
                        let warning = format!(
                            "monodis {} output contains error indicators for {} assembly",
                            test_name, arch_name
                        );
                        result.warnings.push(warning);
                    }

                    // Store result for specific test types
                    match test_name {
                        "basic disassembly" => result.basic_disassembly = Some(disasm_result),
                        "method listing" => result.method_listing = Some(disasm_result),
                        "type listing" => result.type_listing = Some(disasm_result),
                        "assembly info" => result.assembly_info = Some(disasm_result),
                        _ => {}
                    }
                }
                Ok(disasm_result) => {
                    let error = disasm_result.error.as_deref().unwrap_or("Unknown error");
                    result.failures.push(format!("{}: {}", test_name, error));
                }
                Err(e) => {
                    result.failures.push(format!("{}: {}", test_name, e));
                }
            }
        }

        result.success = result.failures.is_empty();

        Ok(result)
    }

    /// Verify specific method in disassembly
    pub fn verify_method(
        &mut self,
        assembly_path: &Path,
        method_name: &str,
    ) -> Result<MethodVerificationResult> {
        let disasm_result = self.disassemble(assembly_path)?;

        if !disasm_result.success {
            return Ok(MethodVerificationResult {
                found: false,
                il_instructions: Vec::new(),
                verification_errors: vec!["Disassembly failed".to_string()],
            });
        }

        let mut result = MethodVerificationResult {
            found: false,
            il_instructions: Vec::new(),
            verification_errors: Vec::new(),
        };

        // Look for the method in the disassembly output
        if disasm_result.output.contains(method_name) {
            result.found = true;
            result.il_instructions = self.extract_method_il(&disasm_result.output, method_name);
        }

        Ok(result)
    }

    /// Extract IL instructions for a specific method from disassembly
    fn extract_method_il(&self, disassembly_output: &str, method_name: &str) -> Vec<String> {
        let lines: Vec<&str> = disassembly_output.lines().collect();
        let mut method_start = None;
        let mut method_end = None;

        // Find method boundaries
        for (i, line) in lines.iter().enumerate() {
            if line.contains(method_name) {
                // Look for opening brace
                for (j, line) in lines.iter().enumerate().skip(i) {
                    if line.trim().starts_with('{') {
                        method_start = Some(j + 1);
                        break;
                    }
                }

                // Look for closing brace
                if let Some(start) = method_start {
                    for (j, line) in lines.iter().enumerate().skip(start) {
                        if line.trim().starts_with('}') {
                            method_end = Some(j);
                            break;
                        }
                    }
                }
                break;
            }
        }

        // Extract IL instructions
        if let (Some(start), Some(end)) = (method_start, method_end) {
            let mut il_instructions = Vec::new();
            for line in &lines[start..end] {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with('.') {
                    if let Some(colon_pos) = trimmed.find(':') {
                        if colon_pos + 1 < trimmed.len() {
                            let instruction = trimmed[colon_pos + 1..].trim();
                            if !instruction.is_empty() {
                                il_instructions.push(instruction.to_string());
                            }
                        }
                    }
                }
            }
            il_instructions
        } else {
            Vec::new()
        }
    }

    /// Verify IL instruction sequence matches expected pattern
    pub fn verify_il_sequence(
        &mut self,
        assembly_path: &Path,
        method_name: &str,
        expected_instructions: &[&str],
    ) -> Result<ILVerificationResult> {
        let method_result = self.verify_method(assembly_path, method_name)?;

        if !method_result.found {
            return Ok(ILVerificationResult {
                method_found: false,
                instructions_match: false,
                expected_count: expected_instructions.len(),
                actual_count: 0,
                mismatches: vec!["Method not found".to_string()],
            });
        }

        let mut result = ILVerificationResult {
            method_found: true,
            instructions_match: true,
            expected_count: expected_instructions.len(),
            actual_count: method_result.il_instructions.len(),
            mismatches: Vec::new(),
        };

        // Check instruction count
        if method_result.il_instructions.len() != expected_instructions.len() {
            result.instructions_match = false;
            result.mismatches.push(format!(
                "Instruction count mismatch: expected {}, got {}",
                expected_instructions.len(),
                method_result.il_instructions.len()
            ));
        }

        // Check each instruction
        for (i, (actual, expected)) in method_result
            .il_instructions
            .iter()
            .zip(expected_instructions.iter())
            .enumerate()
        {
            if actual != expected {
                result.instructions_match = false;
                result.mismatches.push(format!(
                    "Instruction {} mismatch: expected '{}', got '{}'",
                    i, expected, actual
                ));
            }
        }

        Ok(result)
    }

    /// Get user strings from assembly
    pub fn get_user_strings(&mut self, assembly_path: &Path) -> Result<DisassemblyResult> {
        self.get_info(assembly_path, &["--userstrings"])
    }

    /// Verify specific string exists in user strings
    pub fn verify_user_string(
        &mut self,
        assembly_path: &Path,
        expected_string: &str,
    ) -> Result<bool> {
        let strings_result = self.get_user_strings(assembly_path)?;
        Ok(strings_result.success && strings_result.output.contains(expected_string))
    }
}

/// Result of a disassembly operation
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub available: bool,
}

impl DisassemblyResult {
    /// Check if disassembly contains specific text
    pub fn contains(&self, text: &str) -> bool {
        self.output.contains(text)
    }

    /// Get output length
    pub fn output_length(&self) -> usize {
        self.output.len()
    }

    /// Get first few lines of output
    pub fn preview_lines(&self, count: usize) -> Vec<&str> {
        self.output.lines().take(count).collect()
    }
}

/// Comprehensive verification result
#[derive(Debug, Default)]
pub struct VerificationResult {
    pub success: bool,
    pub monodis_available: bool,
    pub basic_disassembly: Option<DisassemblyResult>,
    pub method_listing: Option<DisassemblyResult>,
    pub type_listing: Option<DisassemblyResult>,
    pub assembly_info: Option<DisassemblyResult>,
    pub warnings: Vec<String>,
    pub failures: Vec<String>,
}

impl VerificationResult {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if verification was completely successful
    pub fn is_fully_successful(&self) -> bool {
        self.success && self.monodis_available && self.failures.is_empty()
    }

    /// Get summary of verification status
    pub fn summary(&self) -> String {
        if !self.monodis_available {
            "monodis not available".to_string()
        } else if self.is_fully_successful() {
            "All verifications passed".to_string()
        } else {
            format!(
                "{} failures, {} warnings",
                self.failures.len(),
                self.warnings.len()
            )
        }
    }
}

/// Result of verifying a specific method
#[derive(Debug)]
pub struct MethodVerificationResult {
    pub found: bool,
    pub il_instructions: Vec<String>,
    pub verification_errors: Vec<String>,
}

/// Result of IL instruction sequence verification
#[derive(Debug)]
pub struct ILVerificationResult {
    pub method_found: bool,
    pub instructions_match: bool,
    pub expected_count: usize,
    pub actual_count: usize,
    pub mismatches: Vec<String>,
}

impl ILVerificationResult {
    /// Check if IL verification was successful
    pub fn is_successful(&self) -> bool {
        self.method_found && self.instructions_match
    }

    /// Get detailed error summary
    pub fn error_summary(&self) -> String {
        if !self.method_found {
            "Method not found".to_string()
        } else if self.mismatches.is_empty() {
            "All instructions match".to_string()
        } else {
            self.mismatches.join("; ")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::mono::disassembly::{
        DisassemblyResult, ILVerificationResult, MonoDisassembler,
    };

    #[test]
    fn test_disassembler_creation() {
        let disasm = MonoDisassembler::new();
        assert!(disasm.available.is_none());
    }

    #[test]
    fn test_disassembly_result() {
        let result = DisassemblyResult {
            success: true,
            output: "Hello World".to_string(),
            error: None,
            available: true,
        };

        assert!(result.contains("Hello"));
        assert_eq!(result.output_length(), 11);
        assert_eq!(result.preview_lines(1), vec!["Hello World"]);
    }

    #[test]
    fn test_il_verification_result() {
        let result = ILVerificationResult {
            method_found: true,
            instructions_match: true,
            expected_count: 2,
            actual_count: 2,
            mismatches: Vec::new(),
        };

        assert!(result.is_successful());
        assert_eq!(result.error_summary(), "All instructions match");
    }
}
