//! IL disassembly verification using platform-native tools
//!
//! This module provides cross-platform IL disassembly verification for dotscope-generated
//! assemblies. It automatically detects and uses the appropriate disassembler tool:
//! - **Windows**: `ildasm.exe` from Windows SDK
//! - **macOS/Linux**: `monodis` from Mono framework
//!
//! This catches structural issues that might not surface during execution.

use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Disassembler backend type
#[derive(Debug, Clone, PartialEq)]
pub enum DisassemblerBackend {
    /// Mono disassembler (monodis) - available on macOS/Linux
    Monodis,
    /// Microsoft IL Disassembler (ildasm.exe) - available on Windows with SDK
    Ildasm(PathBuf),
    /// Cross-platform .NET global tool (dotnet ildasm)
    DotnetIldasm,
}

impl DisassemblerBackend {
    /// Get a display name for the backend
    pub fn name(&self) -> &str {
        match self {
            DisassemblerBackend::Monodis => "monodis",
            DisassemblerBackend::Ildasm(_) => "ildasm",
            DisassemblerBackend::DotnetIldasm => "dotnet-ildasm",
        }
    }
}

/// IL Disassembler that automatically selects the appropriate backend
#[derive(Default)]
pub struct ILDisassembler {
    backend: Option<DisassemblerBackend>,
    detection_done: bool,
}

impl ILDisassembler {
    /// Create new disassembler instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Detect and cache the available disassembler backend
    fn detect_backend(&mut self) -> Option<&DisassemblerBackend> {
        if self.detection_done {
            return self.backend.as_ref();
        }

        self.detection_done = true;

        // On Windows, try ildasm.exe first (native SDK tool)
        #[cfg(target_os = "windows")]
        {
            if let Some(ildasm_path) = Self::find_ildasm() {
                self.backend = Some(DisassemblerBackend::Ildasm(ildasm_path));
                return self.backend.as_ref();
            }
        }

        // Try monodis (available on macOS/Linux, sometimes on Windows via Mono)
        if Command::new("monodis").arg("--help").output().is_ok() {
            self.backend = Some(DisassemblerBackend::Monodis);
            return self.backend.as_ref();
        }

        // Try dotnet-ildasm as cross-platform fallback
        // This is a .NET global tool that works on any platform with dotnet SDK
        if Self::is_dotnet_ildasm_available() {
            self.backend = Some(DisassemblerBackend::DotnetIldasm);
            return self.backend.as_ref();
        }

        // On non-Windows, also try ildasm as last resort (in case available via Wine or similar)
        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ildasm_path) = Self::find_ildasm() {
                self.backend = Some(DisassemblerBackend::Ildasm(ildasm_path));
                return self.backend.as_ref();
            }
        }

        None
    }

    /// Check if dotnet-ildasm global tool is available
    fn is_dotnet_ildasm_available() -> bool {
        // Try running "dotnet ildasm --help" to check if the tool is installed
        Command::new("dotnet")
            .args(["ildasm", "--help"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Find ildasm.exe on Windows
    #[cfg(target_os = "windows")]
    fn find_ildasm() -> Option<PathBuf> {
        // Common paths where ildasm.exe might be found on Windows
        let sdk_base = Path::new(r"C:\Program Files (x86)\Microsoft SDKs\Windows");

        // Try different SDK versions in order of preference (newest first)
        let sdk_versions = [
            r"v10.0A\bin\NETFX 4.8.1 Tools",
            r"v10.0A\bin\NETFX 4.8 Tools",
            r"v10.0A\bin\NETFX 4.7.2 Tools",
            r"v10.0A\bin\NETFX 4.7.1 Tools",
            r"v10.0A\bin\NETFX 4.7 Tools",
            r"v10.0A\bin\NETFX 4.6.2 Tools",
            r"v10.0A\bin\NETFX 4.6.1 Tools",
            r"v10.0A\bin\NETFX 4.6 Tools",
            r"v8.1A\bin\NETFX 4.5.1 Tools",
            r"v8.0A\bin\NETFX 4.0 Tools",
        ];

        for version in sdk_versions {
            let ildasm_path = sdk_base.join(version).join("ildasm.exe");
            if ildasm_path.exists() {
                return Some(ildasm_path);
            }

            // Also check x64 subdirectory
            let ildasm_path_x64 = sdk_base.join(version).join("x64").join("ildasm.exe");
            if ildasm_path_x64.exists() {
                return Some(ildasm_path_x64);
            }
        }

        // Try to find via vswhere or PATH
        if let Ok(output) = Command::new("where").arg("ildasm.exe").output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout);
                if let Some(first_line) = path_str.lines().next() {
                    let path = PathBuf::from(first_line.trim());
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    /// Find ildasm on non-Windows (unlikely but possible)
    #[cfg(not(target_os = "windows"))]
    fn find_ildasm() -> Option<PathBuf> {
        // On non-Windows, ildasm might be available via .NET SDK tools or Wine
        if let Ok(output) = Command::new("which").arg("ildasm").output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let path = PathBuf::from(path_str.trim());
                if path.exists() {
                    return Some(path);
                }
            }
        }
        None
    }

    /// Check if any disassembler is available
    pub fn is_available(&mut self) -> bool {
        self.detect_backend().is_some()
    }

    /// Get the active backend (if any)
    pub fn active_backend(&mut self) -> Option<&DisassemblerBackend> {
        self.detect_backend()
    }

    /// Perform basic disassembly of an assembly
    pub fn disassemble(&mut self, assembly_path: &Path) -> Result<DisassemblyResult> {
        let backend = match self.detect_backend() {
            Some(b) => b.clone(),
            None => {
                return Ok(DisassemblyResult {
                    success: false,
                    output: String::new(),
                    error: Some(
                        "No IL disassembler available (neither monodis nor ildasm)".to_string(),
                    ),
                    available: false,
                    backend_used: None,
                });
            }
        };

        match &backend {
            DisassemblerBackend::Monodis => self.disassemble_with_monodis(assembly_path),
            DisassemblerBackend::Ildasm(path) => {
                self.disassemble_with_ildasm(assembly_path, path.clone())
            }
            DisassemblerBackend::DotnetIldasm => self.disassemble_with_dotnet_ildasm(assembly_path),
        }
    }

    /// Disassemble using monodis
    fn disassemble_with_monodis(&self, assembly_path: &Path) -> Result<DisassemblyResult> {
        let output = Command::new("monodis")
            .arg(assembly_path)
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute monodis: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
            backend_used: Some(DisassemblerBackend::Monodis),
        })
    }

    /// Disassemble using ildasm.exe
    fn disassemble_with_ildasm(
        &self,
        assembly_path: &Path,
        ildasm_path: PathBuf,
    ) -> Result<DisassemblyResult> {
        // ildasm outputs to stdout with /TEXT flag
        let output = Command::new(&ildasm_path)
            .arg("/TEXT")
            .arg("/NOBAR")
            .arg(assembly_path)
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute ildasm: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
            backend_used: Some(DisassemblerBackend::Ildasm(ildasm_path)),
        })
    }

    /// Disassemble using dotnet-ildasm global tool
    fn disassemble_with_dotnet_ildasm(&self, assembly_path: &Path) -> Result<DisassemblyResult> {
        // dotnet ildasm <assembly_path>
        let output = Command::new("dotnet")
            .arg("ildasm")
            .arg(assembly_path)
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute dotnet ildasm: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
            backend_used: Some(DisassemblerBackend::DotnetIldasm),
        })
    }

    /// Get specific information using backend-specific flags
    pub fn get_info(
        &mut self,
        assembly_path: &Path,
        info_type: InfoType,
    ) -> Result<DisassemblyResult> {
        let backend = match self.detect_backend() {
            Some(b) => b.clone(),
            None => {
                return Ok(DisassemblyResult {
                    success: false,
                    output: String::new(),
                    error: Some("No IL disassembler available".to_string()),
                    available: false,
                    backend_used: None,
                });
            }
        };

        match &backend {
            DisassemblerBackend::Monodis => self.get_info_monodis(assembly_path, info_type),
            DisassemblerBackend::Ildasm(path) => {
                self.get_info_ildasm(assembly_path, path.clone(), info_type)
            }
            DisassemblerBackend::DotnetIldasm => {
                self.get_info_dotnet_ildasm(assembly_path, info_type)
            }
        }
    }

    /// Get info using monodis
    fn get_info_monodis(
        &self,
        assembly_path: &Path,
        info_type: InfoType,
    ) -> Result<DisassemblyResult> {
        let flags = match info_type {
            InfoType::Basic => vec![],
            InfoType::Methods => vec!["--method"],
            InfoType::Types => vec!["--typedef"],
            InfoType::Assembly => vec!["--assembly"],
            InfoType::UserStrings => vec!["--userstrings"],
        };

        let mut cmd = Command::new("monodis");
        for flag in &flags {
            cmd.arg(flag);
        }
        cmd.arg(assembly_path);

        let output = cmd
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute monodis: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
            backend_used: Some(DisassemblerBackend::Monodis),
        })
    }

    /// Get info using ildasm
    fn get_info_ildasm(
        &self,
        assembly_path: &Path,
        ildasm_path: PathBuf,
        info_type: InfoType,
    ) -> Result<DisassemblyResult> {
        // ildasm uses different flags than monodis
        let flags: Vec<&str> = match info_type {
            InfoType::Basic => vec!["/TEXT", "/NOBAR"],
            InfoType::Methods => vec!["/TEXT", "/NOBAR"], // ildasm includes methods in basic output
            InfoType::Types => vec!["/TEXT", "/NOBAR", "/CLASSLIST"],
            InfoType::Assembly => vec!["/TEXT", "/NOBAR", "/METADATA"],
            InfoType::UserStrings => vec!["/TEXT", "/NOBAR", "/METADATA=STRINGSONLY"],
        };

        let mut cmd = Command::new(&ildasm_path);
        for flag in &flags {
            cmd.arg(flag);
        }
        cmd.arg(assembly_path);

        let output = cmd
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute ildasm: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
            backend_used: Some(DisassemblerBackend::Ildasm(ildasm_path)),
        })
    }

    /// Get info using dotnet-ildasm
    fn get_info_dotnet_ildasm(
        &self,
        assembly_path: &Path,
        info_type: InfoType,
    ) -> Result<DisassemblyResult> {
        // dotnet-ildasm has limited options compared to monodis/ildasm
        // Most info types just use basic disassembly since it includes everything
        let args: Vec<&str> = match info_type {
            InfoType::Basic => vec![],
            InfoType::Methods => vec![],  // Full output includes methods
            InfoType::Types => vec![],    // Full output includes types
            InfoType::Assembly => vec![], // Full output includes assembly info
            InfoType::UserStrings => vec![], // dotnet-ildasm includes strings in output
        };

        let mut cmd = Command::new("dotnet");
        cmd.arg("ildasm");
        for arg in &args {
            cmd.arg(arg);
        }
        cmd.arg(assembly_path);

        let output = cmd
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute dotnet ildasm: {}", e)))?;

        Ok(DisassemblyResult {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).to_string(),
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            available: true,
            backend_used: Some(DisassemblerBackend::DotnetIldasm),
        })
    }

    /// Test comprehensive disassembly verification
    pub fn test_verification(
        &mut self,
        file_path: &Path,
        arch_name: &str,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::new();

        let backend = match self.detect_backend() {
            Some(b) => {
                result.disassembler_available = true;
                result.backend_used = Some(b.name().to_string());
                b.clone()
            }
            None => {
                result.disassembler_available = false;
                return Ok(result);
            }
        };

        // Test different info types
        let test_options = [
            ("basic disassembly", InfoType::Basic),
            ("method listing", InfoType::Methods),
            ("type listing", InfoType::Types),
            ("assembly info", InfoType::Assembly),
        ];

        for (test_name, info_type) in test_options {
            match self.get_info(file_path, info_type) {
                Ok(disasm_result) if disasm_result.success => {
                    let output_len = disasm_result.output.len();

                    // Basic validation
                    if output_len < 50 {
                        let warning = format!(
                            "{} {} output unusually short ({} chars) for {} assembly - indicates corruption",
                            backend.name(), test_name, output_len, arch_name
                        );
                        result.warnings.push(warning);
                    }

                    // Check for error indicators (be careful: "error" might appear in legitimate IL)
                    let lower_output = disasm_result.output.to_lowercase();
                    if lower_output.contains("invalid metadata")
                        || lower_output.contains("bad image format")
                        || lower_output.contains("corrupt")
                    {
                        let warning = format!(
                            "{} {} output contains error indicators for {} assembly",
                            backend.name(),
                            test_name,
                            arch_name
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
        self.get_info(assembly_path, InfoType::UserStrings)
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

/// Information type to retrieve from disassembler
#[derive(Debug, Clone, Copy)]
pub enum InfoType {
    /// Basic full disassembly
    Basic,
    /// Method listing only
    Methods,
    /// Type listing only
    Types,
    /// Assembly metadata
    Assembly,
    /// User strings from #US heap
    UserStrings,
}

/// Result of a disassembly operation
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub available: bool,
    pub backend_used: Option<DisassemblerBackend>,
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
    /// Whether any IL disassembler is available
    pub disassembler_available: bool,
    /// Which backend was used (if any)
    pub backend_used: Option<String>,
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
        self.success && self.disassembler_available && self.failures.is_empty()
    }

    /// Get summary of verification status
    pub fn summary(&self) -> String {
        if !self.disassembler_available {
            "No IL disassembler available".to_string()
        } else if self.is_fully_successful() {
            format!(
                "All verifications passed (using {})",
                self.backend_used.as_deref().unwrap_or("unknown")
            )
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
    use super::*;

    #[test]
    fn test_disassembler_creation() {
        let disasm = ILDisassembler::new();
        assert!(!disasm.detection_done);
        assert!(disasm.backend.is_none());
    }

    #[test]
    fn test_disassembly_result() {
        let result = DisassemblyResult {
            success: true,
            output: "Hello World".to_string(),
            error: None,
            available: true,
            backend_used: Some(DisassemblerBackend::Monodis),
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

    #[test]
    fn test_backend_name() {
        assert_eq!(DisassemblerBackend::Monodis.name(), "monodis");
        assert_eq!(
            DisassemblerBackend::Ildasm(PathBuf::from("test.exe")).name(),
            "ildasm"
        );
    }

    #[test]
    fn test_verification_result_summary() {
        let mut result = VerificationResult::new();
        assert_eq!(result.summary(), "No IL disassembler available");

        result.disassembler_available = true;
        result.success = true;
        result.backend_used = Some("monodis".to_string());
        assert_eq!(result.summary(), "All verifications passed (using monodis)");

        result.failures.push("test failure".to_string());
        result.warnings.push("test warning".to_string());
        assert_eq!(result.summary(), "1 failures, 1 warnings");
    }
}
