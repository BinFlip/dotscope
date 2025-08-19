//! C# compilation utilities for mono testing
//!
//! This module handles compilation of C# source code to .NET assemblies
//! with platform-specific flags and comprehensive error handling.

use crate::prelude::*;
use crate::test::mono::runner::ArchConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

/// C# compiler configuration and utilities
pub struct CSharpCompiler {
    compiler_available: Option<bool>,
}

impl CSharpCompiler {
    /// Create new compiler instance
    pub fn new() -> Self {
        Self {
            compiler_available: None,
        }
    }

    /// Check if C# compiler is available
    pub fn is_available(&mut self) -> bool {
        if let Some(available) = self.compiler_available {
            return available;
        }

        let available = Command::new("csc").arg("/help").output().is_ok();
        self.compiler_available = Some(available);
        available
    }

    /// Compile C# source code to executable for specific architecture
    pub fn compile_executable(
        &mut self,
        source_code: &str,
        output_path: &Path,
        arch: &ArchConfig,
    ) -> Result<CompilationResult> {
        if !self.is_available() {
            return Ok(CompilationResult {
                success: false,
                output_path: None,
                error: Some("csc (C# compiler) not available - cannot run test".to_string()),
                warnings: Vec::new(),
            });
        }

        // Create source file
        let source_file = output_path.with_extension("cs");
        std::fs::write(&source_file, source_code)
            .map_err(|e| Error::Error(format!("Failed to write source file: {}", e)))?;

        // Build compilation command
        let mut cmd = Command::new("csc");
        cmd.arg(format!("/out:{}", output_path.display()));

        // Add architecture-specific platform flags
        for flag in &arch.platform_flags {
            cmd.arg(flag);
        }

        cmd.arg(&source_file);

        // Execute compilation
        let output = cmd
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute csc: {}", e)))?;

        let mut result = CompilationResult {
            success: output.status.success(),
            output_path: if output.status.success() {
                Some(output_path.to_path_buf())
            } else {
                None
            },
            error: None,
            warnings: Vec::new(),
        };

        if output.status.success() {
            // Parse any warnings from stdout/stderr
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Look for warning patterns in the output
            for line in stdout.lines().chain(stderr.lines()) {
                if line.contains("warning") {
                    result.warnings.push(line.to_string());
                }
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            result.error = Some(format!("C# compilation failed: {}", stderr));
        }

        Ok(result)
    }

    /// Compile source code for multiple architectures
    pub fn compile_for_architectures(
        &mut self,
        source_code: &str,
        base_path: &Path,
        base_name: &str,
        architectures: &[ArchConfig],
    ) -> Result<Vec<ArchCompilationResult>> {
        let mut results = Vec::new();

        for arch in architectures {
            let output_path =
                base_path.join(format!("{}_{}.exe", base_name, arch.filename_component()));

            match self.compile_executable(source_code, &output_path, arch) {
                Ok(compilation_result) => {
                    results.push(ArchCompilationResult {
                        architecture: arch.clone(),
                        compilation: compilation_result,
                    });
                }
                Err(e) => {
                    results.push(ArchCompilationResult {
                        architecture: arch.clone(),
                        compilation: CompilationResult {
                            success: false,
                            output_path: None,
                            error: Some(e.to_string()),
                            warnings: Vec::new(),
                        },
                    });
                }
            }
        }

        Ok(results)
    }

    /// Check if Mono C# compiler (mcs) is available as fallback
    pub fn mcs_available() -> bool {
        Command::new("mcs").arg("--help").output().is_ok()
    }

    /// Compile using mcs as fallback compiler
    pub fn compile_with_mcs(source_code: &str, output_path: &Path) -> Result<CompilationResult> {
        if !Self::mcs_available() {
            return Ok(CompilationResult {
                success: false,
                output_path: None,
                error: Some("mcs (Mono C# compiler) not available".to_string()),
                warnings: Vec::new(),
            });
        }

        // Create source file
        let source_file = output_path.with_extension("cs");
        std::fs::write(&source_file, source_code)
            .map_err(|e| Error::Error(format!("Failed to write source file: {}", e)))?;

        let mut cmd = Command::new("mcs");
        cmd.arg(format!("-out:{}", output_path.display()));
        cmd.arg(&source_file);

        let output = cmd
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute mcs: {}", e)))?;

        Ok(CompilationResult {
            success: output.status.success(),
            output_path: if output.status.success() {
                Some(output_path.to_path_buf())
            } else {
                None
            },
            error: if !output.status.success() {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            } else {
                None
            },
            warnings: Vec::new(),
        })
    }
}

/// Result of a compilation operation
#[derive(Debug, Clone)]
pub struct CompilationResult {
    pub success: bool,
    pub output_path: Option<PathBuf>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

impl CompilationResult {
    /// Check if compilation was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get the compiled executable path (panics if compilation failed)
    pub fn executable_path(&self) -> &Path {
        self.output_path
            .as_ref()
            .expect("Compilation failed - no executable path")
    }

    /// Get executable path if compilation succeeded
    pub fn try_executable_path(&self) -> Option<&Path> {
        self.output_path.as_deref()
    }
}

/// Architecture-specific compilation result
#[derive(Debug)]
pub struct ArchCompilationResult {
    pub architecture: ArchConfig,
    pub compilation: CompilationResult,
}

/// Common C# source code templates for testing
pub mod templates {
    /// Basic Hello World program
    pub const HELLO_WORLD: &str = r#"
using System;

class Program 
{
    static void Main() 
    {
        Console.WriteLine("Hello from dotscope test!");
    }
}
"#;

    /// Simple class with method for testing
    pub const SIMPLE_CLASS: &str = r#"
using System;

public class TestClass 
{
    public static void Main() 
    {
        Console.WriteLine("Test class executed successfully!");
    }
    
    public static int Add(int a, int b) 
    {
        return a + b;
    }
}
"#;

    /// Template for reflection testing
    pub const REFLECTION_TEMPLATE: &str = r#"
using System;
using System.Reflection;

class Program 
{{
    static void Main()
    {{
        try 
        {{
            Assembly assembly = Assembly.LoadFrom(@"{assembly_path}");
            {test_code}
        }} 
        catch (Exception ex) 
        {{
            Console.WriteLine($"ERROR: {{ex.Message}}");
            Environment.Exit(1);
        }}
    }}
}}
"#;
}

#[cfg(test)]
mod tests {
    use crate::test::mono::compilation::{templates, CSharpCompiler, CompilationResult};
    use std::path::{Path, PathBuf};

    #[test]
    fn test_compiler_creation() {
        let compiler = CSharpCompiler::new();
        assert!(compiler.compiler_available.is_none());
    }

    #[test]
    fn test_compilation_result() {
        let result = CompilationResult {
            success: true,
            output_path: Some(PathBuf::from("/test/path.exe")),
            error: None,
            warnings: Vec::new(),
        };

        assert!(result.is_success());
        assert_eq!(
            result.try_executable_path().unwrap(),
            Path::new("/test/path.exe")
        );
    }

    #[test]
    fn test_mcs_availability() {
        // This will vary by system, but should not panic
        let _ = CSharpCompiler::mcs_available();
    }

    #[test]
    fn test_template_constants() {
        assert!(templates::HELLO_WORLD.contains("Console.WriteLine"));
        assert!(templates::SIMPLE_CLASS.contains("public class TestClass"));
        assert!(templates::REFLECTION_TEMPLATE.contains("{assembly_path}"));
    }
}
