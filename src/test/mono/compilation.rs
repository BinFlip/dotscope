//! C# compilation utilities for mono testing
//!
//! This module handles compilation of C# source code to .NET assemblies
//! with platform-specific flags and comprehensive error handling.

use crate::prelude::*;
use crate::test::mono::runner::ArchConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Available C# compiler types
#[derive(Debug, Clone, PartialEq)]
pub enum CompilerType {
    /// Traditional csc.exe compiler (Windows/.NET Framework)
    Csc,
    /// Modern dotnet CLI build approach
    DotNet,
    /// Mono C# compiler (cross-platform)
    Mcs,
}

/// C# compiler configuration and utilities
pub struct CSharpCompiler {
    available_compiler: Option<CompilerType>,
}

impl CSharpCompiler {
    /// Create new compiler instance
    pub fn new() -> Self {
        Self {
            available_compiler: None,
        }
    }

    /// Detect and return the available compiler type
    pub fn detect_compiler(&mut self) -> Option<CompilerType> {
        if let Some(ref compiler) = self.available_compiler {
            return Some(compiler.clone());
        }

        // Try csc first (traditional .NET Framework/Core compiler)
        if Command::new("csc").arg("/help").output().is_ok() {
            self.available_compiler = Some(CompilerType::Csc);
            return Some(CompilerType::Csc);
        }

        // Try dotnet (modern .NET approach)
        if Command::new("dotnet").arg("--version").output().is_ok() {
            self.available_compiler = Some(CompilerType::DotNet);
            return Some(CompilerType::DotNet);
        }

        // Try mcs (Mono C# compiler)
        if Command::new("mcs").arg("--help").output().is_ok() {
            self.available_compiler = Some(CompilerType::Mcs);
            return Some(CompilerType::Mcs);
        }

        self.available_compiler = None;
        None
    }

    /// Check if any C# compiler is available
    pub fn is_available(&mut self) -> bool {
        self.detect_compiler().is_some()
    }

    /// Compile C# source code to executable for specific architecture
    pub fn compile_executable(
        &mut self,
        source_code: &str,
        output_path: &Path,
        arch: &ArchConfig,
    ) -> Result<CompilationResult> {
        let compiler_type = match self.detect_compiler() {
            Some(compiler) => compiler,
            None => {
                return Ok(CompilationResult {
                    success: false,
                    output_path: None,
                    error: Some("No C# compiler available - cannot run test".to_string()),
                    warnings: Vec::new(),
                    compiler_used: None,
                });
            }
        };

        // Create source file
        let source_file = output_path.with_extension("cs");
        std::fs::write(&source_file, source_code)
            .map_err(|e| Error::Error(format!("Failed to write source file: {}", e)))?;

        // Compile using the appropriate strategy
        let output = match compiler_type {
            CompilerType::Csc => self.compile_with_csc(&source_file, output_path, arch)?,
            CompilerType::DotNet => self.compile_with_dotnet(&source_file, output_path, arch)?,
            CompilerType::Mcs => self.compile_with_mcs(&source_file, output_path, arch)?,
        };

        let mut result = CompilationResult {
            success: output.status.success(),
            output_path: if output.status.success() {
                Some(output_path.to_path_buf())
            } else {
                None
            },
            error: None,
            warnings: Vec::new(),
            compiler_used: Some(compiler_type.clone()),
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
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined_output = if !stdout.is_empty() && !stderr.is_empty() {
                format!("stdout: {}\nstderr: {}", stdout, stderr)
            } else if !stdout.is_empty() {
                stdout.to_string()
            } else {
                stderr.to_string()
            };
            result.error = Some(format!("C# compilation failed: {}", combined_output));
        }

        Ok(result)
    }

    /// Compile using traditional csc.exe compiler
    fn compile_with_csc(
        &self,
        source_file: &Path,
        output_path: &Path,
        arch: &ArchConfig,
    ) -> Result<std::process::Output> {
        let mut cmd = Command::new("csc");
        cmd.arg(format!("/out:{}", output_path.display()));

        // Add architecture-specific platform flags
        for flag in &arch.platform_flags {
            cmd.arg(flag);
        }

        cmd.arg(source_file);
        cmd.output()
            .map_err(|e| Error::Error(format!("Failed to execute csc: {}", e)))
    }

    /// Compile using modern dotnet CLI
    fn compile_with_dotnet(
        &self,
        source_file: &Path,
        output_path: &Path,
        arch: &ArchConfig,
    ) -> Result<std::process::Output> {
        let temp_project_dir = output_path.parent().unwrap().join("temp_dotnet_project");

        // Ensure clean temp directory
        if temp_project_dir.exists() {
            std::fs::remove_dir_all(&temp_project_dir).ok();
        }
        std::fs::create_dir_all(&temp_project_dir)
            .map_err(|e| Error::Error(format!("Failed to create temp project dir: {}", e)))?;

        // Determine target platform based on architecture
        let platform_target = match arch.name.as_str() {
            "x86" => "    <PlatformTarget>x86</PlatformTarget>\n",
            "x64" => "    <PlatformTarget>x64</PlatformTarget>\n",
            "arm64" => "    <PlatformTarget>ARM64</PlatformTarget>\n",
            _ => "",
        };

        // Create project file with architecture support
        let project_content = format!(
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
{}    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>"#,
            platform_target
        );

        let project_file = temp_project_dir.join("TempProject.csproj");
        std::fs::write(&project_file, project_content)
            .map_err(|e| Error::Error(format!("Failed to write project file: {}", e)))?;

        // Copy source file as Program.cs
        let program_cs = temp_project_dir.join("Program.cs");
        std::fs::copy(source_file, &program_cs)
            .map_err(|e| Error::Error(format!("Failed to copy source: {}", e)))?;

        // Build the project
        let mut build_cmd = Command::new("dotnet");
        build_cmd
            .arg("build")
            .arg("--configuration")
            .arg("Release")
            .arg("--output")
            .arg(output_path.parent().unwrap())
            .current_dir(&temp_project_dir);

        let build_output = build_cmd
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute dotnet build: {}", e)))?;

        // Find and move the built executable to expected location
        if build_output.status.success() {
            let output_dir = output_path.parent().unwrap();
            let built_exe = output_dir.join("TempProject.exe");
            let built_dll = output_dir.join("TempProject.dll");

            // Try to find the built executable
            if built_exe.exists() {
                if let Err(e) = std::fs::rename(&built_exe, output_path) {
                    eprintln!("Warning: Failed to move executable: {}", e);
                }
            } else if built_dll.exists() {
                // On some platforms, it might be a .dll, copy it as .exe
                if let Err(e) = std::fs::copy(&built_dll, output_path) {
                    eprintln!("Warning: Failed to copy executable: {}", e);
                }
            }
        }

        // Clean up temp directory
        std::fs::remove_dir_all(&temp_project_dir).ok();

        Ok(build_output)
    }

    /// Compile using Mono mcs compiler
    fn compile_with_mcs(
        &self,
        source_file: &Path,
        output_path: &Path,
        arch: &ArchConfig,
    ) -> Result<std::process::Output> {
        let mut cmd = Command::new("mcs");
        cmd.arg(format!("-out:{}", output_path.display()));

        // Add architecture-specific flags if supported
        match arch.name.as_str() {
            "x86" => {
                cmd.arg("-platform:x86");
            }
            "x64" => {
                cmd.arg("-platform:x64");
            }
            "arm64" => {
                cmd.arg("-platform:arm64");
            }
            _ => {
                // Use anycpu as default
                cmd.arg("-platform:anycpu");
            }
        }

        cmd.arg(source_file);
        cmd.output()
            .map_err(|e| Error::Error(format!("Failed to execute mcs: {}", e)))
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
                            compiler_used: None,
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
}

/// Result of a compilation operation
#[derive(Debug, Clone)]
pub struct CompilationResult {
    pub success: bool,
    pub output_path: Option<PathBuf>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    /// The compiler type that was used for this compilation
    pub compiler_used: Option<CompilerType>,
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
        assert!(compiler.available_compiler.is_none());
    }

    #[test]
    fn test_compilation_result() {
        let result = CompilationResult {
            success: true,
            output_path: Some(PathBuf::from("/test/path.exe")),
            error: None,
            warnings: Vec::new(),
            compiler_used: None,
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
