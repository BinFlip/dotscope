//! C# compilation utilities
//!
//! This module handles compilation of C# source code to .NET assemblies using
//! available compilers (dotnet CLI, csc, or mcs). It automatically detects which
//! compiler is available and handles platform-specific compilation flags.

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
#[derive(Default)]
pub struct CSharpCompiler {
    available_compiler: Option<CompilerType>,
}

impl CSharpCompiler {
    /// Create new compiler instance
    pub fn new() -> Self {
        Self::default()
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
        // For dotnet, we need to use .dll extension because that's what the SDK produces
        // and the dotnet runtime expects
        let actual_output_path = match compiler_type {
            CompilerType::DotNet => {
                let dll_path = output_path.with_extension("dll");
                // Clean up any leftover .exe file with the same name to avoid confusion
                if output_path.extension().map(|e| e == "exe").unwrap_or(false) {
                    std::fs::remove_file(output_path).ok();
                }
                dll_path
            }
            _ => output_path.to_path_buf(),
        };

        let output = match compiler_type {
            CompilerType::Csc => self.compile_with_csc(&source_file, output_path, arch)?,
            CompilerType::DotNet => {
                self.compile_with_dotnet(&source_file, &actual_output_path, arch)?
            }
            CompilerType::Mcs => self.compile_with_mcs(&source_file, output_path, arch)?,
        };

        let mut result = CompilationResult {
            success: output.status.success(),
            output_path: if output.status.success() {
                Some(actual_output_path)
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
        // Generate a unique project name based on the output file name to avoid conflicts
        // when multiple assemblies are compiled (e.g., test assembly and reflection test)
        let project_name = output_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("TempProject")
            .replace(['-', ' ', '.'], "_"); // Sanitize for valid project name

        let temp_project_dir = output_path
            .parent()
            .unwrap()
            .join(format!("temp_dotnet_{}", project_name));

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
        // Disable ImplicitUsings because our test code has explicit 'using' statements.
        // Disable Nullable because our test code doesn't use nullable annotations.
        // Set explicit version 1.0.0.0 to ensure assembly identity is predictable.
        let project_content = format!(
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>{}</AssemblyName>
    <AssemblyVersion>1.0.0.0</AssemblyVersion>
    <FileVersion>1.0.0.0</FileVersion>
    <Version>1.0.0</Version>
{}    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
  </PropertyGroup>
</Project>"#,
            project_name, platform_target
        );

        let csproj_name = format!("{}.csproj", project_name);
        let project_file = temp_project_dir.join(&csproj_name);
        std::fs::write(&project_file, project_content)
            .map_err(|e| Error::Error(format!("Failed to write project file: {}", e)))?;

        // Copy source file as Program.cs
        let program_cs = temp_project_dir.join("Program.cs");
        std::fs::copy(source_file, &program_cs)
            .map_err(|e| Error::Error(format!("Failed to copy source: {}", e)))?;

        // Build the project without --output flag to avoid dotnet SDK issues
        // with scanning the output directory for .cs files
        let mut build_cmd = Command::new("dotnet");
        build_cmd
            .arg("build")
            .arg("--configuration")
            .arg("Release")
            .current_dir(&temp_project_dir);

        let build_output = build_cmd
            .output()
            .map_err(|e| Error::Error(format!("Failed to execute dotnet build: {}", e)))?;

        // Find and copy the built files to expected location
        // The build output is in temp_project_dir/bin/Release/net8.0/
        if build_output.status.success() {
            let build_dir = temp_project_dir.join("bin/Release/net8.0");
            let built_dll = build_dir.join(format!("{}.dll", project_name));
            let runtime_config = build_dir.join(format!("{}.runtimeconfig.json", project_name));

            // Copy the dll to the expected output path
            if built_dll.exists() {
                std::fs::copy(&built_dll, output_path).ok();
            }

            // Also copy the runtimeconfig.json (needed to run the app)
            if runtime_config.exists() {
                let output_runtime_config = output_path.with_extension("runtimeconfig.json");
                std::fs::copy(&runtime_config, &output_runtime_config).ok();
            }

            // Note: We intentionally do NOT copy deps.json for simple test assemblies.
            // The deps.json file is mainly needed for assemblies with external dependencies,
            // and can actually cause issues when the assembly is moved from the build location.
            // Our test assemblies only use System.* types which are always available.
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
            // Use LoadFile for better isolation when loading modified assemblies
            Assembly assembly = Assembly.LoadFile(@"{assembly_path}");
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
    fn test_template_constants() {
        assert!(templates::HELLO_WORLD.contains("Console.WriteLine"));
        assert!(templates::SIMPLE_CLASS.contains("public class TestClass"));
        assert!(templates::REFLECTION_TEMPLATE.contains("{assembly_path}"));
    }
}
