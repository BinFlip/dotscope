//! C# compilation utilities
//!
//! This module handles compilation of C# source code to .NET assemblies using
//! the detected compiler from TestCapabilities.

use crate::prelude::*;
use crate::test::mono::capabilities::{Architecture, Compiler, TestCapabilities};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of a compilation operation
#[derive(Debug, Clone)]
pub struct CompilationResult {
    /// Whether compilation succeeded
    pub success: bool,
    /// Path to the compiled assembly (if successful)
    pub output_path: Option<PathBuf>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Compiler warnings
    pub warnings: Vec<String>,
    /// Which compiler was used
    pub compiler: Option<Compiler>,
}

impl CompilationResult {
    /// Create a successful result
    pub fn success(path: PathBuf, compiler: Compiler) -> Self {
        Self {
            success: true,
            output_path: Some(path),
            error: None,
            warnings: Vec::new(),
            compiler: Some(compiler),
        }
    }

    /// Create a failed result
    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            output_path: None,
            error: Some(error),
            warnings: Vec::new(),
            compiler: None,
        }
    }

    /// Check if compilation was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get the compiled assembly path (panics if compilation failed)
    pub fn assembly_path(&self) -> &Path {
        self.output_path
            .as_ref()
            .expect("Compilation failed - no assembly path")
    }

    /// Get assembly path if compilation succeeded
    pub fn try_assembly_path(&self) -> Option<&Path> {
        self.output_path.as_deref()
    }
}

/// Compile C# source code to an executable assembly
///
/// Uses the compiler from TestCapabilities and handles platform-specific compilation.
pub fn compile(
    capabilities: &TestCapabilities,
    source_code: &str,
    output_dir: &Path,
    name: &str,
    arch: &Architecture,
) -> Result<CompilationResult> {
    let compiler = match capabilities.compiler {
        Some(c) => c,
        None => {
            return Ok(CompilationResult::failure(
                "No C# compiler available".to_string(),
            ))
        }
    };

    // Write source code to file
    let source_path = output_dir.join(format!("{}.cs", name));
    std::fs::write(&source_path, source_code)
        .map_err(|e| Error::Other(format!("Failed to write source file: {}", e)))?;

    match compiler {
        Compiler::Csc => compile_with_csc(&source_path, output_dir, name, arch, true),
        Compiler::Mcs => compile_with_mcs(&source_path, output_dir, name, arch, true),
        Compiler::DotNet => compile_with_dotnet(&source_path, output_dir, name, arch, true),
    }
}

/// Compile C# source code with optimizations disabled (debug mode)
///
/// This produces assemblies that preserve the source code structure more faithfully,
/// which is important for analysis testing where we want to verify CFG/SSA properties
/// match the original source code rather than optimized IL.
pub fn compile_debug(
    capabilities: &TestCapabilities,
    source_code: &str,
    output_dir: &Path,
    name: &str,
    arch: &Architecture,
) -> Result<CompilationResult> {
    let compiler = match capabilities.compiler {
        Some(c) => c,
        None => {
            return Ok(CompilationResult::failure(
                "No C# compiler available".to_string(),
            ))
        }
    };

    // Write source code to file
    let source_path = output_dir.join(format!("{}.cs", name));
    std::fs::write(&source_path, source_code)
        .map_err(|e| Error::Other(format!("Failed to write source file: {}", e)))?;

    match compiler {
        Compiler::Csc => compile_with_csc(&source_path, output_dir, name, arch, false),
        Compiler::Mcs => compile_with_mcs(&source_path, output_dir, name, arch, false),
        Compiler::DotNet => compile_with_dotnet(&source_path, output_dir, name, arch, false),
    }
}

/// Compile using the Roslyn csc compiler
fn compile_with_csc(
    source_path: &Path,
    output_dir: &Path,
    name: &str,
    arch: &Architecture,
    optimize: bool,
) -> Result<CompilationResult> {
    let output_path = output_dir.join(format!("{}.exe", name));

    let mut cmd = Command::new("csc");
    cmd.arg(format!("/out:{}", output_path.display()));
    cmd.arg("/nologo");

    // Add optimization flags
    if optimize {
        cmd.arg("/optimize+");
    } else {
        cmd.arg("/optimize-");
        cmd.arg("/debug+");
    }

    // Add platform flag if specified
    if let Some(flag) = arch.csc_flag {
        cmd.arg(flag);
    }

    cmd.arg(source_path);

    let output = cmd
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute csc: {}", e)))?;

    if output.status.success() {
        let mut result = CompilationResult::success(output_path, Compiler::Csc);
        result.warnings = extract_warnings(&output.stdout, &output.stderr);
        Ok(result)
    } else {
        let error = format_compiler_error(&output.stdout, &output.stderr);
        Ok(CompilationResult::failure(error))
    }
}

/// Compile using the Mono mcs compiler
fn compile_with_mcs(
    source_path: &Path,
    output_dir: &Path,
    name: &str,
    arch: &Architecture,
    optimize: bool,
) -> Result<CompilationResult> {
    let output_path = output_dir.join(format!("{}.exe", name));

    let mut cmd = Command::new("mcs");
    cmd.arg(format!("-out:{}", output_path.display()));

    // Add optimization flags
    if optimize {
        cmd.arg("-optimize+");
    } else {
        cmd.arg("-optimize-");
        cmd.arg("-debug");
    }

    // Add platform flag
    let platform = match arch.name {
        "x86" => "x86",
        "x64" => "x64",
        "arm64" => "arm64",
        _ => "anycpu",
    };
    cmd.arg(format!("-platform:{}", platform));

    cmd.arg(source_path);

    let output = cmd
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute mcs: {}", e)))?;

    if output.status.success() {
        let mut result = CompilationResult::success(output_path, Compiler::Mcs);
        result.warnings = extract_warnings(&output.stdout, &output.stderr);
        Ok(result)
    } else {
        let error = format_compiler_error(&output.stdout, &output.stderr);
        Ok(CompilationResult::failure(error))
    }
}

/// Compile using the dotnet SDK
fn compile_with_dotnet(
    source_path: &Path,
    output_dir: &Path,
    name: &str,
    arch: &Architecture,
    optimize: bool,
) -> Result<CompilationResult> {
    // Create a temporary project directory
    let project_dir = output_dir.join(format!("_dotnet_{}", name));

    // Clean up any previous attempt
    if project_dir.exists() {
        std::fs::remove_dir_all(&project_dir).ok();
    }
    std::fs::create_dir_all(&project_dir)
        .map_err(|e| Error::Other(format!("Failed to create project directory: {}", e)))?;

    // Create project file
    let platform_target = arch
        .dotnet_platform
        .map(|p| format!("    <PlatformTarget>{}</PlatformTarget>\n", p))
        .unwrap_or_default();

    let optimize_setting = if optimize {
        "    <Optimize>true</Optimize>\n"
    } else {
        "    <Optimize>false</Optimize>\n    <DebugType>full</DebugType>\n"
    };

    let csproj_content = format!(
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>{name}</AssemblyName>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <ImplicitUsings>disable</ImplicitUsings>
    <Nullable>disable</Nullable>
{optimize_setting}{platform_target}  </PropertyGroup>
</Project>"#
    );

    let csproj_path = project_dir.join(format!("{}.csproj", name));
    std::fs::write(&csproj_path, csproj_content)
        .map_err(|e| Error::Other(format!("Failed to write project file: {}", e)))?;

    // Copy source file
    let program_path = project_dir.join("Program.cs");
    std::fs::copy(source_path, &program_path)
        .map_err(|e| Error::Other(format!("Failed to copy source file: {}", e)))?;

    // Build with appropriate configuration
    let configuration = if optimize { "Release" } else { "Debug" };
    let build_output = Command::new("dotnet")
        .arg("build")
        .arg("--configuration")
        .arg(configuration)
        .arg("--nologo")
        .current_dir(&project_dir)
        .output()
        .map_err(|e| Error::Other(format!("Failed to execute dotnet build: {}", e)))?;

    if !build_output.status.success() {
        let error = format_compiler_error(&build_output.stdout, &build_output.stderr);
        // Clean up
        std::fs::remove_dir_all(&project_dir).ok();
        return Ok(CompilationResult::failure(error));
    }

    // Find and copy the built assembly
    let build_output_dir = project_dir.join(format!("bin/{}/net8.0", configuration));
    let built_dll = build_output_dir.join(format!("{}.dll", name));
    let built_runtimeconfig = build_output_dir.join(format!("{}.runtimeconfig.json", name));

    // Copy to output directory
    let output_dll = output_dir.join(format!("{}.dll", name));
    let output_runtimeconfig = output_dir.join(format!("{}.runtimeconfig.json", name));

    if built_dll.exists() {
        std::fs::copy(&built_dll, &output_dll)
            .map_err(|e| Error::Other(format!("Failed to copy assembly: {}", e)))?;
    } else {
        std::fs::remove_dir_all(&project_dir).ok();
        return Ok(CompilationResult::failure(
            "Build succeeded but assembly not found".to_string(),
        ));
    }

    if built_runtimeconfig.exists() {
        std::fs::copy(&built_runtimeconfig, &output_runtimeconfig).ok();
    }

    // Clean up project directory
    std::fs::remove_dir_all(&project_dir).ok();

    let mut result = CompilationResult::success(output_dll, Compiler::DotNet);
    result.warnings = extract_warnings(&build_output.stdout, &build_output.stderr);
    Ok(result)
}

/// Extract warnings from compiler output
fn extract_warnings(stdout: &[u8], stderr: &[u8]) -> Vec<String> {
    let stdout_str = String::from_utf8_lossy(stdout);
    let stderr_str = String::from_utf8_lossy(stderr);

    stdout_str
        .lines()
        .chain(stderr_str.lines())
        .filter(|line| line.contains("warning"))
        .map(|s| s.to_string())
        .collect()
}

/// Format compiler error output
fn format_compiler_error(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout_str = String::from_utf8_lossy(stdout);
    let stderr_str = String::from_utf8_lossy(stderr);

    if !stderr_str.is_empty() {
        stderr_str.to_string()
    } else if !stdout_str.is_empty() {
        stdout_str.to_string()
    } else {
        "Compilation failed with unknown error".to_string()
    }
}

/// Common C# source code templates for testing
pub mod templates {
    /// Basic Hello World program
    pub const HELLO_WORLD: &str = r#"using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("Hello from dotscope test!");
    }
}
"#;

    /// Simple class with static method for testing
    pub const SIMPLE_CLASS: &str = r#"using System;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_compilation_result() {
        let success = CompilationResult::success(PathBuf::from("/test/path.exe"), Compiler::Csc);
        assert!(success.is_success());
        assert_eq!(
            success.try_assembly_path().unwrap(),
            Path::new("/test/path.exe")
        );

        let failure = CompilationResult::failure("Test error".to_string());
        assert!(!failure.is_success());
        assert!(failure.try_assembly_path().is_none());
    }

    #[test]
    fn test_compile_hello_world() -> Result<()> {
        let caps = TestCapabilities::detect();
        if !caps.can_test() {
            println!("Skipping: no compiler available");
            return Ok(());
        }

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();

        let result = compile(
            &caps,
            templates::HELLO_WORLD,
            temp_dir.path(),
            "hello",
            arch,
        )?;

        assert!(
            result.is_success(),
            "Compilation failed: {:?}",
            result.error
        );
        assert!(result.try_assembly_path().unwrap().exists());

        Ok(())
    }
}
