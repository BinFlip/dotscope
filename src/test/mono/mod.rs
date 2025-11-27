//! .NET assembly verification framework
//!
//! This module provides utilities for verifying that .NET assemblies generated or modified
//! by dotscope are valid and executable. It uses the available .NET tools (compilers, runtimes,
//! disassemblers) to validate that binary output is correct and interoperable with the .NET ecosystem.
//!
//! # Architecture
//!
//! The framework automatically detects available tools and adapts to the platform:
//!
//! - **Compilers**: `csc` (Roslyn), `mcs` (Mono), `dotnet` SDK
//! - **Runtimes**: `mono`, `dotnet`
//! - **Disassemblers**: `monodis`, `ildasm`, `dotnet-ildasm`
//!
//! # Modules
//!
//! - [`capabilities`] - Platform detection and tool availability
//! - [`runner`] - Test orchestration and temporary directory management
//! - [`compilation`] - C# compilation
//! - [`execution`] - Assembly execution
//! - [`disassembly`] - IL disassembly
//! - [`reflection`] - Reflection-based method invocation testing
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use dotscope::test::mono::{TestRunner, TestCapabilities};
//! use dotscope::test::mono::compilation::{compile, templates};
//! use dotscope::test::mono::execution::execute;
//!
//! # fn main() -> dotscope::Result<()> {
//! // Create test runner (auto-detects platform capabilities)
//! let runner = TestRunner::new()?;
//! let caps = runner.capabilities();
//!
//! // Run tests for all supported architectures
//! let results = runner.for_each_architecture(|arch, dir, caps| {
//!     // Compile a test program
//!     let result = compile(caps, templates::HELLO_WORLD, dir, "test", arch)?;
//!
//!     // Execute it
//!     let exec = execute(caps, result.assembly_path())?;
//!
//!     Ok(exec.is_success())
//! });
//!
//! // Check results
//! assert!(TestRunner::all_passed(&results));
//! # Ok(())
//! # }
//! ```
//!
//! # Complete Test Example
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//! use dotscope::test::mono::{TestRunner, run_complete_test};
//!
//! # fn main() -> dotscope::Result<()> {
//! let runner = TestRunner::new()?;
//!
//! // Source code to compile
//! let source = r#"
//! using System;
//! public class TestClass {
//!     public static void Main() { Console.WriteLine("Hello!"); }
//!     public static int Add(int a, int b) { return a + b; }
//! }
//! "#;
//!
//! // Run complete test (compile, modify, execute, verify)
//! let results = run_complete_test(
//!     &runner,
//!     source,
//!     |ctx| {
//!         // Modify the assembly using dotscope builders
//!         Ok(())
//!     },
//! )?;
//!
//! // Check results for each architecture
//! for result in &results {
//!     println!("{}: {}", result.architecture.name,
//!         if result.is_fully_successful() { "PASS" } else { "FAIL" });
//! }
//! # Ok(())
//! # }
//! ```

pub mod capabilities;
pub mod compilation;
pub mod disassembly;
pub mod execution;
pub mod reflection;
pub mod runner;

// Re-export main types
pub use capabilities::{Architecture, TestCapabilities};
pub use reflection::MethodTest;
pub use runner::TestRunner;

use crate::prelude::*;
use std::path::Path;

/// Result of a complete test run for one architecture
#[derive(Debug)]
pub struct CompleteTestResult {
    /// The architecture tested
    pub architecture: Architecture,
    /// Whether compilation succeeded
    pub compilation_success: bool,
    /// Whether assembly modification succeeded
    pub modification_success: bool,
    /// Whether execution succeeded
    pub execution_success: bool,
    /// Whether disassembly verification succeeded
    pub disassembly_success: bool,
    /// Whether reflection tests succeeded
    pub reflection_success: bool,
    /// Error messages
    pub errors: Vec<String>,
}

impl CompleteTestResult {
    /// Check if all test phases were successful
    pub fn is_fully_successful(&self) -> bool {
        self.compilation_success
            && self.modification_success
            && self.execution_success
            && self.disassembly_success
            && self.reflection_success
            && self.errors.is_empty()
    }

    /// Check if at least compilation and modification worked
    pub fn is_buildable(&self) -> bool {
        self.compilation_success && self.modification_success
    }

    /// Get a summary string
    pub fn summary(&self) -> String {
        if self.is_fully_successful() {
            format!("{}: All tests passed", self.architecture.name)
        } else {
            format!(
                "{}: compile={}, modify={}, exec={}, disasm={}, reflect={}, errors={}",
                self.architecture.name,
                self.compilation_success,
                self.modification_success,
                self.execution_success,
                self.disassembly_success,
                self.reflection_success,
                self.errors.len()
            )
        }
    }
}

/// Run a complete test workflow: compile, modify, execute, verify
///
/// This function orchestrates a full integration test:
/// 1. Compile C# source code
/// 2. Modify the assembly using dotscope
/// 3. Execute the modified assembly
/// 4. Verify with disassembly
/// 5. Run reflection tests
pub fn run_complete_test<M>(
    runner: &TestRunner,
    source_code: &str,
    modify_fn: M,
) -> Result<Vec<CompleteTestResult>>
where
    M: Fn(&mut crate::BuilderContext) -> Result<()>,
{
    let caps = runner.capabilities();
    let mut results = Vec::new();

    for arch in runner.architectures() {
        let mut result = CompleteTestResult {
            architecture: arch.clone(),
            compilation_success: false,
            modification_success: false,
            execution_success: false,
            disassembly_success: false,
            reflection_success: false,
            errors: Vec::new(),
        };

        // Create architecture-specific directory
        let arch_dir = match runner.arch_dir(arch) {
            Ok(d) => d,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to create directory: {}", e));
                results.push(result);
                continue;
            }
        };

        // 1. Compile
        let compile_result = match compilation::compile(caps, source_code, &arch_dir, "test", arch)
        {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(format!("Compilation error: {}", e));
                results.push(result);
                continue;
            }
        };

        if !compile_result.is_success() {
            result
                .errors
                .push(format!("Compilation failed: {:?}", compile_result.error));
            results.push(result);
            continue;
        }
        result.compilation_success = true;

        let original_path = compile_result.assembly_path();

        // 2. Modify assembly
        let modified_dir = arch_dir.join("modified");
        std::fs::create_dir_all(&modified_dir).ok();
        let modified_path = modified_dir.join(
            original_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("modified.dll")),
        );

        match modify_assembly(original_path, &modified_path, &modify_fn) {
            Ok(_) => {
                result.modification_success = true;

                // Copy runtimeconfig.json if it exists
                if let Some(stem) = original_path.file_stem().and_then(|s| s.to_str()) {
                    if let Some(parent) = original_path.parent() {
                        let config_src = parent.join(format!("{}.runtimeconfig.json", stem));
                        if config_src.exists() {
                            let config_dst =
                                modified_dir.join(format!("{}.runtimeconfig.json", stem));
                            std::fs::copy(&config_src, &config_dst).ok();
                        }
                    }
                }
            }
            Err(e) => {
                result.errors.push(format!("Modification failed: {}", e));
                results.push(result);
                continue;
            }
        }

        // 3. Execute
        match execution::execute(caps, &modified_path) {
            Ok(exec_result) => {
                if exec_result.is_success() {
                    result.execution_success = true;
                } else {
                    result
                        .errors
                        .push(format!("Execution failed: {}", exec_result.error_summary()));
                }
            }
            Err(e) => {
                result.errors.push(format!("Execution error: {}", e));
            }
        }

        // 4. Disassembly verification
        if caps.can_disassemble() {
            match disassembly::disassemble(caps, &modified_path) {
                Ok(disasm_result) => {
                    if disasm_result.is_success() {
                        result.disassembly_success = true;
                    } else {
                        result
                            .errors
                            .push(format!("Disassembly failed: {:?}", disasm_result.error));
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Disassembly error: {}", e));
                }
            }
        } else {
            // No disassembler available, mark as success (optional check)
            result.disassembly_success = true;
        }

        // 5. Reflection verification
        match reflection::verify_assembly_loadable(caps, &modified_path, &modified_dir, arch) {
            Ok(refl_result) => {
                if refl_result.is_success() {
                    result.reflection_success = true;
                } else {
                    result.errors.push(format!(
                        "Reflection failed: {}",
                        refl_result.error_summary()
                    ));
                }
            }
            Err(e) => {
                result.errors.push(format!("Reflection error: {}", e));
            }
        }

        results.push(result);
    }

    Ok(results)
}

/// Run a complete test workflow with custom reflection tests
///
/// This is like `run_complete_test` but allows specifying custom method tests
/// that verify the generated methods work correctly with specific inputs/outputs.
///
/// The `create_tests_fn` receives the path to the modified assembly and returns
/// a list of `MethodTest` to run against it.
pub fn run_complete_test_with_reflection<M, T>(
    runner: &TestRunner,
    source_code: &str,
    modify_fn: M,
    create_tests_fn: T,
) -> Result<Vec<CompleteTestResult>>
where
    M: Fn(&mut crate::BuilderContext) -> Result<()>,
    T: Fn(&Path) -> Vec<reflection::MethodTest>,
{
    let caps = runner.capabilities();
    let mut results = Vec::new();

    for arch in runner.architectures() {
        let mut result = CompleteTestResult {
            architecture: arch.clone(),
            compilation_success: false,
            modification_success: false,
            execution_success: false,
            disassembly_success: false,
            reflection_success: false,
            errors: Vec::new(),
        };

        // Create architecture-specific directory
        let arch_dir = match runner.arch_dir(arch) {
            Ok(d) => d,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to create directory: {}", e));
                results.push(result);
                continue;
            }
        };

        // 1. Compile
        let compile_result = match compilation::compile(caps, source_code, &arch_dir, "test", arch)
        {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(format!("Compilation error: {}", e));
                results.push(result);
                continue;
            }
        };

        if !compile_result.is_success() {
            result
                .errors
                .push(format!("Compilation failed: {:?}", compile_result.error));
            results.push(result);
            continue;
        }
        result.compilation_success = true;

        let original_path = compile_result.assembly_path();

        // 2. Modify assembly
        let modified_dir = arch_dir.join("modified");
        std::fs::create_dir_all(&modified_dir).ok();
        let modified_path = modified_dir.join(
            original_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("modified.dll")),
        );

        match modify_assembly(original_path, &modified_path, &modify_fn) {
            Ok(_) => {
                result.modification_success = true;

                // Copy runtimeconfig.json if it exists
                if let Some(stem) = original_path.file_stem().and_then(|s| s.to_str()) {
                    if let Some(parent) = original_path.parent() {
                        let config_src = parent.join(format!("{}.runtimeconfig.json", stem));
                        if config_src.exists() {
                            let config_dst =
                                modified_dir.join(format!("{}.runtimeconfig.json", stem));
                            std::fs::copy(&config_src, &config_dst).ok();
                        }
                    }
                }
            }
            Err(e) => {
                result.errors.push(format!("Modification failed: {}", e));
                results.push(result);
                continue;
            }
        }

        // 3. Execute (basic execution test)
        match execution::execute(caps, &modified_path) {
            Ok(exec_result) => {
                if exec_result.is_success() {
                    result.execution_success = true;
                } else {
                    result
                        .errors
                        .push(format!("Execution failed: {}", exec_result.error_summary()));
                }
            }
            Err(e) => {
                result.errors.push(format!("Execution error: {}", e));
            }
        }

        // 4. Disassembly verification
        if caps.can_disassemble() {
            match disassembly::disassemble(caps, &modified_path) {
                Ok(disasm_result) => {
                    if disasm_result.is_success() {
                        result.disassembly_success = true;
                    } else {
                        result
                            .errors
                            .push(format!("Disassembly failed: {:?}", disasm_result.error));
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Disassembly error: {}", e));
                }
            }
        } else {
            // No disassembler available, mark as success (optional check)
            result.disassembly_success = true;
        }

        // 5. Reflection tests with custom method invocations
        let method_tests = create_tests_fn(&modified_path);
        if method_tests.is_empty() {
            // No custom tests, just verify assembly is loadable
            match reflection::verify_assembly_loadable(caps, &modified_path, &modified_dir, arch) {
                Ok(refl_result) => {
                    if refl_result.is_success() {
                        result.reflection_success = true;
                    } else {
                        result.errors.push(format!(
                            "Reflection failed: {}",
                            refl_result.error_summary()
                        ));
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Reflection error: {}", e));
                }
            }
        } else {
            // Run custom method tests
            match reflection::run_reflection_test(
                caps,
                &modified_path,
                &method_tests,
                &modified_dir,
                arch,
            ) {
                Ok(refl_result) => {
                    if refl_result.is_success() {
                        result.reflection_success = true;
                    } else {
                        result.errors.push(format!(
                            "Reflection test failed: {}",
                            refl_result.error_summary()
                        ));
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Reflection error: {}", e));
                }
            }
        }

        results.push(result);
    }

    Ok(results)
}

/// Modify an assembly using dotscope
fn modify_assembly<M>(original_path: &Path, modified_path: &Path, modify_fn: &M) -> Result<()>
where
    M: Fn(&mut crate::BuilderContext) -> Result<()>,
{
    use crate::prelude::*;

    let view = CilAssemblyView::from_path(original_path)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    modify_fn(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(modified_path)?;

    Ok(())
}

/// Check if all complete test results are successful
pub fn all_successful(results: &[CompleteTestResult]) -> bool {
    results.iter().all(|r| r.is_fully_successful())
}

/// Get error summary for failed tests
pub fn error_summary(results: &[CompleteTestResult]) -> String {
    let failed: Vec<_> = results
        .iter()
        .filter(|r| !r.is_fully_successful())
        .collect();

    if failed.is_empty() {
        "All tests passed".to_string()
    } else {
        failed
            .iter()
            .map(|r| format!("{}: {}", r.architecture.name, r.errors.join(", ")))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_detection() {
        let caps = TestCapabilities::detect();
        println!("Detected: {}", caps.summary());
    }

    #[test]
    fn test_runner_creation() -> Result<()> {
        let runner = TestRunner::new()?;
        println!("Runner capabilities: {}", runner.capabilities().summary());
        println!(
            "Supported architectures: {:?}",
            runner
                .architectures()
                .iter()
                .map(|a| a.name)
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn test_complete_workflow() -> Result<()> {
        let runner = TestRunner::new()?;

        let results = run_complete_test(&runner, compilation::templates::HELLO_WORLD, |_ctx| {
            // No modifications - just test the workflow
            Ok(())
        })?;

        for result in &results {
            println!("{}", result.summary());
        }

        // At least compilation should work
        assert!(
            results.iter().all(|r| r.compilation_success),
            "Compilation should succeed"
        );

        Ok(())
    }
}
