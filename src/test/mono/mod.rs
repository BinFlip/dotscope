//! .NET assembly verification framework for dotscope testing
//!
//! This module provides utilities for verifying that .NET assemblies generated or modified
//! by dotscope are valid and executable. It uses official .NET tools (dotnet CLI, Mono runtime,
//! monodis) to validate that our binary output is correct and interoperable with the .NET ecosystem.
//!
//! # Purpose
//!
//! When dotscope modifies or generates .NET assemblies, we need to verify that:
//! 1. The resulting binaries are structurally valid (can be loaded by .NET runtimes)
//! 2. Added/modified code executes correctly (methods can be called via reflection)
//! 3. Metadata is properly formatted (monodis can disassemble without errors)
//!
//! This framework automates these verification steps across multiple platforms and architectures.
//!
//! # Architecture
//!
//! The framework is organized into specialized modules:
//!
//! - **`runner`** - Test orchestration, temporary folder management, and architecture configuration
//! - **`compilation`** - C# compilation using available compilers (dotnet CLI, csc, mcs)
//! - **`execution`** - Assembly execution via .NET runtime (dotnet) or Mono
//! - **`disassembly`** - IL disassembly verification using monodis
//! - **`reflection`** - Dynamic method invocation tests via .NET reflection
//!
//! # Usage Examples
//!
//! ## Basic Test Setup
//!
//! ```rust,no_run
//! use dotscope::test::mono::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let runner = MonoTestRunner::new()?;
//! let mut compiler = CSharpCompiler::new();
//! let mut runtime = MonoRuntime::new();
//!
//! // Compile test program for both architectures
//! let results = compiler.compile_for_architectures(
//!     r#"
//!     using System;
//!     class Program {
//!         static void Main() {
//!             Console.WriteLine("Hello World!");
//!         }
//!     }
//!     "#,
//!     runner.temp_path(),
//!     "test",
//!     runner.architectures()
//! )?;
//!
//! // Test execution on each architecture
//! for result in &results {
//!     if let Some(exe_path) = result.compilation.try_executable_path() {
//!         let exec_result = runtime.execute_assembly(exe_path)?;
//!         println!("{}: {}", result.architecture.name, exec_result.is_success());
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Assembly Modification and Verification
//!
//! ```rust,no_run
//! use dotscope::test::mono::*;
//! use dotscope::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let runner = MonoTestRunner::new()?;
//! let mut compiler = CSharpCompiler::new();
//! let mut disassembler = ILDisassembler::new();
//!
//! // Compile original assembly
//! let arch = ArchConfig::x64();
//! let exe_path = runner.create_arch_file_path("test", &arch, ".exe");
//! let compilation_result = compiler.compile_executable(
//!     compilation::templates::HELLO_WORLD,
//!     &exe_path,
//!     &arch
//! )?;
//!
//! if compilation_result.is_success() {
//!     // Modify assembly using dotscope
//!     let view = CilAssemblyView::from_path(&exe_path)?;
//!     let assembly = CilAssembly::new(view);
//!     let mut context = BuilderContext::new(assembly);
//!
//!     // Add custom method
//!     let _method_token = MethodBuilder::new("CustomMethod")
//!         .public()
//!         .static_method()
//!         .returns(dotscope::metadata::signatures::TypeSignature::Void)
//!         .implementation(|body| {
//!             body.implementation(|asm| {
//!                 asm.ret()?;
//!                 Ok(())
//!             })
//!         })
//!         .build(&mut context)?;
//!
//!     let mut assembly = context.finish();
//!     assembly.validate_and_apply_changes()?;
//!     
//!     let modified_path = runner.create_arch_file_path("test_modified", &arch, ".exe");
//!     assembly.write_to_file(&modified_path)?;
//!
//!     // Verify the modification
//!     let verification = disassembler.verify_method(&modified_path, "CustomMethod")?;
//!     println!("Custom method found: {}", verification.found);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Reflection-Based Testing
//!
//! ```rust,no_run
//! use dotscope::test::mono::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let runner = MonoTestRunner::new()?;
//! let mut executor = ReflectionTestExecutor::new();
//!
//! // Create reflection test for method with parameters
//! let test_program = ReflectionTestBuilder::new()
//!     .assembly_path("/path/to/modified.exe")
//!     .test_method("AddNumbers")
//!         .description("Test addition: 5 + 7 = 12")
//!         .parameters(vec![5, 7])
//!         .expect(12)
//!     .and()
//!     .test_method("AddNumbers")
//!         .description("Test addition: 100 + 200 = 300")
//!         .parameters(vec![100, 200])
//!         .expect(300)
//!     .build();
//!
//! // Execute the reflection test
//! let result = executor.execute_test(&test_program, runner.temp_path())?;
//! result.print_results("Addition Test");
//! # Ok(())
//! # }
//! ```
//!
//! ## Complete Integration Test
//!
//! ```rust,no_run
//! use dotscope::test::mono::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let runner = MonoTestRunner::new()?;
//!
//! let results = runner.run_for_all_architectures(|arch, temp_path| {
//!     println!("Testing {} architecture", arch.name);
//!
//!     // 1. Compile original program
//!     let mut compiler = CSharpCompiler::new();
//!     let exe_path = temp_path.join(format!("test_{}.exe", arch.filename_component()));
//!     let compilation = compiler.compile_executable(
//!         compilation::templates::SIMPLE_CLASS,
//!         &exe_path,
//!         arch
//!     )?;
//!
//!     if !compilation.is_success() {
//!         return Err(dotscope::Error::Error("Compilation failed".to_string()));
//!     }
//!
//!     // 2. Test original execution
//!     let mut runtime = MonoRuntime::new();
//!     let original_result = runtime.execute_assembly(&exe_path)?;
//!
//!     // 3. Create modified assembly (your custom modifications here)
//!     let modified_path = temp_path.join(format!("modified_{}.exe", arch.filename_component()));
//!     std::fs::copy(&exe_path, &modified_path)?;
//!
//!     // 4. Test mono compatibility
//!     let compat_result = runtime.test_compatibility(&modified_path)?;
//!
//!     // 5. Verify disassembly
//!     let mut disassembler = MonoDisassembler::new();
//!     let verification = disassembler.test_verification(&modified_path, &arch.name)?;
//!
//!     Ok((original_result, compat_result, verification))
//! })?;
//!
//! // Check if all tests passed
//! assert!(MonoTestRunner::all_tests_passed(&results));
//! # Ok(())
//! # }
//! ```
//!
//! # Platform Support
//!
//! The framework automatically adapts to the available tools on each platform:
//!
//! - **Windows**: Uses csc.exe or dotnet CLI for compilation, .NET runtime for execution
//! - **macOS/Linux**: Uses dotnet CLI or mcs for compilation, dotnet or mono for execution
//! - **ARM64**: Uses AnyCPU configuration for cross-architecture compatibility
//!
//! # Customization
//!
//! - **Custom Architectures**: Define `ArchConfig` for specific platform requirements
//! - **Reflection Tests**: Build test scenarios with `ReflectionTestBuilder`
//! - **Error Handling**: All operations return `Result` types for robust error handling

pub mod compilation;
pub mod disassembly;
pub mod execution;
pub mod reflection;
pub mod runner;

// Re-export main types for convenience
pub use compilation::CSharpCompiler;
pub use disassembly::ILDisassembler;
pub use execution::{MonoRuntime, RuntimeType};
pub use reflection::{ReflectionTestBuilder, ReflectionTestExecutor};
pub use runner::{ArchConfig, MonoTestRunner};

/// Common result type for mono testing operations
pub type MonoTestResult<T> = crate::Result<T>;

/// Convenience function to create a complete test environment
pub fn create_test_environment() -> MonoTestResult<TestEnvironment> {
    Ok(TestEnvironment {
        runner: MonoTestRunner::new()?,
        compiler: CSharpCompiler::new(),
        runtime: MonoRuntime::new(),
        disassembler: ILDisassembler::new(),
        reflection_executor: ReflectionTestExecutor::new(),
    })
}

/// Complete test environment with all tools
pub struct TestEnvironment {
    pub runner: MonoTestRunner,
    pub compiler: CSharpCompiler,
    pub runtime: MonoRuntime,
    pub disassembler: ILDisassembler,
    pub reflection_executor: ReflectionTestExecutor,
}

impl TestEnvironment {
    /// Run a complete test workflow
    pub fn run_complete_test<F, M>(
        &mut self,
        source_code: &str,
        modify_assembly: M,
        create_reflection_test: F,
    ) -> MonoTestResult<Vec<CompleteTestResult>>
    where
        F: Fn(&std::path::Path) -> String,
        M: Fn(&mut crate::BuilderContext) -> crate::Result<()>,
    {
        let mut results = Vec::new();

        for arch in self.runner.architectures().to_vec() {
            let mut arch_result = CompleteTestResult {
                architecture: arch.clone(),
                compilation_success: false,
                modification_success: false,
                execution_success: false,
                compatibility_success: false,
                disassembly_success: false,
                reflection_success: false,
                errors: Vec::new(),
            };

            // 1. Compile source
            let requested_exe_path = self.runner.create_arch_file_path("test", &arch, ".exe");
            let comp_result =
                match self
                    .compiler
                    .compile_executable(source_code, &requested_exe_path, &arch)
                {
                    Ok(comp_result) if comp_result.is_success() => {
                        arch_result.compilation_success = true;
                        // Set the appropriate runtime based on which compiler was used
                        if let Some(ref compiler_type) = comp_result.compiler_used {
                            self.runtime
                                .set_runtime(RuntimeType::for_compiler(compiler_type));
                        }
                        comp_result
                    }
                    Ok(comp_result) => {
                        arch_result.errors.push(format!(
                            "Compilation failed: {}",
                            comp_result.error.as_deref().unwrap_or("Unknown error")
                        ));
                        results.push(arch_result);
                        continue;
                    }
                    Err(e) => {
                        arch_result.errors.push(format!("Compilation error: {}", e));
                        results.push(arch_result);
                        continue;
                    }
                };

            // Get the actual output path (may differ from requested path for dotnet SDK)
            let actual_exe_path = comp_result.executable_path();

            // 2. Modify assembly
            // Save modified assembly with the SAME filename as the original but in a
            // per-architecture subdirectory. This is critical because:
            // 1. .NET validates that the assembly's internal name matches the filename
            // 2. Each architecture must be isolated to prevent cross-probing conflicts
            let original_filename = actual_exe_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("test.dll");
            let modified_dir = self.runner.temp_path().join("modified").join(&arch.name);
            std::fs::create_dir_all(&modified_dir).ok();
            let modified_path = modified_dir.join(original_filename);

            match self.modify_assembly_internal(actual_exe_path, &modified_path, &modify_assembly) {
                Ok(_) => {
                    arch_result.modification_success = true;

                    // Copy runtimeconfig.json from original to modified assembly location
                    // This is required for .NET 8+ runtime to execute the assembly
                    let original_stem = actual_exe_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");

                    if let Some(original_dir) = actual_exe_path.parent() {
                        let original_runtimeconfig =
                            original_dir.join(format!("{}.runtimeconfig.json", original_stem));
                        if original_runtimeconfig.exists() {
                            let modified_runtimeconfig =
                                modified_dir.join(format!("{}.runtimeconfig.json", original_stem));
                            std::fs::copy(&original_runtimeconfig, &modified_runtimeconfig).ok();
                        }
                    }
                }
                Err(e) => {
                    arch_result
                        .errors
                        .push(format!("Modification failed: {}", e));
                    results.push(arch_result);
                    continue;
                }
            }

            // 3. Test execution
            match self.runtime.execute_assembly(&modified_path) {
                Ok(exec_result) if exec_result.is_success() => {
                    arch_result.execution_success = true;
                }
                Ok(_) => {
                    arch_result.errors.push("Execution failed".to_string());
                }
                Err(e) => {
                    arch_result.errors.push(format!("Execution error: {}", e));
                }
            }

            // 4. Test compatibility
            match self.runtime.test_compatibility(&modified_path) {
                Ok(compat_result) if compat_result.is_fully_compatible() => {
                    arch_result.compatibility_success = true;
                }
                Ok(_) => {
                    arch_result
                        .errors
                        .push("Compatibility test failed".to_string());
                }
                Err(e) => {
                    arch_result
                        .errors
                        .push(format!("Compatibility error: {}", e));
                }
            }

            // 5. Test disassembly
            match self
                .disassembler
                .test_verification(&modified_path, &arch.name)
            {
                Ok(disasm_result) if disasm_result.is_fully_successful() => {
                    arch_result.disassembly_success = true;
                }
                Ok(_) => {
                    arch_result
                        .errors
                        .push("Disassembly verification failed".to_string());
                }
                Err(e) => {
                    arch_result.errors.push(format!("Disassembly error: {}", e));
                }
            }

            // 6. Test reflection
            // Execute the reflection test from the modified directory so .NET can
            // properly resolve assembly references during reflection calls
            let reflection_test = create_reflection_test(&modified_path);
            match self
                .reflection_executor
                .execute_test(&reflection_test, &modified_dir)
            {
                Ok(refl_result) if refl_result.is_successful() => {
                    arch_result.reflection_success = true;
                }
                Ok(refl_result) => {
                    let error_details = format!(
                        "Reflection test failed: compilation_success={}, execution_success={}, error={}",
                        refl_result.compilation_success,
                        refl_result.execution_success,
                        refl_result.error_summary()
                    );
                    arch_result.errors.push(error_details);
                }
                Err(e) => {
                    arch_result.errors.push(format!("Reflection error: {}", e));
                }
            }

            results.push(arch_result);
        }

        Ok(results)
    }

    fn modify_assembly_internal<M>(
        &self,
        original_path: &std::path::Path,
        modified_path: &std::path::Path,
        modify_fn: &M,
    ) -> crate::Result<()>
    where
        M: Fn(&mut crate::BuilderContext) -> crate::Result<()>,
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
}

/// Complete test result for all verification steps
#[derive(Debug)]
pub struct CompleteTestResult {
    pub architecture: ArchConfig,
    pub compilation_success: bool,
    pub modification_success: bool,
    pub execution_success: bool,
    pub compatibility_success: bool,
    pub disassembly_success: bool,
    pub reflection_success: bool,
    pub errors: Vec<String>,
}

impl CompleteTestResult {
    /// Check if all test steps were successful
    pub fn is_fully_successful(&self) -> bool {
        self.compilation_success
            && self.modification_success
            && self.execution_success
            && self.compatibility_success
            && self.disassembly_success
            && self.reflection_success
            && self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::test::mono::runner::ArchConfig;
    use crate::test::mono::{create_test_environment, CompleteTestResult, MonoTestResult};

    #[test]
    fn test_create_test_environment() -> MonoTestResult<()> {
        let _env = create_test_environment()?;
        Ok(())
    }

    #[test]
    fn test_complete_test_result() {
        let result = CompleteTestResult {
            architecture: ArchConfig::x64(),
            compilation_success: true,
            modification_success: true,
            execution_success: false,
            compatibility_success: false,
            disassembly_success: true,
            reflection_success: false,
            errors: vec!["Test error".to_string()],
        };

        assert!(!result.is_fully_successful());
    }

    #[test]
    fn test_arch_config_methods() {
        let arch = ArchConfig::x86();
        assert_eq!(arch.filename_component(), "x86");

        let standard_archs = ArchConfig::standard_architectures();
        assert_eq!(standard_archs.len(), 2);
    }
}
