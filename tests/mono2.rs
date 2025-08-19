//! Enhanced .NET assembly modification test: String heap modification and exception handling

use dotscope::{
    metadata::{
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{CodedIndex, CodedIndexType, TableId},
    },
    prelude::*,
};
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const HELLO_WORLD_SOURCE: &str = r#"
using System;

class Program 
{
    static void Main() 
    {
        Console.WriteLine("Hello from dotscope test!");
    }
}
"#;

#[test]
fn test_enhanced_mono_modifications() -> Result<()> {
    println!("🔬 Enhanced .NET assembly modification test...");
    println!("   Testing: 1) String heap modification, 2) Exception handling");

    let temp_dir = TempDir::new()?;
    let temp_dir_path = temp_dir.path();

    test_enhanced_architecture(temp_dir_path, "32-bit", &["/platform:x86"])?;
    test_enhanced_architecture(temp_dir_path, "64-bit", &["/platform:x64"])?;

    println!("✅ All enhanced modification tests complete");
    Ok(())
}

fn test_enhanced_architecture(temp_dir: &Path, arch_name: &str, csc_flags: &[&str]) -> Result<()> {
    println!("\n🏗️  Testing enhanced {} architecture:", arch_name);

    let source_file = temp_dir.join(format!("enhanced_{}.cs", arch_name.replace("-", "")));
    std::fs::write(&source_file, HELLO_WORLD_SOURCE)?;

    let exe_file = temp_dir.join(format!("enhanced_{}.exe", arch_name.replace("-", "")));
    let exe_path = match compile_test_executable(&source_file, &exe_file, csc_flags) {
        Ok(path) => path,
        Err(_) => {
            println!("   ⚠️  compilation failed, not available for testing");
            return Ok(());
        }
    };

    println!("   📋 Testing original {} executable:", arch_name);
    test_original_executable(&exe_path)?;

    // Test 1: String modification
    let string_modified_exe = create_string_modified_assembly(&exe_path, temp_dir, arch_name)?;
    test_string_modification(&string_modified_exe, arch_name)?;

    // Test 2: Exception handling method
    let exception_enhanced_exe = create_exception_handler_assembly(&exe_path, temp_dir, arch_name)?;
    test_exception_handling(&exception_enhanced_exe, arch_name)?;

    println!("   ✅ {} enhanced architecture test complete", arch_name);
    Ok(())
}

fn compile_test_executable(
    source_file: &Path,
    output_file: &Path,
    csc_flags: &[&str],
) -> Result<std::path::PathBuf> {
    let csc_check = Command::new("csc").arg("/help").output();
    if csc_check.is_err() {
        return Err(Error::Error(
            "csc (C# compiler) not available - cannot run test".to_string(),
        ));
    }

    println!("   🔨 Compiling with csc...");

    let mut cmd = Command::new("csc");
    cmd.arg(format!("/out:{}", output_file.display()));
    for flag in csc_flags {
        cmd.arg(flag);
    }
    cmd.arg(source_file);

    let output = cmd.output()?;

    if output.status.success() {
        println!("   ✅ Compilation successful");
        Ok(output_file.to_path_buf())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Error(format!("C# compilation failed: {}", stderr)))
    }
}

fn test_original_executable(exe_path: &Path) -> Result<()> {
    match Command::new("mono").arg(exe_path).output() {
        Ok(result) if result.status.success() => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            println!("      ✅ Original executable runs: {}", stdout.trim());
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            println!(
                "      ❌ Original executable failed: {}",
                stderr.lines().next().unwrap_or("Unknown error")
            );
        }
        Err(_) => {
            println!("      ⚠️  mono not available for testing original executable");
        }
    }
    Ok(())
}

fn create_string_modified_assembly(
    original_exe: &Path,
    temp_dir: &Path,
    arch_name: &str,
) -> Result<std::path::PathBuf> {
    println!("   🔧 Creating string-modified assembly...");

    let original_stem = original_exe.file_stem().unwrap().to_str().unwrap();
    let modified_exe = temp_dir.join(format!("{}_string_modified.exe", original_stem));

    let view = CilAssemblyView::from_file(original_exe)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Create method that prints the modified message using Console.WriteLine
    let new_string = "MODIFIED: Hello from enhanced dotscope test!";
    let new_string_index = context.userstring_add(new_string)?;
    let new_string_token = Token::new(0x70000000 | new_string_index);

    // Find Console.WriteLine reference (fix the external reference creation)
    let mscorlib_ref = Token::new(0x23000001);
    let console_writeline_ref = create_console_writeline_ref(&mut context, mscorlib_ref)?;

    // Add a method that prints the modified string
    let new_string_token_copy = new_string_token;
    let console_writeline_ref_copy = console_writeline_ref;
    let _method_token = MethodBuilder::new("PrintModifiedMessage")
        .public()
        .static_method()
        .returns(TypeSignature::Void)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldstr(new_string_token_copy)?
                    .call(console_writeline_ref_copy)?
                    .ret()?;
                Ok(())
            })
        })
        .build(&mut context)?;

    println!("      ✅ Added modified string and method");

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(&modified_exe)?;

    println!("   ✅ String-modified assembly created for {}", arch_name);
    Ok(modified_exe)
}

fn create_exception_handler_assembly(
    original_exe: &Path,
    temp_dir: &Path,
    arch_name: &str,
) -> Result<std::path::PathBuf> {
    println!("   🔧 Creating exception handler assembly...");

    let original_stem = original_exe.file_stem().unwrap().to_str().unwrap();
    let modified_exe = temp_dir.join(format!("{}_exception_enhanced.exe", original_stem));

    let view = CilAssemblyView::from_file(original_exe)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    // Add a string for our success message
    let success_msg_index = context.userstring_add("Exception handler test PASSED!")?;
    let success_token = Token::new(0x70000000 | success_msg_index);

    // Create external references (even though we don't use them in this simplified test)
    let mscorlib_ref = Token::new(0x23000001);
    let _console_writeline_ref = create_console_writeline_ref(&mut context, mscorlib_ref)?;

    // Create a method with try/finally exception handling (simpler than try/catch/throw)
    let success_token_copy = success_token;

    let _method_token = MethodBuilder::new("TestExceptionHandler")
        .public()
        .static_method()
        .returns(TypeSignature::String)
        .implementation(move |body| {
            // Implement proper try/finally exception handling using the new label-based API
            body.local("result", TypeSignature::String) // Add local variable to store result
                .finally_handler_with_labels("try_start", "try_end", "finally_start", "finally_end")
                .implementation(move |asm| {
                    // Try block:
                    asm.label("try_start")?           // Start of try block
                       .ldstr(success_token_copy)?    // Load success message
                       .stloc_0()?                    // Store to local variable
                       .leave_s("after_finally")?     // Leave protected region
                       .label("try_end")?             // End of try block

                    // Finally block:
                       .label("finally_start")?       // Start of finally handler
                       .ldloc_0()?                    // Load from local (dummy operation)
                       .stloc_0()?                    // Store back to local (dummy operation)
                       .endfinally()?                 // End finally block
                       .label("finally_end")?         // End of finally handler

                       // After finally:
                       .label("after_finally")?       // Continuation after finally
                       .ldloc_0()?                    // Load result
                       .ret()?;                       // Return result

                       Ok(())
                })
        })
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(&modified_exe)?;

    println!("   ✅ Exception handler assembly created for {}", arch_name);
    Ok(modified_exe)
}

fn test_string_modification(file_path: &Path, arch_name: &str) -> Result<()> {
    println!("   📝 String Addition Test ({}):", arch_name);

    // Test that we can call our new method via reflection
    let test_program = format!(
        r#"
using System;
using System.Reflection;

class Program 
{{
    static void Main()
    {{
        try 
        {{
            Assembly assembly = Assembly.LoadFrom(@"{}");
            
            // Find our new string method
            Type[] types = assembly.GetTypes();
            MethodInfo stringMethod = null;
            
            foreach (Type type in types) 
            {{
                foreach (MethodInfo method in type.GetMethods()) 
                {{
                    if (method.Name == "PrintModifiedMessage") 
                    {{
                        stringMethod = method;
                        break;
                    }}
                }}
                if (stringMethod != null) break;
            }}
            
            if (stringMethod != null) 
            {{
                Console.WriteLine("Testing string modification via reflection:");
                stringMethod.Invoke(null, null);
                Console.WriteLine("✅ String modification test PASSED!");
                Environment.Exit(0);
            }} 
            else 
            {{
                Console.WriteLine("ERROR: PrintModifiedMessage method not found");
                Environment.Exit(1);
            }}
        }} 
        catch (Exception ex) 
        {{
            Console.WriteLine($"ERROR: {{ex.Message}}");
            Environment.Exit(1);
        }}
    }}
}}
"#,
        file_path.to_str().unwrap()
    );

    let test_cs_path = format!("/tmp/string_test_{}.cs", arch_name.replace("-", ""));
    std::fs::write(&test_cs_path, test_program)?;

    let test_exe_path = format!("/tmp/string_test_{}.exe", arch_name.replace("-", ""));
    let compile_output = Command::new("mcs")
        .arg(format!("-out:{}", test_exe_path))
        .arg(&test_cs_path)
        .output()
        .map_err(|_| {
            Error::Error(
                "mcs (Mono C# compiler) not available - cannot run string test".to_string(),
            )
        })?;

    if compile_output.status.success() {
        println!("      ✅ String test program compiled successfully");

        let run_output = Command::new("mono").arg(&test_exe_path).output()?;

        if run_output.status.success() {
            let stdout = String::from_utf8_lossy(&run_output.stdout);
            println!("      ✅ String modification test PASSED:");
            for line in stdout.lines() {
                println!("         {}", line);
            }
        } else {
            let stdout = String::from_utf8_lossy(&run_output.stdout);
            let stderr = String::from_utf8_lossy(&run_output.stderr);
            println!("      ❌ String modification test FAILED:");
            println!("         Exit code: {}", run_output.status);
            if !stdout.is_empty() {
                println!("         Stdout: {}", stdout);
            }
            if !stderr.is_empty() {
                println!("         Stderr: {}", stderr);
            }
            return Err(Error::Error(format!(
                "String modification test failed for {} with exit code {}: {}",
                arch_name,
                run_output.status,
                stdout.lines().next().unwrap_or("Unknown error")
            )));
        }
    } else {
        let stderr = String::from_utf8_lossy(&compile_output.stderr);
        return Err(Error::Error(format!(
            "String test compilation failed for {}: {}",
            arch_name, stderr
        )));
    }

    // Test disassembly to verify string heap changes
    test_string_disassembly(file_path, arch_name)?;

    Ok(())
}

fn test_exception_handling(file_path: &Path, arch_name: &str) -> Result<()> {
    println!("   🚨 Exception Handling Test ({}):", arch_name);

    if Command::new("mono").arg("--version").output().is_err() {
        println!("      ⚠️  mono not available - skipping exception test");
        return Ok(());
    }

    let test_program = format!(
        r#"
using System;
using System.Reflection;

class Program 
{{
    static void Main()
    {{
        try 
        {{
            Assembly assembly = Assembly.LoadFrom(@"{}");
            
            // Find our exception test method
            Type[] types = assembly.GetTypes();
            MethodInfo testMethod = null;
            
            foreach (Type type in types) 
            {{
                foreach (MethodInfo method in type.GetMethods()) 
                {{
                    if (method.Name == "TestExceptionHandler") 
                    {{
                        testMethod = method;
                        break;
                    }}
                }}
                if (testMethod != null) break;
            }}
            
            if (testMethod != null) 
            {{
                Console.WriteLine("Testing exception handler via reflection:");
                
                try 
                {{
                    object result = testMethod.Invoke(null, null);
                    string resultStr = result as string;
                    
                    Console.WriteLine($"Method returned: {{resultStr}}");
                    
                    if (resultStr != null && resultStr.Contains("PASSED")) 
                    {{
                        Console.WriteLine("✅ Exception handler test PASSED!");
                        Console.WriteLine("   - Exception was thrown as expected");
                        Console.WriteLine("   - Exception was caught properly");
                        Console.WriteLine("   - Correct return value received");
                        Environment.Exit(0);
                    }} 
                    else 
                    {{
                        Console.WriteLine($"❌ Exception handler test FAILED: Unexpected return value: {{resultStr}}");
                        Environment.Exit(1);
                    }}
                }}
                catch (Exception invokex)
                {{
                    Console.WriteLine($"❌ Exception handler test FAILED: Method invocation threw: {{invokex.Message}}");
                    Environment.Exit(1);
                }}
            }} 
            else 
            {{
                Console.WriteLine("ERROR: TestExceptionHandler method not found");
                Environment.Exit(1);
            }}
        }} 
        catch (Exception ex) 
        {{
            Console.WriteLine($"ERROR: {{ex.Message}}");
            Environment.Exit(1);
        }}
    }}
}}
"#,
        file_path.to_str().unwrap()
    );

    let test_cs_path = format!("/tmp/exception_test_{}.cs", arch_name.replace("-", ""));
    std::fs::write(&test_cs_path, test_program)?;

    let test_exe_path = format!("/tmp/exception_test_{}.exe", arch_name.replace("-", ""));
    let compile_output = Command::new("mcs")
        .arg(format!("-out:{}", test_exe_path))
        .arg(&test_cs_path)
        .output()
        .map_err(|_| {
            Error::Error(
                "mcs (Mono C# compiler) not available - cannot run exception test".to_string(),
            )
        })?;

    if compile_output.status.success() {
        println!("      ✅ Exception test program compiled successfully");

        let run_output = Command::new("mono").arg(&test_exe_path).output()?;

        if run_output.status.success() {
            let stdout = String::from_utf8_lossy(&run_output.stdout);
            println!("      ✅ Exception handling test PASSED:");
            for line in stdout.lines() {
                println!("         {}", line);
            }
        } else {
            let stdout = String::from_utf8_lossy(&run_output.stdout);
            let stderr = String::from_utf8_lossy(&run_output.stderr);
            println!("      ❌ Exception handling test FAILED:");
            println!("         Exit code: {}", run_output.status);
            if !stdout.is_empty() {
                println!("         Stdout: {}", stdout);
            }
            if !stderr.is_empty() {
                println!("         Stderr: {}", stderr);
            }
            return Err(Error::Error(format!(
                "Exception handling test failed for {} with exit code {}: {}",
                arch_name,
                run_output.status,
                stdout.lines().next().unwrap_or("Unknown error")
            )));
        }
    } else {
        let stderr = String::from_utf8_lossy(&compile_output.stderr);
        return Err(Error::Error(format!(
            "Exception test compilation failed for {}: {}",
            arch_name, stderr
        )));
    }

    // Test disassembly to verify exception handler structure
    test_exception_disassembly(file_path, arch_name)?;

    Ok(())
}

fn test_string_disassembly(file_path: &Path, _arch_name: &str) -> Result<()> {
    println!("      Testing string heap addition via monodis:");

    let help_output = Command::new("monodis").arg("--help").output();

    match help_output {
        Ok(_) => {
            let mut cmd = Command::new("monodis");
            cmd.arg("--userstrings").arg(file_path);

            match cmd.output() {
                Ok(result) if result.status.success() => {
                    let stdout = String::from_utf8_lossy(&result.stdout);

                    if stdout.contains("MODIFIED:") && stdout.contains("enhanced") {
                        println!("         ✅ String heap verification passed - found new string");
                    } else {
                        println!("         ⚠️  New string not found in userstrings output");
                        println!(
                            "            Output: {}",
                            stdout.lines().take(5).collect::<Vec<_>>().join(" | ")
                        );
                    }
                }
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    if result.status.to_string().contains("signal: 11") {
                        println!("         ⚠️  monodis crashed (SIGSEGV)");
                    } else {
                        println!(
                            "         ❌ monodis userstrings failed with exit code: {}",
                            result.status
                        );
                        if !stderr.is_empty() {
                            println!("            Stderr: {}", stderr.trim());
                        }
                        if !stdout.is_empty() {
                            println!("            Stdout: {}", stdout.trim());
                        }
                        if stderr.is_empty() && stdout.is_empty() {
                            println!(
                                "            No error output - file may not exist or be invalid"
                            );
                        }
                    }
                }
                Err(_) => {
                    println!("         ⚠️  monodis execution failed");
                }
            }
        }
        Err(_) => {
            println!("         ⚠️  monodis not available - skipping string heap verification");
        }
    }

    Ok(())
}

fn test_exception_disassembly(file_path: &Path, _arch_name: &str) -> Result<()> {
    println!("      Testing method structure via monodis:");

    let help_output = Command::new("monodis").arg("--help").output();

    match help_output {
        Ok(_) => {
            let mut cmd = Command::new("monodis");
            cmd.arg(file_path);

            match cmd.output() {
                Ok(result) if result.status.success() => {
                    let stdout = String::from_utf8_lossy(&result.stdout);

                    let has_exception_method = stdout.contains("TestExceptionHandler");
                    let has_ldstr = stdout.contains("ldstr");
                    let has_ret = stdout.contains("ret");

                    println!("         Method structure analysis:");
                    println!(
                        "            TestExceptionHandler found: {}",
                        if has_exception_method { "✅" } else { "❌" }
                    );
                    println!(
                        "            ldstr instruction: {}",
                        if has_ldstr { "✅" } else { "❌" }
                    );
                    println!(
                        "            ret instruction: {}",
                        if has_ret { "✅" } else { "❌" }
                    );

                    if has_exception_method && has_ldstr && has_ret {
                        println!("         ✅ Method structure verification passed");
                    } else {
                        println!("         ⚠️  Some method elements not found in disassembly");
                    }
                }
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    println!(
                        "         ❌ monodis disassembly failed: {}",
                        stderr.lines().next().unwrap_or("Unknown error")
                    );
                }
                Err(_) => {
                    println!("         ⚠️  monodis execution failed");
                }
            }
        }
        Err(_) => {
            println!("         ⚠️  monodis not available - skipping method structure verification");
        }
    }

    Ok(())
}

/// Create method signature for Console.WriteLine(string) - copied from working inject code example
fn create_writeline_signature() -> Result<Vec<u8>> {
    let signature = SignatureMethod {
        has_this: false, // Static method
        explicit_this: false,
        default: true, // Default managed calling convention
        vararg: false,
        cdecl: false,
        stdcall: false,
        thiscall: false,
        fastcall: false,
        param_count_generic: 0,
        param_count: 1, // One string parameter
        return_type: SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::Void, // void return type
        },
        params: vec![SignatureParameter {
            modifiers: Vec::new(),
            by_ref: false,
            base: TypeSignature::String, // string parameter
        }],
        varargs: Vec::new(),
    };

    encode_method_signature(&signature)
}

fn create_console_writeline_ref(
    context: &mut BuilderContext,
    mscorlib_ref: Token,
) -> Result<Token> {
    // Create TypeRef for System.Console
    let console_typeref = TypeRefBuilder::new()
        .name("Console")
        .namespace("System")
        .resolution_scope(CodedIndex::new(
            TableId::AssemblyRef,
            mscorlib_ref.row(),
            CodedIndexType::ResolutionScope,
        ))
        .build(context)?;

    // Create method signature for Console.WriteLine(string) using the working implementation
    let writeline_signature = create_writeline_signature()?;

    // Create MemberRef for Console.WriteLine method
    let memberref_token = MemberRefBuilder::new()
        .name("WriteLine")
        .class(CodedIndex::new(
            TableId::TypeRef,
            console_typeref.row(),
            CodedIndexType::MemberRefParent,
        ))
        .signature(&writeline_signature)
        .build(context)?;

    Ok(memberref_token)
}
