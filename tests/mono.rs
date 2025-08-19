//! Comprehensive .NET assembly generation and runtime compatibility test

use dotscope::{metadata::signatures::TypeSignature, prelude::*};
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
fn test_mono_runtime() -> Result<()> {
    println!("🔬 Analyzing runtime architecture and execution compatibility...");

    let temp_dir = TempDir::new()?;
    let temp_dir_path = temp_dir.path();

    test_architecture(temp_dir_path, "32-bit", &["/platform:x86"])?;
    test_architecture(temp_dir_path, "64-bit", &["/platform:x64"])?;

    println!("✅ All architecture tests complete");
    Ok(())
}

fn test_architecture(temp_dir: &Path, arch_name: &str, csc_flags: &[&str]) -> Result<()> {
    println!("\n🏗️  Testing {} architecture:", arch_name);

    let source_file = temp_dir.join(format!("helloworld_{}.cs", arch_name.replace("-", "")));
    std::fs::write(&source_file, HELLO_WORLD_SOURCE)?;

    let exe_file = temp_dir.join(format!("helloworld_{}.exe", arch_name.replace("-", "")));
    let exe_path = match compile_test_executable(&source_file, &exe_file, csc_flags) {
        Ok(path) => path,
        Err(_) => {
            println!("   ⚠️  compilation failed, not available for testing");
            return Ok(());
        }
    };

    println!("   📋 Testing original {} executable:", arch_name);
    test_original_executable(&exe_path)?;

    let modified_exe = create_modified_assembly(&exe_path, temp_dir)?;

    analyze_pe_structure(&modified_exe, arch_name)?;
    test_mono_compatibility(&modified_exe, arch_name)?;
    test_runtime_execution(&modified_exe, arch_name)?;

    println!("   ✅ {} architecture test complete", arch_name);

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

fn create_modified_assembly(original_exe: &Path, temp_dir: &Path) -> Result<std::path::PathBuf> {
    println!("   🔧 Creating modified assembly with dotscope...");

    let original_stem = original_exe.file_stem().unwrap().to_str().unwrap();
    let modified_exe = temp_dir.join(format!("{}_modified.exe", original_stem));

    let view = CilAssemblyView::from_file(original_exe)?;
    let assembly = CilAssembly::new(view);
    let mut context = BuilderContext::new(assembly);

    let _method_token = MethodBuilder::new("DotScopeAddedMethod")
        .public()
        .static_method()
        .parameter("a", TypeSignature::I4)
        .parameter("b", TypeSignature::I4)
        .returns(TypeSignature::I4)
        .implementation(|body| {
            body.implementation(|asm| {
                asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                Ok(())
            })
        })
        .build(&mut context)?;

    let mut assembly = context.finish();
    assembly.validate_and_apply_changes()?;
    assembly.write_to_file(&modified_exe)?;

    println!("   ✅ Modified assembly created");
    Ok(modified_exe)
}

fn analyze_pe_structure(file_path: &Path, arch_name: &str) -> Result<()> {
    println!("   🏗️  PE Structure Analysis ({}):", arch_name);

    let assembly = CilObject::from_file(file_path)?;
    let file = assembly.file();

    println!(
        "      File format: {}",
        if file.is_pe32_plus_format()? {
            "PE32+"
        } else {
            "PE32"
        }
    );
    println!("      File alignment: 0x{:X}", file.file_alignment()?);
    println!("      Section alignment: 0x{:X}", file.section_alignment()?);

    let mut sections: Vec<_> = file.sections().iter().collect();
    sections.sort_by_key(|s| s.virtual_address);

    println!("      Sections:");
    for (i, section) in sections.iter().enumerate() {
        let characteristics = section.characteristics;
        let is_executable = (characteristics & 0x20000000) != 0;
        let is_readable = (characteristics & 0x40000000) != 0;
        let is_writable = (characteristics & 0x80000000) != 0;

        println!(
            "        {}: {} ({}{}{})",
            i,
            section.name.as_str(),
            if is_executable { "X" } else { "-" },
            if is_readable { "R" } else { "-" },
            if is_writable { "W" } else { "-" }
        );
        println!(
            "           Virtual:  RVA=0x{:08X}, Size=0x{:08X}",
            section.virtual_address, section.virtual_size
        );
        println!(
            "           Physical: Offset=0x{:08X}, Size=0x{:08X}",
            section.pointer_to_raw_data, section.size_of_raw_data
        );
    }

    let methods = assembly.methods();
    for entry in methods.iter() {
        let method = entry.value();
        if method.name == "DotScopeAddedMethod" {
            if let Some(body) = method.body.get() {
                println!("      🎯 Added test method found:");
                println!("         Name: {}", method.name);
                println!("         Code size: {} bytes", body.size_code);
                break;
            }
        }
    }

    Ok(())
}

fn test_mono_compatibility(file_path: &Path, arch_name: &str) -> Result<()> {
    println!("   🐒 Mono Compatibility Test ({}):", arch_name);

    let output = Command::new("mono").arg("--version").output();

    match output {
        Ok(result) if result.status.success() => {
            let version = String::from_utf8_lossy(&result.stdout);
            println!(
                "      Mono version: {}",
                version.lines().next().unwrap_or("unknown")
            );
        }
        _ => {
            println!("      ⚠️  Mono not available - skipping mono tests");
            return Ok(());
        }
    }

    let output = Command::new("mono").arg(file_path).output();

    match output {
        Ok(result) if result.status.success() => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            println!("      ✅ Mono execution successful: {}", stdout.trim());
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            println!("      ❌ Mono execution FAILED:");
            for line in stderr.lines().take(3) {
                println!("         {}", line);
            }

            return Err(Error::Error(format!(
                "Mono execution failed for {}: {}",
                arch_name,
                stderr.lines().next().unwrap_or("Unknown error")
            )));
        }
        Err(e) => {
            println!("      ❌ Mono execution error: {}", e);
            return Err(Error::Error(format!(
                "Failed to run mono for {}: {}",
                arch_name, e
            )));
        }
    }

    test_monodis_disassembly(file_path, arch_name)?;

    Ok(())
}

fn test_runtime_execution(file_path: &Path, arch_name: &str) -> Result<()> {
    println!("   🚀 Runtime Execution Test ({}):", arch_name);

    if Command::new("mono").arg("--version").output().is_err() {
        println!("      ⚠️  mono not available - skipping reflection test");
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
            
            // Find our test method
            Type[] types = assembly.GetTypes();
            MethodInfo testMethod = null;
            
            foreach (Type type in types) 
            {{
                foreach (MethodInfo method in type.GetMethods()) 
                {{
                    if (method.Name == "DotScopeAddedMethod") 
                    {{
                        testMethod = method;
                        break;
                    }}
                }}
                if (testMethod != null) break;
            }}
            
            if (testMethod != null) 
            {{
                int[][] testCases = {{
                    new int[] {{5, 7, 12}},
                    new int[] {{100, 200, 300}},
                    new int[] {{-10, 25, 15}},
                    new int[] {{0, 0, 0}},
                    new int[] {{-50, -30, -80}}
                }};
                
                Console.WriteLine("Testing DotScopeAddedMethod with multiple parameter combinations:");
                
                for (int i = 0; i < testCases.Length; i++)
                {{
                    int a = testCases[i][0];
                    int b = testCases[i][1]; 
                    int expected = testCases[i][2];
                    
                    object[] parameters = {{ a, b }};
                    object result = testMethod.Invoke(null, parameters);
                    
                    Console.WriteLine($"  Test {{i + 1}}: {{a}} + {{b}} = {{result}} (expected: {{expected}})");
                    
                    if (result is int actualValue && actualValue == expected) 
                    {{
                        Console.WriteLine($"    ✅ Test {{i + 1}} PASSED");
                    }} 
                    else 
                    {{
                        Console.WriteLine($"    ❌ Test {{i + 1}} FAILED: Expected {{expected}}, got {{result}}");
                        Environment.Exit(1);
                    }}
                }}
                
                Console.WriteLine("SUCCESS: All parameter combination tests passed!");
                Environment.Exit(0);
            }} 
            else 
            {{
                Console.WriteLine("ERROR: DotScopeAddedMethod not found");
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

    let test_cs_path = format!(
        "/tmp/runtime_execution_test_{}.cs",
        arch_name.replace("-", "")
    );
    std::fs::write(&test_cs_path, test_program)?;

    println!("      Testing reflection-based method invocation:");

    let test_exe_path = format!(
        "/tmp/runtime_execution_test_{}.exe",
        arch_name.replace("-", "")
    );
    let compile_output = Command::new("mcs")
        .arg(format!("-out:{}", test_exe_path))
        .arg(&test_cs_path)
        .output()
        .map_err(|_| {
            Error::Error(
                "mcs (Mono C# compiler) not available - cannot run reflection test".to_string(),
            )
        })?;

    if compile_output.status.success() {
        println!("      ✅ Test program compiled successfully");

        let run_output = Command::new("mono").arg(&test_exe_path).output()?;

        if run_output.status.success() {
            let stdout = String::from_utf8_lossy(&run_output.stdout);
            println!("      ✅ Reflection test PASSED:");
            for line in stdout.lines() {
                println!("         {}", line);
            }
        } else {
            let stdout = String::from_utf8_lossy(&run_output.stdout);
            let stderr = String::from_utf8_lossy(&run_output.stderr);
            println!("      ❌ Reflection test FAILED:");
            println!("         Exit code: {}", run_output.status);
            if !stdout.is_empty() {
                println!("         Stdout: {}", stdout);
            }
            if !stderr.is_empty() {
                println!("         Stderr: {}", stderr);
            }
            return Err(Error::Error(format!(
                "Reflection test failed for {} with exit code {}: {}",
                arch_name,
                run_output.status,
                stdout.lines().next().unwrap_or("Unknown error")
            )));
        }
    } else {
        let stderr = String::from_utf8_lossy(&compile_output.stderr);
        return Err(Error::Error(format!(
            "Reflection test compilation failed for {}: {}",
            arch_name, stderr
        )));
    }

    Ok(())
}

fn test_monodis_disassembly(file_path: &Path, arch_name: &str) -> Result<()> {
    println!("      Testing monodis disassembly:");

    let help_output = Command::new("monodis").arg("--help").output();

    match help_output {
        Ok(result) => {
            let help_text = String::from_utf8_lossy(&result.stderr);
            if help_text.contains("monodis") || help_text.contains("Usage") {
                println!("      🔍 monodis available - testing comprehensive disassembly");

                let test_options = [
                    ("basic disassembly", vec![]),
                    ("method listing", vec!["--method"]),
                    ("type listing", vec!["--typedef"]),
                    ("assembly info", vec!["--assembly"]),
                ];

                for (test_name, args) in test_options {
                    println!("         Testing {}:", test_name);

                    let mut cmd = Command::new("monodis");
                    for arg in &args {
                        cmd.arg(arg);
                    }
                    cmd.arg(file_path);

                    match cmd.output() {
                        Ok(result) if result.status.success() => {
                            let stdout = String::from_utf8_lossy(&result.stdout);

                            if stdout.contains("DotScopeAddedMethod") {
                                println!(
                                    "            ✅ {} passed - found DotScopeAddedMethod",
                                    test_name
                                );

                                if test_name == "basic disassembly" {
                                    verify_method_disassembly(&stdout, arch_name)?;
                                }
                            } else if test_name == "method listing" {
                                return Err(Error::Error(format!(
                                "monodis method listing succeeded but DotScopeAddedMethod not found in {} assembly output",
                                arch_name
                            )));
                            } else {
                                println!("            ✅ {} passed", test_name);
                            }

                            if stdout.len() < 50 {
                                return Err(Error::Error(format!(
                                "monodis {} output unusually short ({} chars) for {} assembly - indicates corruption",
                                test_name, stdout.len(), arch_name
                            )));
                            }

                            if stdout.to_lowercase().contains("error")
                                || stdout.to_lowercase().contains("invalid")
                            {
                                return Err(Error::Error(format!(
                                "monodis {} output contains error indicators for {} assembly: {}",
                                test_name, arch_name, stdout.lines().take(3).collect::<Vec<_>>().join(" | ")
                            )));
                            }
                        }
                        Ok(result) => {
                            let stderr = String::from_utf8_lossy(&result.stderr);
                            println!(
                                "            ❌ {} FAILED (exit code: {})",
                                test_name, result.status
                            );
                            if !stderr.is_empty() {
                                println!(
                                    "               Error: {}",
                                    stderr.lines().next().unwrap_or("")
                                );
                            }

                            return Err(Error::Error(format!(
                                "monodis {} failed on {} assembly: {}",
                                test_name,
                                arch_name,
                                stderr.lines().next().unwrap_or("Unknown error")
                            )));
                        }
                        Err(e) => {
                            println!("            ❌ {} crashed: {}", test_name, e);
                            return Err(Error::Error(format!(
                                "monodis {} crashed when processing {} assembly: {}",
                                test_name, arch_name, e
                            )));
                        }
                    }
                }

                println!("      ✅ All monodis tests passed");
            } else {
                println!("      ⚠️  monodis not available - skipping disassembly test");
            }
        }
        Err(_) => {
            println!("      ⚠️  monodis not available - skipping disassembly test");
        }
    }

    Ok(())
}

fn verify_method_disassembly(disassembly_output: &str, arch_name: &str) -> Result<()> {
    println!("            🔍 Verifying IL instruction sequence for DotScopeAddedMethod");

    if disassembly_output.len() < 100 {
        return Err(Error::Error(format!(
            "Disassembly output too short ({} chars) for {} assembly - indicates parsing failure",
            disassembly_output.len(),
            arch_name
        )));
    }

    let lines: Vec<&str> = disassembly_output.lines().collect();
    let mut method_start = None;
    let mut method_end = None;

    for (i, line) in lines.iter().enumerate() {
        if line.contains("DotScopeAddedMethod")
            && (line.contains("int32") || line.contains("(int32,int32)"))
        {
            for (j, line) in lines.iter().enumerate().skip(i) {
                if line.trim().starts_with("{") {
                    method_start = Some(j + 1);
                    break;
                }
            }

            if let Some(start) = method_start {
                for (j, line) in lines.iter().enumerate().skip(start) {
                    if line.trim().starts_with("}") {
                        method_end = Some(j);
                        break;
                    }
                }
            }
            break;
        }
    }

    let (start, end) = match (method_start, method_end) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            return Err(Error::Error(format!(
                "Could not find DotScopeAddedMethod body in {} assembly disassembly",
                arch_name
            )));
        }
    };

    println!(
        "               Method body found at lines {} to {}",
        start + 1,
        end + 1
    );

    let mut il_instructions = Vec::new();
    for line in &lines[start..end] {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with(".") {
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

    println!(
        "               Found {} IL instructions:",
        il_instructions.len()
    );
    for (i, instruction) in il_instructions.iter().enumerate() {
        println!("                  {}: {}", i, instruction);
    }

    let expected_instructions = ["ldarg.0", "ldarg.1", "add", "ret"];

    if il_instructions.len() != expected_instructions.len() {
        return Err(Error::Error(format!(
            "DotScopeAddedMethod in {} assembly has {} IL instructions, expected {}. Found: {:?}",
            arch_name,
            il_instructions.len(),
            expected_instructions.len(),
            il_instructions
        )));
    }

    for (i, (found, expected)) in il_instructions
        .iter()
        .zip(expected_instructions.iter())
        .enumerate()
    {
        if found != expected {
            return Err(Error::Error(format!(
                "DotScopeAddedMethod in {} assembly IL instruction {} mismatch: found '{}', expected '{}'",
                arch_name, i, found, expected
            )));
        }
    }

    println!("            ✅ IL instruction verification passed - all {} instructions match expectations", il_instructions.len());
    Ok(())
}
