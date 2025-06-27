//! # Basic Assembly Analysis
//!
//! **What this example teaches:**
//! - Loading .NET assemblies from files using `CilObject::from_file()`
//! - Accessing basic metadata (assembly info, module info)
//! - Iterating through methods and examining method bodies
//! - Using the prelude for convenient access to common types
//!
//! **When to use this pattern:**
//! - Starting point for any .NET assembly analysis
//! - Quick inspection of assembly contents
//! - Learning the basic dotscope API patterns
//!
//! **Prerequisites:**
//! - Basic understanding of .NET assemblies
//! - Familiarity with Rust error handling

use dotscope::prelude::*;
use std::{env, path::Path};

fn main() -> Result<()> {
    // Get the path from command line arguments or use a default
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-dotnet-assembly>", args[0]);
        eprintln!();
        eprintln!("This example demonstrates basic .NET assembly analysis patterns:");
        eprintln!("  • Loading assemblies with error handling");
        eprintln!("  • Accessing assembly and module metadata");
        eprintln!("  • Iterating through methods safely");
        eprintln!("  • Using the prelude for clean, consistent code");
        return Ok(());
    }

    let path = Path::new(&args[1]);

    // Load and analyze a .NET assembly using dotscope
    // This demonstrates the primary entry point for assembly analysis
    println!("🔍 Loading .NET assembly: {}", path.display());

    let assembly = match CilObject::from_file(path) {
        Ok(assembly) => {
            println!("✅ Successfully loaded assembly");
            assembly
        }
        Err(e) => {
            eprintln!("❌ Failed to load assembly: {e}");
            eprintln!();
            eprintln!("Common causes:");
            eprintln!("  • File is not a valid .NET assembly");
            eprintln!("  • File is corrupted or truncated");
            eprintln!("  • Insufficient permissions to read the file");
            eprintln!("  • File is not in PE format");
            eprintln!();
            eprintln!("Try with a known good .NET assembly like:");
            eprintln!("  {} tests/samples/WindowsBase.dll", args[0]);
            return Err(e);
        }
    };

    // Access methods using types from the prelude
    // The methods() call returns a MethodMap that provides efficient access to all methods
    let methods = assembly.methods();
    println!("📊 Found {} methods in the assembly", methods.len());

    // Demonstrate accessing methods from the method map
    // We'll examine the first 5 methods to show the API patterns
    println!("\n🔧 Examining first 5 methods:");
    for (count, entry) in methods.iter().take(5).enumerate() {
        let token = entry.key();
        let method = entry.value();
        println!(
            "{}. Method: {} (Token: 0x{:08X})",
            count + 1,
            method.name,
            token.value()
        );

        // Access method body if available
        // Note: .get() returns Option<&MethodBody> - use this pattern for safe access
        if let Some(body) = method.body.get() {
            println!("  - Has method body with {} bytes of IL", body.size_code);
            println!("    Max stack depth: {}", body.max_stack);

            // Show additional method body information
            if body.local_var_sig_token != 0 {
                println!(
                    "    Has local variables (token: 0x{:08X})",
                    body.local_var_sig_token
                );
            }
            if !body.exception_handlers.is_empty() {
                println!(
                    "    Has {} exception handler(s)",
                    body.exception_handlers.len()
                );
            }
        } else {
            println!("  - No method body (abstract or extern)");
        }
    }

    // Demonstrate assembly metadata access
    // Assembly metadata provides version info, culture, and other assembly-level details
    println!("\n📋 Assembly Metadata:");
    if let Some(assembly_info) = assembly.assembly() {
        println!("✅ Assembly Information:");
        println!("  - Name: {}", assembly_info.name);
        println!(
            "  - Version: {}.{}.{}.{}",
            assembly_info.major_version,
            assembly_info.minor_version,
            assembly_info.build_number,
            assembly_info.revision_number
        );

        // Show culture information if available
        if let Some(ref culture) = assembly_info.culture {
            println!("  - Culture: {culture}");
        } else {
            println!("  - Culture: neutral");
        }
    } else {
        println!("⚠️  No assembly metadata found (this is unusual for .NET assemblies)");
    }

    // Show module information
    // The module represents the physical file containing the assembly
    if let Some(module) = assembly.module() {
        println!("✅ Module Information:");
        println!("  - Module: {}", module.name);
        println!("  - MVID: {}", module.mvid);
    } else {
        println!("⚠️  No module metadata found");
    }

    // Summary of what we've learned
    println!("\n🎯 Analysis Summary:");
    println!("  - Assembly loaded successfully using CilObject::from_file()");
    println!(
        "  - Accessed {} methods via assembly.methods()",
        methods.len()
    );
    println!("  - Demonstrated safe metadata access patterns");
    println!("  - Used prelude types for clean, readable code");

    println!("\n💡 Next Steps:");
    println!("  - Try the 'comprehensive' example for deeper analysis");
    println!("  - Explore 'disassembly' for IL instruction details");
    println!("  - Check 'metadata' for low-level table access");

    Ok(())
}
