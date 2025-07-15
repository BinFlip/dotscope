//! # .NET Assembly Modification Example
//!
//! **What this example teaches:**
//! - Loading assemblies for modification using `CilAssemblyView` and `CilAssembly`
//! - Adding and modifying heap content (strings, blobs, GUIDs, user strings)
//! - Adding and modifying metadata table rows
//! - Adding native imports and exports for P/Invoke scenarios
//! - Proper validation and error handling for assembly modifications
//! - Writing modified assemblies to disk with full PE compliance
//!
//! **When to use this pattern:**
//! - Building .NET assembly editing tools
//! - Automated assembly patching and instrumentation
//! - Adding metadata for analysis frameworks
//! - Implementing code injection or hooking utilities
//! - Educational purposes to understand .NET assembly structure
//!
//! **Prerequisites:**
//! - Understanding of .NET metadata structures
//! - Familiarity with ECMA-335 specification concepts
//! - Basic knowledge of P/Invoke and native interoperability

use dotscope::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    prelude::*,
    CilAssembly, CilAssemblyView, ReferenceHandlingStrategy,
};
use std::{env, path::Path};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <source-assembly> <output-assembly>", args[0]);
        eprintln!();
        eprintln!("This example demonstrates comprehensive .NET assembly modification:");
        eprintln!("  • Adding strings, blobs, GUIDs, and user strings to heaps");
        eprintln!("  • Modifying existing heap content");
        eprintln!("  • Adding and updating metadata table rows");
        eprintln!("  • Deleting table rows with reference handling");
        eprintln!("  • Adding native imports for P/Invoke scenarios");
        eprintln!("  • Adding native exports for module interoperability");
        eprintln!("  • Validating changes and writing modified assembly");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} input.dll modified.dll", args[0]);
        return Ok(());
    }

    let source_path = Path::new(&args[1]);
    let output_path = Path::new(&args[2]);

    println!("🔧 .NET Assembly Modification Tool");
    println!("📖 Source: {}", source_path.display());
    println!("📝 Output: {}", output_path.display());
    println!();

    // Load the assembly for modification
    println!("📂 Loading assembly for modification...");
    let view = match CilAssemblyView::from_file(source_path) {
        Ok(view) => {
            println!("✅ Successfully loaded assembly view");
            view
        }
        Err(e) => {
            eprintln!("❌ Failed to load assembly: {e}");
            eprintln!();
            eprintln!("Common causes:");
            eprintln!("  • File is not a valid .NET assembly");
            eprintln!("  • File is corrupted or in an unsupported format");
            eprintln!("  • Insufficient permissions to read the file");
            return Err(e);
        }
    };

    // Create mutable assembly for editing
    let mut assembly = CilAssembly::new(view);
    println!("🔄 Created mutable assembly wrapper");
    println!();

    // === Heap Modifications ===
    println!("🗂️  HEAP MODIFICATIONS");
    println!("═══════════════════════");

    // Add strings to the string heap
    println!("📝 Adding strings to #Strings heap...");
    let hello_index = assembly.string_add("Hello from modified assembly!")?;
    let debug_index = assembly.string_add("DEBUG_MODIFIED")?;
    let version_index = assembly.string_add("v2.0.0-modified")?;
    println!("  ✅ Added 'Hello from modified assembly!' at index {hello_index}");
    println!("  ✅ Added 'DEBUG_MODIFIED' at index {debug_index}");
    println!("  ✅ Added 'v2.0.0-modified' at index {version_index}");

    // Add blobs to the blob heap
    println!("📦 Adding blobs to #Blob heap...");
    let signature_blob = vec![0x07, 0x01, 0x0E]; // Sample method signature blob
    let custom_data_blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let signature_index = assembly.blob_add(&signature_blob)?;
    let custom_data_index = assembly.blob_add(&custom_data_blob)?;
    println!("  ✅ Added method signature blob at index {signature_index}");
    println!("  ✅ Added custom data blob at index {custom_data_index}");

    // Add GUIDs to the GUID heap
    println!("🆔 Adding GUIDs to #GUID heap...");
    let module_guid = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];
    let type_guid = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let module_guid_index = assembly.guid_add(&module_guid)?;
    let type_guid_index = assembly.guid_add(&type_guid)?;
    println!("  ✅ Added module GUID at index {module_guid_index}");
    println!("  ✅ Added type GUID at index {type_guid_index}");

    // Add user strings to the user string heap
    println!("💭 Adding user strings to #US heap...");
    let user_message = assembly.userstring_add("This assembly has been modified!")?;
    let user_warning = assembly.userstring_add("⚠️ MODIFIED ASSEMBLY")?;
    println!("  ✅ Added user message at index {user_message}");
    println!("  ✅ Added user warning at index {user_warning}");

    // Demonstrate heap modifications
    println!("✏️  Updating existing heap content...");
    // Note: In a real scenario, you would know the indices of existing content
    // For demonstration, we'll update our newly added strings
    assembly.string_update(debug_index, "RELEASE_MODIFIED")?;
    assembly.blob_update(custom_data_index, &[0xFF, 0xEE, 0xDD, 0xCC])?;
    println!("  ✅ Updated debug string to 'RELEASE_MODIFIED'");
    println!("  ✅ Updated custom data blob");
    println!();

    // === Native Import Management ===
    println!("📚 NATIVE IMPORT MANAGEMENT");
    println!("═══════════════════════════");

    // Add native DLL imports
    println!("📥 Adding native DLL imports...");
    assembly.add_native_import_dll("kernel32.dll")?;
    assembly.add_native_import_dll("user32.dll")?;
    assembly.add_native_import_dll("advapi32.dll")?;
    println!("  ✅ Added kernel32.dll to import table");
    println!("  ✅ Added user32.dll to import table");
    println!("  ✅ Added advapi32.dll to import table");

    // Add native function imports
    println!("⚙️  Adding native function imports...");
    assembly.add_native_import_function("kernel32.dll", "GetCurrentProcessId")?;
    assembly.add_native_import_function("kernel32.dll", "ExitProcess")?;
    assembly.add_native_import_function("user32.dll", "MessageBoxW")?;
    assembly.add_native_import_function("advapi32.dll", "RegOpenKeyExW")?;
    println!("  ✅ Added GetCurrentProcessId from kernel32.dll");
    println!("  ✅ Added ExitProcess from kernel32.dll");
    println!("  ✅ Added MessageBoxW from user32.dll");
    println!("  ✅ Added RegOpenKeyExW from advapi32.dll");

    // Add ordinal-based imports
    println!("🔢 Adding ordinal-based imports...");
    assembly.add_native_import_function_by_ordinal("user32.dll", 120)?; // MessageBoxW ordinal
    println!("  ✅ Added function by ordinal 120 from user32.dll");
    println!();

    // === Table Row Operations ===
    println!("📊 METADATA TABLE OPERATIONS");
    println!("═══════════════════════════");

    // Add a new TypeDef row (simplified example)
    println!("➕ Adding new metadata table rows...");

    // Create a sample TypeDef row
    // Note: In real scenarios, you'd need to carefully construct valid metadata
    let new_typedef = TypeDefRaw {
        rid: 0,                 // Will be set by the add operation
        token: Token::new(0),   // Will be set by the add operation
        offset: 0,              // Will be set by the add operation
        flags: 0x00100001,      // Class, Public
        type_name: debug_index, // Reference to our added string
        type_namespace: 0,      // No namespace (root)
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,  // Start of field list
        method_list: 1, // Start of method list
    };

    let new_typedef_rid =
        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(new_typedef))?;
    println!("  ✅ Added new TypeDef row with RID {new_typedef_rid}");

    // Update an existing table row (if any exist)
    println!("✏️  Updating existing table rows...");
    // Note: This is just an example - in practice you'd identify specific rows to modify
    if assembly.original_table_row_count(TableId::TypeDef) > 0 {
        // Get and modify the first TypeDef row
        if let Some(tables) = assembly.view().tables() {
            if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
                if let Some(first_row) = typedef_table.get(1) {
                    let mut modified_row = first_row.clone();
                    modified_row.type_name = version_index; // Point to our version string

                    assembly.table_row_update(
                        TableId::TypeDef,
                        1,
                        TableDataOwned::TypeDef(modified_row),
                    )?;
                    println!("  ✅ Updated TypeDef row 1 name to point to version string");
                }
            }
        }
    }

    // Demonstrate row deletion with reference handling
    println!("🗑️  Demonstrating table row deletion...");
    // Note: Be very careful with deletions as they can break assembly integrity
    // For safety, we'll only delete the row we just added
    assembly.table_row_remove(
        TableId::TypeDef,
        new_typedef_rid,
        ReferenceHandlingStrategy::FailIfReferenced,
    )?;
    println!("  ✅ Deleted newly added TypeDef row (RID {new_typedef_rid}) safely");
    println!();

    // === Validation and Assembly Writing ===
    println!("✅ VALIDATION AND OUTPUT");
    println!("═══════════════════════");

    // Validate all changes before writing
    println!("🔍 Validating assembly modifications...");
    match assembly.validate_and_apply_changes() {
        Ok(()) => {
            println!("  ✅ All modifications validated successfully");
            println!("  ✅ Index remapping applied");
        }
        Err(e) => {
            eprintln!("  ❌ Validation failed: {e}");
            eprintln!();
            eprintln!("Common validation issues:");
            eprintln!("  • Invalid table references or circular dependencies");
            eprintln!("  • Heap index out of bounds");
            eprintln!("  • Conflicting operations on the same data");
            eprintln!("  • Metadata integrity violations");
            return Err(e);
        }
    }

    // Write the modified assembly
    println!("💾 Writing modified assembly to disk...");
    match assembly.write_to_file(output_path) {
        Ok(()) => {
            println!(
                "  ✅ Successfully wrote modified assembly to {}",
                output_path.display()
            );
        }
        Err(e) => {
            eprintln!("  ❌ Failed to write assembly: {e}");
            eprintln!();
            eprintln!("Common write issues:");
            eprintln!("  • Insufficient disk space or permissions");
            eprintln!("  • Invalid output path");
            eprintln!("  • PE structure generation errors");
            eprintln!("  • Heap size limit exceeded");
            return Err(e);
        }
    }
    println!();

    // === Summary ===
    println!("🎯 MODIFICATION SUMMARY");
    println!("═══════════════════════");
    println!("Successfully demonstrated:");
    println!("  📝 String heap modifications (add, update)");
    println!("  📦 Blob heap operations");
    println!("  🆔 GUID heap management");
    println!("  💭 User string heap operations");
    println!("  📚 Native import additions (by name and ordinal)");
    println!("  📊 Metadata table row operations (add, update, delete)");
    println!("  🔍 Comprehensive validation pipeline");
    println!("  💾 Modified assembly generation");
    println!();

    println!("💡 NEXT STEPS");
    println!("═════════════");
    println!("  • Verify the modified assembly with tools like:");
    println!("    - ildasm.exe (Microsoft IL Disassembler)");
    println!("    - dotPeek (JetBrains .NET Decompiler)");
    println!("    - PEBear (PE structure analyzer)");
    println!("  • Test loading the modified assembly in .NET runtime");
    println!("  • Experiment with more complex metadata modifications");
    println!("  • Try the comprehensive.rs example for analysis capabilities");
    println!();

    println!("⚠️  IMPORTANT NOTES");
    println!("═══════════════════");
    println!("  • Modified assemblies may not be loadable if metadata integrity is violated");
    println!("  • Always validate assemblies before deployment");
    println!("  • Backup original assemblies before modification");
    println!("  • Some modifications may require code signing updates");
    println!("  • Test thoroughly in isolated environments first");

    Ok(())
}
