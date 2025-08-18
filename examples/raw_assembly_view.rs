//! Raw Assembly View Example
//!
//! This example demonstrates how to use `CilAssemblyView` for direct access to
//! .NET assembly metadata structures. Unlike `CilObject` which provides processed
//! and resolved metadata, `CilAssemblyView` gives you raw access to the file
//! structure - perfect for building editing tools.

use dotscope::prelude::*;
use std::env;

fn main() -> Result<()> {
    // Get assembly path from command line or use default
    let args: Vec<String> = env::args().collect();
    let assembly_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("tests/samples/WindowsBase.dll");

    println!("🔍 Raw Assembly Analysis: {assembly_path}");
    println!("{}", "=".repeat(60));

    // Load assembly using CilAssemblyView for raw metadata access
    let view = CilAssemblyView::from_file(assembly_path.as_ref())?;

    // 1. Display COR20 Header Information
    display_cor20_header(&view);

    // 2. Display Metadata Root Information
    display_metadata_root(&view);

    // 3. Display Stream Information
    display_streams(&view);

    // 4. Display Metadata Tables Information
    display_tables(&view)?;

    // 5. Demonstrate String Heap Access
    demonstrate_string_access(&view)?;

    // 6. Demonstrate Blob Heap Access
    demonstrate_blob_access(&view)?;

    // 7. Display File-level Information
    display_file_info(&view);

    Ok(())
}

fn display_cor20_header(view: &CilAssemblyView) {
    println!("\n📋 COR20 Header (.NET CLR Header)");
    println!("{}", "-".repeat(40));

    let header = view.cor20header();
    println!("• Metadata RVA: 0x{:08X}", header.meta_data_rva);
    println!("• Metadata Size: {} bytes", header.meta_data_size);
    println!("• Runtime Flags: 0x{:08X}", header.flags);

    if header.entry_point_token != 0 {
        println!("• Entry Point Token: 0x{:08X}", header.entry_point_token);
    }

    if header.resource_rva != 0 {
        println!(
            "• Resources RVA: 0x{:08X} (Size: {})",
            header.resource_rva, header.resource_size
        );
    }
}

fn display_metadata_root(view: &CilAssemblyView) {
    println!("\n🗂️  Metadata Root");
    println!("{}", "-".repeat(40));

    let root = view.metadata_root();
    println!("• Signature: 0x{:08X}", root.signature);
    println!("• Version: {}", root.version);
    println!("• Stream Count: {}", root.stream_headers.len());
}

fn display_streams(view: &CilAssemblyView) {
    println!("\n📊 Metadata Streams");
    println!("{}", "-".repeat(40));

    for (idx, stream) in view.streams().iter().enumerate() {
        println!("{}. {} stream:", idx + 1, stream.name);
        println!("   • Offset: 0x{:08X}", stream.offset);
        println!("   • Size: {} bytes", stream.size);

        // Show what we have access to for each stream
        match stream.name.as_str() {
            "#~" | "#-" => {
                if let Some(tables) = view.tables() {
                    println!(
                        "   • Schema: {}.{}",
                        tables.major_version, tables.minor_version
                    );
                    println!("   • Valid Tables: 0x{:016X}", tables.valid);
                }
            }
            "#Strings" => {
                if let Some(_strings) = view.strings() {
                    println!("   • Available for string lookups");
                }
            }
            "#US" => {
                if let Some(_us) = view.userstrings() {
                    println!("   • Available for user string lookups");
                }
            }
            "#GUID" => {
                if let Some(_guids) = view.guids() {
                    println!("   • Available for GUID lookups");
                }
            }
            "#Blob" => {
                if let Some(_blobs) = view.blobs() {
                    println!("   • Available for blob lookups");
                }
            }
            _ => {
                println!("   • Unknown stream type");
            }
        }
    }
}

fn display_tables(view: &CilAssemblyView) -> Result<()> {
    println!("\n🗃️  Metadata Tables");
    println!("{}", "-".repeat(40));

    if let Some(tables) = view.tables() {
        println!(
            "• Schema Version: {}.{}",
            tables.major_version, tables.minor_version
        );
        println!("• Valid Tables: 0x{:016X}", tables.valid);
        println!("• Sorted Tables: 0x{:016X}", tables.sorted);

        // Count and display which tables are present
        let table_count = tables.valid.count_ones();
        println!("• Total Tables Present: {table_count}");

        if tables.valid & (1u64 << TableId::Module as u8) != 0 {
            println!("  ✓ Module table present");
        }
        if tables.valid & (1u64 << TableId::TypeDef as u8) != 0 {
            println!("  ✓ TypeDef table present");
        }
        if tables.valid & (1u64 << TableId::MethodDef as u8) != 0 {
            println!("  ✓ MethodDef table present");
        }
        if tables.valid & (1u64 << TableId::Field as u8) != 0 {
            println!("  ✓ Field table present");
        }
        if tables.valid & (1u64 << TableId::AssemblyRef as u8) != 0 {
            println!("  ✓ AssemblyRef table present");
        }
    } else {
        println!("⚠️  No metadata tables found (no #~ or #- stream)");
    }

    Ok(())
}

fn demonstrate_string_access(view: &CilAssemblyView) -> Result<()> {
    println!("\n🔤 String Heap Access");
    println!("{}", "-".repeat(40));

    if let Some(strings) = view.strings() {
        println!("String heap available - demonstrating lookups:");

        for (offset, entry) in strings.iter().take(10) {
            println!("  • Offset: {offset} - String: '{entry}'");
        }
    } else {
        println!("❌ No string heap available");
    }

    Ok(())
}

fn demonstrate_blob_access(view: &CilAssemblyView) -> Result<()> {
    println!("\n📦 Blob Heap Access");
    println!("{}", "-".repeat(40));

    if let Some(blobs) = view.blobs() {
        println!("Blob heap available - demonstrating lookups:");

        for (offset, data) in blobs.iter().take(10) {
            println!(
                "  • Offset: {} - Size: {} bytes - Data: {:02X?}...",
                offset,
                data.len(),
                &data[..data.len().min(8)]
            );
        }
    } else {
        println!("❌ No blob heap available");
    }

    Ok(())
}

fn display_file_info(view: &CilAssemblyView) {
    println!("\n💾 File Information");
    println!("{}", "-".repeat(40));

    let file = view.file();
    let data = view.data();

    println!("• File Size: {} bytes", data.len());
    println!("• PE Format: Available");

    // Show some PE header info
    let pe_header = file.header();
    println!("• Machine Type: 0x{:04X}", pe_header.machine);
    println!("• Section Count: {}", pe_header.number_of_sections);
    println!("• Time Stamp: 0x{:08X}", pe_header.time_date_stamp);

    if file.header_optional().is_some() {
        println!("• Optional Header: Present");
    }
}
