//! # Basic Block Decoding Examples
//!
//! **What this example teaches:**
//! - Using the `decode_blocks` function for control flow analysis
//! - Understanding basic block construction from IL bytecode
//! - Working with conditional and unconditional branches
//! - Limiting decoding with size constraints
//!
//! **When to use this pattern:**
//! - Building control flow analyzers
//! - Creating custom disassemblers
//! - Analyzing method control flow patterns
//! - Understanding basic block boundaries
//!
//! **Prerequisites:**
//! - Understanding of basic blocks and control flow
//! - Familiarity with CIL instruction opcodes
//! - Knowledge of branch instructions

use dotscope::prelude::*;

fn main() -> Result<()> {
    // Example: Simple linear code
    println!("=== Example 1: Simple Linear Code ===");
    let code = [0x00, 0x2A]; // nop, ret
    let blocks = decode_blocks(&code, 0, 0x1000, None)?;
    println!("Number of basic blocks: {}", blocks.len());
    println!(
        "Instructions in first block: {}",
        blocks[0].instructions.len()
    );
    for (i, instruction) in blocks[0].instructions.iter().enumerate() {
        println!(
            "  {}: {} (RVA: 0x{:X})",
            i, instruction.mnemonic, instruction.rva
        );
    }

    // Example: Conditional branch
    println!("\n=== Example 2: Conditional Branch ===");
    let code = [
        0x00, // nop
        0x2C, 0x02, // brfalse.s +2 (skip next instruction)
        0x2A, // ret (false path)
        0x2A, // ret (true path - branch target)
    ];
    let blocks = decode_blocks(&code, 0, 0x2000, None)?;
    println!("Number of basic blocks: {}", blocks.len());
    for (i, block) in blocks.iter().enumerate() {
        println!(
            "Block {}: {} instructions, RVA: 0x{:X}",
            i,
            block.instructions.len(),
            block.rva
        );
        for instruction in &block.instructions {
            println!("  {} (RVA: 0x{:X})", instruction.mnemonic, instruction.rva);
        }
    }

    // Example: With size limit
    println!("\n=== Example 3: With Size Limit ===");
    let code = [
        0x00, // nop
        0x2A, // ret
        0x00, // nop (should be ignored due to max_size)
        0x2A, // ret (should be ignored due to max_size)
    ];
    let blocks = decode_blocks(&code, 0, 0x3000, Some(2))?;
    println!("Number of basic blocks: {}", blocks.len());
    println!("Instructions in block: {}", blocks[0].instructions.len());
    for instruction in &blocks[0].instructions {
        println!("  {} (RVA: 0x{:X})", instruction.mnemonic, instruction.rva);
    }

    println!("\n✅ All examples completed successfully!");
    Ok(())
}
