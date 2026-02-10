//! x86/x64 native code analysis module.
//!
//! This module provides infrastructure for analyzing x86/x64 machine code,
//! primarily for handling native method stubs used by obfuscators like
//! ConfuserEx's x86Predicate protection.
//!
//! # Architecture
//!
//! ```text
//! x86 bytes → decode (iced-x86) → CFG → SSA → existing codegen → CIL
//! ```
//!
//! The module uses iced-x86 for decoding and provides a simplified instruction
//! representation focused on the operations commonly used in obfuscator stubs.
//!
//! # Components
//!
//! - [`types`] - Simplified x86 instruction types ([`X86Instruction`], [`X86Register`], etc.)
//! - [`decoder`] - Decoding using iced-x86 ([`decode_all`], [`detect_prologue`])
//! - [`cfg`] - Control flow graph construction ([`X86Function`])
//!
//! # Decoding Strategies
//!
//! Two decoding approaches are available:
//!
//! ## Linear Decoding ([`decode_all`])
//!
//! Decodes instructions sequentially from the start until a `RET` instruction.
//! Fast and simple, but vulnerable to anti-disassembly tricks.
//!
//! ## Traversal-Based Decoding ([`decode_function_traversal`])
//!
//! Follows control flow edges from the entry point, only decoding reachable code.
//! More robust against:
//! - Junk bytes inserted between instructions
//! - Data embedded in code sections
//! - Overlapping instructions
//! - Anti-disassembly tricks
//!
//! # Example
//!
//! ```rust,no_run
//! use dotscope::analysis::{decode_x86, detect_x86_prologue, X86Function};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Decode x86 bytecode
//! let bytes = &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]; // mov eax, 1; ret
//! let instructions = decode_x86(bytes, 32, 0x1000)?;
//!
//! // Build CFG from decoded instructions
//! let cfg = X86Function::new(instructions, 32, 0x1000);
//! println!("Blocks: {}", cfg.block_count());
//! println!("Has loops: {}", cfg.has_loops());
//! println!("Is reducible: {}", cfg.is_reducible());
//!
//! // Detect prologue type
//! let prologue = detect_x86_prologue(bytes, 32);
//! println!("Prologue: {:?}", prologue.kind);
//! # Ok(())
//! # }
//! ```
//!
//! # Traversal-Based Example
//!
//! ```rust,ignore
//! use dotscope::analysis::{decode_x86_traversal, X86Function};
//!
//! // Decode using control-flow following (more robust)
//! let result = decode_x86_traversal(bytes, 32, 0x1000, 0)?;
//! println!("Decoded {} instructions", result.instructions.len());
//! println!("Has indirect jumps: {}", result.has_indirect_control_flow);
//!
//! // Build CFG
//! let cfg = X86Function::new(result.instructions, 32, 0x1000);
//! ```
//!
//! # Supported Instructions
//!
//! The decoder supports a subset of x86 instructions commonly used in
//! obfuscator stubs:
//!
//! | Category | Instructions |
//! |----------|--------------|
//! | Data Movement | MOV, MOVZX, MOVSX, LEA, PUSH, POP, XCHG |
//! | Arithmetic | ADD, SUB, IMUL, MUL, NEG, INC, DEC |
//! | Bitwise | AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR |
//! | Comparison | CMP, TEST |
//! | Control Flow | JMP, Jcc (all conditions), CALL, RET |
//! | Miscellaneous | NOP, CDQ, CWDE |
//!
//! Unsupported instructions are captured as [`X86Instruction::Unsupported`]
//! for graceful degradation.
//!
//! # Control Flow Support
//!
//! The CFG builder handles:
//!
//! - **L0**: Linear code (no branches)
//! - **L1**: Forward branches (if-then-else)
//! - **L2**: Reducible control flow (loops with single entry)
//!
//! Irreducible control flow is detected via [`X86Function::is_reducible`].
//!
//! # Analysis Features
//!
//! [`X86Function`] provides:
//!
//! - **Dominator analysis**: Lazy-computed dominator tree via [`X86Function::dominators`]
//! - **Loop detection**: [`X86Function::has_loops`] identifies back edges
//! - **Reducibility check**: [`X86Function::is_reducible`] detects irreducible CFGs
//! - **Edge classification**: [`X86EdgeKind`] distinguishes conditional/unconditional edges
//!
//! # SSA Translation
//!
//! The [`ssa`] module provides translation from x86 CFG to SSA form:
//!
//! ```rust,ignore
//! use dotscope::analysis::{decode_x86, X86Function, X86ToSsaTranslator};
//!
//! // Decode and build CFG
//! let instructions = decode_x86(bytes, 32, 0x1000)?;
//! let cfg = X86Function::new(instructions, 32, 0x1000);
//!
//! // Translate to SSA
//! let translator = X86ToSsaTranslator::new(&cfg);
//! let ssa_function = translator.translate()?;
//! ```
//!
//! The translator handles:
//! - Register versioning (new SSA variable per write)
//! - Phi node insertion at control flow join points
//! - CMP/TEST + Jcc fusion into `BranchCmp`
//! - Memory operations via `LoadIndirect`/`StoreIndirect`

mod cfg;
mod decoder;
mod flags;
mod ssa;
mod types;

// Re-export primary types
pub use cfg::{X86BasicBlock, X86Function};
pub use decoder::{
    decode_all, decode_all_permissive, decode_function_traversal, decode_single, detect_epilogue,
    detect_prologue, TraversalDecodeResult,
};
pub use types::{
    DecodedInstruction, EpilogueInfo, PrologueInfo, PrologueKind, X86Condition, X86EdgeKind,
    X86Instruction, X86Memory, X86Operand, X86Register,
};

// Re-export SSA translation types
#[allow(unused_imports)]
pub use flags::{condition_to_cmp, FlagProducer, FlagState};
#[allow(unused_imports)]
pub use ssa::X86ToSsaTranslator;

#[cfg(test)]
mod tests {
    use crate::analysis::x86::{
        decode_all, decode_all_permissive, detect_prologue, PrologueKind, X86Function,
        X86Instruction, X86Operand, X86Register,
    };

    /// Test the full pipeline: decode -> build CFG
    #[test]
    fn test_full_pipeline_linear() {
        // Simple function: return arg + 5
        // Simulated DynCipher-style code (without prologue for simplicity)
        let bytes = [
            0x58, // pop eax (get argument)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];

        let instructions = decode_all(&bytes, 32, 0).unwrap();
        assert_eq!(instructions.len(), 3);

        let cfg = X86Function::new(instructions, 32, 0);
        assert_eq!(cfg.block_count(), 1);
        assert!(!cfg.has_loops());
        assert!(cfg.is_reducible());
    }

    /// Test conditional branch
    #[test]
    fn test_full_pipeline_conditional() {
        // if (arg < 10) { arg += 5 } return arg
        let bytes = [
            0x58, // pop eax
            0x83, 0xf8, 0x0a, // cmp eax, 10
            0x7d, 0x03, // jge skip (+3)
            0x83, 0xc0, 0x05, // add eax, 5
            0xc3, // ret
        ];

        let instructions = decode_all(&bytes, 32, 0).unwrap();
        let cfg = X86Function::new(instructions, 32, 0);

        // Should have multiple blocks
        assert!(cfg.block_count() >= 2);
        assert!(!cfg.has_loops());
        assert!(cfg.is_reducible());
    }

    /// Test loop detection
    #[test]
    fn test_full_pipeline_loop() {
        // while (arg > 0) { arg-- } return arg
        let bytes = [
            0x58, // pop eax (0)
            0x83, 0xf8, 0x00, // cmp eax, 0 (1)
            0x7e, 0x04, // jle exit (4)
            0x48, // dec eax (6)
            0xeb, 0xf8, // jmp back to cmp (7) - goes back to offset 1
            0xc3, // ret (9)
        ];

        let instructions = decode_all(&bytes, 32, 0).unwrap();
        let cfg = X86Function::new(instructions, 32, 0);

        assert!(cfg.has_loops());
        assert!(cfg.is_reducible()); // Simple while loop is reducible
    }

    /// Test DynCipher prologue detection
    #[test]
    fn test_dyncipher_prologue_detection() {
        let prologue_bytes = [
            0x89, 0xe0, // mov eax, esp
            0x53, // push ebx
            0x57, // push edi
            0x56, // push esi
            0x29, 0xe0, // sub eax, esp
            0x83, 0xf8, 0x18, // cmp eax, 24
            0x74, 0x07, // je +7
            0x8b, 0x44, 0x24, 0x10, // mov eax, [esp + 16]
            0x50, // push eax
            0xeb, 0x01, // jmp +1
            0x51, // push ecx
            // Body would follow...
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x5e, // pop esi
            0x5f, // pop edi
            0x5b, // pop ebx
            0xc3, // ret
        ];

        let prologue = detect_prologue(&prologue_bytes, 32);
        assert_eq!(prologue.kind, PrologueKind::DynCipher);
        assert_eq!(prologue.size, 20);
    }

    /// Test 64-bit support
    #[test]
    fn test_64bit_support() {
        // mov rax, 0x123456789; ret
        let bytes = [
            0x48, 0xb8, 0x89, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00,
            0x00, // mov rax, 0x123456789
            0xc3, // ret
        ];

        let instructions = decode_all(&bytes, 64, 0).unwrap();
        assert_eq!(instructions.len(), 2);

        match &instructions[0].instruction {
            X86Instruction::Mov { dst, src } => {
                assert_eq!(dst.as_register(), Some(X86Register::Rax));
                assert_eq!(src.as_immediate(), Some(0x123456789));
            }
            _ => panic!("Expected Mov instruction"),
        }
    }

    /// Test permissive decoding
    #[test]
    fn test_permissive_decode() {
        // Include some unsupported instruction (e.g., CPUID)
        let bytes = [
            0x0f, 0xa2, // cpuid (unsupported)
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xc3, // ret
        ];

        // Permissive should succeed
        let result = decode_all_permissive(&bytes, 32, 0);
        assert!(result.is_ok());
        let instructions = result.unwrap();

        // Should have the unsupported instruction captured
        assert!(matches!(
            instructions[0].instruction,
            X86Instruction::Unsupported { .. }
        ));
    }

    /// Test memory operand handling
    #[test]
    fn test_memory_operand() {
        // mov eax, [ebx + ecx*4 + 8]
        // ret
        let bytes = [
            0x8b, 0x44, 0x8b, 0x08, // mov eax, [ebx + ecx*4 + 8]
            0xc3, // ret
        ];

        let instructions = decode_all(&bytes, 32, 0).unwrap();
        match &instructions[0].instruction {
            X86Instruction::Mov { src, .. } => match src {
                X86Operand::Memory(mem) => {
                    assert_eq!(mem.base, Some(X86Register::Ebx));
                    assert_eq!(mem.index, Some(X86Register::Ecx));
                    assert_eq!(mem.scale, 4);
                    assert_eq!(mem.displacement, 8);
                }
                _ => panic!("Expected memory operand"),
            },
            _ => panic!("Expected Mov instruction"),
        }
    }
}
