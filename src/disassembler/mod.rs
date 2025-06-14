//! CIL (Common Intermediate Language) disassembler and instruction decoding engine.
//!
//! This module provides comprehensive support for decoding, analyzing, and disassembling CIL bytecode
//! from .NET assemblies. It includes instruction parsing, control flow analysis, stack effect tracking,
//! and basic block construction.
//!
//! # Key Types
//! - [`Instruction`] - Represents a decoded CIL instruction
//! - [`BasicBlock`] - A sequence of instructions with single entry/exit
//! - [`Operand`] - Instruction operands (immediates, tokens, targets)
//! - [`FlowType`] - How instructions affect control flow
//!
//! # Main Functions
//! - [`decode_instruction`] - Decode a single instruction
//! - [`decode_stream`] - Decode a sequence of instructions
//! - [`decode_blocks`] - Build basic blocks from instruction stream
//!
//! # Example
//! ```rust,no_run
//! use dotscope::disassembler::decode_instruction;
//! use dotscope::Parser;
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(bytecode);
//! let instruction = decode_instruction(&mut parser, 0x1000)?;
//! println!("Mnemonic: {}", instruction.mnemonic);
//! # Ok::<(), dotscope::Error>(())
//! ```

mod block;
mod decoder;
mod instruction;
mod instructions;
mod visitedmap;

pub use block::BasicBlock;
pub(crate) use decoder::decode_method;
pub use decoder::{decode_blocks, decode_instruction, decode_stream};
pub use instruction::{
    FlowType, Immediate, Instruction, InstructionCategory, Operand, OperandType, StackBehavior,
};
pub use instructions::*;
