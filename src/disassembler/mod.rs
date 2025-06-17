//! CIL (Common Intermediate Language) disassembler and instruction decoding engine.
//!
//! This module provides comprehensive support for decoding, analyzing, and disassembling CIL bytecode
//! from .NET assemblies according to ECMA-335 specifications. It implements a complete disassembly
//! pipeline including instruction parsing, control flow analysis, stack effect tracking, and
//! basic block construction for advanced static analysis capabilities.
//!
//! # Architecture
//!
//! The disassembler is organized into several cooperating components: instruction decoding
//! transforms raw bytecode into structured instruction objects, control flow analysis builds
//! basic blocks with predecessor/successor relationships, and metadata integration provides
//! semantic context for method-level analysis.
//!
//! # Key Components
//!
//! - [`crate::disassembler::Instruction`] - Complete decoded CIL instruction representation
//! - [`crate::disassembler::BasicBlock`] - Control flow basic block with instruction sequences
//! - [`crate::disassembler::Operand`] - Type-safe instruction operand representation
//! - [`crate::disassembler::FlowType`] - Control flow behavior classification
//! - [`crate::disassembler::decode_instruction`] - Core single instruction decoder
//! - [`crate::disassembler::decode_stream`] - Linear instruction sequence decoder
//! - [`crate::disassembler::decode_blocks`] - Complete control flow analysis with basic blocks
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::disassembler::{decode_instruction, decode_stream, decode_blocks};
//! use dotscope::Parser;
//!
//! // Decode a single instruction
//! let bytecode = &[0x2A]; // ret
//! let mut parser = Parser::new(bytecode);
//! let instruction = decode_instruction(&mut parser, 0x1000)?;
//! println!("Instruction: {}", instruction.mnemonic);
//!
//! // Decode a sequence of instructions
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(bytecode);
//! let instructions = decode_stream(&mut parser, 0x1000)?;
//! assert_eq!(instructions.len(), 2);
//!
//! // Decode with control flow analysis
//! let bytecode = &[0x00, 0x2A]; // nop, ret
//! let blocks = decode_blocks(bytecode, 0, 0x1000, None)?;
//! assert_eq!(blocks.len(), 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::method`] - Provides method-level disassembly and caching
//! - [`crate::metadata::token`] - Resolves metadata token references in operands

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
pub(crate) use visitedmap::VisitedMap;
