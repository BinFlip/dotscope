//! CIL instruction encoding and assembly functionality.
//!
//! This module provides the core instruction encoding capabilities for generating CIL bytecode
//! from high-level instruction representations. It serves as the reverse counterpart to the
//! decoder module, using the same instruction metadata tables for maximum consistency and code reuse.
//!
//! # Architecture
//!
//! The encoder follows a mirror approach to the decoder, reusing existing type definitions and
//! instruction metadata while providing reverse lookup capabilities. This ensures type safety
//! and maintains consistency between assembly and disassembly operations.
//!
//! # Key Components
//!
//! - [`InstructionEncoder`] - Core encoding engine for CIL instructions
//! - [`LabelFixup`] - Label resolution system for branch instructions
//! - Reverse lookup tables generated from existing [`crate::assembly::INSTRUCTIONS`] tables
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
//!
//! let mut encoder = InstructionEncoder::new();
//!
//! // Encode simple instructions
//! encoder.emit_instruction("nop", None)?;
//! encoder.emit_instruction("ldarg.0", None)?;
//! encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(5))))?;
//! encoder.emit_instruction("add", None)?;
//! encoder.emit_instruction("ret", None)?;
//!
//! let bytecode = encoder.finalize()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Label Resolution
//!
//! ```rust,no_run
//! use dotscope::assembly::InstructionEncoder;
//!
//! let mut encoder = InstructionEncoder::new();
//!
//! encoder.emit_instruction("ldarg.0", None)?;
//! encoder.emit_branch("br.s", "end_label")?;
//! encoder.emit_instruction("ldarg.1", None)?;
//! encoder.define_label("end_label")?;
//! encoder.emit_instruction("ret", None)?;
//!
//! let bytecode = encoder.finalize()?; // Labels resolved automatically
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    assembly::{
        instruction::{FlowType, Immediate, Operand, OperandType},
        instructions::{CilInstruction, INSTRUCTIONS, INSTRUCTIONS_FE},
    },
    Error, Result,
};
use std::{collections::HashMap, sync::OnceLock};

/// Reverse lookup table mapping mnemonics to opcode information.
///
/// This static lookup table provides efficient O(1) mnemonic-to-opcode resolution by creating
/// a HashMap from the existing instruction tables. Each entry maps an instruction mnemonic
/// (e.g., "nop", "add", "br.s") to a tuple containing:
/// - Primary opcode byte
/// - Prefix byte (0x00 for single-byte instructions, 0xFE for extended instructions)  
/// - Reference to the instruction metadata
///
/// This approach maximizes code reuse by building on the existing static instruction tables
/// rather than duplicating instruction definitions.
static MNEMONIC_TO_OPCODE: OnceLock<
    HashMap<&'static str, (u8, u8, &'static CilInstruction<'static>)>,
> = OnceLock::new();

fn get_mnemonic_lookup(
) -> &'static HashMap<&'static str, (u8, u8, &'static CilInstruction<'static>)> {
    MNEMONIC_TO_OPCODE.get_or_init(|| {
        let mut map = HashMap::new();

        // Single-byte instructions (0x00 to 0xE0)
        for (opcode, instr) in INSTRUCTIONS.iter().enumerate() {
            if !instr.instr.is_empty() {
                let opcode_u8 = u8::try_from(opcode)
                    .unwrap_or_else(|_| panic!("Opcode {} exceeds u8 range", opcode));
                map.insert(instr.instr, (opcode_u8, 0, instr));
            }
        }

        // Extended instructions (0xFE prefix)
        for (opcode, instr) in INSTRUCTIONS_FE.iter().enumerate() {
            if !instr.instr.is_empty() {
                let opcode_u8 = u8::try_from(opcode)
                    .unwrap_or_else(|_| panic!("Opcode {} exceeds u8 range", opcode));
                map.insert(instr.instr, (opcode_u8, 0xFE, instr));
            }
        }

        map
    })
}

/// Label fixup information for branch instruction resolution.
///
/// This structure tracks unresolved label references during the encoding process,
/// allowing forward and backward branch resolution when the final bytecode positions
/// are calculated.
#[derive(Debug, Clone)]
pub struct LabelFixup {
    /// The target label name to resolve
    pub label: String,
    /// Position in bytecode where the branch offset should be written  
    pub fixup_position: usize,
    /// Size of the branch offset field (1, 2, or 4 bytes)
    pub offset_size: u8,
    /// Position of the branch instruction for relative offset calculation
    pub instruction_position: usize,
}

/// Core CIL instruction encoder.
///
/// This encoder provides low-level instruction encoding capabilities, transforming
/// mnemonics and operands into CIL bytecode. It handles operand type validation,
/// opcode lookup, and maintains a label resolution system for branch instructions.
///
/// # Thread Safety
///
/// [`InstructionEncoder`] is not [`std::marker::Send`] or [`std::marker::Sync`] as it contains
/// mutable state for bytecode generation and label tracking. Create separate instances
/// for concurrent encoding operations.
///
/// # Examples
///
/// ## Basic Instruction Encoding
///
/// ```rust,no_run  
/// use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
///
/// let mut encoder = InstructionEncoder::new();
///
/// // Simple instructions without operands
/// encoder.emit_instruction("nop", None)?;
/// encoder.emit_instruction("ret", None)?;
///
/// // Instructions with immediate operands
/// encoder.emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(42))))?;
/// encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(1))))?;
///
/// let result = encoder.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Branch Instructions with Labels
///
/// ```rust,no_run
/// use dotscope::assembly::InstructionEncoder;
///
/// let mut encoder = InstructionEncoder::new();
///
/// encoder.emit_instruction("ldarg.0", None)?;
/// encoder.emit_branch("brfalse.s", "false_case")?;
/// encoder.emit_instruction("ldc.i4.1", None)?;
/// encoder.emit_branch("br.s", "end")?;
///
/// encoder.define_label("false_case")?;
/// encoder.emit_instruction("ldc.i4.0", None)?;
///
/// encoder.define_label("end")?;
/// encoder.emit_instruction("ret", None)?;
///
/// let bytecode = encoder.finalize()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct InstructionEncoder {
    /// Generated bytecode buffer
    bytecode: Vec<u8>,
    /// Defined label positions (label_name -> byte_position)
    labels: HashMap<String, u32>,
    /// Pending branch fixups awaiting label resolution
    fixups: Vec<LabelFixup>,
    /// Current stack depth (number of items on evaluation stack)
    current_stack_depth: i16,
    /// Maximum stack depth reached during encoding
    max_stack_depth: u16,
}

impl InstructionEncoder {
    /// Create a new instruction encoder.
    ///
    /// Initializes an empty encoder ready for instruction emission. The encoder
    /// maintains internal state for bytecode generation and label resolution.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    /// // Ready for instruction emission
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytecode: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
            current_stack_depth: 0,
            max_stack_depth: 0,
        }
    }

    /// Emit a CIL instruction with optional operand.
    ///
    /// This method performs instruction encoding by looking up the mnemonic in the
    /// reverse lookup table, validating the operand type, and emitting the appropriate
    /// bytecode sequence.
    ///
    /// # Parameters
    ///
    /// * `mnemonic` - The instruction mnemonic (e.g., "nop", "add", "ldarg.s")
    /// * `operand` - Optional operand for the instruction, must match expected type
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mnemonic is not recognized
    /// - The operand type doesn't match the instruction's expected operand type
    /// - The operand is missing when required or present when not expected
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::{InstructionEncoder, Operand, Immediate};
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// // Instructions without operands
    /// encoder.emit_instruction("nop", None)?;
    /// encoder.emit_instruction("add", None)?;
    /// encoder.emit_instruction("ret", None)?;
    ///
    /// // Instructions with operands  
    /// encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(2))))?;
    /// encoder.emit_instruction("ldc.i4", Some(Operand::Immediate(Immediate::Int32(100))))?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_instruction(&mut self, mnemonic: &str, operand: Option<Operand>) -> Result<()> {
        let (opcode, prefix, metadata) = get_mnemonic_lookup()
            .get(mnemonic)
            .ok_or_else(|| Error::InvalidMnemonic(mnemonic.to_string()))?;

        // Emit prefix byte if needed (0xFE for extended instructions)
        if *prefix != 0 {
            self.bytecode.push(*prefix);
        }

        // Emit primary opcode
        self.bytecode.push(*opcode);

        // Emit operand based on expected type
        self.emit_operand(operand, metadata.op_type)?;

        // Update stack tracking
        self.update_stack_depth(metadata.stack_pops, metadata.stack_pushes)?;

        Ok(())
    }

    /// Emit a branch instruction with label reference.
    ///
    /// This method handles branch instructions that reference labels, creating
    /// fixup entries for later resolution. The branch offset will be calculated
    /// and written during the finalization process.
    ///
    /// # Parameters
    ///
    /// * `mnemonic` - The branch instruction mnemonic (e.g., "br.s", "brfalse", "brtrue.s")
    /// * `label` - The target label name to branch to
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is not a recognized branch instruction.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// encoder.emit_branch("br.s", "target_label")?;
    /// encoder.emit_instruction("nop", None)?;
    /// encoder.define_label("target_label")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn emit_branch(&mut self, mnemonic: &str, label: &str) -> Result<()> {
        let (opcode, prefix, metadata) = get_mnemonic_lookup()
            .get(mnemonic)
            .ok_or_else(|| Error::InvalidMnemonic(mnemonic.to_string()))?;

        // Verify this is actually a branch instruction
        if !matches!(
            metadata.flow,
            FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Leave
        ) {
            return Err(Error::InvalidBranchInstruction(mnemonic.to_string()));
        }

        let instruction_start = self.bytecode.len();

        // Emit prefix byte if needed
        if *prefix != 0 {
            self.bytecode.push(*prefix);
        }

        // Emit primary opcode
        self.bytecode.push(*opcode);

        // Determine offset size and create fixup
        let offset_size = match metadata.op_type {
            OperandType::Int8 => 1,
            OperandType::Int16 => 2,
            OperandType::Int32 => 4,
            _ => return Err(Error::InvalidBranchOperandType),
        };

        // Record fixup for later resolution
        let fixup = LabelFixup {
            label: label.to_string(),
            fixup_position: self.bytecode.len(),
            offset_size,
            instruction_position: instruction_start,
        };
        self.fixups.push(fixup);

        // Emit placeholder bytes for the offset (will be filled during finalization)
        for _ in 0..offset_size {
            self.bytecode.push(0);
        }

        // Update stack tracking for branch instructions
        self.update_stack_depth(metadata.stack_pops, metadata.stack_pushes)?;

        Ok(())
    }

    /// Define a label at the current bytecode position.
    ///
    /// Labels mark positions in the bytecode that can be referenced by branch
    /// instructions. Each label must have a unique name within the encoder scope.
    ///
    /// # Parameters
    ///
    /// * `name` - Unique label name
    ///
    /// # Errors
    ///
    /// Returns an error if a label with the same name has already been defined.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    ///
    /// encoder.emit_instruction("nop", None)?;
    /// encoder.define_label("loop_start")?;
    /// encoder.emit_instruction("ldarg.0", None)?;
    /// encoder.emit_branch("br.s", "loop_start")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn define_label(&mut self, name: &str) -> Result<()> {
        if self.labels.contains_key(name) {
            return Err(Error::DuplicateLabel(name.to_string()));
        }

        let bytecode_len = u32::try_from(self.bytecode.len())
            .map_err(|_| malformed_error!("Bytecode length exceeds u32 range"))?;
        self.labels.insert(name.to_string(), bytecode_len);
        Ok(())
    }

    /// Finalize encoding and resolve all label references.
    ///
    /// This method completes the encoding process by resolving all pending label
    /// fixups and calculating branch offsets. After finalization, the encoder
    /// cannot be used for further instruction emission.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The complete CIL bytecode with all labels resolved
    /// - The maximum stack depth required during execution
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any referenced labels are undefined
    /// - Branch offsets exceed the allowed range for their instruction type
    /// - Stack underflow occurred during encoding (negative stack depth)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::InstructionEncoder;
    ///
    /// let mut encoder = InstructionEncoder::new();
    /// encoder.emit_instruction("ldc.i4.1", None)?; // Pushes 1 item
    /// encoder.emit_instruction("ret", None)?;     // Returns with 1 item
    ///
    /// let (bytecode, max_stack) = encoder.finalize()?;
    /// assert_eq!(bytecode, vec![0x17, 0x2A]); // ldc.i4.1, ret
    /// assert_eq!(max_stack, 1); // Maximum stack depth was 1
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn finalize(mut self) -> Result<(Vec<u8>, u16)> {
        // ToDo: Avoid the copy
        let fixups = self.fixups.clone();

        for fixup in &fixups {
            let label_position = self
                .labels
                .get(&fixup.label)
                .ok_or_else(|| Error::UndefinedLabel(fixup.label.clone()))?;

            // Calculate relative offset from end of branch instruction to label
            // The end of the instruction is the fixup position + offset size
            let next_instruction_pos = fixup.fixup_position + fixup.offset_size as usize;

            let label_pos_i32 = i32::try_from(*label_position)
                .map_err(|_| malformed_error!("Label position exceeds i32 range"))?;
            let next_instr_pos_i32 = i32::try_from(next_instruction_pos)
                .map_err(|_| malformed_error!("Instruction position exceeds i32 range"))?;

            let offset = label_pos_i32 - next_instr_pos_i32;

            self.write_branch_offset(offset, fixup)?;
        }

        Ok((self.bytecode, self.max_stack_depth))
    }

    /// Emit operand bytes based on the expected operand type.
    ///
    /// This internal method handles the encoding of instruction operands according
    /// to their expected types, performing validation and byte serialization.
    fn emit_operand(&mut self, operand: Option<Operand>, expected: OperandType) -> Result<()> {
        match expected {
            OperandType::None => {
                if operand.is_some() {
                    return Err(Error::UnexpectedOperand);
                }
            }
            OperandType::Int8 => {
                if let Some(Operand::Immediate(Immediate::Int8(val))) = operand {
                    self.bytecode.push(val.to_le_bytes()[0]);
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int8".to_string(),
                    });
                }
            }
            OperandType::UInt8 => {
                if let Some(Operand::Immediate(Immediate::UInt8(val))) = operand {
                    self.bytecode.push(val);
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt8".to_string(),
                    });
                }
            }
            OperandType::Int16 => {
                if let Some(Operand::Immediate(Immediate::Int16(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int16".to_string(),
                    });
                }
            }
            OperandType::UInt16 => {
                if let Some(Operand::Immediate(Immediate::UInt16(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt16".to_string(),
                    });
                }
            }
            OperandType::Int32 => {
                if let Some(Operand::Immediate(Immediate::Int32(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int32".to_string(),
                    });
                }
            }
            OperandType::UInt32 => {
                if let Some(Operand::Immediate(Immediate::UInt32(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt32".to_string(),
                    });
                }
            }
            OperandType::Int64 => {
                if let Some(Operand::Immediate(Immediate::Int64(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Int64".to_string(),
                    });
                }
            }
            OperandType::UInt64 => {
                if let Some(Operand::Immediate(Immediate::UInt64(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "UInt64".to_string(),
                    });
                }
            }
            OperandType::Float32 => {
                if let Some(Operand::Immediate(Immediate::Float32(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Float32".to_string(),
                    });
                }
            }
            OperandType::Float64 => {
                if let Some(Operand::Immediate(Immediate::Float64(val))) = operand {
                    self.bytecode.extend_from_slice(&val.to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Float64".to_string(),
                    });
                }
            }
            OperandType::Token => {
                if let Some(Operand::Token(token)) = operand {
                    self.bytecode
                        .extend_from_slice(&token.value().to_le_bytes());
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Token".to_string(),
                    });
                }
            }
            OperandType::Switch => {
                if let Some(Operand::Switch(targets)) = operand {
                    // Switch format: count (4 bytes) + targets (4 bytes each)
                    let targets_len = u32::try_from(targets.len())
                        .map_err(|_| malformed_error!("Too many switch targets"))?;
                    self.bytecode.extend_from_slice(&targets_len.to_le_bytes());
                    for target in targets {
                        self.bytecode.extend_from_slice(&target.to_le_bytes());
                    }
                } else {
                    return Err(Error::WrongOperandType {
                        expected: "Switch".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Write a branch offset at the specified fixup position.
    ///
    /// This internal method writes the calculated branch offset into the bytecode
    /// at the position specified by the fixup, using the appropriate byte size.
    fn write_branch_offset(&mut self, offset: i32, fixup: &LabelFixup) -> Result<()> {
        match fixup.offset_size {
            1 => {
                if offset < i32::from(i8::MIN) || offset > i32::from(i8::MAX) {
                    return Err(Error::BranchOffsetOutOfRange {
                        offset,
                        instruction_size: 1,
                    });
                }
                let offset_i8 = i8::try_from(offset)
                    .map_err(|_| malformed_error!("Branch offset exceeds i8 range"))?;
                self.bytecode[fixup.fixup_position] = offset_i8.to_le_bytes()[0];
            }
            2 => {
                if offset < i32::from(i16::MIN) || offset > i32::from(i16::MAX) {
                    return Err(Error::BranchOffsetOutOfRange {
                        offset,
                        instruction_size: 2,
                    });
                }
                let offset_i16 = i16::try_from(offset)
                    .map_err(|_| malformed_error!("Branch offset exceeds i16 range"))?;
                let bytes = offset_i16.to_le_bytes();
                self.bytecode[fixup.fixup_position..fixup.fixup_position + 2]
                    .copy_from_slice(&bytes);
            }
            4 => {
                let bytes = offset.to_le_bytes();
                self.bytecode[fixup.fixup_position..fixup.fixup_position + 4]
                    .copy_from_slice(&bytes);
            }
            _ => return Err(Error::InvalidBranchOffsetSize(fixup.offset_size)),
        }
        Ok(())
    }

    /// Update stack depth tracking based on instruction stack behavior.
    ///
    /// This internal method applies the stack effects of an instruction and validates
    /// that stack underflow doesn't occur.
    ///
    /// # Parameters
    ///
    /// * `pops` - Number of items the instruction pops from the stack
    /// * `pushes` - Number of items the instruction pushes onto the stack
    ///
    /// # Errors
    ///
    /// Returns an error if stack underflow would occur (negative stack depth).
    fn update_stack_depth(&mut self, pops: u8, pushes: u8) -> Result<()> {
        // Apply stack effect
        let net_effect = i16::from(pushes) - i16::from(pops);
        self.current_stack_depth += net_effect;

        // Check for stack underflow
        if self.current_stack_depth < 0 {
            return Err(crate::malformed_error!(
                "Stack underflow: depth became {} after instruction with {} pops, {} pushes",
                self.current_stack_depth,
                pops,
                pushes
            ));
        }

        // Update maximum stack depth
        let current_depth_u16 = u16::try_from(self.current_stack_depth)
            .map_err(|_| malformed_error!("Stack depth exceeds u16 range"))?;
        self.max_stack_depth = self.max_stack_depth.max(current_depth_u16);

        Ok(())
    }

    /// Get the current maximum stack depth without finalizing the encoder.
    ///
    /// This method allows checking the maximum stack depth that has been reached
    /// so far during encoding without consuming the encoder.
    ///
    /// # Returns
    ///
    /// The maximum stack depth reached so far during instruction encoding.
    #[must_use]
    pub fn max_stack_depth(&self) -> u16 {
        self.max_stack_depth
    }

    /// Get the current stack depth without finalizing the encoder.
    ///
    /// This method returns the current number of items on the evaluation stack.
    /// Useful for debugging or validation during encoding.
    ///
    /// # Returns
    ///
    /// The current stack depth (number of items on evaluation stack).
    #[must_use]
    pub fn current_stack_depth(&self) -> i16 {
        self.current_stack_depth
    }

    /// Get the position of a defined label.
    ///
    /// This method allows accessing label positions before finalization,
    /// which is useful for exception handler offset calculation.
    ///
    /// # Parameters
    ///
    /// * `label_name` - The name of the label to look up
    ///
    /// # Returns
    ///
    /// The byte position of the label if it exists, otherwise None.
    #[must_use]
    pub fn get_label_position(&self, label_name: &str) -> Option<u32> {
        self.labels.get(label_name).copied()
    }
}

impl Default for InstructionEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{Immediate, Operand};

    #[test]
    fn test_encoder_creation() {
        let encoder = InstructionEncoder::new();
        assert!(encoder.bytecode.is_empty());
        assert!(encoder.labels.is_empty());
        assert!(encoder.fixups.is_empty());
    }

    #[test]
    fn test_simple_instruction_encoding() -> Result<()> {
        let mut encoder = InstructionEncoder::new();

        encoder.emit_instruction("nop", None)?;
        encoder.emit_instruction("ret", None)?;

        let (bytecode, _max_stack) = encoder.finalize()?;
        assert_eq!(bytecode, vec![0x00, 0x2A]); // nop = 0x00, ret = 0x2A

        Ok(())
    }

    #[test]
    fn test_instruction_with_operands() -> Result<()> {
        let mut encoder = InstructionEncoder::new();

        encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::Int8(1))))?;
        encoder.emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(42))))?;

        let (bytecode, _max_stack) = encoder.finalize()?;
        // ldarg.s = 0x0E, ldarg index = 1, ldc.i4.s = 0x1F, immediate = 42
        assert_eq!(bytecode, vec![0x0E, 0x01, 0x1F, 42]);

        Ok(())
    }

    #[test]
    fn test_label_resolution() -> Result<()> {
        let mut encoder = InstructionEncoder::new();

        encoder.emit_instruction("nop", None)?; // 0x00
        encoder.emit_branch("br.s", "target")?; // 0x2B + offset
        encoder.emit_instruction("nop", None)?; // 0x00
        encoder.define_label("target")?;
        encoder.emit_instruction("ret", None)?; // 0x2A

        let (bytecode, _max_stack) = encoder.finalize()?;
        // br.s offset should be 1 (skip the nop instruction)
        assert_eq!(bytecode, vec![0x00, 0x2B, 0x01, 0x00, 0x2A]);

        Ok(())
    }

    #[test]
    fn test_invalid_mnemonic() {
        let mut encoder = InstructionEncoder::new();
        let result = encoder.emit_instruction("invalid_instruction", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_operand_type() {
        let mut encoder = InstructionEncoder::new();
        // ldarg.s expects Int8, but we provide UInt32
        let result =
            encoder.emit_instruction("ldarg.s", Some(Operand::Immediate(Immediate::UInt32(1))));
        assert!(result.is_err());
    }

    #[test]
    fn test_undefined_label() {
        let mut encoder = InstructionEncoder::new();
        encoder.emit_branch("br.s", "undefined_label").unwrap();
        let result = encoder.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_label() -> Result<()> {
        let mut encoder = InstructionEncoder::new();
        encoder.define_label("test_label")?;
        let result = encoder.define_label("test_label");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_reverse_lookup_table_completeness() {
        // Verify that our reverse lookup table contains all non-empty instructions
        let mut instruction_count = 0;

        // Count single-byte instructions
        for instr in INSTRUCTIONS.iter() {
            if !instr.instr.is_empty() {
                instruction_count += 1;
                assert!(get_mnemonic_lookup().contains_key(instr.instr));
            }
        }

        // Count extended instructions
        for instr in INSTRUCTIONS_FE.iter() {
            if !instr.instr.is_empty() {
                instruction_count += 1;
                assert!(get_mnemonic_lookup().contains_key(instr.instr));
            }
        }

        // Verify the lookup table has exactly the expected number of entries
        assert_eq!(get_mnemonic_lookup().len(), instruction_count);
    }
}
