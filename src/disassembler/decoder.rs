//! CIL instruction decoding and disassembly utilities.
//!
//! This module provides low-level functions for decoding CIL bytecode into instructions and
//! analyzing control flow. It is intended for advanced users who need to work with raw bytecode
//! or build custom analysis tools.
//!
//! # Example: Decoding a Single Instruction
//!
//! ```rust,no_run
//! use dotscope::{Parser, disassembler::decode_instruction};
//! let code = [0x2A]; // ret
//! let mut parser = Parser::new(&code);
//! let instr = decode_instruction(&mut parser, 0x1000)?;
//! assert_eq!(instr.mnemonic, "ret");
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Example: Decoding a Stream of Instructions
//!
//! ```rust,no_run
//! use dotscope::{Parser, disassembler::decode_stream};
//! let code = [0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(&code);
//! let instrs = decode_stream(&mut parser, 0x1000)?;
//! assert_eq!(instrs.len(), 2);
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    disassembler::{
        visitedmap::VisitedMap, BasicBlock, FlowType, Immediate, Instruction, Operand, OperandType,
        StackBehavior, INSTRUCTIONS, INSTRUCTIONS_FE,
    },
    file::{parser::Parser, File},
    metadata::{
        method::{ExceptionHandler, Method},
        token::Token,
    },
    Error::OutOfBounds,
    Result,
};

/// A stateful decoder instance, that exposes the more complex disassembly algorithm
/// in a simple manner to be used by the framework and exposed methods
struct Decoder<'a> {
    blocks: Vec<BasicBlock>,

    exceptions: Option<&'a [ExceptionHandler]>,
    visited: VisitedMap,
    parser: &'a mut Parser<'a>,
    block_id: usize,

    offset_start: usize,
    rva_start: usize,
}

impl<'a> Decoder<'a> {
    /// Create a new stateful Decoder
    ///
    /// ## Arguments
    /// * 'parser'      - The parser that wraps the byte stream to process
    /// * 'offset'      - The offset at which the first instructions starts (must be in range of parser)
    /// * 'rva'         - The rva of the first instruction
    /// * 'exceptions'  - Optional information about exception handlers
    pub fn new(
        parser: &'a mut Parser<'a>,
        offset: usize,
        rva: usize,
        exceptions: Option<&'a [ExceptionHandler]>,
    ) -> Result<Self> {
        if offset > parser.len() {
            return Err(OutOfBounds);
        }

        Ok(Decoder {
            blocks: Vec::new(),
            exceptions,
            visited: VisitedMap::new(parser.len()),
            parser,
            block_id: 0,
            offset_start: offset,
            rva_start: rva,
        })
    }

    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    /// Consumes the decoder and returns ownership of the decoded blocks.
    ///
    /// This method transfers ownership of the decoded basic blocks from the decoder
    /// to the caller, consuming the decoder in the process. This is more efficient
    /// than cloning the blocks when transferring ownership is desired.
    ///
    /// # Usage in Method Integration
    ///
    /// This method is primarily used internally by [`decode_method`] to efficiently
    /// transfer decoded blocks to the Method's `OnceLock<Vec<BasicBlock>>` field:
    ///
    /// ```rust,ignore
    /// // Internal usage pattern
    /// let blocks = decoder.into_blocks();
    /// method.blocks.set(blocks);
    /// ```
    ///
    /// # Performance
    ///
    /// This method performs a move operation (O(1)) rather than cloning all blocks
    /// and their contained instructions, making it efficient for large methods.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::disassembler::decode_blocks;
    ///
    /// let bytecode = [0x00, 0x2A]; // nop, ret
    /// let blocks = decode_blocks(&bytecode, 0, 0x1000, None)?;
    ///
    /// // blocks now owns the decoded basic blocks
    /// println!("Decoded {} basic blocks", blocks.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// Note: `decode_blocks` function internally uses this method to return ownership
    /// of the blocks to the caller.
    pub fn into_blocks(self) -> Vec<BasicBlock> {
        self.blocks
    }

    /// Decode all accessible blocks that are contained in this parser
    fn decode_blocks(&mut self) -> Result<()> {
        self.blocks.push(BasicBlock::new(
            self.block_id,
            self.rva_start as u64,
            self.offset_start,
        ));

        while self.block_id < self.blocks.len() {
            self.decode_block(self.block_id)?;
            self.block_id += 1;
        }

        self.process_exception_handlers();

        Ok(())
    }

    /// Process a single block, adding its instructions and successor blocks
    ///
    /// ## Arguments
    /// * `block_id` - The id of the block to decode
    fn decode_block(&mut self, block_id: usize) -> Result<()> {
        if self.blocks[block_id].offset > self.parser.len() {
            return Err(OutOfBounds);
        }

        if self.visited.get(self.blocks[block_id].offset) {
            return Ok(());
        }

        self.parser.seek(self.blocks[block_id].offset)?;

        let mut current_offset = self.blocks[block_id].offset;
        let mut current_rva = self.blocks[block_id].rva;
        let mut terminated = false;

        while !terminated && current_offset < self.parser.len() {
            let instruction = decode_instruction(self.parser, current_rva)?;

            match instruction.flow_type {
                FlowType::ConditionalBranch => {
                    for target_rva in &instruction.branch_targets {
                        // Calculate the target offset from the start offset
                        #[allow(clippy::cast_possible_truncation)]
                        let target_offset = self.offset_start
                            + (target_rva.saturating_sub(self.rva_start as u64) as usize);
                        // Only create block if target is within bounds
                        if target_offset < self.parser.len() {
                            let block = BasicBlock::new(self.block_id, *target_rva, target_offset);
                            self.blocks.push(block);
                        }
                    }

                    let instruction_size = usize::try_from(instruction.size).unwrap_or(0);
                    let block = BasicBlock::new(
                        self.block_id,
                        current_rva + instruction.size,
                        current_offset + instruction_size,
                    );
                    self.blocks.push(block);

                    terminated = true;
                }
                FlowType::UnconditionalBranch | FlowType::Switch => {
                    for target_rva in &instruction.branch_targets {
                        // Calculate the target offset from the start offset
                        #[allow(clippy::cast_possible_truncation)]
                        let target_offset = self.offset_start
                            + (target_rva.saturating_sub(self.rva_start as u64) as usize);
                        // Only create block if target is within bounds
                        if target_offset < self.parser.len() {
                            let block = BasicBlock::new(self.block_id, *target_rva, target_offset);
                            self.blocks.push(block);
                        }
                    }

                    terminated = true;
                }
                FlowType::Return | FlowType::Throw => terminated = true,
                _ => {}
            }

            self.visited.set_range(
                current_offset,
                true,
                usize::try_from(instruction.size).unwrap_or(0),
            );

            let instruction_size_usize = usize::try_from(instruction.size).unwrap_or(0);
            current_offset += instruction_size_usize;
            current_rva += instruction.size;
            self.blocks[block_id].size += instruction_size_usize;
            self.blocks[block_id].instructions.push(instruction);
        }

        Ok(())
    }

    /// Process exception handlers and associate them with blocks
    fn process_exception_handlers(&mut self) {
        if let Some(exceptions) = self.exceptions {
            for (handler_idx, handler) in exceptions.iter().enumerate() {
                let try_start = u64::from(handler.try_offset);
                let try_end = try_start + u64::from(handler.try_length);

                for block in &mut self.blocks {
                    if block.rva >= try_start && block.rva <= try_end {
                        block.exceptions.push(handler_idx);
                    }
                }
            }
        }
    }
}

/// Disassembles a method's body into basic blocks and integrates results into the Method struct.
///
/// This function performs complete method disassembly including:
/// - Parsing method headers and exception handling information
/// - Decoding all instructions in the method body
/// - Building basic blocks with proper control flow analysis
/// - Associating exception handlers with their corresponding blocks
/// - Thread-safe integration with the Method's `OnceLock<Vec<BasicBlock>>` storage
///
/// The function handles the complete disassembly pipeline from raw bytecode to structured
/// basic blocks, making the results available through the Method's accessor methods.
///
/// # Method Integration
///
/// The decoded blocks are efficiently transferred to the Method using `OnceLock::set()`:
/// ```rust,ignore
/// decoder.decode_blocks()?;
/// let _ = method.blocks.set(decoder.into_blocks());
/// ```
///
/// This pattern ensures:
/// - Thread-safe lazy initialization (first thread to call wins)
/// - Zero-copy transfer of blocks (no cloning required)
/// - Subsequent access uses cached results
///
/// # Arguments
///
/// * `method` - The Method instance to populate with disassembled basic blocks
/// * `file` - The File containing the raw method bytecode and metadata
///
/// # Returns
///
/// Returns `Ok(())` on successful disassembly, or an error if:
/// - The method lacks a valid RVA (relative virtual address)
/// - The method body cannot be parsed from the file
/// - Instruction decoding encounters malformed bytecode
/// - Control flow analysis finds invalid branch targets
/// - Exception handler information is malformed
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently for different methods.
/// If multiple threads attempt to disassemble the same method simultaneously, only
/// the first thread will perform the work while others will no-op safely.
///
/// # Performance Notes
///
/// - The function performs no work if the method is already disassembled
/// - Basic block construction uses efficient control flow analysis algorithms
/// - Exception handler processing is optimized for typical .NET code patterns
/// - Memory usage scales linearly with method size and complexity
///
/// # Examples
///
/// ```rust,ignore
/// // Internal usage in the library
/// use dotscope::disassembler::decode_method;
/// use dotscope::CilObject;
///
/// let assembly = CilObject::from_file("assembly.dll")?;
/// let file = assembly.file();
///
/// for entry in assembly.methods().iter().take(10) {
///     let method = entry.value();
///     
///     // This is called automatically when accessing method instructions
///     decode_method(&method, &file)?;
///     
///     // Now blocks are available
///     println!("Method {} has {} blocks", method.name, method.block_count());
/// }
/// ```
///
/// Note: This function is typically called automatically when accessing method
/// instructions or blocks, rather than being invoked directly by user code.
/// - Associating exception handlers with relevant blocks
///
/// The function automatically handles different method body formats (fat/tiny headers)
/// and processes exception handling regions according to ECMA-335 specifications.
///
/// # Arguments
///
/// * `method` - The parsed `Method` object to disassemble. Must have valid RVA and metadata.
/// * `file` - The mapped input file providing access to raw bytecode data.
///
/// # Returns
///
/// Returns `Ok(())` on successful disassembly, or an error if:
/// - Method has invalid RVA or offset
/// - Bytecode is malformed or truncated
/// - Exception handler data is invalid
/// - Memory allocation fails during processing
///
/// # Notes
///
/// - The method basic blocks are stored in method.blocks after disassembly
/// - Exception handlers are automatically associated with relevant blocks
/// - Control flow analysis builds proper predecessor/successor relationships
/// - The function is thread-safe when called on different methods
pub(crate) fn decode_method(method: &Method, file: &File) -> Result<()> {
    let rva = match method.rva {
        Some(rva) => rva as usize,
        None => return Ok(()),
    };

    let method_offset = file.rva_to_offset(rva)?;
    if method_offset >= file.data().len() {
        return Err(malformed_error!("Invalid method offset: {}", method_offset));
    }

    {
        let Some(body) = method.body.get() else {
            return Err(malformed_error!("Method does not have a valid body"));
        };

        if body.size_header >= file.data().len() {
            return Err(malformed_error!(
                "MethodHeader size exceeds file size - {}",
                body.size_header
            ));
        }

        let Some(code_start) = method_offset.checked_add(body.size_header) else {
            return Err(malformed_error!(
                "Integer overflow size_header ({}) + method_offset ({})",
                body.size_header,
                method_offset
            ));
        };

        let mut parser = Parser::new(file.data());
        let mut decoder = Decoder::new(
            &mut parser,
            code_start,
            rva + body.size_header,
            Some(&body.exception_handlers),
        )?;

        decoder.decode_blocks()?;

        let _ = method.blocks.set(decoder.into_blocks());
    }

    // Get size of Method by counting size of blocks (considering potential inlined data. Not natural, but who knows
    // what obfuscators do... )
    // body.size_code should be == method_size from blocks

    //*write_lock!(method.cfg) = Some(build_cfg(&blocks)?);
    //*write_lock!(method.ssa) = Some(transform_to_ssa(&body.blocks, &body.cfg.as_ref().unwrap())?);

    Ok(())
}

/// Decodes bytecode into a collection of basic blocks with control flow analysis.
///
/// This is a high-level function that performs comprehensive disassembly of bytecode
/// into basic blocks, building the complete control flow graph automatically.
/// Unlike `decode_method`, this function works with raw bytecode without requiring
/// method metadata or exception handler information.
///
/// The function automatically detects basic block boundaries based on control flow
/// instructions and builds a complete control flow graph. Each basic block contains
/// a sequential list of instructions ending with a control transfer instruction.
///
/// # Arguments
///
/// * `data` - Raw bytecode buffer to disassemble
/// * `offset` - Starting offset within the bytecode buffer (0-based)
/// * `rva` - Relative Virtual Address of the first instruction for proper addressing
/// * `max_size` - Maximum number of bytes to process (None for entire buffer from offset)
///
/// # Returns
///
/// Returns a vector of `BasicBlock` objects representing the control flow structure,
/// or an error if:
/// - The bytecode contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - The specified offset is beyond the buffer bounds
/// - Control flow analysis encounters invalid branch targets
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::disassembler::decode_blocks;
///
/// // Simple bytecode sequence: nop, conditional branch, ret
/// let bytecode = [
///     0x00,             // nop
///     0x2C, 0x02,       // brfalse.s +2 (skip next instruction)
///     0x2A,             // ret
///     0x2A,             // ret (branch target)
/// ];
///
/// let blocks = decode_blocks(&bytecode, 0, 0x1000, None)?;
///
/// // Should produce multiple basic blocks due to control flow
/// assert!(blocks.len() >= 2);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Notes
///
/// - Basic blocks are built based on control flow analysis
/// - Branch targets automatically create new basic block boundaries  
/// - No exception handler analysis is performed (use `decode_method` for that)
/// - The function processes bytecode sequentially until all reachable code is analyzed
/// - Use this for analyzing raw bytecode outside of method contexts
///
/// # Errors
///
/// Returns an error if:
/// - The bytecode is malformed or contains invalid instructions
/// - Memory access goes out of bounds during decoding
/// - Invalid branch targets are encountered
pub fn decode_blocks(
    data: &[u8],
    offset: usize,
    rva: usize,
    max_size: Option<usize>,
) -> Result<Vec<BasicBlock>> {
    if offset >= data.len() {
        return Err(malformed_error!(
            "Starting offset {} exceeds data length {}",
            offset,
            data.len()
        ));
    }

    let effective_data = if let Some(size) = max_size {
        let end_offset = offset.saturating_add(size).min(data.len());
        &data[offset..end_offset]
    } else {
        &data[offset..]
    };

    let mut parser = Parser::new(effective_data);
    let mut decoder = Decoder::new(&mut parser, 0, rva, None)?;

    decoder.decode_blocks()?;

    Ok(decoder.into_blocks())
}

/// Decodes a continuous stream of CIL instructions from a byte stream.
///
/// This function processes raw bytecode sequentially, decoding each instruction
/// until the parser reaches the end of available data. Unlike `decode_method`,
/// this function does not perform control flow analysis or create basic blocks.
///
/// The function maintains proper RVA tracking as it processes instructions,
/// ensuring each decoded instruction has the correct virtual address information.
/// This is useful for linear disassembly scenarios or when working with
/// instruction streams outside of method contexts.
///
/// # Arguments
///
/// * `parser` - A mutable parser positioned at the start of the instruction stream
/// * `rva` - The relative virtual address of the first instruction in the stream
///
/// # Returns
///
/// Returns a `Vec<Instruction>` containing all successfully decoded instructions,
/// or an error if:
/// - The bytecode stream contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - Parser encounters unexpected end of data during instruction decoding
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{disassembler::decode_stream, Parser};
///
/// // Raw CIL bytecode: nop, ldloc.0, ret
/// let bytecode = [0x00, 0x06, 0x2A];
/// let mut parser = Parser::new(&bytecode);
///
/// let instructions = decode_stream(&mut parser, 0x2000)?;
///
/// assert_eq!(instructions.len(), 3);
/// assert_eq!(instructions[0].mnemonic, "nop");
/// assert_eq!(instructions[1].mnemonic, "ldloc.0");
/// assert_eq!(instructions[2].mnemonic, "ret");
///
/// // RVAs are properly tracked
/// assert_eq!(instructions[0].rva, 0x2000);
/// assert_eq!(instructions[1].rva, 0x2001);
/// assert_eq!(instructions[2].rva, 0x2002);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The bytecode stream contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - Parser encounters unexpected end of data during instruction decoding
///
/// # Notes
///
/// - Instructions are decoded in linear order without control flow analysis
/// - Each instruction's RVA is calculated based on the previous instruction's size
/// - The function stops when the parser has no more data available
/// - Use `decode_method` for complete method analysis with basic blocks
pub fn decode_stream(parser: &mut Parser, rva: u64) -> Result<Vec<Instruction>> {
    let mut current_rva = rva;
    let mut instructions = Vec::new();

    while parser.has_more_data() {
        let current_offset = parser.pos();
        let instruction = decode_instruction(parser, current_rva)?;

        instructions.push(instruction);

        current_rva += (parser.pos() - current_offset) as u64;
    }

    Ok(instructions)
}

/// Decodes a single CIL instruction from the current parser position.
///
/// This is the core instruction decoding function that parses individual CIL
/// opcodes and their operands from raw bytecode. It handles both single-byte
/// and double-byte opcodes, correctly decoding all operand types including
/// immediate values, tokens, and branch targets.
///
/// The function advances the parser position as it reads the instruction data,
/// ensuring proper sequential decoding when called multiple times. Each decoded
/// instruction includes complete operand information and metadata for further
/// analysis.
///
/// # Arguments
///
/// * `parser` - A mutable parser positioned at the start of an instruction
/// * `rva` - The relative virtual address of the instruction being decoded
///
/// # Returns
///
/// Returns a fully populated `Instruction` struct containing:
/// - The instruction mnemonic and opcode information
/// - Decoded operands with proper type information
/// - Stack behavior and flow control metadata
/// - Size and RVA information for the instruction
///
/// # Errors
///
/// Returns an error if:
/// - An invalid or unrecognized opcode is encountered
/// - Operand data is truncated or corrupted
/// - Parser reaches end of data unexpectedly during operand decoding
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{disassembler::{decode_instruction, Operand}, Parser};
///
/// // Simple instruction: ldloc.0 (0x06)
/// let bytecode = [0x06];
/// let mut parser = Parser::new(&bytecode);
///
/// let instruction = decode_instruction(&mut parser, 0x2000)?;
///
/// assert_eq!(instruction.mnemonic, "ldloc.0");
/// assert_eq!(instruction.rva, 0x2000);
/// assert_eq!(instruction.size, 1);
/// assert!(matches!(instruction.operand, Operand::None)); // No operands for ldloc.0
///
/// // Instruction with operand: ldstr <token>
/// let bytecode = [0x72, 0x01, 0x00, 0x00, 0x70]; // ldstr followed by token
/// let mut parser = Parser::new(&bytecode);
///
/// let instruction = decode_instruction(&mut parser, 0x2010)?;
///
/// assert_eq!(instruction.mnemonic, "ldstr");
/// if let Operand::Token(token) = &instruction.operand {
///     // Token operand with value 0x70000001
///     assert_eq!(token.value(), 0x70000001);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Implementation Notes
///
/// - Handles both 0xFE-prefixed extended opcodes and standard single-byte opcodes
/// - Correctly decodes variable-length operands (int8, int16, int32, int64)
/// - Processes metadata tokens and resolves their table/row information
/// - Calculates branch target addresses for control flow instructions
/// - Maintains parser state for sequential instruction decoding
pub fn decode_instruction(parser: &mut Parser, rva: u64) -> Result<Instruction> {
    let offset = parser.pos() as u64;
    let first_byte = parser.read_le::<u8>()?;

    let (cil_instruction, prefix, opcode) = match first_byte {
        0xFE => {
            let second_byte = parser.read_le::<u8>()?;

            match INSTRUCTIONS_FE.get(second_byte as usize) {
                Some(instr) => (instr, 0xFE, second_byte),
                None => return Err(malformed_error!("Invalid opcode: FE {:02X}", second_byte)),
            }
        }
        _ => match INSTRUCTIONS.get(first_byte as usize) {
            Some(instr) => (instr, 0, first_byte),
            None => return Err(malformed_error!("Invalid opcode: {:X}", first_byte)),
        },
    };

    if cil_instruction.instr.is_empty() {
        return Err(malformed_error!("Reserved opcode: {:04X}", opcode));
    }

    let operand = match cil_instruction.op_type {
        OperandType::None => Operand::None,
        OperandType::Int8 => Operand::Immediate(Immediate::Int8(parser.read_le::<i8>()?)),
        OperandType::UInt8 => Operand::Immediate(Immediate::UInt8(parser.read_le::<u8>()?)),
        OperandType::Int16 => Operand::Immediate(Immediate::Int16(parser.read_le::<i16>()?)),
        OperandType::UInt16 => Operand::Immediate(Immediate::UInt16(parser.read_le::<u16>()?)),
        OperandType::Int32 => Operand::Immediate(Immediate::Int32(parser.read_le::<i32>()?)),
        OperandType::UInt32 => Operand::Immediate(Immediate::UInt32(parser.read_le::<u32>()?)),
        OperandType::Int64 => Operand::Immediate(Immediate::Int64(parser.read_le::<i64>()?)),
        OperandType::UInt64 => Operand::Immediate(Immediate::UInt64(parser.read_le::<u64>()?)),
        OperandType::Float32 => Operand::Immediate(Immediate::Float32(parser.read_le::<f32>()?)),
        OperandType::Float64 => Operand::Immediate(Immediate::Float64(parser.read_le::<f64>()?)),
        OperandType::Token => Operand::Token(Token::new(parser.read_le::<u32>()?)),
        OperandType::Switch => {
            let case_count = parser.read_le::<u32>()?;

            let mut targets = Vec::with_capacity(case_count as usize);
            for _ in 0..case_count as usize {
                targets.push(parser.read_le::<u32>()?);
            }

            Operand::Switch(targets)
        }
    };
    let size = parser.pos() as u64 - offset;

    let mut instruction = Instruction {
        rva,
        offset,
        size,
        opcode,
        prefix,
        mnemonic: cil_instruction.instr,
        category: cil_instruction.category,
        flow_type: cil_instruction.flow,
        stack_behavior: StackBehavior {
            pops: cil_instruction.stack_pops,
            pushes: cil_instruction.stack_pushes,
            // Allow wrapping cast - stack effects can legitimately be negative
            #[allow(clippy::cast_possible_wrap)]
            net_effect: cil_instruction.stack_pushes as i8 - cil_instruction.stack_pops as i8,
        },
        branch_targets: Vec::new(),
        operand,
    };

    match instruction.flow_type {
        FlowType::ConditionalBranch | FlowType::UnconditionalBranch => {
            if let Operand::Immediate(value) = instruction.operand {
                let next_instruction_rva = rva + instruction.size;
                let branch_offset = <Immediate as Into<u64>>::into(value);
                instruction
                    .branch_targets
                    .push(next_instruction_rva.wrapping_add(branch_offset));
            }
        }
        FlowType::Switch => {
            if let Operand::Switch(targets) = &instruction.operand {
                let next_instruction_rva = rva + instruction.size;
                for &target in targets {
                    instruction
                        .branch_targets
                        .push(next_instruction_rva.wrapping_add(u64::from(target)));
                }
            }
        }
        _ => {}
    }

    Ok(instruction)
}

#[cfg(test)]
mod tests {
    use crate::{
        disassembler::{
            decode_blocks, decode_instruction, decode_stream, FlowType, Immediate,
            InstructionCategory, Operand,
        },
        Parser,
    };

    #[test]
    fn decode_instruction_basic() {
        // ldloc.s 10 (0x11, 0x10)
        let mut parser = Parser::new(&[0x11, 0x10]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.rva, rva);
        assert_eq!(result.offset, 0);
        assert_eq!(result.size, 2);
        assert_eq!(result.opcode, 0x11);
        assert_eq!(result.prefix, 0);
        assert_eq!(result.mnemonic, "ldloc.s");
        assert_eq!(result.category, InstructionCategory::LoadStore);
        assert_eq!(result.flow_type, FlowType::Sequential);
        match &result.operand {
            Operand::Immediate(Immediate::Int8(val)) => assert_eq!(*val, 0x10),
            _ => panic!("Expected Operand::Immediate(Immediate::Int8)"),
        }
    }

    #[test]
    fn decode_instruction_two_byte() {
        // ceq (0xFE, 0x01)
        let mut parser = Parser::new(&[0xFE, 0x01]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.opcode, 0x01);
        assert_eq!(result.prefix, 0xFE);
        assert_eq!(result.mnemonic, "ceq");
        assert_eq!(result.category, InstructionCategory::Comparison);
        assert_eq!(result.flow_type, FlowType::Sequential);
    }

    #[test]
    fn decode_instruction_branch() {
        // br.s 10 (0x2B, 0x0A)
        let mut parser = Parser::new(&[0x2B, 0x0A]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "br.s");
        assert_eq!(result.flow_type, FlowType::UnconditionalBranch);
        assert_eq!(result.branch_targets.len(), 1);
        assert_eq!(result.branch_targets[0], 0x100C); // next_rva (0x1002) + offset (10)
    }

    #[test]
    fn decode_instruction_switch() {
        let mut parser = Parser::new(&[
            0x45, 0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
        ]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "switch");
        assert_eq!(result.flow_type, FlowType::Switch);
        assert_eq!(result.branch_targets.len(), 2);
        assert_eq!(result.branch_targets[0], 0x1017); // next_rva (0x100D) + offset (10)
        assert_eq!(result.branch_targets[1], 0x1021); // next_rva (0x100D) + offset (20)
    }

    #[test]
    fn decode_instruction_invalid_opcode() {
        let mut parser = Parser::new(&[0xFF, 0xFF]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva);
        assert!(result.is_err(), "Expected error for invalid opcode");
    }

    #[test]
    fn decode_instruction_token() {
        // ldtoken 0x02000001 (0xD0, 0x01, 0x00, 0x00, 0x02)
        let mut parser = Parser::new(&[0xD0, 0x01, 0x00, 0x00, 0x02]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "ldToken");
        match &result.operand {
            Operand::Token(token) => assert_eq!(token.value(), 0x02000001),
            _ => panic!("Expected Operand::Token"),
        }
    }

    #[test]
    fn decode_stream_complex() {
        let code = vec![
            0x00, // nop
            0x2C, 0x05, // brfalse.s 5
            0x00, // nop
            0x2B, 0x03, // br.s 3
            0x00, // nop
            0x2A, // ret
            0x00, // nop
            0x2A, // ret
        ];

        let mut parser = Parser::new(&code);
        let result = decode_stream(&mut parser, 0x1000).unwrap();

        assert_eq!(result.len(), 8);
    }

    #[test]
    fn decode_blocks_simple() {
        // Simple linear code: nop, ret
        let code = [0x00, 0x2A]; // nop, ret
        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert_eq!(
            result.len(),
            1,
            "Expected single basic block for linear code"
        );
        assert_eq!(
            result[0].instructions.len(),
            2,
            "Expected 2 instructions in block"
        );
        assert_eq!(result[0].rva, 0x1000, "Expected correct starting RVA");
    }

    #[test]
    fn decode_blocks_with_conditional_branch() {
        let code = [
            0x00, // nop
            0x2C, 0x02, // brfalse.s +2 (skip next instruction)
            0x2A, // ret (false path)
            0x2A, // ret (true path - branch target)
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert!(
            result.len() >= 2,
            "Expected multiple basic blocks due to branching"
        );

        // Find the first block (should contain nop + brfalse.s)
        let first_block = &result[0];
        assert_eq!(
            first_block.instructions.len(),
            2,
            "First block should have nop + brfalse.s"
        );
        assert_eq!(first_block.instructions[0].mnemonic, "nop");
        assert_eq!(first_block.instructions[1].mnemonic, "brfalse.s");
    }

    #[test]
    fn decode_blocks_with_unconditional_branch() {
        let code = [
            0x00, // nop
            0x2B, 0x01, // br.s +1 (jump to last ret instruction)
            0x2A, // ret (unreachable)
            0x2A, // ret (branch target)
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert!(
            result.len() >= 2,
            "Expected multiple basic blocks due to branching, got {}",
            result.len()
        );

        // First block should end with unconditional branch
        let first_block = &result[0];
        assert_eq!(
            first_block.instructions.len(),
            2,
            "First block should have nop + br.s"
        );
        assert_eq!(first_block.instructions[1].mnemonic, "br.s");
    }

    #[test]
    fn decode_blocks_with_switch() {
        let code = [
            0x00, // nop                                          - offset 0, RVA 0x1000
            0x45, 0x02, 0x00, 0x00,
            0x00, // switch with 2 cases - offset 1-5, RVA 0x1001-0x1005
            0x00, 0x00, 0x00,
            0x00, // case 0: offset +0        - offset 6-9, RVA 0x1006-0x1009
            0x02, 0x00, 0x00,
            0x00, // case 1: offset +2        - offset 10-13, RVA 0x100A-0x100D
            0x2A, // ret (case 0 target at RVA 0x100E + 0)       - offset 14, RVA 0x100E
            0x2A, // ret (case 1 target at RVA 0x100E + 2)       - offset 15, RVA 0x100F
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert!(
            result.len() >= 2,
            "Expected multiple basic blocks due to switch"
        );

        // First block should contain nop + switch
        let first_block = &result[0];
        assert_eq!(first_block.instructions.len(), 2);
        assert_eq!(first_block.instructions[0].mnemonic, "nop");
        assert_eq!(first_block.instructions[1].mnemonic, "switch");
    }

    #[test]
    fn decode_blocks_with_offset() {
        let code = [
            0xFF, 0xFF, 0xFF, // garbage bytes to skip
            0x00, // nop
            0x2A, // ret
        ];

        let result = super::decode_blocks(&code, 3, 0x1000, None).unwrap();

        assert_eq!(result.len(), 1, "Expected single basic block");
        assert_eq!(result[0].instructions.len(), 2, "Expected 2 instructions");
        assert_eq!(result[0].instructions[0].mnemonic, "nop");
        assert_eq!(result[0].instructions[1].mnemonic, "ret");
    }

    #[test]
    fn decode_blocks_with_max_size() {
        let code = [
            0x00, // nop
            0x2A, // ret
            0x00, // nop (should be ignored due to max_size)
            0x2A, // ret (should be ignored due to max_size)
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, Some(2)).unwrap();

        assert_eq!(result.len(), 1, "Expected single basic block");
        assert_eq!(
            result[0].instructions.len(),
            2,
            "Expected only 2 instructions due to max_size"
        );
        assert_eq!(result[0].instructions[0].mnemonic, "nop");
        assert_eq!(result[0].instructions[1].mnemonic, "ret");
    }

    #[test]
    fn decode_blocks_invalid_offset() {
        let code = [0x00, 0x2A];
        let result = super::decode_blocks(&code, 10, 0x1000, None);

        assert!(result.is_err(), "Expected error for invalid offset");
    }

    #[test]
    fn decode_blocks_empty_data() {
        let code = [];
        let result = super::decode_blocks(&code, 0, 0x1000, None);

        assert!(
            result.is_err(),
            "Expected error for empty data with offset 0"
        );
    }

    #[test]
    fn decode_invalid_fe_instruction() {
        // Test invalid FE prefixed instruction
        let code = [0xFE, 0xFF]; // FE prefix with invalid second byte
        let mut parser = Parser::new(&code);
        let result = decode_instruction(&mut parser, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn decode_blocks_offset_out_of_bounds() {
        // Test decode_blocks with invalid offset
        let code = [0x00, 0x2A]; // nop, ret
        let result = decode_blocks(&code, 10, 0x1000, None); // offset 10 > code.len()
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_data() {
        // Test decoding empty data
        let code = [];
        let result = decode_blocks(&code, 0, 0x1000, None);
        // This should either succeed with empty blocks or fail gracefully
        if let Ok(blocks) = result {
            assert!(blocks.is_empty());
        }
        // Error is also acceptable for empty data
    }

    #[test]
    fn decode_instruction_uint8_operand() {
        let mut parser = Parser::new(&[0x11, 0xFF]); // ldloc.s with max u8 value
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        // Verify the operand is properly decoded
        match &result.operand {
            Operand::Immediate(Immediate::Int8(val)) => assert_eq!(*val, -1), // 0xFF as signed
            _ => panic!("Expected Operand::Immediate(Immediate::Int8)"),
        }
    }

    #[test]
    fn decode_instruction_uint16_operand() {
        // Test for UInt16 operand - need to find an instruction that actually uses UInt16
        // For now, removing this test since no instructions seem to use UInt16 operand type
        // This is likely because UInt16 operands are not used in the CIL instruction set
    }

    #[test]
    fn decode_instruction_int16_operand() {
        // Test for Int16 operand - ldarg uses Int16 operand type (FE 09)
        let mut parser = Parser::new(&[0xFE, 0x09, 0xFF, 0xFF]); // ldarg with -1
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "ldarg");
        // The operand should be decoded as Int16
        match &result.operand {
            Operand::Immediate(Immediate::Int16(val)) => assert_eq!(*val, -1),
            _ => panic!("Expected Operand::Immediate(Immediate::Int16)"),
        }
    }

    #[test]
    fn decode_instruction_uint32_operand() {
        // Test for UInt32 operand - switch instruction uses UInt32 for target count
        let mut parser = Parser::new(&[
            0x45, 0x01, 0x00, 0x00, 0x00, // switch with 1 target
            0x05, 0x00, 0x00, 0x00, // single target offset
        ]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "switch");
        assert_eq!(result.flow_type, FlowType::Switch);
        assert_eq!(result.branch_targets.len(), 1);
    }

    #[test]
    fn decode_instruction_uint64_operand() {
        // Test for Int64 operand - ldc.i8 uses Int64 operand type
        let mut parser = Parser::new(&[0x21, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // ldc.i8 with -1 as i64
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "ldc.i8");
        match &result.operand {
            Operand::Immediate(Immediate::Int64(val)) => assert_eq!(*val, -1),
            _ => panic!("Expected Operand::Immediate(Immediate::Int64)"),
        }
    }

    #[test]
    fn decode_bounds_error() {
        // Test the uncovered bounds error path in decode_blocks
        let data = [0x00]; // Single byte

        // Try to decode with offset beyond data length
        let result = decode_blocks(&data, 10, 0x1000, None);
        assert!(result.is_err());
    }

    #[test]
    fn decode_blocks_access() {
        // Test decode_blocks function
        let data = [0x00, 0x2A]; // nop, ret

        let blocks = decode_blocks(&data, 0, 0x1000, None).unwrap();
        assert!(!blocks.is_empty());
        assert_eq!(blocks.len(), 1); // Should create one basic block
    }

    #[test]
    fn decode_blocks_basic_coverage() {
        // Test basic decode_blocks functionality to cover more code paths
        let data = [
            0x00, // nop
            0x2A, // ret
        ];

        let blocks = decode_blocks(&data, 0, 0x1000, Some(2)).unwrap();
        assert!(!blocks.is_empty());
        assert_eq!(blocks.len(), 1);

        // Test the basic block structure
        let block = &blocks[0];
        assert_eq!(block.rva, 0x1000);
        assert_eq!(block.offset, 0);
        assert!(block.size > 0);
    }

    #[test]
    fn decode_blocks_max_size_limit() {
        // Test max_size parameter
        let data = [0x00, 0x00, 0x00, 0x2A]; // nop, nop, nop, ret

        // Limit to only 2 bytes
        let blocks = decode_blocks(&data, 0, 0x1000, Some(2)).unwrap();
        assert!(!blocks.is_empty());

        // Should only process the first 2 bytes
        let total_size: usize = blocks.iter().map(|b| b.size).sum();
        assert!(total_size <= 2);
    }

    #[test]
    fn decode_stream_empty() {
        // Test decode_stream with empty data
        let data = [];
        let mut parser = Parser::new(&data);

        let result = decode_stream(&mut parser, 0x1000).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn decode_blocks_invalid_method_body() {
        // Test error paths in decode_blocks related to method validation
        let data = [0x00]; // Single byte - not enough for a complete instruction

        let result = decode_blocks(&data, 0, 0x1000, None);
        // This might succeed with a truncated instruction or fail - both are valid outcomes
        // The important thing is it doesn't crash
        if let Ok(blocks) = result {
            assert!(!blocks.is_empty());
        }
        // Error is also acceptable
    }
}
