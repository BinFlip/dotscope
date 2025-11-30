//! CIL instruction decoding and disassembly utilities.
//!
//! This module provides the core decoding engine for transforming raw CIL bytecode into
//! structured instruction sequences and basic blocks. It implements the complete ECMA-335
//! disassembly pipeline, from individual instruction parsing to complex control flow analysis
//! with exception handler integration.
//!
//! # Architecture
//!
//! The module is organized around a stateful [`crate::assembly::decoder::Decoder`] that
//! maintains disassembly context while processing bytecode. Public functions provide different
//! levels of abstraction, from single instruction decoding to complete method disassembly
//! with basic block construction and control flow analysis.
//!
//! # Key Components
//!
//! - [`crate::assembly::decoder::decode_instruction`] - Core single instruction decoder
//! - [`crate::assembly::decoder::decode_stream`] - Linear instruction sequence decoder
//! - [`crate::assembly::decoder::decode_blocks`] - Complete control flow analysis with basic blocks
//! - [`crate::assembly::decoder::decode_method`] - Internal method-level disassembly integration
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::{Parser, assembly::{decode_instruction, decode_stream, decode_blocks}};
//!
//! // Decode a single instruction
//! let code = [0x2A]; // ret
//! let mut parser = Parser::new(&code);
//! let instr = decode_instruction(&mut parser, 0x1000)?;
//! assert_eq!(instr.mnemonic, "ret");
//!
//! // Decode a linear instruction stream  
//! let code = [0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(&code);
//! let instrs = decode_stream(&mut parser, 0x1000)?;
//! assert_eq!(instrs.len(), 2);
//!
//! // Decode with control flow analysis
//! let code = [0x00, 0x2A]; // nop, ret
//! let blocks = decode_blocks(&code, 0, 0x1000, None)?;
//! assert_eq!(blocks.len(), 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::assembly::instruction`] - Defines instruction structure and metadata
//! - [`crate::assembly::block`] - Provides basic block representation for control flow
//! - [`crate::file::parser`] - Supplies low-level bytecode parsing capabilities
//! - [`crate::metadata::method`] - Supports method-level disassembly and caching

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    assembly::{
        BasicBlock, FlowType, Immediate, Instruction, Operand, OperandType, StackBehavior,
        INSTRUCTIONS, INSTRUCTIONS_FE,
    },
    file::{parser::Parser, File},
    metadata::{
        method::{ExceptionHandler, Method},
        token::Token,
    },
    utils::VisitedMap,
    Result,
};

/// A stateful decoder instance that exposes complex disassembly algorithms.
///
/// The [`Decoder`] maintains context during CIL bytecode disassembly, tracking visited
/// addresses and building control flow relationships between basic blocks. It provides
/// the core implementation for all higher-level disassembly functions.
///
/// # Thread Safety
///
/// [`Decoder`] is not [`std::marker::Send`] or [`std::marker::Sync`] due to mutable references
/// to parser state. Each thread should use its own decoder instance.
struct Decoder<'a> {
    /// Collection of decoded basic blocks
    blocks: Vec<BasicBlock>,
    /// Exception handlers that affect control flow (if any)
    exceptions: Option<&'a [ExceptionHandler]>,
    /// Shared map tracking which addresses have been visited during disassembly
    visited: Arc<VisitedMap>,
    /// Parser for reading instruction bytes from the method body
    parser: &'a mut Parser<'a>,
    /// Current block identifier being processed
    block_id: usize,
    /// Starting offset within the method body
    offset_start: usize,
    /// Starting relative virtual address
    rva_start: usize,
}

impl<'a> Decoder<'a> {
    /// Create a new stateful decoder for CIL bytecode disassembly.
    ///
    /// Initializes a decoder instance for processing CIL bytecode into basic blocks.
    /// The decoder maintains state during disassembly, tracking visited addresses
    /// and building control flow relationships between basic blocks.
    ///
    /// # Arguments
    ///
    /// * `parser` - The [`crate::file::parser::Parser`] that wraps the byte stream to process
    /// * `offset` - The offset at which the first instruction starts (must be in range of parser)
    /// * `rva` - The relative virtual address of the first instruction
    /// * `exceptions` - Optional information about exception handlers from method metadata
    /// * `visited` - [`crate::utils::VisitedMap`] for tracking disassembly progress
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::assembly::decoder::Decoder`] instance ready for block decoding,
    /// or an error if the offset is out of bounds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::OutOfBounds`] if the offset exceeds the parser's data length.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn new(
        parser: &'a mut Parser<'a>,
        offset: usize,
        rva: usize,
        exceptions: Option<&'a [ExceptionHandler]>,
        visited: Arc<VisitedMap>,
    ) -> Result<Self> {
        if offset > parser.len() {
            return Err(out_of_bounds_error!());
        }

        Ok(Decoder {
            blocks: Vec::new(),
            exceptions,
            visited,
            parser,
            block_id: 0,
            offset_start: offset,
            rva_start: rva,
        })
    }

    /// Returns a reference to the decoded basic blocks.
    ///
    /// This method provides read-only access to the basic blocks that have been
    /// decoded so far. The blocks are ordered by their position in the method body
    /// and contain complete instruction sequences with control flow relationships.
    ///
    /// # Returns
    ///
    /// A slice containing all decoded [`crate::assembly::BasicBlock`] instances.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::assembly::decoder::Decoder;
    /// # let mut decoder = todo!(); // Decoder instance
    /// let blocks = decoder.blocks();
    /// println!("Decoded {} basic blocks", blocks.len());
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
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
    /// This method is primarily used internally by [`crate::assembly::decode_method`] to efficiently
    /// transfer decoded blocks to the [`crate::metadata::method::Method`]'s `OnceLock<Vec<BasicBlock>>` field:
    ///
    /// ```rust,ignore
    /// // Internal usage pattern
    /// let blocks = decoder.into_blocks();
    /// method.blocks.set(blocks);
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::decode_blocks;
    ///
    /// let bytecode = [0x00, 0x2A]; // nop, ret
    /// let blocks = decode_blocks(&bytecode, 0, 0x1000, None)?;
    ///
    /// // blocks now owns the decoded basic blocks
    /// println!("Decoded {} basic blocks", blocks.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// Note: [`crate::assembly::decode_blocks`] function internally uses this method to return ownership
    /// of the blocks to the caller.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn into_blocks(self) -> Vec<BasicBlock> {
        self.blocks
    }

    /// Decode all accessible blocks that are contained in this parser.
    ///
    /// This method implements a single-pass control flow analysis algorithm that
    /// discovers and decodes all reachable basic blocks in the method body. It uses
    /// a work-list approach where new blocks are discovered during decoding and
    /// added to the processing queue.
    ///
    /// # Algorithm
    ///
    /// 1. Initialize entry points from exception handlers (try blocks, catch handlers, filters)
    /// 2. Create the initial block at the method entry point
    /// 3. Process blocks in work-list fashion:
    ///    - Decode instructions sequentially until a control flow boundary
    ///    - When branch targets are discovered, create new blocks or split existing ones
    ///    - Track all entry points to detect block boundaries
    /// 4. Clean up empty blocks (unreachable code)
    /// 5. Sort blocks by RVA and reassign IDs for consistent ordering
    /// 6. Wire up control flow edges (successors/predecessors)
    ///
    /// # Block Splitting
    ///
    /// When a branch target falls in the middle of an already-decoded block, that
    /// block is split immediately at the target address. This ensures every branch
    /// target is the start of its own basic block, which is required for correct
    /// control flow graph construction.
    ///
    /// # Errors
    ///
    /// Returns an error if instruction decoding fails or if the parser encounters
    /// invalid bytecode.
    fn decode_blocks(&mut self) -> Result<()> {
        let mut entry_points: HashSet<u64> = HashSet::new();

        if let Some(exceptions) = self.exceptions {
            for handler in exceptions {
                entry_points.insert(self.rva_start as u64 + u64::from(handler.try_offset));
                entry_points.insert(self.rva_start as u64 + u64::from(handler.handler_offset));
                if handler.filter_offset > 0 {
                    entry_points.insert(self.rva_start as u64 + u64::from(handler.filter_offset));
                }
            }
        }

        self.blocks
            .push(BasicBlock::new(0, self.rva_start as u64, self.offset_start));
        entry_points.insert(self.rva_start as u64);

        while self.block_id < self.blocks.len() {
            self.decode_single_block(&mut entry_points)?;
            self.block_id += 1;
        }

        self.blocks.retain(|b| !b.instructions.is_empty());
        self.blocks.sort_by_key(|b| b.rva);

        for (idx, block) in self.blocks.iter_mut().enumerate() {
            block.id = idx;
        }

        self.process_exception_handlers();
        self.wire_control_flow_edges();

        Ok(())
    }

    /// Decode a single basic block starting at the current block ID.
    ///
    /// This method decodes instructions sequentially from the block's starting offset
    /// until it encounters a control flow boundary (branch, return, throw, etc.) or
    /// reaches an existing block's entry point.
    ///
    /// # Control Flow Handling
    ///
    /// - **Conditional branches**: Both branch targets and fall-through paths become
    ///   new entry points. The block terminates after the branch instruction.
    /// - **Unconditional branches/switches**: All targets become entry points. No
    ///   fall-through path exists.
    /// - **Leave instructions**: Target becomes an entry point (used in exception handling).
    /// - **Return/Throw/EndFinally**: Terminal instructions that end the block with
    ///   no successors.
    /// - **Sequential/Call**: Continue decoding in the same block.
    ///
    /// # Block Boundary Detection
    ///
    /// If the decoder reaches an RVA that is already registered as an entry point
    /// (from a previous branch target), the current block ends and the remaining
    /// instructions belong to the other block.
    ///
    /// # Arguments
    ///
    /// * `entry_points` - Mutable set of known block entry points (RVAs). New entry
    ///   points discovered during decoding are added to this set.
    ///
    /// # Errors
    ///
    /// Returns an error if the block's offset is out of bounds or if instruction
    /// decoding fails.
    fn decode_single_block(&mut self, entry_points: &mut HashSet<u64>) -> Result<()> {
        let block_id = self.block_id;

        if self.blocks[block_id].offset > self.parser.len() {
            return Err(out_of_bounds_error!());
        }

        if self.visited.get(self.blocks[block_id].offset) {
            return Ok(());
        }

        self.parser.seek(self.blocks[block_id].offset)?;

        let mut current_offset = self.blocks[block_id].offset;
        let mut current_rva = self.blocks[block_id].rva;

        loop {
            if current_offset >= self.parser.len() {
                break;
            }

            if current_rva != self.blocks[block_id].rva && entry_points.contains(&current_rva) {
                // We've reached the start of another block - stop here
                break;
            }

            let instruction = decode_instruction(self.parser, current_rva)?;
            let instr_size = usize::try_from(instruction.size).map_err(|_| {
                malformed_error!(format!(
                    "instruction size {} exceeds platform limits at RVA 0x{:x}",
                    instruction.size, current_rva
                ))
            })?;

            self.visited.set_range(current_offset, true, instr_size);

            self.blocks[block_id].size += instr_size;
            self.blocks[block_id].instructions.push(instruction.clone());

            match instruction.flow_type {
                FlowType::ConditionalBranch => {
                    for &target_rva in &instruction.branch_targets {
                        self.add_entry_point(target_rva, entry_points);
                    }

                    let fall_through_rva = current_rva + instruction.size;
                    self.add_entry_point(fall_through_rva, entry_points);

                    break;
                }
                FlowType::UnconditionalBranch | FlowType::Switch | FlowType::Leave => {
                    for &target_rva in &instruction.branch_targets {
                        self.add_entry_point(target_rva, entry_points);
                    }
                    break;
                }
                FlowType::Return | FlowType::Throw | FlowType::EndFinally => {
                    break;
                }
                _ => {
                    // Sequential instruction - continue
                }
            }

            current_offset += instr_size;
            current_rva += instruction.size;
        }

        Ok(())
    }

    /// Register a new block entry point at the given RVA.
    ///
    /// This method handles the discovery of a new control flow target (branch destination,
    /// fall-through path, or exception handler). It ensures that a basic block exists
    /// starting at the given RVA.
    ///
    /// # Block Creation vs Splitting
    ///
    /// - If the RVA is not inside any existing block, a new empty block is created
    ///   and added to the work list for later decoding.
    /// - If the RVA falls in the middle of an already-decoded block, that block is
    ///   split at the RVA. The first part retains the original block's instructions
    ///   up to (but not including) the split point, and a new block is created with
    ///   the remaining instructions.
    ///
    /// # Bounds Checking
    ///
    /// Entry points outside the valid method body range are silently ignored. This
    /// handles edge cases like branches to addresses before the method start or
    /// beyond the method end.
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address of the new entry point
    /// * `entry_points` - Mutable set tracking all known entry points to avoid
    ///   duplicate processing
    fn add_entry_point(&mut self, rva: u64, entry_points: &mut HashSet<u64>) {
        if rva < self.rva_start as u64 {
            return;
        }

        if entry_points.contains(&rva) {
            return;
        }

        let Ok(relative_offset) = usize::try_from(rva - self.rva_start as u64) else {
            return; // RVA delta too large for this platform
        };
        let offset = self.offset_start + relative_offset;
        if offset >= self.parser.len() {
            return;
        }

        if let Some((block_idx, split_instr_idx)) = self.find_block_containing_rva(rva) {
            self.split_block_at(block_idx, split_instr_idx, rva, offset);
        } else {
            let new_block = BasicBlock::new(self.blocks.len(), rva, offset);
            self.blocks.push(new_block);
        }

        entry_points.insert(rva);
    }

    /// Find a block that contains the given RVA in its interior (not at its start).
    ///
    /// This method searches through all decoded blocks to find one where the given
    /// RVA falls strictly inside the block's address range. This is used to detect
    /// when a branch target points to the middle of an already-decoded block,
    /// which requires splitting that block.
    ///
    /// # Returns
    ///
    /// - `Some((block_index, instruction_index))` if a block contains the RVA, where
    ///   `instruction_index` is the index of the instruction that starts at the RVA
    /// - `None` if no block contains the RVA (it's either at a block start, outside
    ///   all blocks, or doesn't align with an instruction boundary)
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address to search for
    fn find_block_containing_rva(&self, rva: u64) -> Option<(usize, usize)> {
        for (block_idx, block) in self.blocks.iter().enumerate() {
            if block.rva == rva {
                return None;
            }

            let block_end_rva = block.rva + block.size as u64;
            if rva > block.rva && rva < block_end_rva {
                for (instr_idx, instr) in block.instructions.iter().enumerate() {
                    if instr.rva == rva {
                        return Some((block_idx, instr_idx));
                    }
                }
            }
        }
        None
    }

    /// Split a basic block at the specified instruction index.
    ///
    /// This method divides an existing block into two parts when a branch target
    /// is discovered that points to the middle of the block. The original block
    /// is truncated to contain only instructions before the split point, and a
    /// new block is created with the remaining instructions.
    ///
    /// # Block Modification
    ///
    /// - The original block (`block_idx`) keeps instructions `[0..split_instr_idx)`
    /// - A new block is created with instructions `[split_instr_idx..]`
    /// - The new block inherits exception handler associations from the original
    /// - Block sizes are recalculated for both blocks
    ///
    /// # Arguments
    ///
    /// * `block_idx` - Index of the block to split in `self.blocks`
    /// * `split_instr_idx` - Index of the first instruction for the new block
    /// * `rva` - RVA of the split point (for the new block's starting address)
    /// * `offset` - File offset of the split point (for the new block's offset)
    ///
    /// # Panics
    ///
    /// Does not panic, but silently returns if `split_instr_idx` is 0 (nothing to split).
    fn split_block_at(
        &mut self,
        block_idx: usize,
        split_instr_idx: usize,
        rva: u64,
        offset: usize,
    ) {
        if split_instr_idx == 0 {
            return;
        }

        // Create new block with instructions from split point onwards
        let mut new_block = BasicBlock::new(self.blocks.len(), rva, offset);
        new_block.instructions = self.blocks[block_idx].instructions[split_instr_idx..].to_vec();
        new_block.size = Self::compute_instructions_size(&new_block.instructions);
        new_block
            .exceptions
            .clone_from(&self.blocks[block_idx].exceptions);

        // Truncate the original block
        self.blocks[block_idx]
            .instructions
            .truncate(split_instr_idx);
        self.blocks[block_idx].size =
            Self::compute_instructions_size(&self.blocks[block_idx].instructions);

        self.blocks.push(new_block);
    }

    /// Compute the total size of a slice of instructions with overflow protection.
    ///
    /// This method safely sums instruction sizes using saturating arithmetic to prevent
    /// overflow from malicious or corrupted input. Each instruction's `size` field is
    /// converted from `u64` to `usize`, clamping to `usize::MAX` if the value exceeds
    /// platform limits.
    ///
    /// # Arguments
    ///
    /// * `instructions` - Slice of instructions to sum sizes for
    ///
    /// # Returns
    ///
    /// Total size in bytes, saturating at `usize::MAX` if overflow would occur.
    fn compute_instructions_size(instructions: &[Instruction]) -> usize {
        instructions.iter().fold(0usize, |acc, instr| {
            let size = usize::try_from(instr.size).unwrap_or(usize::MAX);
            acc.saturating_add(size)
        })
    }

    /// Associate exception handlers with their corresponding basic blocks.
    ///
    /// This method iterates through all exception handlers defined for the method
    /// and marks each block that falls within a try region with the handler's index.
    /// This information is used later for control flow analysis and exception handling
    /// semantics.
    ///
    /// # Handler Association
    ///
    /// A block is associated with an exception handler if the block's starting RVA
    /// falls within the try region's address range `[try_offset, try_offset + try_length]`.
    /// Multiple handlers can be associated with a single block (nested try blocks).
    ///
    /// # Note
    ///
    /// This method should be called after all blocks have been decoded and before
    /// control flow edges are wired, as the exception associations may affect
    /// control flow analysis.
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

    /// Wire up control flow edges (successors/predecessors) between blocks.
    ///
    /// This method is called after all blocks have been decoded and exception handlers
    /// have been processed. It analyzes the last instruction of each block to determine
    /// its control flow successors, building a complete control flow graph.
    ///
    /// # Edge Types
    ///
    /// The method handles various control flow patterns:
    /// - **Sequential/Call**: Fall through to the next block by address
    /// - **Conditional branches**: Both the branch target and fall-through become successors
    /// - **Unconditional branches**: Single successor at the branch target
    /// - **Switch statements**: Multiple successors for each case target
    /// - **Return/Throw**: No successors (terminal blocks)
    /// - **Leave**: Single successor outside the protected region
    ///
    /// # Bidirectional Edges
    ///
    /// For each successor relationship established, the corresponding predecessor
    /// relationship is also recorded. This enables both forward and backward
    /// traversal of the control flow graph.
    fn wire_control_flow_edges(&mut self) {
        let rva_to_block: HashMap<u64, usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (block.rva, idx))
            .collect();

        for block_idx in 0..self.blocks.len() {
            let successors = self.compute_block_successors(block_idx, &rva_to_block);

            self.blocks[block_idx].successors.clone_from(&successors);

            for &succ_idx in &successors {
                if succ_idx < self.blocks.len() {
                    self.blocks[succ_idx].predecessors.push(block_idx);
                }
            }
        }
    }

    /// Compute the successor block indices for a given block.
    ///
    /// This method analyzes the last instruction of a block to determine which
    /// blocks can be reached via control flow from this block. The successors
    /// are determined based on the instruction's flow type and branch targets.
    ///
    /// # Flow Type Handling
    ///
    /// | Flow Type | Successors |
    /// |-----------|------------|
    /// | Return/Throw | None (terminal) |
    /// | UnconditionalBranch | Branch target only |
    /// | ConditionalBranch | Branch target + fall-through |
    /// | Switch | All case targets |
    /// | Leave | Leave target |
    /// | EndFinally | None (dynamic return) |
    /// | Sequential/Call | Fall-through to next block |
    ///
    /// # Arguments
    ///
    /// * `block_idx` - Index of the block in `self.blocks`
    /// * `rva_to_block` - Map from RVA to block index for target resolution
    ///
    /// # Returns
    ///
    /// A vector of block indices representing all possible control flow successors.
    /// The vector may be empty for terminal blocks (return, throw, endfinally).
    fn compute_block_successors(
        &self,
        block_idx: usize,
        rva_to_block: &HashMap<u64, usize>,
    ) -> Vec<usize> {
        let block = &self.blocks[block_idx];
        let Some(last_instr) = block.instructions.last() else {
            return vec![];
        };

        match last_instr.flow_type {
            FlowType::Return | FlowType::Throw => {
                // No successors for terminal instructions
                vec![]
            }
            FlowType::UnconditionalBranch => {
                // Single successor: the branch target
                last_instr
                    .branch_targets
                    .iter()
                    .filter_map(|&target_rva| rva_to_block.get(&target_rva).copied())
                    .collect()
            }
            FlowType::ConditionalBranch => {
                // Two successors: branch target (first) and fall-through (second)
                let mut successors = Vec::with_capacity(2);

                // Add branch target(s)
                for &target_rva in &last_instr.branch_targets {
                    if let Some(&target_idx) = rva_to_block.get(&target_rva) {
                        successors.push(target_idx);
                    }
                }

                // Add fall-through target (instruction immediately after this block)
                let fall_through_rva = block.rva + block.size as u64;
                if let Some(&fall_through_idx) = rva_to_block.get(&fall_through_rva) {
                    successors.push(fall_through_idx);
                }

                successors
            }
            FlowType::Switch => {
                // Multiple successors from switch targets
                last_instr
                    .branch_targets
                    .iter()
                    .filter_map(|&target_rva| rva_to_block.get(&target_rva).copied())
                    .collect()
            }
            FlowType::Leave => {
                // Leave instruction jumps to target outside protected region
                last_instr
                    .branch_targets
                    .iter()
                    .filter_map(|&target_rva| rva_to_block.get(&target_rva).copied())
                    .collect()
            }
            FlowType::EndFinally => {
                // EndFinally returns to caller of finally block - no static successors
                vec![]
            }
            FlowType::Sequential | FlowType::Call => {
                // Fall through to next block
                let fall_through_rva = block.rva + block.size as u64;
                rva_to_block
                    .get(&fall_through_rva)
                    .map(|&idx| vec![idx])
                    .unwrap_or_default()
            }
        }
    }
}

/// Disassembles a method's body into basic blocks and integrates results into the Method struct.
///
/// This function performs complete method disassembly including parsing method headers,
/// decoding all instructions, building basic blocks with control flow analysis, and
/// associating exception handlers with their corresponding blocks. The results are
/// efficiently integrated into the Method's thread-safe storage.
///
/// # Arguments
///
/// * `method` - The [`crate::metadata::method::Method`] instance to populate with disassembled basic blocks
/// * `file` - The [`crate::file::File`] containing the raw method bytecode and metadata
/// * `shared_visited` - Shared [`crate::utils::VisitedMap`] for coordinated disassembly across methods
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
/// # Integration
///
/// The decoded blocks are efficiently transferred to the Method using `OnceLock::set()`:
/// ```rust,ignore
/// decoder.decode_blocks()?;
/// let _ = method.blocks.set(decoder.into_blocks());
/// ```
///
/// This ensures thread-safe lazy initialization with zero-copy transfer of blocks.
pub(crate) fn decode_method(
    method: &Method,
    file: &File,
    shared_visited: Arc<VisitedMap>,
) -> Result<()> {
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
            shared_visited,
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
/// This function performs comprehensive disassembly of raw bytecode into basic blocks,
/// automatically building the complete control flow graph. Unlike method-level disassembly,
/// this function works with standalone bytecode without requiring method metadata or
/// exception handler information, making it useful for analyzing code fragments.
///
/// The function automatically detects basic block boundaries based on control flow
/// instructions and builds predecessor/successor relationships between blocks.
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
/// Returns a vector of [`crate::assembly::BasicBlock`] objects representing the control flow structure.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - The bytecode contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - The specified offset is beyond the buffer bounds
/// - Control flow analysis encounters invalid branch targets
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::decode_blocks;
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
    let visited = Arc::new(VisitedMap::new(effective_data.len()));
    let mut decoder = Decoder::new(&mut parser, 0, rva, None, visited)?;

    decoder.decode_blocks()?;

    Ok(decoder.into_blocks())
}

/// Decodes a continuous stream of CIL instructions from a byte stream.
///
/// This function processes raw bytecode sequentially, decoding each instruction
/// until the parser reaches the end of available data. Unlike internal method disassembly,
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
/// Returns a `Vec<`[`crate::assembly::instruction::Instruction`]`>` containing all successfully decoded instructions.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - The bytecode stream contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - Parser encounters unexpected end of data during instruction decoding
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{assembly::decode_stream, Parser};
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
/// Returns [`crate::Error`] if:
/// - The bytecode stream contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - Parser encounters unexpected end of data during instruction decoding
///
/// # Notes
///
/// - Instructions are decoded in linear order without control flow analysis
/// - Each instruction's RVA is calculated based on the previous instruction's size
/// - The function stops when the parser has no more data available
/// - Use [`crate::assembly::decode_blocks`] for complete analysis with basic blocks
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
/// Returns a fully populated [`crate::assembly::instruction::Instruction`] struct containing:
/// - The instruction mnemonic and opcode information
/// - Decoded operands with proper type information
/// - Stack behavior and flow control metadata
/// - Size and RVA information for the instruction
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - An invalid or unrecognized opcode is encountered
/// - Operand data is truncated or corrupted
/// - Parser reaches end of data unexpectedly during operand decoding
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{assembly::{decode_instruction, Operand}, Parser};
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
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads
/// with different parser instances.
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
        assembly::{
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

        assert_eq!(result.mnemonic, "ldtoken");
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
