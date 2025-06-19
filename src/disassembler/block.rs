//! Basic block representation for CIL control flow analysis.
//!
//! This module defines the fundamental building blocks for control flow analysis in .NET assemblies.
//! Basic blocks represent maximal sequences of CIL instructions with single entry and exit points,
//! enabling sophisticated program analysis, optimization, and understanding capabilities.
//!
//! # Architecture
//!
//! The module is organized around the central [`crate::disassembler::block::BasicBlock`] type, which
//! encapsulates instruction sequences and their control flow relationships. Basic blocks form the
//! foundation for constructing control flow graphs that enable dead code elimination, reachability
//! analysis, and other static analysis techniques.
//!
//! # Key Components
//!
//! - [`crate::disassembler::block::BasicBlock`] - Core basic block representation with instruction sequences
//! - [`crate::disassembler::block::BasicBlock::new`] - Factory method for creating new basic blocks
//! - [`crate::disassembler::block::BasicBlock::is_entry`] - Identifies entry points in control flow
//! - [`crate::disassembler::block::BasicBlock::is_exit`] - Identifies termination points in control flow
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::disassembler::BasicBlock;
//!
//! // Create a basic block at method entry point
//! let entry_block = BasicBlock::new(0, 0x2000, 0x1000);
//!
//! // Verify it's an entry block (no predecessors)
//! assert!(entry_block.is_entry());
//! assert!(!entry_block.is_exit());
//!
//! // Basic blocks start with empty instruction sequences
//! assert_eq!(entry_block.instructions.len(), 0);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::disassembler::decoder`] - Provides instructions for basic block construction
//! - [`crate::disassembler::instruction`] - Defines the instruction types contained in blocks
//! - [`crate::disassembler::decode_blocks`] - Function that constructs basic blocks from bytecode

use crate::disassembler::{FlowType, Instruction};

/// Represents a basic block in the control flow graph.
///
/// A basic block is a maximal sequence of instructions with the following properties:
/// - Single entry point (only the first instruction can be a branch target)
/// - Single exit point (only the last instruction can be a branch or fall-through)
/// - No internal control flow changes
///
/// Basic blocks are fundamental units for control flow analysis, optimization,
/// and program understanding. They are constructed by the [`crate::disassembler::decode_blocks`] function
/// during disassembly and used by various analysis algorithms.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::disassembler::BasicBlock;
///
/// // Create a new basic block
/// let block = BasicBlock::new(0, 0x1000, 0x500);
///
/// // Check if it's an entry block (no predecessors)
/// assert!(block.is_entry());
///
/// // Basic blocks start empty
/// assert_eq!(block.instructions.len(), 0);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`BasicBlock`] is [`std::marker::Send`] and [`std::marker::Sync`] as all fields are thread-safe types.
/// Multiple threads can safely read from the same block concurrently, but mutation requires
/// external synchronization.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique identifier for this block within the method
    pub id: usize,
    /// Relative virtual address where this block starts
    pub rva: u64,
    /// File offset where this block starts
    pub offset: usize,
    /// Total size in bytes of all instructions in this block
    pub size: usize,
    /// All instructions contained in this block, in execution order
    pub instructions: Vec<Instruction>,
    /// IDs of blocks that can transfer control to this block
    pub predecessors: Vec<usize>,
    /// IDs of blocks that this block can transfer control to
    pub successors: Vec<usize>,
    /// Indices of exception handlers that cover this block
    pub exceptions: Vec<usize>,
}

impl BasicBlock {
    /// Creates a new basic block with the specified properties.
    ///
    /// The block is initialized with empty instruction, predecessor, successor,
    /// and exception handler vectors. The size is set to 0 and will be updated
    /// as instructions are added.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this block within the method
    /// * `rva` - Relative virtual address where this block starts
    /// * `offset` - File offset where this block starts in bytes
    ///
    /// # Returns
    ///
    /// A new [`BasicBlock`] instance ready for instruction insertion.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::disassembler::BasicBlock;
    ///
    /// // Create a block at the beginning of a method
    /// let entry_block = BasicBlock::new(0, 0x2000, 0x1000);
    /// assert_eq!(entry_block.id, 0);
    /// assert_eq!(entry_block.rva, 0x2000);
    /// assert_eq!(entry_block.offset, 0x1000);
    /// assert_eq!(entry_block.size, 0);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn new(id: usize, rva: u64, offset: usize) -> Self {
        Self {
            id,
            rva,
            offset,
            size: 0,
            instructions: Vec::new(),
            predecessors: Vec::new(),
            successors: Vec::new(),
            exceptions: Vec::new(),
        }
    }

    /// Returns a reference to the first instruction in this block.
    ///
    /// This is useful for analyzing the entry point of a basic block,
    /// checking for branch targets, or examining block-level properties.
    ///
    /// # Returns
    ///
    /// `Some(&`[`crate::disassembler::Instruction`]`)` if the block contains at least one instruction,
    /// `None` if the block is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::disassembler::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // Empty block returns None
    /// assert!(block.instruction_first().is_none());
    ///
    /// // After adding instructions, returns the first one
    /// // block.instructions.push(some_instruction);
    /// // assert!(block.instruction_first().is_some());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn instruction_first(&self) -> Option<&Instruction> {
        self.instructions.first()
    }

    /// Returns a reference to the last instruction in this block.
    ///
    /// This is particularly important for control flow analysis as the
    /// last instruction determines how control exits the block (branch,
    /// fall-through, return, etc.). The [`crate::disassembler::FlowType`] of the last
    /// instruction determines the block's control flow behavior.
    ///
    /// # Returns
    ///
    /// `Some(&`[`crate::disassembler::Instruction`]`)` if the block contains at least one instruction,
    /// `None` if the block is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::disassembler::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // Empty block returns None
    /// assert!(block.instruction_last().is_none());
    ///
    /// // The last instruction determines block exit behavior
    /// // if let Some(last) = block.instruction_last() {
    /// //     println!("Block exits with: {:?}", last.flow_type);
    /// // }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn instruction_last(&self) -> Option<&Instruction> {
        self.instructions.last()
    }

    /// Checks if this block is an entry block (has no predecessors).
    ///
    /// Entry blocks are special because they represent the start of execution
    /// paths. In methods, there's typically one main entry block, plus additional
    /// entry blocks for exception handlers.
    ///
    /// # Returns
    ///
    /// `true` if this block has no predecessors (is an entry point),
    /// `false` if other blocks can transfer control to this block.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::disassembler::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // New blocks start as entry blocks
    /// assert!(block.is_entry());
    ///
    /// // Adding a predecessor makes it non-entry
    /// block.predecessors.push(1);
    /// assert!(!block.is_entry());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_entry(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// Checks if this block is an exit block (terminates execution).
    ///
    /// Exit blocks end with instructions that don't fall through to
    /// other blocks, such as return statements or throw instructions.
    /// These blocks represent the end of execution paths. The determination
    /// is based on the [`crate::disassembler::FlowType`] of the last instruction.
    ///
    /// # Returns
    ///
    /// `true` if the block's last instruction has [`crate::disassembler::FlowType::Return`] or
    /// [`crate::disassembler::FlowType::Throw`], `false` if the block can transfer control to
    /// other blocks or is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::disassembler::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // Empty blocks are not exit blocks
    /// assert!(!block.is_exit());
    ///
    /// // Blocks ending with return/throw are exit blocks
    /// // (This example assumes you have a return instruction)
    /// // block.instructions.push(return_instruction);
    /// // assert!(block.is_exit());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_exit(&self) -> bool {
        if let Some(last_instr) = self.instruction_last() {
            matches!(last_instr.flow_type, FlowType::Return | FlowType::Throw)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disassembler::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior};

    fn create_sample_instruction(flow_type: FlowType) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode: 0x00, // nop
            prefix: 0,
            mnemonic: "nop",
            category: InstructionCategory::Misc,
            flow_type,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: Vec::new(),
        }
    }

    #[test]
    fn test_basic_block_new() {
        let block = BasicBlock::new(42, 0x2000, 0x1500);

        assert_eq!(block.id, 42);
        assert_eq!(block.rva, 0x2000);
        assert_eq!(block.offset, 0x1500);
        assert_eq!(block.size, 0);
        assert!(block.instructions.is_empty());
        assert!(block.predecessors.is_empty());
        assert!(block.successors.is_empty());
        assert!(block.exceptions.is_empty());
    }

    #[test]
    fn test_basic_block_new_zero_values() {
        let block = BasicBlock::new(0, 0, 0);

        assert_eq!(block.id, 0);
        assert_eq!(block.rva, 0);
        assert_eq!(block.offset, 0);
        assert_eq!(block.size, 0);
    }

    #[test]
    fn test_basic_block_new_max_values() {
        let block = BasicBlock::new(usize::MAX, u64::MAX, usize::MAX);

        assert_eq!(block.id, usize::MAX);
        assert_eq!(block.rva, u64::MAX);
        assert_eq!(block.offset, usize::MAX);
    }

    #[test]
    fn test_instruction_first_empty_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(block.instruction_first().is_none());
    }

    #[test]
    fn test_instruction_first_single_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let instr = create_sample_instruction(FlowType::Sequential);
        block.instructions.push(instr);

        let first = block.instruction_first().unwrap();
        assert_eq!(first.flow_type, FlowType::Sequential);
    }

    #[test]
    fn test_instruction_first_multiple_instructions() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let first_instr = create_sample_instruction(FlowType::Sequential);
        let second_instr = create_sample_instruction(FlowType::ConditionalBranch);

        block.instructions.push(first_instr);
        block.instructions.push(second_instr);

        let first = block.instruction_first().unwrap();
        assert_eq!(first.flow_type, FlowType::Sequential);
    }

    #[test]
    fn test_instruction_last_empty_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(block.instruction_last().is_none());
    }

    #[test]
    fn test_instruction_last_single_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let instr = create_sample_instruction(FlowType::Return);
        block.instructions.push(instr);

        let last = block.instruction_last().unwrap();
        assert_eq!(last.flow_type, FlowType::Return);
    }

    #[test]
    fn test_instruction_last_multiple_instructions() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let first_instr = create_sample_instruction(FlowType::Sequential);
        let last_instr = create_sample_instruction(FlowType::ConditionalBranch);

        block.instructions.push(first_instr);
        block.instructions.push(last_instr);

        let last = block.instruction_last().unwrap();
        assert_eq!(last.flow_type, FlowType::ConditionalBranch);
    }

    #[test]
    fn test_is_entry_new_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(block.is_entry());
    }

    #[test]
    fn test_is_entry_with_predecessors() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block.predecessors.push(1);
        assert!(!block.is_entry());
    }

    #[test]
    fn test_is_entry_multiple_predecessors() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block.predecessors.push(1);
        block.predecessors.push(2);
        block.predecessors.push(3);
        assert!(!block.is_entry());
    }

    #[test]
    fn test_is_entry_after_removing_predecessors() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block.predecessors.push(1);
        assert!(!block.is_entry());

        block.predecessors.clear();
        assert!(block.is_entry());
    }

    #[test]
    fn test_is_exit_empty_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(!block.is_exit());
    }

    #[test]
    fn test_is_exit_return_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let return_instr = create_sample_instruction(FlowType::Return);
        block.instructions.push(return_instr);

        assert!(block.is_exit());
    }

    #[test]
    fn test_is_exit_throw_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let throw_instr = create_sample_instruction(FlowType::Throw);
        block.instructions.push(throw_instr);

        assert!(block.is_exit());
    }

    #[test]
    fn test_is_exit_non_terminating_instructions() {
        let flow_types = [
            FlowType::Sequential,
            FlowType::ConditionalBranch,
            FlowType::UnconditionalBranch,
            FlowType::Call,
        ];

        for flow_type in &flow_types {
            let mut block = BasicBlock::new(0, 0x1000, 0x500);
            let instr = create_sample_instruction(*flow_type);
            block.instructions.push(instr);

            assert!(
                !block.is_exit(),
                "Block with {:?} should not be exit",
                flow_type
            );
        }
    }

    #[test]
    fn test_is_exit_multiple_instructions_last_return() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));
        block
            .instructions
            .push(create_sample_instruction(FlowType::Call));
        block
            .instructions
            .push(create_sample_instruction(FlowType::Return));

        assert!(block.is_exit());
    }

    #[test]
    fn test_is_exit_multiple_instructions_last_non_terminating() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block
            .instructions
            .push(create_sample_instruction(FlowType::Return));
        block
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));

        assert!(!block.is_exit());
    }

    #[test]
    fn test_basic_block_debug_format() {
        let block = BasicBlock::new(5, 0x3000, 0x2000);
        let debug_str = format!("{:?}", block);

        assert!(debug_str.contains("BasicBlock"));
        assert!(debug_str.contains("id: 5"));
        assert!(debug_str.contains("rva: 12288")); // 0x3000 in decimal
        assert!(debug_str.contains("offset: 8192")); // 0x2000 in decimal
    }

    #[test]
    fn test_basic_block_clone() {
        let mut original = BasicBlock::new(1, 0x1000, 0x500);
        original.size = 42;
        original
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));
        original.predecessors.push(2);
        original.successors.push(3);
        original.exceptions.push(4);

        let cloned = original.clone();

        assert_eq!(cloned.id, original.id);
        assert_eq!(cloned.rva, original.rva);
        assert_eq!(cloned.offset, original.offset);
        assert_eq!(cloned.size, original.size);
        assert_eq!(cloned.instructions.len(), original.instructions.len());
        assert_eq!(cloned.predecessors, original.predecessors);
        assert_eq!(cloned.successors, original.successors);
        assert_eq!(cloned.exceptions, original.exceptions);
    }

    #[test]
    fn test_complex_control_flow_scenario() {
        // Test a more complex scenario with multiple blocks
        let mut entry_block = BasicBlock::new(0, 0x1000, 0x500);
        let mut branch_block = BasicBlock::new(1, 0x1010, 0x510);
        let mut exit_block = BasicBlock::new(2, 0x1020, 0x520);

        // Set up control flow relationships
        entry_block.successors = vec![1, 2];
        branch_block.predecessors = vec![0];
        branch_block.successors = vec![2];
        exit_block.predecessors = vec![0, 1];

        // Add instructions
        entry_block
            .instructions
            .push(create_sample_instruction(FlowType::ConditionalBranch));
        branch_block
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));
        exit_block
            .instructions
            .push(create_sample_instruction(FlowType::Return));

        // Verify properties
        assert!(entry_block.is_entry());
        assert!(!entry_block.is_exit());

        assert!(!branch_block.is_entry());
        assert!(!branch_block.is_exit());

        assert!(!exit_block.is_entry());
        assert!(exit_block.is_exit());
    }

    #[test]
    fn test_exception_handling_blocks() {
        let mut try_block = BasicBlock::new(0, 0x1000, 0x500);
        let mut catch_block = BasicBlock::new(1, 0x1010, 0x510);

        // Set up exception handling
        try_block.exceptions = vec![0, 1];
        catch_block.exceptions = vec![0];

        // Both blocks can still be entry blocks despite exception handling
        assert!(try_block.is_entry());
        assert!(catch_block.is_entry());

        // Exception information is preserved
        assert_eq!(try_block.exceptions.len(), 2);
        assert_eq!(catch_block.exceptions.len(), 1);
    }

    #[test]
    fn test_block_size_and_offset_boundaries() {
        let mut block = BasicBlock::new(0, u64::MAX, usize::MAX);
        block.size = usize::MAX;

        assert_eq!(block.rva, u64::MAX);
        assert_eq!(block.offset, usize::MAX);
        assert_eq!(block.size, usize::MAX);
    }

    #[test]
    fn test_empty_vectors_behavior() {
        let block = BasicBlock::new(0, 0x1000, 0x500);

        // Test that empty vectors behave correctly
        assert!(block.instructions.is_empty());
        assert!(block.predecessors.is_empty());
        assert!(block.successors.is_empty());
        assert!(block.exceptions.is_empty());

        // Test capacity (should be 0 for new empty vectors)
        assert_eq!(block.instructions.capacity(), 0);
        assert_eq!(block.predecessors.capacity(), 0);
        assert_eq!(block.successors.capacity(), 0);
        assert_eq!(block.exceptions.capacity(), 0);
    }
}
