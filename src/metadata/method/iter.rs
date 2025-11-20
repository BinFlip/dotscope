//! Iterator implementations for method instruction traversal.
//!
//! This module provides efficient iteration over method instructions without copying.
//! The main iterator yields instructions in execution order across all basic blocks,
//! enabling seamless analysis of the complete instruction stream.
//!
//! # Architecture Notes
//!
//! The iterator operates on a slice of basic blocks (`&[BasicBlock]`) rather than
//! a specific container type, providing flexibility and compatibility with both
//! `Vec<BasicBlock>` and other slice-like containers. This design supports the
//! Method struct's `OnceLock<Vec<BasicBlock>>` architecture while remaining generic.
//!
//! # Key Components
//!
//! - [`InstructionIterator`] - Iterator that yields instructions across all basic blocks
//!
//! # Thread Safety
//!
//! The iterator itself is not `Send` or `Sync` as it holds references to the underlying
//! data, but it can be safely created from thread-safe Method instances since it only
//! borrows immutable references to the blocks.
//!
//! # Examples
//!
//! ## Basic Iteration
//!
//! ```rust,ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//! let methods = assembly.methods();
//!
//! for entry in methods.iter().take(5) {
//!     let method = entry.value();
//!     println!("Method: {} has {} instructions",
//!              method.name, method.instruction_count());
//!     
//!     for (i, instruction) in method.instructions().enumerate() {
//!         let operand_str = match &instruction.operand {
//!             dotscope::assembly::Operand::None => String::new(),
//!             _ => format!("{:?}", instruction.operand),
//!         };
//!         println!("  [{}] {} {}", i, instruction.mnemonic, operand_str);
//!         
//!         if i >= 5 { break; } // Limit for readability
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Combined with Block Analysis
//!
//! ```rust,ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//! let methods = assembly.methods();
//!
//! for entry in methods.iter().take(3) {
//!     let method = entry.value();
//!     println!("Method: {} - {} blocks, {} total instructions",
//!              method.name, method.block_count(), method.instruction_count());
//!
//!     // Analyze each block separately
//!     for (block_index, block) in method.blocks() {
//!         println!("  Block {}: {} instructions", block_index, block.instructions.len());
//!     }
//!     
//!     // Then iterate over all instructions linearly
//!     let mut instruction_index = 0;
//!     for instruction in method.instructions() {
//!         if instruction.mnemonic.contains("call") {
//!             println!("    Call instruction at index {}: {}",
//!                     instruction_index, instruction.mnemonic);
//!         }
//!         instruction_index += 1;
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::assembly::BasicBlock;

/// Iterator over all instructions in a method, yielding them in execution order.
///
/// This iterator efficiently traverses all basic blocks in a method and yields
/// their instructions without copying. Instructions are yielded in the order
/// they would be executed (basic block order, then instruction order within blocks).
///
/// The iterator provides accurate size hints and handles empty basic blocks gracefully,
/// making it suitable for both simple iteration and collection operations.
///
/// # Architecture
///
/// The iterator operates on a slice of `BasicBlock`s (`&[BasicBlock]`), making it
/// compatible with the Method's `OnceLock<Vec<BasicBlock>>` storage while remaining
/// generic enough to work with other slice-like containers.
///
/// Internal state tracking:
/// - `current_block`: Index of the current basic block being processed
/// - `current_instruction`: Index within the current basic block's instruction vector
/// - Automatically advances to the next non-empty block when a block is exhausted
///
/// # Thread Safety
///
/// The iterator itself is not `Send` or `Sync` as it holds references to the underlying
/// instruction data. However, it can be safely created from thread-safe Method instances
/// since it only borrows immutable references.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
/// for entry in assembly.methods().iter().take(3) {
///     let method = entry.value();
///     let mut instruction_count = 0;
///     
///     for instruction in method.instructions() {
///         println!("IL_{:04X}: {} {:?}",
///                 instruction.offset, instruction.mnemonic, instruction.operand);
///         instruction_count += 1;
///         
///         if instruction_count >= 10 { break; } // Limit for readability
///     }
///     
///     println!("Method {} has {} total instructions",
///              method.name, method.instruction_count());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Collecting and Analyzing Instructions
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
/// for entry in assembly.methods().iter().take(1) {
///     let method = entry.value();
///     
///     // Use size hint for efficient pre-allocation
///     let (lower_bound, upper_bound) = method.instructions().size_hint();
///     println!("Expected {} to {:?} instructions", lower_bound, upper_bound);
///     
///     // Collect specific instruction types
///     let call_instructions: Vec<_> = method.instructions()
///         .filter(|instr| instr.mnemonic.starts_with("call"))
///         .collect();
///         
///     println!("Found {} call instructions in {}",
///              call_instructions.len(), method.name);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Iterator Combinators
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
/// for entry in assembly.methods().iter().take(5) {
///     let method = entry.value();
///     
///     // Count different instruction types
///     let branch_count = method.instructions()
///         .filter(|instr| instr.mnemonic.contains("br"))
///         .count();
///         
///     let load_count = method.instructions()
///         .filter(|instr| instr.mnemonic.starts_with("ld"))
///         .count();
///         
///     println!("{}: {} branches, {} loads",
///              method.name, branch_count, load_count);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
pub struct InstructionIterator<'a> {
    /// Reference to the basic blocks being iterated
    blocks: &'a [BasicBlock],
    /// Index of the current basic block
    current_block: usize,
    /// Index of the current instruction within the current block
    current_instruction: usize,
}

impl<'a> InstructionIterator<'a> {
    /// Create a new instruction iterator for the given basic blocks.
    ///
    /// The iterator will traverse all basic blocks in order, yielding instructions
    /// from each block sequentially. Empty blocks are handled gracefully and skipped
    /// automatically during iteration.
    ///
    /// This method is typically called internally by [`crate::metadata::method::Method::instructions()`] rather
    /// than being used directly, but it can be useful for testing or when working
    /// with standalone basic block collections.
    ///
    /// # Arguments
    ///
    /// * `blocks` - Reference to the collection of basic blocks to iterate over.
    ///   Can be any slice-like container (`&[BasicBlock]`, `&Vec<BasicBlock>`, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// // This is typically called by method.instructions() internally
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(1) {
    ///     let method = entry.value();
    ///     
    ///     // Direct creation (usually not needed)
    ///     if let Some(blocks) = method.blocks.get() {
    ///         let iter = dotscope::metadata::method::InstructionIterator::new(blocks);
    ///         println!("Created iterator for {} blocks", blocks.len());
    ///         
    ///         for instruction in iter.take(5) {
    ///             println!("  {}", instruction.mnemonic);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new(blocks: &'a [BasicBlock]) -> Self {
        Self {
            blocks,
            current_block: 0,
            current_instruction: 0,
        }
    }
}

impl<'a> Iterator for InstructionIterator<'a> {
    type Item = &'a crate::assembly::Instruction;

    /// Advances the iterator and returns the next instruction.
    ///
    /// This method traverses basic blocks in order, yielding instructions from each
    /// block sequentially. When a block is exhausted, it automatically advances to
    /// the next non-empty block using recursive calls to handle empty blocks gracefully.
    ///
    /// # Returns
    ///
    /// - `Some(&Instruction)` if there are more instructions
    /// - `None` if all instructions have been yielded
    ///
    /// # Implementation Notes
    ///
    /// The method uses recursive calls to skip empty blocks, which is safe because:
    /// - The recursion depth is bounded by the number of consecutive empty blocks
    /// - Empty blocks are relatively rare in typical IL code
    /// - Each recursive call advances the block index, preventing infinite recursion
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_block >= self.blocks.len() {
            return None;
        }

        let block = self.blocks.get(self.current_block)?;

        if self.current_instruction >= block.instructions.len() {
            self.current_block += 1;
            self.current_instruction = 0;
            return self.next(); // Recursive call to handle empty blocks
        }

        let instruction = &block.instructions[self.current_instruction];
        self.current_instruction += 1;
        Some(instruction)
    }

    /// Provides a size hint for the remaining instructions in the iterator.
    ///
    /// This method calculates the exact number of remaining instructions by summing
    /// the instruction counts across all remaining basic blocks, accounting for the
    /// current position within the current block.
    ///
    /// # Returns
    ///
    /// A tuple `(lower_bound, Some(upper_bound))` where both bounds are equal,
    /// providing an exact count of remaining instructions. This enables efficient
    /// pre-allocation when collecting instructions into containers.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(1) {
    ///     let method = entry.value();
    ///     let mut iter = method.instructions();
    ///     
    ///     let (lower, upper) = iter.size_hint();
    ///     println!("Iterator has exactly {} instructions remaining", lower);
    ///     assert_eq!(Some(lower), upper);
    ///     
    ///     // Efficient pre-allocation based on size hint
    ///     let mut instructions = Vec::with_capacity(lower);
    ///     instructions.extend(iter);
    ///     assert_eq!(instructions.len(), lower);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut remaining = 0;
        for i in self.current_block..self.blocks.len() {
            if let Some(block) = self.blocks.get(i) {
                if i == self.current_block {
                    remaining += block
                        .instructions
                        .len()
                        .saturating_sub(self.current_instruction);
                } else {
                    remaining += block.instructions.len();
                }
            }
        }
        (remaining, Some(remaining))
    }
}

/// Implementation of `ExactSizeIterator` trait.
///
/// This implementation is valid because the `size_hint()` method provides exact bounds
/// for the remaining number of instructions. This enables optimizations in standard
/// library collection methods and provides the `len()` method for getting the exact
/// remaining count.
///
/// # Benefits
///
/// - Enables `iter.len()` to get exact remaining instruction count
/// - Allows standard library to optimize collection operations
/// - Provides stronger guarantees for iterator consumers
/// - Compatible with parallel processing libraries that require exact sizes
impl ExactSizeIterator for InstructionIterator<'_> {}
