//! Exception handler representation in SSA form.
//!
//! This module provides the [`SsaExceptionHandler`] type which preserves exception handler
//! information from the original method body through SSA transformations, enabling accurate
//! exception handler emission during code generation.
//!
//! # Exception Handler Preservation
//!
//! When converting CIL to SSA form, exception handlers need special treatment:
//!
//! 1. **Original offsets**: The original IL byte offsets for try/handler regions are preserved
//! 2. **Block mapping**: During SSA construction, we map these offsets to SSA block IDs
//! 3. **Offset remapping**: During code generation, we use block offsets to compute new IL offsets
//!
//! This ensures exception handlers remain valid even when SSA optimizations change instruction
//! sizes or reorder blocks.

use crate::metadata::{
    method::{ExceptionHandler, ExceptionHandlerFlags},
    token::Token,
};

/// Exception handler information preserved in SSA form.
///
/// This structure preserves the original exception handler data from the method body
/// so it can be accurately emitted during code generation. The offsets are preserved
/// as-is from the original method body, and are remapped during code generation
/// based on the new block layout.
///
/// Additionally, block indices can be set to enable offset remapping when the
/// code is regenerated with different instruction sizes.
#[derive(Debug, Clone)]
pub struct SsaExceptionHandler {
    /// Exception handler type flags (EXCEPTION, FILTER, FINALLY, or FAULT).
    pub flags: ExceptionHandlerFlags,

    /// Original byte offset of the protected try block start.
    pub try_offset: u32,

    /// Length of the protected try block in bytes.
    pub try_length: u32,

    /// Original byte offset of the exception handler code start.
    pub handler_offset: u32,

    /// Length of the exception handler code in bytes.
    pub handler_length: u32,

    /// For EXCEPTION handlers: the class token for the caught exception type.
    /// For FILTER handlers: the offset of the filter expression.
    pub class_token_or_filter: u32,

    /// Block ID where the try region starts (set during SSA construction).
    pub try_start_block: Option<usize>,

    /// Block ID where the try region ends (exclusive, set during SSA construction).
    pub try_end_block: Option<usize>,

    /// Block ID where the handler region starts (set during SSA construction).
    pub handler_start_block: Option<usize>,

    /// Block ID where the handler region ends (exclusive, set during SSA construction).
    pub handler_end_block: Option<usize>,

    /// Block ID where the filter expression starts (for FILTER handlers).
    pub filter_start_block: Option<usize>,
}

impl SsaExceptionHandler {
    /// Creates a new SSA exception handler from the original exception handler.
    #[must_use]
    pub fn from_exception_handler(handler: &ExceptionHandler) -> Self {
        // For EXCEPTION handlers, get the class token from filter_offset (which stores it)
        // For FILTER handlers, this is the actual filter offset
        let class_token_or_filter = if handler.flags == ExceptionHandlerFlags::EXCEPTION {
            // Try to get token from handler type, otherwise use filter_offset
            handler
                .handler
                .as_ref()
                .map_or(handler.filter_offset, |t| t.token.value())
        } else {
            handler.filter_offset
        };

        Self {
            flags: handler.flags,
            try_offset: handler.try_offset,
            try_length: handler.try_length,
            handler_offset: handler.handler_offset,
            handler_length: handler.handler_length,
            class_token_or_filter,
            try_start_block: None,
            try_end_block: None,
            handler_start_block: None,
            handler_end_block: None,
            filter_start_block: None,
        }
    }

    /// Returns the class token for EXCEPTION handlers.
    #[must_use]
    pub fn class_token(&self) -> Option<Token> {
        if self.flags == ExceptionHandlerFlags::EXCEPTION {
            Some(Token::new(self.class_token_or_filter))
        } else {
            None
        }
    }

    /// Returns the filter offset for FILTER handlers.
    #[must_use]
    pub fn filter_offset(&self) -> Option<u32> {
        if self.flags == ExceptionHandlerFlags::FILTER {
            Some(self.class_token_or_filter)
        } else {
            None
        }
    }

    /// Checks if block indices have been set for offset remapping.
    #[must_use]
    pub fn has_block_mapping(&self) -> bool {
        self.try_start_block.is_some() && self.handler_start_block.is_some()
    }

    /// Remaps block indices using the provided block remapping.
    ///
    /// This method updates all block index fields (`try_start_block`, `try_end_block`,
    /// `handler_start_block`, `handler_end_block`, `filter_start_block`) to reflect
    /// block renumbering that occurs during SSA canonicalization.
    ///
    /// # Arguments
    ///
    /// * `block_remap` - A slice where `block_remap[old_idx]` contains:
    ///   - `Some(new_idx)` if the block at `old_idx` was kept and is now at `new_idx`
    ///   - `None` if the block at `old_idx` was removed
    ///
    /// # Behavior
    ///
    /// For each block index field:
    /// - If the field is `None`, it remains `None`
    /// - If the field contains an index that maps to `Some(new_idx)`, it's updated to `new_idx`
    /// - If the field contains an index that maps to `None` (block removed), the field becomes `None`
    /// - If the index is out of bounds in `block_remap`, the field becomes `None`
    ///
    /// # Why This Is Necessary
    ///
    /// During SSA canonicalization, empty blocks may be removed and remaining blocks
    /// are renumbered to maintain contiguous indices. Without remapping, exception
    /// handler block indices would become stale, causing code generation to:
    /// 1. Fail to find block offsets (falling back to original IL offsets)
    /// 2. Produce incorrect exception handler regions
    /// 3. Generate invalid IL that crashes at runtime
    ///
    /// # Example
    ///
    /// ```text
    /// // Before canonicalization: blocks [0, 1, 2, 3, 4]
    /// // Block 1 is empty and removed
    /// // After canonicalization: blocks [0, 2, 3, 4] → renumbered to [0, 1, 2, 3]
    ///
    /// // block_remap = [Some(0), None, Some(1), Some(2), Some(3)]
    ///
    /// // If handler_start_block was Some(3), it becomes Some(2)
    /// // If try_start_block was Some(1), it becomes None (block removed)
    /// ```
    pub fn remap_block_indices(&mut self, block_remap: &[Option<usize>]) {
        self.try_start_block = self
            .try_start_block
            .and_then(|idx| block_remap.get(idx).copied().flatten());

        self.try_end_block = self
            .try_end_block
            .and_then(|idx| block_remap.get(idx).copied().flatten());

        self.handler_start_block = self
            .handler_start_block
            .and_then(|idx| block_remap.get(idx).copied().flatten());

        self.handler_end_block = self
            .handler_end_block
            .and_then(|idx| block_remap.get(idx).copied().flatten());

        self.filter_start_block = self
            .filter_start_block
            .and_then(|idx| block_remap.get(idx).copied().flatten());
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::method::ExceptionHandlerFlags;

    use super::*;

    #[test]
    fn test_remap_block_indices_basic() {
        let mut handler = SsaExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            class_token_or_filter: 0x01000001,
            try_start_block: Some(0),
            try_end_block: Some(2),
            handler_start_block: Some(3),
            handler_end_block: Some(4),
            filter_start_block: None,
        };

        // Simulate block compaction: blocks 0, 2, 3, 4 kept; block 1 removed
        // Old: [0, 1, 2, 3, 4] -> New: [0, -, 1, 2, 3]
        let block_remap = vec![Some(0), None, Some(1), Some(2), Some(3)];

        handler.remap_block_indices(&block_remap);

        assert_eq!(handler.try_start_block, Some(0)); // 0 -> 0
        assert_eq!(handler.try_end_block, Some(1)); // 2 -> 1
        assert_eq!(handler.handler_start_block, Some(2)); // 3 -> 2
        assert_eq!(handler.handler_end_block, Some(3)); // 4 -> 3
    }

    #[test]
    fn test_remap_block_indices_removed_block() {
        let mut handler = SsaExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            class_token_or_filter: 0x01000001,
            try_start_block: Some(1), // This block will be removed
            try_end_block: Some(2),
            handler_start_block: Some(3),
            handler_end_block: None,
            filter_start_block: None,
        };

        // Block 1 is removed
        let block_remap = vec![Some(0), None, Some(1), Some(2)];

        handler.remap_block_indices(&block_remap);

        assert_eq!(handler.try_start_block, None); // Block was removed
        assert_eq!(handler.try_end_block, Some(1)); // 2 -> 1
        assert_eq!(handler.handler_start_block, Some(2)); // 3 -> 2
    }

    #[test]
    fn test_remap_block_indices_filter_handler() {
        let mut handler = SsaExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_offset: 0,
            try_length: 10,
            handler_offset: 15,
            handler_length: 5,
            class_token_or_filter: 10, // Filter offset
            try_start_block: Some(0),
            try_end_block: Some(1),
            handler_start_block: Some(3),
            handler_end_block: Some(4),
            filter_start_block: Some(2), // Filter block
        };

        // All blocks shift by -1 except block 0
        let block_remap = vec![Some(0), Some(1), Some(2), Some(3), Some(4)];

        handler.remap_block_indices(&block_remap);

        assert_eq!(handler.try_start_block, Some(0));
        assert_eq!(handler.filter_start_block, Some(2));
        assert_eq!(handler.handler_start_block, Some(3));
    }
}
