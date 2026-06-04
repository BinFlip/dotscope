//! Re-export shim — generic SSA exception handlers live in `analyssa::ir::exception`.
//!
//! CIL-specific construction (`from_exception_handler`) and the
//! `class_token` accessor are provided here, since they reference dotscope
//! metadata types that analyssa doesn't see.

use analyssa::ir::exception::SsaExceptionHandler as AnalyssaSsaExceptionHandler;

use crate::{
    analysis::ssa::target::CilTarget,
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags},
        token::Token,
    },
};

/// CIL-defaulted alias of `analyssa::ir::exception::SsaExceptionHandler`.
pub type SsaExceptionHandler<T = CilTarget> = AnalyssaSsaExceptionHandler<T>;

/// Creates a new SSA exception handler from the original CIL exception handler.
///
/// CIL-specific factory; callers historically used
/// `SsaExceptionHandler::from_exception_handler(...)` (an inherent method on
/// the CIL impl). After the analyssa extraction it's a free function because
/// orphan rules forbid inherent impls on foreign types.
#[must_use]
pub fn from_exception_handler(handler: &ExceptionHandler) -> SsaExceptionHandler {
    let class_token_or_filter = if handler.flags == ExceptionHandlerFlags::EXCEPTION {
        handler
            .handler
            .as_ref()
            .map_or(handler.filter_offset, |t| t.token.value())
    } else {
        handler.filter_offset
    };

    SsaExceptionHandler {
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

/// CIL-specific extension methods on `SsaExceptionHandler<CilTarget>`.
pub trait SsaExceptionHandlerCilExt {
    /// Returns the class token for EXCEPTION handlers.
    fn class_token(&self) -> Option<Token>;
}

impl SsaExceptionHandlerCilExt for AnalyssaSsaExceptionHandler<CilTarget> {
    fn class_token(&self) -> Option<Token> {
        if self.flags == ExceptionHandlerFlags::EXCEPTION {
            Some(Token::new(self.class_token_or_filter))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::method::ExceptionHandlerFlags;

    use super::*;

    // Lock T to CilTarget for tests; they construct `SsaExceptionHandler` with
    // CIL flags directly.
    type SsaExceptionHandler = super::SsaExceptionHandler<CilTarget>;

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

    #[test]
    fn test_remap_end_block_finds_next_surviving() {
        let mut handler = SsaExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            class_token_or_filter: 0x01000001,
            try_start_block: Some(0),
            try_end_block: Some(2), // Block 2 is removed
            handler_start_block: Some(3),
            handler_end_block: Some(5), // Block 5 is removed
            filter_start_block: None,
        };

        // Blocks 2 and 5 removed; next surviving after 2 is block 3 (new idx 1),
        // next surviving after 5 is block 6 (new idx 3)
        let block_remap = vec![Some(0), None, None, Some(1), None, None, Some(3)];

        handler.remap_block_indices(&block_remap);

        assert_eq!(handler.try_start_block, Some(0));
        assert_eq!(handler.try_end_block, Some(1)); // Found next surviving (block 3 -> 1)
        assert_eq!(handler.handler_start_block, Some(1));
        assert_eq!(handler.handler_end_block, Some(3)); // Found next surviving (block 6 -> 3)
    }

    #[test]
    fn test_remap_end_block_none_when_no_surviving() {
        let mut handler = SsaExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            class_token_or_filter: 0x01000001,
            try_start_block: Some(0),
            try_end_block: Some(1),
            handler_start_block: Some(2),
            handler_end_block: Some(3), // Last block, removed, no surviving after it
            filter_start_block: None,
        };

        // Block 3 removed, nothing after it
        let block_remap = vec![Some(0), Some(1), Some(2), None];

        handler.remap_block_indices(&block_remap);

        assert_eq!(handler.handler_end_block, None); // No surviving block after 3
    }
}
