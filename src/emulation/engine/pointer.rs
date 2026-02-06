//! Instruction pointer for tracking execution position.
//!
//! The [`InstructionPointer`] tracks the current position within a method's
//! bytecode during emulation, supporting sequential advancement and branching.

use std::fmt;

use crate::metadata::token::Token;

/// Tracks the current execution position during emulation.
///
/// The instruction pointer maintains the current method token and the
/// byte offset within that method's IL code. It supports sequential
/// advancement and branching to arbitrary offsets.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::InstructionPointer;
/// use dotscope::metadata::token::Token;
///
/// // Create pointer at start of method
/// let mut ip = InstructionPointer::new(Token::new(0x06000001));
/// assert_eq!(ip.offset(), 0);
///
/// // Advance past a 5-byte instruction
/// ip.advance(5);
/// assert_eq!(ip.offset(), 5);
///
/// // Branch to new location
/// ip.branch_to(100);
/// assert_eq!(ip.offset(), 100);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstructionPointer {
    /// The method containing the current instruction.
    method: Token,

    /// Byte offset within the method's IL code.
    offset: u32,

    /// Size of the current instruction (used for fall-through calculation).
    current_size: u32,
}

impl InstructionPointer {
    /// Creates a new instruction pointer at the start of a method.
    #[must_use]
    pub fn new(method: Token) -> Self {
        InstructionPointer {
            method,
            offset: 0,
            current_size: 0,
        }
    }

    /// Creates an instruction pointer at a specific offset.
    #[must_use]
    pub fn at_offset(method: Token, offset: u32) -> Self {
        InstructionPointer {
            method,
            offset,
            current_size: 0,
        }
    }

    /// Returns the current method token.
    #[must_use]
    pub fn method(&self) -> Token {
        self.method
    }

    /// Returns the current byte offset within the method.
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Sets the size of the current instruction.
    ///
    /// This is used to calculate the fall-through address for sequential execution.
    pub fn set_current_size(&mut self, size: u32) {
        self.current_size = size;
    }

    /// Returns the size of the current instruction.
    #[must_use]
    pub fn current_size(&self) -> u32 {
        self.current_size
    }

    /// Returns the offset of the next instruction (fall-through address).
    #[must_use]
    pub fn next_offset(&self) -> u32 {
        self.offset + self.current_size
    }

    /// Advances to the next instruction (sequential execution).
    pub fn advance(&mut self, instruction_size: u32) {
        self.offset += instruction_size;
        self.current_size = 0;
    }

    /// Advances using the stored current instruction size.
    pub fn advance_current(&mut self) {
        self.offset += self.current_size;
        self.current_size = 0;
    }

    /// Branches to an absolute offset within the same method.
    pub fn branch_to(&mut self, target_offset: u32) {
        self.offset = target_offset;
        self.current_size = 0;
    }

    /// Branches to a relative offset from the current position.
    ///
    /// The offset is relative to the end of the current instruction.
    #[allow(clippy::cast_sign_loss)] // Intentional: we handle negative offsets separately
    pub fn branch_relative(&mut self, relative_offset: i32) {
        let base = self.next_offset();
        if relative_offset >= 0 {
            self.offset = base.wrapping_add(relative_offset as u32);
        } else {
            self.offset = base.wrapping_sub(relative_offset.unsigned_abs());
        }
        self.current_size = 0;
    }

    /// Switches to a different method (for call operations).
    ///
    /// Returns the current state so it can be restored on return.
    #[must_use]
    pub fn enter_method(&mut self, new_method: Token) -> InstructionPointer {
        let saved = *self;
        self.method = new_method;
        self.offset = 0;
        self.current_size = 0;
        saved
    }

    /// Restores the instruction pointer from a saved state.
    pub fn restore(&mut self, saved: InstructionPointer) {
        *self = saved;
    }

    /// Checks if this pointer is at the start of a method.
    #[must_use]
    pub fn is_at_start(&self) -> bool {
        self.offset == 0
    }
}

impl fmt::Debug for InstructionPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IP {{ method: 0x{:08X}, offset: 0x{:04X} }}",
            self.method.value(),
            self.offset
        )
    }
}

impl fmt::Display for InstructionPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}:0x{:04X}", self.method.value(), self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_pointer_creation() {
        let method = Token::new(0x06000001);
        let ip = InstructionPointer::new(method);

        assert_eq!(ip.method().value(), 0x06000001);
        assert_eq!(ip.offset(), 0);
        assert!(ip.is_at_start());
    }

    #[test]
    fn test_instruction_pointer_at_offset() {
        let method = Token::new(0x06000001);
        let ip = InstructionPointer::at_offset(method, 100);

        assert_eq!(ip.offset(), 100);
        assert!(!ip.is_at_start());
    }

    #[test]
    fn test_advance() {
        let method = Token::new(0x06000001);
        let mut ip = InstructionPointer::new(method);

        ip.advance(5);
        assert_eq!(ip.offset(), 5);

        ip.advance(3);
        assert_eq!(ip.offset(), 8);
    }

    #[test]
    fn test_advance_current() {
        let method = Token::new(0x06000001);
        let mut ip = InstructionPointer::new(method);

        ip.set_current_size(5);
        assert_eq!(ip.next_offset(), 5);

        ip.advance_current();
        assert_eq!(ip.offset(), 5);
        assert_eq!(ip.current_size(), 0);
    }

    #[test]
    fn test_branch_to() {
        let method = Token::new(0x06000001);
        let mut ip = InstructionPointer::new(method);

        ip.advance(10);
        ip.branch_to(50);
        assert_eq!(ip.offset(), 50);
    }

    #[test]
    fn test_branch_relative_forward() {
        let method = Token::new(0x06000001);
        let mut ip = InstructionPointer::at_offset(method, 10);
        ip.set_current_size(2);

        // Branch forward 10 bytes from end of instruction (at 12)
        ip.branch_relative(10);
        assert_eq!(ip.offset(), 22);
    }

    #[test]
    fn test_branch_relative_backward() {
        let method = Token::new(0x06000001);
        let mut ip = InstructionPointer::at_offset(method, 50);
        ip.set_current_size(2);

        // Branch backward 10 bytes from end of instruction (at 52)
        ip.branch_relative(-10);
        assert_eq!(ip.offset(), 42);
    }

    #[test]
    fn test_enter_method() {
        let method1 = Token::new(0x06000001);
        let method2 = Token::new(0x06000002);
        let mut ip = InstructionPointer::at_offset(method1, 25);

        let saved = ip.enter_method(method2);

        assert_eq!(ip.method().value(), 0x06000002);
        assert_eq!(ip.offset(), 0);
        assert_eq!(saved.method().value(), 0x06000001);
        assert_eq!(saved.offset(), 25);
    }

    #[test]
    fn test_restore() {
        let method1 = Token::new(0x06000001);
        let method2 = Token::new(0x06000002);
        let mut ip = InstructionPointer::at_offset(method1, 25);

        let saved = ip.enter_method(method2);
        ip.advance(10);
        ip.restore(saved);

        assert_eq!(ip.method().value(), 0x06000001);
        assert_eq!(ip.offset(), 25);
    }

    #[test]
    fn test_debug_display() {
        let method = Token::new(0x06000001);
        let ip = InstructionPointer::at_offset(method, 0x100);

        let debug = format!("{ip:?}");
        assert!(debug.contains("0x06000001"));
        assert!(debug.contains("0x0100"));

        let display = format!("{ip}");
        assert!(display.contains("0x06000001"));
        assert!(display.contains("0x0100"));
    }

    #[test]
    fn test_equality() {
        let method = Token::new(0x06000001);
        let ip1 = InstructionPointer::at_offset(method, 50);
        let ip2 = InstructionPointer::at_offset(method, 50);
        let ip3 = InstructionPointer::at_offset(method, 100);

        assert_eq!(ip1, ip2);
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_copy() {
        let method = Token::new(0x06000001);
        let ip1 = InstructionPointer::at_offset(method, 50);
        let ip2 = ip1; // Copy

        assert_eq!(ip1, ip2);
    }
}
