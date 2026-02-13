//! Step and emulation result types.
//!
//! This module defines the result types returned by the interpreter
//! after executing instructions and completing emulation.

use std::fmt;

use crate::{
    emulation::{engine::stats::LimitExceeded, EmValue},
    metadata::token::Token,
};

/// Result of executing a single instruction.
///
/// This enum represents all possible outcomes after stepping through
/// one CIL instruction, allowing the execution controller to make
/// appropriate decisions about continuing execution.
#[derive(Clone, Debug)]
pub enum StepResult {
    /// Continue execution at the next sequential instruction.
    Continue,

    /// Branch to a specific byte offset within the current method.
    Branch {
        /// Target byte offset.
        target: u64,
    },

    /// Return from the current method.
    Return {
        /// Return value, if any.
        value: Option<EmValue>,
    },

    /// Call another method.
    Call {
        /// Token of the method to call.
        method: Token,
        /// Arguments for the call.
        args: Vec<EmValue>,
        /// Whether this is a virtual call.
        is_virtual: bool,
    },

    /// Construct a new object.
    NewObj {
        /// Token of the constructor to call.
        constructor: Token,
        /// Arguments for the constructor.
        args: Vec<EmValue>,
    },

    /// Create a new array.
    NewArray {
        /// Token of the element type.
        element_type: Token,
        /// Length of the array.
        length: usize,
    },

    /// Load a string from the #US heap.
    LoadString {
        /// User string token.
        token: Token,
    },

    /// Load a static field value.
    LoadStaticField {
        /// Token of the static field.
        field: Token,
    },

    /// Store a value to a static field.
    StoreStaticField {
        /// Token of the static field.
        field: Token,
        /// Value to store.
        value: EmValue,
    },

    /// Throw an exception.
    Throw {
        /// The exception object.
        exception: EmValue,
    },

    /// Leave a protected region (try/catch/finally).
    Leave {
        /// Target offset to leave to.
        target: u64,
    },

    /// End of a finally block.
    EndFinally,

    /// End of a filter block.
    EndFilter {
        /// Filter result value (converted from EmValue).
        value: EmValue,
    },

    /// Rethrow the current exception.
    Rethrow,

    /// Breakpoint instruction encountered.
    Breakpoint,

    /// Tail call prefix was set.
    TailCall {
        /// Token of the method to tail-call.
        method: Token,
        /// Arguments for the call.
        args: Vec<EmValue>,
    },

    /// Copy a value type from one address to another.
    CopyObject {
        /// Token of the type to copy.
        type_token: Token,
    },

    /// Cast an object to a specific type.
    CastClass {
        /// Token of the type to cast to.
        type_token: Token,
    },

    /// Check if an object is an instance of a type.
    IsInst {
        /// Token of the type to check.
        type_token: Token,
    },

    /// Unbox a boxed value type (returns address).
    Unbox {
        /// Token of the value type.
        type_token: Token,
    },

    /// Box a value type.
    Box {
        /// Token of the value type.
        type_token: Token,
    },

    /// Unbox a boxed value type or cast reference type.
    UnboxAny {
        /// Token of the type.
        type_token: Token,
    },

    /// Extract address from typed reference.
    RefAnyVal {
        /// Token of the expected type.
        type_token: Token,
    },

    /// Make a typed reference.
    MkRefAny {
        /// Token of the type.
        type_token: Token,
    },

    /// Load metadata token as runtime handle.
    LoadToken {
        /// The metadata token to load.
        token: Token,
    },

    /// Load a function pointer.
    LoadFunctionPointer {
        /// Token of the method.
        method: Token,
    },

    /// Load a virtual function pointer.
    LoadVirtualFunctionPointer {
        /// Token of the method.
        method: Token,
    },

    /// Indirect call through a function pointer (calli instruction).
    CallIndirect {
        /// StandAloneSig token containing the call site signature.
        signature: Token,
        /// Function pointer from the stack (contains method token).
        function_pointer: EmValue,
    },

    /// Allocate space on the local stack.
    LocalAlloc {
        /// Size to allocate.
        size: EmValue,
    },

    /// Initialize a value type at an address.
    InitObj {
        /// Token of the type.
        type_token: Token,
    },

    /// Copy a block of memory.
    CopyBlock {
        /// Destination address.
        dest: EmValue,
        /// Source address.
        src: EmValue,
        /// Number of bytes to copy.
        size: EmValue,
    },

    /// Initialize a block of memory.
    InitBlock {
        /// Address to initialize.
        addr: EmValue,
        /// Value to fill with.
        value: EmValue,
        /// Number of bytes to initialize.
        size: EmValue,
    },

    /// Get size of a type.
    SizeOf {
        /// Token of the type.
        type_token: Token,
    },

    /// Get type from typed reference.
    RefAnyType,

    /// Get argument list handle (for varargs methods).
    ArgList,
}

impl StepResult {
    /// Returns `true` if this result continues normal sequential execution.
    #[must_use]
    pub fn is_continue(&self) -> bool {
        matches!(self, StepResult::Continue)
    }

    /// Returns `true` if this result represents a method return.
    #[must_use]
    pub fn is_return(&self) -> bool {
        matches!(self, StepResult::Return { .. })
    }

    /// Returns `true` if this result transfers control elsewhere.
    #[must_use]
    pub fn is_control_transfer(&self) -> bool {
        !matches!(self, StepResult::Continue | StepResult::Breakpoint)
    }

    /// Returns the branch target if this is a branch result.
    #[must_use]
    pub fn branch_target(&self) -> Option<u64> {
        match self {
            StepResult::Branch { target } | StepResult::Leave { target } => Some(*target),
            _ => None,
        }
    }
}

impl fmt::Display for StepResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StepResult::Continue => write!(f, "continue"),
            StepResult::Branch { target } => write!(f, "branch to 0x{target:08X}"),
            StepResult::Return { value } => {
                if let Some(v) = value {
                    write!(f, "return {v:?}")
                } else {
                    write!(f, "return void")
                }
            }
            StepResult::Call {
                method,
                args,
                is_virtual,
            } => {
                let call_type = if *is_virtual { "callvirt" } else { "call" };
                write!(
                    f,
                    "{call_type} 0x{:08X} with {} args",
                    method.value(),
                    args.len()
                )
            }
            StepResult::NewObj { constructor, args } => {
                write!(
                    f,
                    "newobj 0x{:08X} with {} args",
                    constructor.value(),
                    args.len()
                )
            }
            StepResult::NewArray {
                element_type,
                length,
            } => {
                write!(f, "newarr 0x{:08X} length {length}", element_type.value())
            }
            StepResult::LoadString { token } => {
                write!(f, "ldstr 0x{:08X}", token.value())
            }
            StepResult::LoadStaticField { field } => {
                write!(f, "ldsfld 0x{:08X}", field.value())
            }
            StepResult::StoreStaticField { field, .. } => {
                write!(f, "stsfld 0x{:08X}", field.value())
            }
            StepResult::Throw { exception } => write!(f, "throw {exception:?}"),
            StepResult::Leave { target } => write!(f, "leave to 0x{target:08X}"),
            StepResult::EndFinally => write!(f, "endfinally"),
            StepResult::EndFilter { value } => write!(f, "endfilter {value:?}"),
            StepResult::Rethrow => write!(f, "rethrow"),
            StepResult::Breakpoint => write!(f, "breakpoint"),
            StepResult::TailCall { method, args } => {
                write!(
                    f,
                    "tail.call 0x{:08X} with {} args",
                    method.value(),
                    args.len()
                )
            }
            StepResult::CopyObject { type_token } => {
                write!(f, "cpobj 0x{:08X}", type_token.value())
            }
            StepResult::CastClass { type_token } => {
                write!(f, "castclass 0x{:08X}", type_token.value())
            }
            StepResult::IsInst { type_token } => {
                write!(f, "isinst 0x{:08X}", type_token.value())
            }
            StepResult::Unbox { type_token } => {
                write!(f, "unbox 0x{:08X}", type_token.value())
            }
            StepResult::Box { type_token } => {
                write!(f, "box 0x{:08X}", type_token.value())
            }
            StepResult::UnboxAny { type_token } => {
                write!(f, "unbox.any 0x{:08X}", type_token.value())
            }
            StepResult::RefAnyVal { type_token } => {
                write!(f, "refanyval 0x{:08X}", type_token.value())
            }
            StepResult::MkRefAny { type_token } => {
                write!(f, "mkrefany 0x{:08X}", type_token.value())
            }
            StepResult::LoadToken { token } => {
                write!(f, "ldtoken 0x{:08X}", token.value())
            }
            StepResult::LoadFunctionPointer { method } => {
                write!(f, "ldftn 0x{:08X}", method.value())
            }
            StepResult::LoadVirtualFunctionPointer { method } => {
                write!(f, "ldvirtftn 0x{:08X}", method.value())
            }
            StepResult::CallIndirect { signature, .. } => {
                write!(f, "calli 0x{:08X}", signature.value())
            }
            StepResult::LocalAlloc { size } => {
                write!(f, "localloc {size:?}")
            }
            StepResult::InitObj { type_token } => {
                write!(f, "initobj 0x{:08X}", type_token.value())
            }
            StepResult::CopyBlock { .. } => write!(f, "cpblk"),
            StepResult::InitBlock { .. } => write!(f, "initblk"),
            StepResult::SizeOf { type_token } => {
                write!(f, "sizeof 0x{:08X}", type_token.value())
            }
            StepResult::RefAnyType => write!(f, "refanytype"),
            StepResult::ArgList => write!(f, "arglist"),
        }
    }
}

/// Final outcome of emulation.
///
/// This represents the terminal state of an emulation session,
/// whether it completed successfully, hit a limit, or encountered an error.
#[derive(Clone, Debug)]
pub enum EmulationOutcome {
    /// Method completed successfully with return value.
    Completed {
        /// Return value from the emulated method.
        return_value: Option<EmValue>,
        /// Number of instructions executed.
        instructions: u64,
    },

    /// An exception was thrown and not caught.
    UnhandledException {
        /// The exception that was thrown.
        exception: EmValue,
        /// Instructions executed before exception.
        instructions: u64,
    },

    /// Execution was halted due to reaching a limit.
    LimitReached {
        /// Which limit was exceeded.
        limit: LimitExceeded,
        /// Partial result if available.
        partial_state: Option<Box<EmValue>>,
    },

    /// Execution requires symbolic reasoning to continue.
    ///
    /// This occurs when the emulator encounters a branch condition
    /// or operation that depends on a symbolic value.
    RequiresSymbolic {
        /// Description of what requires symbolic execution.
        reason: String,
        /// The symbolic value involved.
        value: EmValue,
        /// Instructions executed before stopping.
        instructions: u64,
    },

    /// A breakpoint was hit.
    Breakpoint {
        /// Offset where breakpoint was hit.
        offset: u32,
        /// Instructions executed before breakpoint.
        instructions: u64,
    },

    /// Emulation was stopped by user request.
    Stopped {
        /// Reason for stopping.
        reason: String,
        /// Instructions executed before stopping.
        instructions: u64,
    },
}

impl EmulationOutcome {
    /// Returns `true` if emulation completed successfully.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, EmulationOutcome::Completed { .. })
    }

    /// Returns the return value if emulation completed successfully.
    #[must_use]
    pub fn return_value(&self) -> Option<&EmValue> {
        match self {
            EmulationOutcome::Completed { return_value, .. } => return_value.as_ref(),
            _ => None,
        }
    }

    /// Returns the instruction count.
    #[must_use]
    pub fn instructions_executed(&self) -> u64 {
        match self {
            EmulationOutcome::LimitReached { .. } => 0, // Unknown from limit info
            EmulationOutcome::Completed { instructions, .. }
            | EmulationOutcome::UnhandledException { instructions, .. }
            | EmulationOutcome::RequiresSymbolic { instructions, .. }
            | EmulationOutcome::Breakpoint { instructions, .. }
            | EmulationOutcome::Stopped { instructions, .. } => *instructions,
        }
    }
}

impl fmt::Display for EmulationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmulationOutcome::Completed {
                return_value,
                instructions,
            } => {
                if let Some(value) = return_value {
                    write!(
                        f,
                        "completed with {value:?} after {instructions} instructions"
                    )
                } else {
                    write!(f, "completed (void) after {instructions} instructions")
                }
            }
            EmulationOutcome::UnhandledException {
                exception,
                instructions,
            } => {
                write!(
                    f,
                    "unhandled exception {exception:?} after {instructions} instructions"
                )
            }
            EmulationOutcome::LimitReached { limit, .. } => {
                write!(f, "limit reached: {limit}")
            }
            EmulationOutcome::RequiresSymbolic { reason, .. } => {
                write!(f, "requires symbolic execution: {reason}")
            }
            EmulationOutcome::Breakpoint {
                offset,
                instructions,
            } => {
                write!(
                    f,
                    "breakpoint at 0x{offset:08X} after {instructions} instructions"
                )
            }
            EmulationOutcome::Stopped {
                reason,
                instructions,
            } => {
                write!(f, "stopped: {reason} after {instructions} instructions")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_step_result_continue() {
        let result = StepResult::Continue;
        assert!(result.is_continue());
        assert!(!result.is_return());
        assert!(!result.is_control_transfer());
    }

    #[test]
    fn test_step_result_return() {
        let result = StepResult::Return {
            value: Some(EmValue::I32(42)),
        };
        assert!(!result.is_continue());
        assert!(result.is_return());
        assert!(result.is_control_transfer());
    }

    #[test]
    fn test_step_result_branch() {
        let result = StepResult::Branch { target: 0x1000 };
        assert!(result.is_control_transfer());
        assert_eq!(result.branch_target(), Some(0x1000));
    }

    #[test]
    fn test_step_result_call() {
        let result = StepResult::Call {
            method: Token::new(0x06000001),
            args: vec![EmValue::I32(1), EmValue::I32(2)],
            is_virtual: false,
        };
        assert!(result.is_control_transfer());

        let display = format!("{result}");
        assert!(display.contains("call"));
        assert!(display.contains("2 args"));
    }

    #[test]
    fn test_step_result_display() {
        let results = vec![
            StepResult::Continue,
            StepResult::Branch { target: 0x100 },
            StepResult::Return { value: None },
            StepResult::Return {
                value: Some(EmValue::I32(42)),
            },
            StepResult::Throw {
                exception: EmValue::Null,
            },
            StepResult::Leave { target: 0x200 },
            StepResult::EndFinally,
            StepResult::EndFilter {
                value: EmValue::I32(1),
            },
            StepResult::Rethrow,
            StepResult::Breakpoint,
        ];

        for result in results {
            let display = format!("{result}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_emulation_outcome_completed() {
        let outcome = EmulationOutcome::Completed {
            return_value: Some(EmValue::I32(100)),
            instructions: 500,
        };

        assert!(outcome.is_completed());
        assert_eq!(outcome.return_value(), Some(&EmValue::I32(100)));
        assert_eq!(outcome.instructions_executed(), 500);
    }

    #[test]
    fn test_emulation_outcome_exception() {
        let outcome = EmulationOutcome::UnhandledException {
            exception: EmValue::Null,
            instructions: 250,
        };

        assert!(!outcome.is_completed());
        assert_eq!(outcome.instructions_executed(), 250);
    }

    #[test]
    fn test_emulation_outcome_limit() {
        let outcome = EmulationOutcome::LimitReached {
            limit: LimitExceeded::Timeout {
                elapsed: Duration::from_secs(10),
                limit: Duration::from_secs(5),
            },
            partial_state: None,
        };

        assert!(!outcome.is_completed());

        let display = format!("{outcome}");
        assert!(display.contains("limit"));
    }

    #[test]
    fn test_emulation_outcome_display() {
        let outcome = EmulationOutcome::Completed {
            return_value: Some(EmValue::I32(42)),
            instructions: 100,
        };

        let display = format!("{outcome}");
        assert!(display.contains("completed"));
        assert!(display.contains("100"));
    }
}
