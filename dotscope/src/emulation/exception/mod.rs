//! Exception handling for .NET emulation.
//!
//! This module provides comprehensive exception handling support for .NET Common Language
//! Runtime (CLR) emulation, implementing the structured exception handling (SEH) semantics
//! defined by the ECMA-335 specification.
//!
//! # Overview
//!
//! .NET exception handling involves several key mechanisms:
//!
//! - **Exception clauses** define protected regions (try blocks) and their associated handlers
//!   (catch, filter, finally, fault) in method metadata
//! - **Handler resolution** searches for an appropriate handler when an exception is thrown,
//!   following the CLR's two-pass exception handling model
//! - **Stack unwinding** executes cleanup handlers (finally/fault blocks) while propagating
//!   an exception up the call stack
//! - **Per-thread state** tracks the current exception and pending cleanup operations
//!
//! # Components
//!
//! - [`ExceptionClause`] - Represents exception clause types from method metadata (catch, filter,
//!   finally, fault)
//! - [`ThreadExceptionState`] - Manages per-thread exception tracking, including the active
//!   exception, pending finally blocks, and filter evaluation state
//! - [`ExceptionHandler`] - Provides handler resolution logic for finding appropriate exception
//!   handlers based on exception type and protected regions
//! - [`StackUnwinder`] - Manages stack unwinding during exception propagation, ensuring proper
//!   execution of cleanup handlers
//!
//! # Exception Handling Flow
//!
//! When an exception is thrown:
//!
//! 1. The [`ExceptionHandler`] searches for a matching catch or filter handler in the current
//!    method's exception clauses
//! 2. If no handler is found, the search continues up the call stack via [`StackUnwinder`]
//! 3. Finally and fault handlers are queued for execution during unwinding
//! 4. Once a handler is found, cleanup handlers execute in order before control transfers
//!    to the catch handler
//!
//! # Example
//!
//! ```ignore
//! use dotscope::emulation::exception::{ExceptionHandler, ExceptionClause, ThreadExceptionState};
//! use dotscope::emulation::EmulationContext;
//!
//! // Create exception handler resolver
//! let handler = ExceptionHandler::new();
//!
//! // Find handler for an exception at a given IL offset
//! // Type checking is delegated to EmulationContext
//! let result = handler.find_handler(
//!     &clauses,
//!     throw_offset,
//!     exception_type,
//!     method_token,
//!     |exc, catch| ctx.is_type_compatible(exc, catch),
//! );
//! ```

mod handler;
mod state;
mod types;
mod unwinder;

pub use handler::{ExceptionHandler, FrameSearchInfo, HandlerSearchState, MethodHandlerResult};
pub use state::{ExceptionInfo, PendingFinally, ThreadExceptionState};
pub use types::{ExceptionClause, HandlerMatch, InstructionLocation};
pub use unwinder::{StackUnwinder, UnwindSequenceBuilder, UnwindStepResult};
