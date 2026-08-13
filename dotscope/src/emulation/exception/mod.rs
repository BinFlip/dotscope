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
//! # Exception Handling Flow
//!
//! The search and unwind logic itself lives in
//! [`engine::exhandler`](crate::emulation::engine), which is the only implementation the
//! execution loop calls. This module provides the data it operates on.
//!
//! When an exception is thrown:
//!
//! 1. `find_exception_handler` scans the current method's clauses for a `catch` whose type
//!    matches, or a `filter` to evaluate
//! 2. Any `finally`/`fault` nested inside the matched clause's try region is queued, since the
//!    exception unwinds past it on the way to the handler
//! 3. If no handler matches, every cleanup clause is queued and the search continues up the
//!    call stack
//! 4. Queued cleanup handlers execute before control transfers to the handler
//!
//! Two further implementations of this search — an `ExceptionHandler`/`HandlerSearchState`
//! pair here and a `StackUnwinder` — used to sit alongside it. Neither was reachable from the
//! engine, and they had diverged from it on exactly the point above: whether a `finally` found
//! before a matching `catch` still runs. Three copies of one algorithm, two of them dead and
//! silently disagreeing, is how that defect survived, so they were removed rather than
//! resynchronised.

mod state;
mod types;

pub use state::{ExceptionInfo, PendingFinally, ThreadExceptionState};
pub use types::{ExceptionClause, HandlerMatch, InstructionLocation};
