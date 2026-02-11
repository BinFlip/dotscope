//! Stack unwinding for .NET exception handling.
//!
//! This module provides the logic for unwinding the call stack during exception
//! propagation, ensuring that finally and fault blocks are executed in the correct
//! order as specified by the ECMA-335 standard.
//!
//! # Overview
//!
//! When an exception is thrown and no handler is found in the current method,
//! the stack must be unwound to propagate the exception to calling methods.
//! During unwinding:
//!
//! 1. Each frame on the call stack is examined for handlers
//! 2. Finally and fault blocks in scope are collected for execution
//! 3. These cleanup handlers execute before continuing the search
//! 4. If a catch/filter handler is found, cleanup runs first, then control transfers
//! 5. If no handler is found, the exception is unhandled
//!
//! # Components
//!
//! - [`StackUnwinder`] - Main component that manages the unwind process
//! - [`UnwindStepResult`] - Indicates the next action after processing a frame
//! - [`UnwindSequenceBuilder`] - Helper for building ordered handler sequences
//!
//! # Two-Pass Exception Handling
//!
//! .NET uses a two-pass model:
//! 1. **First pass**: Search for a handler without running cleanup
//! 2. **Second pass**: Run cleanup handlers, then enter the catch
//!
//! This module primarily implements the second pass, executing handlers
//! in the correct order after a handler has been found.
//!
//! # Type Checking
//!
//! Exception type matching is delegated to the caller via a type checker function,
//! typically using [`EmulationContext::is_type_compatible`](crate::emulation::EmulationContext::is_type_compatible).

use crate::{
    emulation::{
        exception::{
            ExceptionClause, ExceptionInfo, HandlerMatch, InstructionLocation, ThreadExceptionState,
        },
        thread::ThreadCallFrame,
    },
    metadata::token::Token,
};

/// Result of a single step in the unwind process.
///
/// After processing a stack frame during exception unwinding, this enum
/// indicates what action the interpreter should take next. The unwind
/// process is driven by repeatedly calling unwind methods and acting
/// on the returned result.
///
/// # State Machine
///
/// The typical flow is:
/// 1. `ExecuteHandler` (finally/fault) -> execute cleanup -> `cleanup_complete()`
/// 2. Repeat step 1 for all cleanup handlers
/// 3. `ExecuteHandler` (catch, is_catch=true) or `ContinueUnwind`
/// 4. `HandlerEntered` when entering a catch, or `UnhandledException` when done
#[derive(Clone, Debug)]
pub enum UnwindStepResult {
    /// A handler should be executed.
    ///
    /// The interpreter should transfer control to the handler and execute
    /// its code. After the handler completes, call the appropriate completion
    /// method (`cleanup_complete()` for finally/fault, or enter catch mode).
    ExecuteHandler {
        /// The handler to execute.
        handler: HandlerMatch,
        /// Whether this is the final handler (a catch that will handle the exception).
        ///
        /// - `true` - This is a catch handler; the exception will be handled
        /// - `false` - This is a cleanup handler (finally/fault/filter);
        ///   more steps may follow
        is_catch: bool,
    },

    /// Continue unwinding to the next stack frame.
    ///
    /// No handler was found in the current frame (or cleanup is complete).
    /// Pop the frame and process the next one.
    ContinueUnwind,

    /// The exception is unhandled.
    ///
    /// No handler was found in any stack frame. The exception should be
    /// reported as unhandled and execution terminated (or handled by a
    /// global exception handler if one exists).
    UnhandledException,

    /// Control has been transferred to a catch handler.
    ///
    /// All cleanup handlers have executed and the exception is now being
    /// handled. The interpreter should continue execution at the handler
    /// location.
    HandlerEntered {
        /// The method containing the handler.
        method: Token,
        /// The IL offset where the handler begins.
        offset: u32,
    },
}

/// Stack unwinder for exception propagation.
///
/// This component manages the process of unwinding the call stack when an exception
/// is thrown, ensuring proper execution of finally and fault blocks in the correct
/// order. It tracks the unwind state, pending cleanup handlers, and builds the
/// exception's stack trace.
///
/// # Usage
///
/// The unwinder is used in a loop, processing each stack frame:
///
/// ```ignore
/// let mut unwinder = StackUnwinder::new();
/// unwinder.begin_unwind(&exception_info);
///
/// loop {
///     let result = unwinder.process_frame(&frame, &clauses, exception_type);
///     match result {
///         UnwindStepResult::ExecuteHandler { handler, is_catch } => {
///             // Execute the handler...
///             if !is_catch {
///                 unwinder.cleanup_complete();
///             }
///         }
///         UnwindStepResult::ContinueUnwind => {
///             // Pop frame and continue
///         }
///         UnwindStepResult::HandlerEntered { method, offset } => {
///             // Transfer control to catch handler
///             break;
///         }
///         UnwindStepResult::UnhandledException => {
///             // No handler found
///             break;
///         }
///     }
/// }
/// ```
///
/// # State Management
///
/// The unwinder maintains internal state across multiple calls. Use [`reset()`](Self::reset)
/// to clear all state and start fresh.
#[derive(Clone, Debug, Default)]
pub struct StackUnwinder {
    /// Current unwind state machine state.
    state: UnwindState,

    /// Queue of pending handlers to execute during unwinding.
    pending_handlers: Vec<PendingHandler>,

    /// Stack trace being built as frames are unwound.
    stack_trace: Vec<InstructionLocation>,
}

/// Internal state machine for the stack unwinder.
///
/// This enum tracks where the unwinder is in the unwind process, enabling
/// the state to persist across multiple method calls.
#[derive(Clone, Debug, Default)]
enum UnwindState {
    /// Not currently unwinding.
    ///
    /// The unwinder is idle and ready to begin a new unwind operation.
    #[default]
    Idle,

    /// Searching for a handler.
    ///
    /// The unwinder is actively searching stack frames for a matching
    /// catch or filter handler.
    Searching {
        /// The type token of the exception being searched for.
        exception_type: Token,
    },

    /// Executing cleanup handlers before entering a catch or continuing.
    ///
    /// Finally and fault handlers are being executed. Once all cleanup
    /// is done, either enter the target handler or continue unwinding.
    ExecutingCleanup {
        /// The type token of the exception being handled.
        exception_type: Token,
        /// The catch/filter handler to enter after cleanup, if found.
        target: Option<HandlerTarget>,
    },

    /// A handler has been found and is ready to be entered.
    ///
    /// All cleanup is complete and control should transfer to the handler.
    HandlerFound {
        /// The handler that will handle the exception.
        target: HandlerTarget,
    },
}

/// A handler queued for execution during unwinding.
///
/// This internal structure pairs a handler with its containing method,
/// enabling the unwinder to track which handlers need to execute and
/// in which order during the cleanup phase of exception handling.
#[derive(Clone, Debug)]
struct PendingHandler {
    /// The handler match information describing the handler type and location.
    handler: HandlerMatch,
    /// The method token identifying the method containing this handler.
    method: Token,
}

/// Information about the target catch/filter handler.
///
/// When a catch or filter handler is found during the search phase, this
/// structure stores the information needed to transfer control to it after
/// all cleanup handlers have executed.
#[derive(Clone, Debug)]
struct HandlerTarget {
    /// The method token identifying the method containing the handler.
    method: Token,
    /// The IL offset where the handler code begins.
    offset: u32,
    /// The type of handler (catch for type-based, filter for condition-based).
    handler_type: HandlerType,
}

/// Type of exception handler (for target tracking).
///
/// This enum distinguishes between the two types of exception handlers
/// that can actually handle an exception (as opposed to cleanup handlers
/// like finally and fault which only run but don't catch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandlerType {
    /// A catch handler that matches based on exception type compatibility.
    Catch,
    /// A filter handler that passed its runtime condition evaluation.
    Filter,
}

impl StackUnwinder {
    /// Creates a new stack unwinder in the idle state.
    ///
    /// # Returns
    ///
    /// A new `StackUnwinder` ready to begin unwinding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if an unwind operation is in progress.
    ///
    /// # Returns
    ///
    /// `true` if the unwinder is actively processing an exception,
    /// `false` if it is idle.
    #[must_use]
    pub fn is_unwinding(&self) -> bool {
        !matches!(self.state, UnwindState::Idle)
    }

    /// Begins unwinding for a thrown exception.
    ///
    /// This initializes the unwinder state, clears any previous pending handlers,
    /// and starts building a new stack trace from the throw location.
    ///
    /// # Arguments
    ///
    /// * `exception_info` - Information about the thrown exception, including
    ///   its type and throw location
    ///
    /// # State Change
    ///
    /// Transitions from `Idle` to `Searching` state.
    pub fn begin_unwind(&mut self, exception_info: &ExceptionInfo) {
        self.state = UnwindState::Searching {
            exception_type: exception_info.type_token,
        };
        self.pending_handlers.clear();
        self.stack_trace.clear();
        self.stack_trace.push(exception_info.throw_location);
    }

    /// Processes a stack frame during exception unwinding.
    ///
    /// This method examines the exception clauses of the current frame to find:
    /// - Matching catch handlers (by type compatibility)
    /// - Filter handlers (for later evaluation)
    /// - Finally/fault handlers (queued for cleanup)
    ///
    /// # Arguments
    ///
    /// * `frame` - The current call frame being examined
    /// * `clauses` - Exception clauses for the method in this frame
    /// * `exception_type` - Type token of the exception being handled
    /// * `is_type_compatible` - A function that checks if an exception type is assignable
    ///   to a catch type. Use [`EmulationContext::is_type_compatible`](crate::emulation::EmulationContext::is_type_compatible).
    ///
    /// # Returns
    ///
    /// An [`UnwindStepResult`] indicating the next action:
    /// - `ExecuteHandler` - Run a handler (cleanup or catch)
    /// - `ContinueUnwind` - No handlers in this frame, continue to caller
    ///
    /// # Stack Trace
    ///
    /// Each processed frame is automatically added to the exception's stack trace.
    pub fn process_frame<F>(
        &mut self,
        frame: &ThreadCallFrame,
        clauses: &[ExceptionClause],
        exception_type: Token,
        is_type_compatible: F,
    ) -> UnwindStepResult
    where
        F: Fn(Token, Token) -> bool,
    {
        let current_offset = frame.ip();
        let method = frame.method();

        // Add to stack trace
        self.stack_trace
            .push(InstructionLocation::new(method, current_offset));

        // Find handlers for this frame
        let mut finally_handlers = Vec::new();
        let mut fault_handlers = Vec::new();
        let mut catch_handler = None;
        let mut filter_handler = None;

        for clause in clauses {
            if !clause.is_in_try(current_offset) {
                continue;
            }

            match clause {
                ExceptionClause::Catch { catch_type, .. } => {
                    // Check type compatibility using the provided checker
                    if is_type_compatible(exception_type, *catch_type) && catch_handler.is_none() {
                        catch_handler = Some(HandlerMatch::Catch {
                            method,
                            handler_offset: clause.handler_offset(),
                        });
                    }
                }

                ExceptionClause::Filter { filter_offset, .. } => {
                    if filter_handler.is_none() {
                        filter_handler = Some(HandlerMatch::Filter {
                            method,
                            filter_offset: *filter_offset,
                            handler_offset: clause.handler_offset(),
                        });
                    }
                }

                ExceptionClause::Finally { .. } => {
                    finally_handlers.push(HandlerMatch::Finally {
                        method,
                        handler_offset: clause.handler_offset(),
                        handler_length: clause.handler_length(),
                        continue_search_after: true,
                    });
                }

                ExceptionClause::Fault { .. } => {
                    fault_handlers.push(HandlerMatch::Fault {
                        method,
                        handler_offset: clause.handler_offset(),
                        handler_length: clause.handler_length(),
                    });
                }
            }
        }

        // If we have a filter, we need to evaluate it first
        if let Some(filter) = filter_handler {
            // Queue finally/fault handlers, then filter
            for h in finally_handlers {
                self.pending_handlers
                    .push(PendingHandler { handler: h, method });
            }
            for h in fault_handlers {
                self.pending_handlers
                    .push(PendingHandler { handler: h, method });
            }

            return UnwindStepResult::ExecuteHandler {
                handler: filter,
                is_catch: false, // Filter needs evaluation first
            };
        }

        // If we have a catch handler
        if let Some(catch) = catch_handler {
            // Queue finally/fault handlers to run before entering catch
            for h in finally_handlers {
                self.pending_handlers
                    .push(PendingHandler { handler: h, method });
            }
            for h in fault_handlers {
                self.pending_handlers
                    .push(PendingHandler { handler: h, method });
            }

            // If there are pending handlers, run them first
            if !self.pending_handlers.is_empty() {
                // Store the catch as the target
                self.state = UnwindState::ExecutingCleanup {
                    exception_type,
                    target: Some(HandlerTarget {
                        method,
                        offset: match &catch {
                            HandlerMatch::Catch { handler_offset, .. } => *handler_offset,
                            _ => unreachable!(),
                        },
                        handler_type: HandlerType::Catch,
                    }),
                };

                let next = self.pending_handlers.remove(0);
                return UnwindStepResult::ExecuteHandler {
                    handler: next.handler,
                    is_catch: false,
                };
            }

            return UnwindStepResult::ExecuteHandler {
                handler: catch,
                is_catch: true,
            };
        }

        // No catch in this frame - queue cleanup and continue unwinding
        for h in finally_handlers {
            self.pending_handlers
                .push(PendingHandler { handler: h, method });
        }
        for h in fault_handlers {
            self.pending_handlers
                .push(PendingHandler { handler: h, method });
        }

        // If we have cleanup handlers, execute them
        if !self.pending_handlers.is_empty() {
            self.state = UnwindState::ExecutingCleanup {
                exception_type,
                target: None,
            };

            let next = self.pending_handlers.remove(0);
            return UnwindStepResult::ExecuteHandler {
                handler: next.handler,
                is_catch: false,
            };
        }

        // No handlers in this frame, continue unwinding
        UnwindStepResult::ContinueUnwind
    }

    /// Called when a cleanup handler (finally/fault) completes execution.
    ///
    /// After executing a finally or fault handler, call this method to
    /// continue the unwind process. It will return the next handler to
    /// execute, or indicate that the catch handler can be entered.
    ///
    /// # Returns
    ///
    /// An [`UnwindStepResult`] indicating the next action:
    /// - `ExecuteHandler` - Another cleanup handler to execute
    /// - `HandlerEntered` - All cleanup done, entering catch handler
    /// - `ContinueUnwind` - All cleanup done, continue to next frame
    pub fn cleanup_complete(&mut self) -> UnwindStepResult {
        // Check if there are more pending handlers
        if !self.pending_handlers.is_empty() {
            let next = self.pending_handlers.remove(0);
            return UnwindStepResult::ExecuteHandler {
                handler: next.handler,
                is_catch: false,
            };
        }

        // Check if we have a target handler to enter
        if let UnwindState::ExecutingCleanup {
            target: Some(target),
            ..
        } = &self.state
        {
            let result = UnwindStepResult::HandlerEntered {
                method: target.method,
                offset: target.offset,
            };
            self.state = UnwindState::Idle;
            return result;
        }

        // Continue unwinding to next frame
        UnwindStepResult::ContinueUnwind
    }

    /// Called when a filter handler completes evaluation.
    ///
    /// After executing a filter clause's evaluation code, call this method
    /// with the result (from the evaluation stack). The filter returns
    /// an integer: non-zero means accept, zero means reject.
    ///
    /// # Arguments
    ///
    /// * `accepted` - Whether the filter accepted the exception (non-zero result)
    /// * `handler_offset` - The IL offset of the handler to enter if accepted
    /// * `method` - The method containing the filter and handler
    ///
    /// # Returns
    ///
    /// An [`UnwindStepResult`] indicating the next action:
    /// - If accepted: `ExecuteHandler` (cleanup) or `HandlerEntered`
    /// - If rejected: `ContinueUnwind` to search for other handlers
    pub fn filter_complete(
        &mut self,
        accepted: bool,
        handler_offset: u32,
        method: Token,
    ) -> UnwindStepResult {
        if accepted {
            // Filter accepted - enter the handler
            if !self.pending_handlers.is_empty() {
                // Run cleanup first
                if let UnwindState::Searching { exception_type } = self.state {
                    self.state = UnwindState::ExecutingCleanup {
                        exception_type,
                        target: Some(HandlerTarget {
                            method,
                            offset: handler_offset,
                            handler_type: HandlerType::Filter,
                        }),
                    };
                }

                let next = self.pending_handlers.remove(0);
                return UnwindStepResult::ExecuteHandler {
                    handler: next.handler,
                    is_catch: false,
                };
            }

            UnwindStepResult::HandlerEntered {
                method,
                offset: handler_offset,
            }
        } else {
            // Filter rejected - continue searching
            UnwindStepResult::ContinueUnwind
        }
    }

    /// Completes the unwind when no handler is found.
    ///
    /// Called when all stack frames have been searched without finding a
    /// matching handler. This resets the unwinder to idle state.
    ///
    /// # Returns
    ///
    /// Always returns [`UnwindStepResult::UnhandledException`].
    pub fn complete_unhandled(&mut self) -> UnwindStepResult {
        self.state = UnwindState::Idle;
        UnwindStepResult::UnhandledException
    }

    /// Resets the unwinder to its initial state.
    ///
    /// Clears all pending handlers, the stack trace, and returns the
    /// unwinder to idle state. Call this to abandon an unwind operation
    /// or to prepare for a new one.
    pub fn reset(&mut self) {
        self.state = UnwindState::Idle;
        self.pending_handlers.clear();
        self.stack_trace.clear();
    }

    /// Gets the stack trace built during unwinding.
    ///
    /// This returns all instruction locations added during the unwind
    /// process, starting from the throw location.
    ///
    /// # Returns
    ///
    /// A slice of instruction locations representing the call stack.
    #[must_use]
    pub fn stack_trace(&self) -> &[InstructionLocation] {
        &self.stack_trace
    }

    /// Applies exception state changes when entering a catch handler.
    ///
    /// This helper method updates the thread's exception state when
    /// control transfers to a catch handler.
    ///
    /// # Arguments
    ///
    /// * `exception_state` - The thread's exception state to update
    pub fn enter_catch_handler(exception_state: &mut ThreadExceptionState) {
        exception_state.enter_catch();
    }

    /// Applies exception state changes when entering a finally handler.
    ///
    /// This helper method updates the thread's exception state when
    /// control transfers to a finally handler.
    ///
    /// # Arguments
    ///
    /// * `exception_state` - The thread's exception state to update
    pub fn enter_finally_handler(exception_state: &mut ThreadExceptionState) {
        exception_state.enter_finally();
    }

    /// Applies exception state changes when exiting a finally handler.
    ///
    /// This helper method updates the thread's exception state when
    /// a finally handler completes (via `endfinally` instruction).
    ///
    /// # Arguments
    ///
    /// * `exception_state` - The thread's exception state to update
    /// * `saved_exception` - Exception to restore if rethrow was requested
    pub fn exit_finally_handler(
        exception_state: &mut ThreadExceptionState,
        saved_exception: Option<ExceptionInfo>,
    ) {
        exception_state.exit_finally(saved_exception);
    }
}

/// Builder for constructing ordered exception handler sequences.
///
/// This helper is used to build a sequence of handlers that should execute
/// during exception handling. Handlers are added in execution order and
/// can be retrieved as a vector.
///
/// # Example
///
/// ```ignore
/// let mut builder = UnwindSequenceBuilder::new();
///
/// // Add cleanup handlers first
/// builder.add_handler(HandlerMatch::Finally { ... });
/// builder.add_handler(HandlerMatch::Finally { ... });
///
/// // Then the catch handler
/// builder.add_handler(HandlerMatch::Catch { ... });
///
/// // Get the final sequence
/// let handlers = builder.build();
/// ```
#[derive(Clone, Debug, Default)]
pub struct UnwindSequenceBuilder {
    /// Handlers in execution order.
    handlers: Vec<HandlerMatch>,
}

impl UnwindSequenceBuilder {
    /// Creates a new empty sequence builder.
    ///
    /// # Returns
    ///
    /// A new `UnwindSequenceBuilder` with no handlers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a single handler to the sequence.
    ///
    /// Handlers are executed in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `handler` - The handler to add to the sequence
    pub fn add_handler(&mut self, handler: HandlerMatch) {
        self.handlers.push(handler);
    }

    /// Adds multiple handlers to the sequence.
    ///
    /// The handlers are added in iteration order and will execute
    /// after any previously added handlers.
    ///
    /// # Arguments
    ///
    /// * `handlers` - An iterator of handlers to add
    pub fn add_handlers(&mut self, handlers: impl IntoIterator<Item = HandlerMatch>) {
        self.handlers.extend(handlers);
    }

    /// Builds the final handler sequence.
    ///
    /// Consumes the builder and returns the handlers as a vector.
    ///
    /// # Returns
    ///
    /// A vector of handlers in execution order.
    #[must_use]
    pub fn build(self) -> Vec<HandlerMatch> {
        self.handlers
    }

    /// Checks if the sequence is empty.
    ///
    /// # Returns
    ///
    /// `true` if no handlers have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Gets the number of handlers in the sequence.
    ///
    /// # Returns
    ///
    /// The count of handlers added to the builder.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::{emulation::HeapRef, metadata::typesystem::CilFlavor};

    use super::*;

    fn create_test_exception() -> ExceptionInfo {
        ExceptionInfo::new(
            HeapRef::new(1),
            Token::new(0x01000010),
            InstructionLocation::new(Token::new(0x06000001), 0x20),
        )
    }

    fn create_test_frame(method: Token, offset: u32) -> ThreadCallFrame {
        let mut frame = ThreadCallFrame::new(method, None, 0, vec![CilFlavor::I4], vec![], false);
        frame.set_ip(offset);
        frame
    }

    /// Simple type checker for tests: exact match or catch-all System.Exception.
    fn test_type_checker(exception_type: Token, catch_type: Token) -> bool {
        // Exact match
        if exception_type == catch_type {
            return true;
        }
        // System.Exception (0x0100_0001) catches everything
        if catch_type.value() == 0x0100_0001 {
            return true;
        }
        false
    }

    #[test]
    fn test_unwinder_begin() {
        let mut unwinder = StackUnwinder::new();
        let exception = create_test_exception();

        assert!(!unwinder.is_unwinding());

        unwinder.begin_unwind(&exception);

        assert!(unwinder.is_unwinding());
        assert_eq!(unwinder.stack_trace().len(), 1);
    }

    #[test]
    fn test_unwinder_reset() {
        let mut unwinder = StackUnwinder::new();
        let exception = create_test_exception();

        unwinder.begin_unwind(&exception);
        assert!(unwinder.is_unwinding());

        unwinder.reset();
        assert!(!unwinder.is_unwinding());
        assert!(unwinder.stack_trace().is_empty());
    }

    #[test]
    fn test_process_frame_with_catch() {
        let mut unwinder = StackUnwinder::new();
        let exception = create_test_exception();

        unwinder.begin_unwind(&exception);

        let method = Token::new(0x06000001);
        let frame = create_test_frame(method, 0x15);

        let clauses = vec![ExceptionClause::Catch {
            try_offset: 0x10,
            try_length: 0x20,
            handler_offset: 0x30,
            handler_length: 0x10,
            catch_type: Token::new(0x0100_0001), // Base exception
        }];

        let result =
            unwinder.process_frame(&frame, &clauses, exception.type_token, test_type_checker);

        match result {
            UnwindStepResult::ExecuteHandler { is_catch, .. } => {
                assert!(is_catch);
            }
            _ => panic!("Expected catch handler"),
        }
    }

    #[test]
    fn test_process_frame_with_finally() {
        let mut unwinder = StackUnwinder::new();
        let exception = create_test_exception();

        unwinder.begin_unwind(&exception);

        let method = Token::new(0x06000001);
        let frame = create_test_frame(method, 0x15);

        // Only finally, no catch
        let clauses = vec![ExceptionClause::Finally {
            try_offset: 0x10,
            try_length: 0x20,
            handler_offset: 0x30,
            handler_length: 0x10,
        }];

        let result =
            unwinder.process_frame(&frame, &clauses, exception.type_token, test_type_checker);

        match result {
            UnwindStepResult::ExecuteHandler { handler, is_catch } => {
                assert!(!is_catch);
                assert!(matches!(handler, HandlerMatch::Finally { .. }));
            }
            _ => panic!("Expected finally handler"),
        }
    }

    #[test]
    fn test_process_frame_continue_unwind() {
        let mut unwinder = StackUnwinder::new();
        let exception = create_test_exception();

        unwinder.begin_unwind(&exception);

        let method = Token::new(0x06000001);
        let frame = create_test_frame(method, 0x50); // Outside any try block

        let clauses = vec![ExceptionClause::Catch {
            try_offset: 0x10,
            try_length: 0x20,
            handler_offset: 0x30,
            handler_length: 0x10,
            catch_type: Token::new(0x01000010),
        }];

        let result =
            unwinder.process_frame(&frame, &clauses, exception.type_token, test_type_checker);

        assert!(matches!(result, UnwindStepResult::ContinueUnwind));
    }

    #[test]
    fn test_cleanup_complete() {
        let mut unwinder = StackUnwinder::new();

        // No pending handlers
        let result = unwinder.cleanup_complete();
        assert!(matches!(result, UnwindStepResult::ContinueUnwind));
    }

    #[test]
    fn test_unwind_sequence_builder() {
        let mut builder = UnwindSequenceBuilder::new();

        assert!(builder.is_empty());

        builder.add_handler(HandlerMatch::Finally {
            method: Token::new(0x06000001),
            handler_offset: 0x30,
            handler_length: 0x10,
            continue_search_after: true,
        });

        builder.add_handler(HandlerMatch::Catch {
            method: Token::new(0x06000001),
            handler_offset: 0x40,
        });

        assert_eq!(builder.len(), 2);

        let sequence = builder.build();
        assert_eq!(sequence.len(), 2);
    }
}
