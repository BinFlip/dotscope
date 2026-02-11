//! Exception handler resolution for .NET emulation.
//!
//! This module provides the logic for finding appropriate exception handlers when an exception
//! is thrown during emulation. It implements the handler search algorithm defined by the
//! ECMA-335 specification, which searches exception clauses in innermost-to-outermost order.
//!
//! # Handler Search Algorithm
//!
//! When an exception is thrown, the handler search proceeds as follows:
//!
//! 1. Exception clauses are examined in order (innermost try block first)
//! 2. For each clause whose try block contains the throw point:
//!    - **Catch clauses**: Check if the exception type is assignable to the catch type
//!    - **Filter clauses**: Return for filter code evaluation
//!    - **Finally/Fault clauses**: Queue for execution during unwinding
//! 3. If a matching catch/filter is found, cleanup handlers execute first
//! 4. If no handler is found in the current method, unwinding continues to the caller
//!
//! # Type Matching
//!
//! Exception type matching follows .NET's inheritance rules: a catch clause matches
//! if the thrown exception type is the same as or derives from the catch type.
//! Type compatibility is determined by a caller-provided function, typically using
//! [`EmulationContext::is_type_compatible`](crate::emulation::EmulationContext::is_type_compatible).

use crate::{
    emulation::exception::{ExceptionClause, HandlerMatch, InstructionLocation},
    metadata::token::Token,
};

/// Exception handler resolver for .NET exception handling.
///
/// This component is responsible for finding appropriate exception handlers when an exception
/// is thrown during emulation. It searches through exception clauses in the current method,
/// respecting the .NET exception handling semantics defined in ECMA-335.
///
/// # Responsibilities
///
/// - Finding catch handlers that match the thrown exception type
/// - Identifying filter handlers that need runtime evaluation
/// - Collecting finally and fault handlers for cleanup during unwinding
///
/// # Type Matching
///
/// Exception type matching is delegated to the caller via a type checker function.
/// The caller (typically the emulation engine) provides this function using
/// [`EmulationContext::is_type_compatible`](crate::emulation::EmulationContext::is_type_compatible)
/// which has full access to the assembly's type hierarchy.
///
/// # Usage
///
/// ```ignore
/// use dotscope::emulation::exception::ExceptionHandler;
/// use dotscope::emulation::EmulationContext;
/// use dotscope::metadata::token::Token;
///
/// let handler = ExceptionHandler::new();
///
/// // Use EmulationContext for type checking
/// let result = handler.find_handler(
///     &clauses,
///     throw_offset,
///     exception_type,
///     method_token,
///     |exc_type, catch_type| ctx.is_type_compatible(exc_type, catch_type),
/// );
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct ExceptionHandler;

/// Result of searching for an exception handler within a single method.
///
/// This enum represents the possible outcomes when searching a method's exception
/// clauses for a handler that matches a thrown exception.
///
/// # Variants
///
/// - [`Found`](MethodHandlerResult::Found) - A matching catch or filter handler was found
/// - [`ExecuteCleanup`](MethodHandlerResult::ExecuteCleanup) - Cleanup handlers must run
///   before continuing (finally/fault blocks, or cleanup before catch)
/// - [`NotFound`](MethodHandlerResult::NotFound) - No handler in this method; continue
///   unwinding to the caller
#[derive(Clone, Debug)]
pub enum MethodHandlerResult {
    /// Found a suitable catch or filter handler in this method.
    ///
    /// The handler can be entered after any pending cleanup handlers complete.
    Found(HandlerMatch),

    /// Cleanup handlers must be executed before continuing.
    ///
    /// This variant is returned when:
    /// - Finally/fault blocks need to run before entering a catch handler
    /// - Finally/fault blocks need to run before continuing the unwind
    ///
    /// The handlers should be executed in order, with the last one potentially
    /// being a catch handler.
    ExecuteCleanup {
        /// Cleanup handlers to execute in order.
        handlers: Vec<HandlerMatch>,
    },

    /// No matching handler was found in this method.
    ///
    /// The exception handling system should continue unwinding to the caller.
    NotFound,
}

impl ExceptionHandler {
    /// Creates a new exception handler resolver.
    ///
    /// # Returns
    ///
    /// A new `ExceptionHandler` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Finds an exception handler for an exception thrown at the given location.
    ///
    /// This method searches through the exception clauses in order (innermost first),
    /// looking for handlers that can handle the thrown exception. The search considers:
    ///
    /// 1. **Catch handlers** - Checked for type compatibility with the exception
    /// 2. **Filter handlers** - Returned for runtime evaluation of the filter code
    /// 3. **Finally/Fault handlers** - Collected for execution during unwinding
    ///
    /// # Arguments
    ///
    /// * `clauses` - Exception clauses for the current method, ordered innermost-first
    /// * `throw_offset` - IL offset where the exception was thrown (or current IP during unwind)
    /// * `exception_type` - Type token of the thrown exception
    /// * `method` - Token of the method being searched
    /// * `is_type_compatible` - A function that checks if an exception type is assignable
    ///   to a catch type. Use [`EmulationContext::is_type_compatible`](crate::emulation::EmulationContext::is_type_compatible).
    ///
    /// # Returns
    ///
    /// A [`MethodHandlerResult`] indicating:
    /// - `Found` if a matching handler was found with no pending cleanup
    /// - `ExecuteCleanup` if cleanup handlers must run (with or without a final catch)
    /// - `NotFound` if no handlers apply in this method
    ///
    /// # Algorithm
    ///
    /// The search proceeds as follows:
    /// 1. Only clauses whose try block contains `throw_offset` are considered
    /// 2. Catch clauses are checked for type compatibility via the provided function
    /// 3. Filter clauses are returned immediately for evaluation
    /// 4. Finally/fault clauses are collected as cleanup handlers
    /// 5. If a catch is found, cleanup runs first, then control transfers to the catch
    pub fn find_handler<F>(
        &self,
        clauses: &[ExceptionClause],
        throw_offset: u32,
        exception_type: Token,
        method: Token,
        is_type_compatible: F,
    ) -> MethodHandlerResult
    where
        F: Fn(Token, Token) -> bool,
    {
        let mut cleanup_handlers = Vec::new();
        let mut found_catch = None;

        // Clauses are ordered innermost-first in .NET metadata
        for clause in clauses {
            // Only consider clauses whose try block contains the throw point
            if !clause.is_in_try(throw_offset) {
                continue;
            }

            match clause {
                ExceptionClause::Catch { catch_type, .. } => {
                    // Check if this catch handler matches the exception type
                    if is_type_compatible(exception_type, *catch_type) {
                        found_catch = Some(HandlerMatch::Catch {
                            method,
                            handler_offset: clause.handler_offset(),
                        });
                        break;
                    }
                }

                ExceptionClause::Filter { filter_offset, .. } => {
                    // Filter handlers need to be evaluated at runtime
                    // Return this so the caller can evaluate the filter
                    found_catch = Some(HandlerMatch::Filter {
                        method,
                        filter_offset: *filter_offset,
                        handler_offset: clause.handler_offset(),
                    });
                    break;
                }

                ExceptionClause::Finally { .. } => {
                    // Finally blocks must run during unwinding
                    cleanup_handlers.push(HandlerMatch::Finally {
                        method,
                        handler_offset: clause.handler_offset(),
                        handler_length: clause.handler_length(),
                        continue_search_after: true,
                    });
                }

                ExceptionClause::Fault { .. } => {
                    // Fault blocks only run on exception path
                    cleanup_handlers.push(HandlerMatch::Fault {
                        method,
                        handler_offset: clause.handler_offset(),
                        handler_length: clause.handler_length(),
                    });
                }
            }
        }

        // If we found a catch handler, we still need to run any cleanup handlers first
        if let Some(catch) = found_catch {
            if cleanup_handlers.is_empty() {
                return MethodHandlerResult::Found(catch);
            }
            // Add the catch as the final handler after cleanup
            cleanup_handlers.push(catch);
            return MethodHandlerResult::ExecuteCleanup {
                handlers: cleanup_handlers,
            };
        }

        // No catch found - return cleanup handlers if any
        if cleanup_handlers.is_empty() {
            MethodHandlerResult::NotFound
        } else {
            MethodHandlerResult::ExecuteCleanup {
                handlers: cleanup_handlers,
            }
        }
    }

    /// Finds finally handlers that must execute for a `leave` instruction.
    ///
    /// When executing a `leave` instruction to exit a protected region (try block),
    /// any finally blocks that protect the current position but not the target must
    /// be executed before control transfers to the target.
    ///
    /// This is distinct from exception handling: `leave` is used for normal control
    /// flow out of try blocks (e.g., `return` or `break` inside a try), not for
    /// exception propagation.
    ///
    /// # Arguments
    ///
    /// * `clauses` - Exception clauses for the method
    /// * `leave_offset` - IL offset of the `leave` instruction
    /// * `target_offset` - Target IL offset where control will transfer
    /// * `method` - Token of the method containing the leave
    ///
    /// # Returns
    ///
    /// A vector of [`HandlerMatch::Finally`] handlers to execute in order before
    /// transferring control to `target_offset`. Empty if no finally blocks need
    /// to run.
    ///
    /// # Example
    ///
    /// For code like:
    /// ```csharp
    /// try {
    ///     if (condition) return; // leave instruction here
    /// } finally {
    ///     Cleanup();
    /// }
    /// ```
    /// This method returns the finally handler so `Cleanup()` runs before returning.
    #[must_use]
    pub fn find_finally_for_leave(
        &self,
        clauses: &[ExceptionClause],
        leave_offset: u32,
        target_offset: u32,
        method: Token,
    ) -> Vec<HandlerMatch> {
        let mut handlers = Vec::new();

        for clause in clauses {
            // Only consider finally clauses
            if !clause.is_finally() {
                continue;
            }

            // Check if we're leaving a try block that this finally protects
            let in_try = clause.is_in_try(leave_offset);
            let target_in_try = clause.is_in_try(target_offset);

            // If we're in the try block but jumping outside it, run the finally
            if in_try && !target_in_try {
                handlers.push(HandlerMatch::Finally {
                    method,
                    handler_offset: clause.handler_offset(),
                    handler_length: clause.handler_length(),
                    continue_search_after: false, // Not searching for catch
                });
            }
        }

        handlers
    }

    /// Checks if an IL offset is within any handler block.
    ///
    /// This is useful for determining if execution is currently inside a
    /// catch, finally, fault, or filter handler block. This information is
    /// needed for proper `rethrow` handling and control flow validation.
    ///
    /// # Arguments
    ///
    /// * `clauses` - Exception clauses for the method
    /// * `offset` - The IL offset to check
    ///
    /// # Returns
    ///
    /// `true` if the offset is within any handler block, `false` otherwise.
    #[must_use]
    pub fn is_in_handler(&self, clauses: &[ExceptionClause], offset: u32) -> bool {
        clauses.iter().any(|c| c.is_in_handler(offset))
    }

    /// Gets the exception clause that owns the handler at the given offset.
    ///
    /// When execution is inside a handler block, this method returns the
    /// exception clause that defines that handler. This is useful for
    /// determining the type of handler being executed and its properties.
    ///
    /// # Arguments
    ///
    /// * `clauses` - Exception clauses for the method
    /// * `offset` - The IL offset within a handler block
    ///
    /// # Returns
    ///
    /// The exception clause containing the handler, or `None` if the offset
    /// is not within any handler block.
    #[must_use]
    pub fn get_handler_clause<'a>(
        &self,
        clauses: &'a [ExceptionClause],
        offset: u32,
    ) -> Option<&'a ExceptionClause> {
        clauses.iter().find(|c| c.is_in_handler(offset))
    }

    /// Builds a formatted stack trace string from instruction locations.
    ///
    /// Creates a human-readable stack trace similar to .NET's exception stack trace
    /// format, with each frame on a separate line prefixed with "at".
    ///
    /// # Arguments
    ///
    /// * `locations` - Slice of instruction locations representing the call stack
    ///
    /// # Returns
    ///
    /// A formatted string with one frame per line.
    ///
    /// # Example Output
    ///
    /// ```text
    ///   at 0x06000001+0x0042
    ///   at 0x06000002+0x0010
    ///   at 0x06000003+0x0005
    /// ```
    #[must_use]
    pub fn build_stack_trace(locations: &[InstructionLocation]) -> String {
        locations
            .iter()
            .map(|loc| format!("  at {loc}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// State for multi-frame exception handler search across the call stack.
///
/// When an exception is thrown, the handler search may span multiple stack frames.
/// This structure tracks the state of that search, including which frames have been
/// searched, what cleanup handlers have been found, and whether a catch handler
/// has been located.
///
/// # Usage
///
/// ```ignore
/// let mut state = HandlerSearchState::new(exception_type, throw_location);
///
/// // Add frames from the call stack (deepest first)
/// state.add_frame(method1, offset1, clauses1);
/// state.add_frame(method2, offset2, clauses2);
///
/// // Search proceeds until a handler is found or all frames are exhausted
/// while !state.is_complete() {
///     // Process each frame...
/// }
/// ```
#[derive(Clone, Debug)]
pub struct HandlerSearchState {
    /// The type token of the exception being handled.
    pub exception_type: Token,

    /// The location where the exception was thrown.
    pub current_location: InstructionLocation,

    /// Stack frames to search, ordered deepest (innermost) first.
    pub frames: Vec<FrameSearchInfo>,

    /// Index of the current frame being searched (0-based).
    pub current_frame: usize,

    /// Cleanup handlers (finally/fault) collected during the search.
    ///
    /// These handlers must execute before entering a catch handler or
    /// before propagating the exception to the next frame.
    pub pending_cleanup: Vec<HandlerMatch>,

    /// The catch or filter handler that will handle the exception, if found.
    pub handler_found: Option<HandlerMatch>,
}

/// Information about a single stack frame for exception handler search.
///
/// This structure contains all the information needed to search for exception
/// handlers within a single method's stack frame during exception propagation.
#[derive(Clone, Debug)]
pub struct FrameSearchInfo {
    /// The method token identifying this stack frame.
    pub method: Token,

    /// The IL offset where execution was when the exception occurred or propagated.
    pub offset: u32,

    /// Exception clauses defined in this method's metadata.
    ///
    /// These clauses define the protected regions (try blocks) and their
    /// associated handlers within this method.
    pub clauses: Vec<ExceptionClause>,
}

impl HandlerSearchState {
    /// Creates a new handler search state for an exception.
    ///
    /// Initializes the search state with the exception type and the location
    /// where the exception was thrown. Stack frames should be added using
    /// [`add_frame`](Self::add_frame) before searching.
    ///
    /// # Arguments
    ///
    /// * `exception_type` - The type token of the thrown exception
    /// * `throw_location` - The instruction location where the exception was thrown
    ///
    /// # Returns
    ///
    /// A new `HandlerSearchState` ready to accept stack frames for searching.
    #[must_use]
    pub fn new(exception_type: Token, throw_location: InstructionLocation) -> Self {
        Self {
            exception_type,
            current_location: throw_location,
            frames: Vec::new(),
            current_frame: 0,
            pending_cleanup: Vec::new(),
            handler_found: None,
        }
    }

    /// Adds a stack frame to the search.
    ///
    /// Frames should be added in order from innermost (current) to outermost (caller).
    /// Each frame's exception clauses will be searched for handlers.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token for this frame
    /// * `offset` - The IL offset within the method
    /// * `clauses` - The exception clauses defined in this method
    pub fn add_frame(&mut self, method: Token, offset: u32, clauses: Vec<ExceptionClause>) {
        self.frames.push(FrameSearchInfo {
            method,
            offset,
            clauses,
        });
    }

    /// Checks if the handler search is complete.
    ///
    /// The search is complete when either:
    /// - A matching handler has been found
    /// - All frames have been searched without finding a handler
    ///
    /// # Returns
    ///
    /// `true` if the search is complete, `false` if more frames need to be searched.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.handler_found.is_some()
            || (!self.frames.is_empty() && self.current_frame >= self.frames.len())
    }

    /// Checks if there are pending cleanup handlers to execute.
    ///
    /// Cleanup handlers (finally/fault blocks) must be executed before entering
    /// a catch handler or before continuing to unwind to the next frame.
    ///
    /// # Returns
    ///
    /// `true` if there are cleanup handlers waiting to be executed.
    #[must_use]
    pub fn has_pending_cleanup(&self) -> bool {
        !self.pending_cleanup.is_empty()
    }

    /// Takes the next cleanup handler from the queue.
    ///
    /// Removes and returns the first pending cleanup handler. Cleanup handlers
    /// should be executed in the order they are returned (FIFO).
    ///
    /// # Returns
    ///
    /// The next cleanup handler to execute, or `None` if no cleanup handlers remain.
    pub fn take_next_cleanup(&mut self) -> Option<HandlerMatch> {
        if self.pending_cleanup.is_empty() {
            None
        } else {
            Some(self.pending_cleanup.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::exception::{
            ExceptionClause, ExceptionHandler, HandlerMatch, HandlerSearchState,
            InstructionLocation, MethodHandlerResult,
        },
        metadata::token::Token,
    };

    fn create_test_clauses() -> Vec<ExceptionClause> {
        vec![
            // Inner try/catch
            ExceptionClause::Catch {
                try_offset: 0x10,
                try_length: 0x20,
                handler_offset: 0x30,
                handler_length: 0x10,
                catch_type: Token::new(0x01000010), // Specific exception type
            },
            // Outer try/finally
            ExceptionClause::Finally {
                try_offset: 0x00,
                try_length: 0x50,
                handler_offset: 0x50,
                handler_length: 0x10,
            },
            // Another catch for broader type
            ExceptionClause::Catch {
                try_offset: 0x00,
                try_length: 0x50,
                handler_offset: 0x60,
                handler_length: 0x10,
                catch_type: Token::new(0x0100_0001), // System.Exception
            },
        ]
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
    fn test_find_matching_catch() {
        let handler = ExceptionHandler::new();
        let clauses = create_test_clauses();
        let method = Token::new(0x06000001);

        // Throw in inner try block with matching type
        let result = handler.find_handler(
            &clauses,
            0x15,
            Token::new(0x01000010),
            method,
            test_type_checker,
        );

        match result {
            MethodHandlerResult::Found(HandlerMatch::Catch { handler_offset, .. }) => {
                assert_eq!(handler_offset, 0x30);
            }
            _ => panic!("Expected to find catch handler"),
        }
    }

    #[test]
    fn test_find_base_exception_catch() {
        let handler = ExceptionHandler::new();
        let clauses = create_test_clauses();
        let method = Token::new(0x06000001);

        // Throw in outer try (but not inner) with unknown type
        // Should match System.Exception catch via the catch-all in test_type_checker
        let result = handler.find_handler(
            &clauses,
            0x05,
            Token::new(0x01000099),
            method,
            test_type_checker,
        );

        match result {
            MethodHandlerResult::ExecuteCleanup { handlers } => {
                // Should have finally + catch
                assert_eq!(handlers.len(), 2);
                assert!(matches!(handlers[0], HandlerMatch::Finally { .. }));
                assert!(matches!(handlers[1], HandlerMatch::Catch { .. }));
            }
            _ => panic!("Expected cleanup handlers"),
        }
    }

    #[test]
    fn test_find_finally_for_leave() {
        let handler = ExceptionHandler::new();
        let clauses = create_test_clauses();
        let method = Token::new(0x06000001);

        // Leave from inside try to outside
        let handlers = handler.find_finally_for_leave(&clauses, 0x20, 0x70, method);

        assert_eq!(handlers.len(), 1);
        match &handlers[0] {
            HandlerMatch::Finally { handler_offset, .. } => {
                assert_eq!(*handler_offset, 0x50);
            }
            _ => panic!("Expected finally handler"),
        }
    }

    #[test]
    fn test_no_handler_found() {
        let handler = ExceptionHandler::new();
        let clauses = vec![ExceptionClause::Catch {
            try_offset: 0x00,
            try_length: 0x10,
            handler_offset: 0x10,
            handler_length: 0x10,
            catch_type: Token::new(0x01000010),
        }];
        let method = Token::new(0x06000001);

        // Throw outside try block
        let result = handler.find_handler(
            &clauses,
            0x50,
            Token::new(0x01000010),
            method,
            test_type_checker,
        );

        assert!(matches!(result, MethodHandlerResult::NotFound));
    }

    #[test]
    fn test_filter_handler() {
        let handler = ExceptionHandler::new();
        let clauses = vec![ExceptionClause::Filter {
            try_offset: 0x00,
            try_length: 0x20,
            handler_offset: 0x30,
            handler_length: 0x10,
            filter_offset: 0x20,
        }];
        let method = Token::new(0x06000001);

        let result = handler.find_handler(
            &clauses,
            0x10,
            Token::new(0x01000010),
            method,
            test_type_checker,
        );

        match result {
            MethodHandlerResult::Found(HandlerMatch::Filter {
                filter_offset,
                handler_offset,
                ..
            }) => {
                assert_eq!(filter_offset, 0x20);
                assert_eq!(handler_offset, 0x30);
            }
            _ => panic!("Expected filter handler"),
        }
    }

    #[test]
    fn test_is_in_handler() {
        let handler = ExceptionHandler::new();
        let clauses = create_test_clauses();

        assert!(!handler.is_in_handler(&clauses, 0x15)); // In try block
        assert!(handler.is_in_handler(&clauses, 0x35)); // In catch handler
        assert!(handler.is_in_handler(&clauses, 0x55)); // In finally handler
    }

    #[test]
    fn test_handler_search_state() {
        let exception_type = Token::new(0x01000010);
        let location = InstructionLocation::new(Token::new(0x06000001), 0x20);

        let mut state = HandlerSearchState::new(exception_type, location);

        assert!(!state.is_complete());
        assert!(!state.has_pending_cleanup());

        state.handler_found = Some(HandlerMatch::Catch {
            method: Token::new(0x06000001),
            handler_offset: 0x30,
        });

        assert!(state.is_complete());
    }
}
