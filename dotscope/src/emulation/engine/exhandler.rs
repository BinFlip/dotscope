//! Exception handling utilities for the emulation engine.
//!
//! This module contains the exception handling support functions used by the
//! [`EmulationController`](super::controller::EmulationController)'s execution
//! loop. It implements the two-pass exception handling model from ECMA-335
//! §III.3.47 (throw) and §12.4.2 (exception handling).
//!
//! # Functions
//!
//! - [`route_clr_exception`] — Top-level exception routing: searches the
//!   current method for a handler, then unwinds the call stack frame by
//!   frame until a matching handler is found or the exception is unhandled.
//! - [`find_exception_handler`] — Searches a single method's exception
//!   handling table for a `catch`/`filter`/`finally`/`fault` clause that
//!   covers the current instruction offset and matches the exception type.
//! - [`schedule_finally_blocks`] — Schedules `finally` blocks for execution
//!   when a `leave` instruction exits a protected region.
//! - [`create_clr_exception`] / [`create_exception_from_type`] — Allocate
//!   synthetic CLR exception objects on the managed heap.
//! - [`wrap_in_target_invocation_exception`] — Wraps an exception in a
//!   `TargetInvocationException`, mirroring reflection invoke semantics.
//! - [`resolve_exception_type`] — Determines the type token of a thrown
//!   exception value by inspecting its `EmValue` kind and heap metadata.
//! - [`apply_handler_match`] — Transfers control to a matched handler,
//!   pushing the exception onto the evaluation stack for `catch`/`filter`.
//! - [`track_cctor_failure_if_needed`] — Records `.cctor` failures in the
//!   [`CctorTracker`] so subsequent type access re-throws the stored exception.
//!
//! # Handler Search Order
//!
//! Exception handlers are searched in the order they appear in the method's
//! exception handling table (innermost-first per ECMA-335). For each clause:
//!
//! 1. Check if the clause's `try` region covers the current offset
//! 2. For `catch` — verify type compatibility via [`EmulationContext::is_type_compatible`]
//! 3. For `filter` — begin filter code execution (the main loop evaluates it)
//! 4. For `finally`/`fault` — schedule for later execution during unwinding
//!
//! # Stack Unwinding
//!
//! When no handler is found in the current method, the controller pops
//! frames from the call stack. At each frame boundary, if the frame was
//! entered via reflection invoke, the exception is wrapped in a
//! `TargetInvocationException` per real .NET behavior.

use crate::{
    emulation::{
        engine::{
            cctors::CctorTracker, context::EmulationContext, error::synthetic_exception,
            interpreter::Interpreter, EmulationError,
        },
        exception::{
            ExceptionClause, ExceptionInfo, HandlerMatch, InstructionLocation, ThreadExceptionState,
        },
        memory::AddressSpace,
        thread::EmulationThread,
        tokens, EmValue,
    },
    metadata::token::Token,
    Result,
};
use log::{debug, trace};

/// Creates a synthetic CLR exception object from an [`EmulationError`].
///
/// Maps the error to its corresponding BCL exception type token via
/// [`EmulationError::to_exception_token`] and allocates a heap object.
///
/// # Arguments
///
/// * `address_space` — The shared address space for heap allocation.
/// * `error` — The emulation error to convert into an exception.
///
/// # Returns
///
/// An `EmValue::ObjectRef` pointing to the newly allocated exception.
///
/// # Errors
///
/// Returns an error if heap allocation fails.
pub fn create_clr_exception(
    address_space: &AddressSpace,
    error: &EmulationError,
) -> Result<EmValue> {
    let type_token = error.to_exception_token();
    let heap_ref = address_space.alloc_object(type_token)?;
    Ok(EmValue::ObjectRef(heap_ref))
}

/// Creates a synthetic CLR exception object from an exception type token.
///
/// Allocates a heap object representing a CLR exception of the given type.
/// Used when hooks or instructions need to throw a specific exception type
/// (e.g., `InvalidOperationException` from a delegate dispatch failure).
///
/// # Arguments
///
/// * `address_space` — The shared address space for heap allocation.
/// * `exception_type` — The synthetic exception type token (e.g.,
///   `synthetic_exception::INVALID_OPERATION`).
///
/// # Returns
///
/// An `EmValue::ObjectRef` pointing to the newly allocated exception.
///
/// # Errors
///
/// Returns an error if heap allocation fails.
pub fn create_exception_from_type(
    address_space: &AddressSpace,
    exception_type: Token,
) -> Result<EmValue> {
    let heap_ref = address_space.alloc_object(exception_type)?;
    Ok(EmValue::ObjectRef(heap_ref))
}

/// Wraps an exception in a `TargetInvocationException`, mirroring real .NET
/// behavior where `MethodBase.Invoke` wraps all target exceptions.
///
/// Creates a new TIE heap object and sets its `InnerException` field to the
/// original exception so that `Exception.get_InnerException` returns it.
///
/// # Arguments
///
/// * `address_space` — The shared address space for heap allocation.
/// * `inner_exception` — The original exception to wrap.
///
/// # Returns
///
/// A tuple `(EmValue::ObjectRef, Token)` containing the TIE object and its
/// type token.
///
/// # Errors
///
/// Returns an error if heap allocation fails.
pub fn wrap_in_target_invocation_exception(
    address_space: &AddressSpace,
    inner_exception: &EmValue,
) -> Result<(EmValue, Token)> {
    let tie_type = synthetic_exception::TARGET_INVOCATION;
    let tie_ref = address_space.alloc_object(tie_type)?;
    // Set InnerException field on the TIE object
    address_space.set_field(
        tie_ref,
        tokens::exception_fields::INNER_EXCEPTION,
        inner_exception.clone(),
    )?;
    Ok((EmValue::ObjectRef(tie_ref), tie_type))
}

/// Routes a CLR exception through CIL exception handling (`catch`/`finally`/`fault`).
///
/// Creates the exception state, searches for a handler in the current method, and
/// if not found, unwinds the call stack looking for handlers in callers.
///
/// # Arguments
///
/// * `address_space` — Shared address space for allocating wrapper exceptions.
/// * `context` — Assembly metadata context for method/type lookup.
/// * `interpreter` — Updated to the handler's entry point if one is found.
/// * `thread` — The emulation thread (frames popped during unwinding).
/// * `current_method` — Token of the method where the exception was thrown.
/// * `exception_type` — Resolved type token of the exception.
/// * `exception` — The exception value (`EmValue::ObjectRef` or other).
///
/// # Returns
///
/// * `Ok(true)` — A handler was found and control was transferred.
/// * `Ok(false)` — The exception is unhandled (caller should return
///   [`EmulationOutcome::UnhandledException`](super::EmulationOutcome::UnhandledException)).
///
/// # Errors
///
/// Returns an error if handler search or heap allocation fails.
pub fn route_clr_exception(
    address_space: &AddressSpace,
    context: &EmulationContext,
    interpreter: &mut Interpreter,
    thread: &mut EmulationThread,
    current_method: Token,
    exception_type: Token,
    exception: EmValue,
) -> Result<bool> {
    let current_offset = interpreter.ip().offset();
    let throw_location = InstructionLocation::new(current_method, current_offset);

    debug!(
        "route_clr_exception: method=0x{:08X} offset=0x{:04X} exc_type=0x{:08X} depth={}",
        current_method.value(),
        current_offset,
        exception_type.value(),
        thread.call_depth()
    );

    // Set up exception state
    if let Some(heap_ref) = exception.as_object_ref() {
        let exception_info = ExceptionInfo::new(heap_ref, exception_type, throw_location);
        thread.exception_state_mut().set_exception(exception_info);
    }

    // Search for exception handler in current method
    if let Some(handler_match) = find_exception_handler(
        context,
        current_method,
        current_offset,
        Some(exception_type),
        thread.exception_state_mut(),
        None,
    )? {
        debug!(
            "  Found handler in current method 0x{:08X}",
            current_method.value()
        );
        thread.stack_mut().clear();
        let target_offset = apply_handler_match(
            &handler_match,
            exception,
            current_offset,
            current_method,
            thread,
        )?;
        interpreter.set_offset(target_offset);
        return Ok(true);
    }

    debug!(
        "  No handler in 0x{:08X}, unwinding...",
        current_method.value()
    );

    // No handler in current method — unwind call stack.
    //
    // Each frame stores: method (the method being executed) and return_offset
    // (the offset in the CALLER where execution resumes after this method returns).
    // When searching for exception handlers in the caller, we need the offset
    // within the caller where the call occurred — that's the return_offset from
    // the frame we're POPPING (the callee), not from the caller's own frame.
    let mut effective_exception_type = exception_type;
    loop {
        if let Some(pending) = thread.exception_state_mut().pop_finally() {
            interpreter.set_method(pending.method);
            interpreter.set_offset(pending.handler_offset);
            thread
                .exception_state_mut()
                .set_leave_target(pending.leave_target);
            return Ok(true);
        }

        // Capture the return_offset from the frame we're about to pop.
        // This is the call site offset in the CALLER method.
        // Also check if the frame was entered via reflection invoke — if so,
        // wrap the exception in TargetInvocationException as real .NET does.
        let (frame_return_offset, frame_is_reflection, frame_method) = thread
            .current_frame()
            .map_or((0, false, Token::new(0)), |f| {
                (f.return_offset(), f.is_reflection_invoke(), f.method())
            });

        // Build stack trace: record the frame being unwound
        if let Some(exc_info) = thread.exception_state_mut().exception_mut() {
            exc_info.push_stack_frame(InstructionLocation::new(frame_method, frame_return_offset));
        }
        if frame_is_reflection {
            let inner = thread
                .exception_state_mut()
                .take_exception_as_value()
                .unwrap_or_else(|| {
                    trace!("No pending exception for extraction in reflection frame");
                    exception.clone()
                });
            if let Ok((tie_val, tie_type)) =
                wrap_in_target_invocation_exception(address_space, &inner)
            {
                effective_exception_type = tie_type;
                if let Some(tie_ref) = tie_val.as_object_ref() {
                    let throw_loc = InstructionLocation::new(frame_method, frame_return_offset);
                    thread
                        .exception_state_mut()
                        .set_exception(ExceptionInfo::new(tie_ref, tie_type, throw_loc));
                }
            }
            debug!(
                "  Wrapping exception in TargetInvocationException (reflection invoke boundary)"
            );
        }

        thread.pop_frame();

        if thread.call_depth() == 0 {
            return Ok(false);
        }

        let caller_frame = thread
            .current_frame()
            .ok_or(EmulationError::InternalError {
                description: "call stack empty during exception unwinding".to_string(),
            })?;
        let caller_method = caller_frame.method();

        if let Some(handler_match) = find_exception_handler(
            context,
            caller_method,
            frame_return_offset,
            Some(effective_exception_type),
            thread.exception_state_mut(),
            None,
        )? {
            let exc = thread
                .exception_state_mut()
                .take_exception_as_value()
                .unwrap_or_else(|| {
                    trace!("No pending exception for extraction");
                    EmValue::Null
                });
            thread.stack_mut().clear();
            let target_offset = apply_handler_match(
                &handler_match,
                exc,
                frame_return_offset,
                caller_method,
                thread,
            )?;
            interpreter.set_method(caller_method);
            interpreter.set_offset(target_offset);
            return Ok(true);
        }
    }
}

/// Finds an exception handler for the given exception at the current offset.
///
/// Searches the method's exception handling table for a handler that covers
/// the current instruction offset and matches the exception type. Handlers
/// are searched in order (innermost first) per ECMA-335.
///
/// # Arguments
///
/// * `context` - The emulation context (for method metadata)
/// * `method_token` - Token of the method to search for handlers
/// * `current_offset` - Current instruction offset within the method
/// * `exception_type` - The resolved type token of the exception (if known)
/// * `exception_state` - Mutable exception state for recording active handlers
/// * `skip_handler_offset` - If provided, skip handlers at or before this offset (for rethrow)
///
/// # Returns
///
/// - `Ok(Some(HandlerMatch))` — A matching handler was found.
/// - `Ok(None)` — No handler matches (exception should propagate).
///
/// # Errors
///
/// Returns an error if the method cannot be resolved from metadata.
#[allow(clippy::too_many_arguments)]
pub fn find_exception_handler(
    context: &EmulationContext,
    method_token: Token,
    current_offset: u32,
    exception_type: Option<Token>,
    exception_state: &mut ThreadExceptionState,
    skip_handler_offset: Option<u32>,
) -> Result<Option<HandlerMatch>> {
    // Get the method's exception handlers — check synthetic methods first
    let clauses = if let Some(handlers) = context.get_synthetic_exception_handlers(method_token) {
        ExceptionClause::from_metadata_handlers(&handlers)
    } else {
        let method = context.get_method(method_token)?;
        let Some(body) = method.body.get() else {
            return Ok(None);
        };
        ExceptionClause::from_metadata_handlers(&body.exception_handlers)
    };

    // Search for a handler that covers the current offset
    // Handlers are processed in order - innermost handlers first (as per ECMA-335)
    for clause in &clauses {
        // Check if this clause's try region covers the current offset
        if !clause.is_in_try(current_offset) {
            continue;
        }

        // For rethrow, skip handlers at or before the current handler
        if let Some(skip_offset) = skip_handler_offset {
            if clause.handler_offset() <= skip_offset {
                continue;
            }
        }

        // Handle based on clause type
        match clause {
            ExceptionClause::Catch { catch_type, .. } => {
                // Check type compatibility
                let is_compatible = match exception_type {
                    Some(exc_token) => context.is_type_compatible(exc_token, *catch_type),
                    // Exception type unknown - accept (best effort)
                    None => true,
                };

                if is_compatible {
                    return Ok(Some(HandlerMatch::Catch {
                        method: method_token,
                        handler_offset: clause.handler_offset(),
                    }));
                }
                // Type mismatch - continue searching
            }

            ExceptionClause::Filter { filter_offset, .. } => {
                // Filter handler - need to execute filter code first
                // Store the handler offset so EndFilter knows where to jump
                let handler_offset = clause.handler_offset();
                exception_state.enter_filter(handler_offset);
                return Ok(Some(HandlerMatch::Filter {
                    method: method_token,
                    filter_offset: *filter_offset,
                    handler_offset,
                }));
            }

            ExceptionClause::Finally { handler_length, .. } => {
                // Finally handler - schedule for execution during unwinding
                exception_state.push_finally(method_token, clause.handler_offset(), None);
                _ = handler_length;
            }

            ExceptionClause::Fault { handler_length, .. } => {
                // Fault handler - like finally but only on exception path
                exception_state.push_finally(method_token, clause.handler_offset(), None);
                _ = handler_length;
            }
        }
    }

    Ok(None)
}

/// Schedules finally blocks to execute when leaving a protected region.
///
/// Finds all `finally` handlers between the current offset and the leave
/// target, and schedules them for execution via the exception state's
/// pending-finally queue. Finally blocks are executed in innermost-first
/// order per ECMA-335.
///
/// # Arguments
///
/// * `context` — Assembly metadata context for method lookup.
/// * `method_token` — Token of the method containing the `leave` instruction.
/// * `current_offset` — Offset of the `leave` instruction.
/// * `leave_target` — Target offset the `leave` instruction wants to jump to.
/// * `exception_state` — Exception state where finally blocks are queued.
///
/// # Errors
///
/// Returns an error if the method's exception handling table cannot be read.
pub fn schedule_finally_blocks(
    context: &EmulationContext,
    method_token: Token,
    current_offset: u32,
    leave_target: u32,
    exception_state: &mut ThreadExceptionState,
) -> Result<()> {
    // Get the method's exception handlers
    let method = context.get_method(method_token)?;
    let Some(body) = method.body.get() else {
        return Ok(());
    };

    // Convert metadata handlers to exception clauses
    let clauses = ExceptionClause::from_metadata_handlers(&body.exception_handlers);

    // Find finally handlers that we're leaving
    // We need to execute finally blocks for any try region we're exiting
    let mut finally_blocks: Vec<(u32, u32)> = Vec::new();

    for clause in &clauses {
        if !clause.is_finally() {
            continue;
        }

        // Check if we're leaving this try region
        let inside_now = clause.is_in_try(current_offset);
        let inside_target = clause.is_in_try(leave_target);

        if inside_now && !inside_target {
            // We're exiting this try region - need to run finally
            finally_blocks.push((clause.handler_offset(), clause.try_offset()));
        }
    }

    // Sort by try_offset descending (innermost first)
    finally_blocks.sort_by_key(|f| std::cmp::Reverse(f.1));

    // Schedule finally blocks in order (innermost first)
    // The last one scheduled will be popped first
    for (i, (handler_offset, _)) in finally_blocks.iter().enumerate() {
        // The last finally should have the actual leave target
        let target = if i == finally_blocks.len().saturating_sub(1) {
            Some(leave_target)
        } else {
            None
        };
        exception_state.push_finally(method_token, *handler_offset, target);
    }

    Ok(())
}

/// Resolves the type token from an exception value.
///
/// Determines the type of an exception by inspecting the value kind and
/// looking up heap objects when necessary.
///
/// # Arguments
///
/// * `exception` — The thrown exception value.
/// * `thread` — The emulation thread (for heap access on `ObjectRef` values).
///
/// # Returns
///
/// - `Some(Token)` for `ObjectRef` (from heap), `ValueType`, or `TypedRef`.
/// - `None` for primitive types or unresolvable values.
pub fn resolve_exception_type(exception: &EmValue, thread: &EmulationThread) -> Option<Token> {
    match exception {
        EmValue::ObjectRef(href) => thread.heap().get_type_token(*href).ok(),
        EmValue::ValueType { type_token, .. } | EmValue::TypedRef { type_token, .. } => {
            Some(*type_token)
        }
        _ => None,
    }
}

/// Applies a handler match result, pushing exception if needed and returning
/// the target offset.
///
/// For catch/filter handlers, pushes the exception onto the evaluation stack
/// so the handler code can access it. For catch handlers, also enters the
/// catch handler state for proper `rethrow` support.
///
/// # Arguments
///
/// * `handler_match` — The matched handler (catch, filter, finally, or fault).
/// * `exception` — The exception value to push for catch/filter handlers.
/// * `origin_offset` — Offset where the exception originated (for catch state).
/// * `method` — Token of the method containing the handler.
/// * `thread` — The emulation thread (for stack push and exception state).
///
/// # Returns
///
/// The instruction offset to jump to for handler execution.
///
/// # Errors
///
/// Returns an error if pushing the exception onto the evaluation stack fails.
pub fn apply_handler_match(
    handler_match: &HandlerMatch,
    exception: EmValue,
    origin_offset: u32,
    method: Token,
    thread: &mut EmulationThread,
) -> Result<u32> {
    match handler_match {
        HandlerMatch::Catch { handler_offset, .. } => {
            thread.push(exception)?;
            thread.exception_state_mut().enter_catch_handler(
                method,
                origin_offset,
                *handler_offset,
            );
            Ok(*handler_offset)
        }
        HandlerMatch::Filter { filter_offset, .. } => {
            thread.push(exception)?;
            Ok(*filter_offset)
        }
        HandlerMatch::Finally { handler_offset, .. }
        | HandlerMatch::Fault { handler_offset, .. } => Ok(*handler_offset),
    }
}

/// Wraps an exception in a `TypeInitializationException`.
///
/// Per ECMA-335, when a .cctor throws, the exception is wrapped in a
/// `TypeInitializationException` with the failing type's name as the message
/// and the original exception as `InnerException`.
///
/// # Arguments
///
/// * `address_space` — The shared address space for heap allocation.
/// * `inner_exception` — The original exception thrown by the .cctor.
/// * `type_name` — The name of the type whose .cctor failed.
///
/// # Returns
///
/// A tuple `(EmValue::ObjectRef, Token)` containing the TIE object and its type token.
///
/// # Errors
///
/// Returns an error if heap allocation fails.
pub fn wrap_in_type_initialization_exception(
    address_space: &AddressSpace,
    inner_exception: &EmValue,
    type_name: &str,
) -> Result<(EmValue, Token)> {
    let tie_type = synthetic_exception::TYPE_INITIALIZATION;
    let tie_ref = address_space.alloc_object(tie_type)?;

    // Set Message field to the failing type's name
    address_space.set_field(
        tie_ref,
        tokens::exception_fields::MESSAGE,
        EmValue::ObjectRef(address_space.heap().alloc_string(type_name)?),
    )?;

    // Set InnerException field to the original exception
    address_space.set_field(
        tie_ref,
        tokens::exception_fields::INNER_EXCEPTION,
        inner_exception.clone(),
    )?;

    Ok((EmValue::ObjectRef(tie_ref), tie_type))
}

/// Records a `.cctor` failure if the current frame is a static constructor.
///
/// When an exception escapes a `.cctor`, the CLR marks the type as
/// permanently failed. Subsequent accesses to that type re-throw the
/// stored exception. This function checks whether the current frame is a
/// `.cctor` and, if so, stores the exception in the [`CctorTracker`].
///
/// # Arguments
///
/// * `cctor_tracker` — Tracker for recording type initialization failures.
/// * `thread` — The emulation thread (for inspecting the current frame).
/// * `exception` — The exception value escaping the `.cctor`.
/// * `context` — Assembly metadata context for resolving the declaring type.
///
/// # Errors
///
/// Returns an error if heap allocation or cctor tracker operations fail.
pub fn track_cctor_failure_if_needed(
    cctor_tracker: &CctorTracker,
    thread: &EmulationThread,
    exception: &EmValue,
    context: &EmulationContext,
) -> Result<()> {
    let Some(frame) = thread.current_frame() else {
        return Ok(());
    };
    if !frame.is_cctor() {
        return Ok(());
    }

    // Find the type that owns this .cctor
    let cctor_token = frame.method();
    let Some(type_token) = context
        .assembly()
        .resolver()
        .declaring_type(cctor_token)
        .map(|t| t.token)
    else {
        return Ok(());
    };

    // Store the exception — use the heap ref if it's an ObjectRef,
    // otherwise allocate a string object describing the error
    let exception_ref = match exception {
        EmValue::ObjectRef(href) => *href,
        other => {
            let desc = format!("TypeInitializationException: {other}");
            thread.heap().alloc_string(&desc)?
        }
    };

    cctor_tracker.mark_type_failed(type_token, exception_ref)?;
    Ok(())
}
