//! High-level emulation controller.
//!
//! The [`EmulationController`] orchestrates method emulation, managing the
//! execution loop, call stack, method resolution, and exception handling.
//!
//! # Architecture
//!
//! The controller sits between the low-level [`Interpreter`] and the high-level
//! [`EmulationProcess`](crate::emulation::process::EmulationProcess). It handles:
//!
//! - **Call resolution**: Dispatches to method hooks or emulated code
//! - **Virtual dispatch**: Resolves virtual method calls based on runtime type
//! - **Exception handling**: Manages try/catch/finally blocks and stack unwinding
//! - **Memory management**: Coordinates heap, statics, and stack through [`AddressSpace`]
//!
//! # Execution Model
//!
//! The controller uses a step-based execution loop:
//!
//! 1. Fetch the instruction at the current IP
//! 2. Execute via the interpreter, producing a [`StepResult`]
//! 3. Handle the result (branch, call, return, exception, etc.)
//! 4. Repeat until completion or limit reached
//!
//! [`Interpreter`]: crate::emulation::engine::Interpreter
//! [`AddressSpace`]: crate::emulation::memory::AddressSpace
//! [`StepResult`]: crate::emulation::engine::StepResult

use std::sync::{Arc, RwLock};

use crate::{
    emulation::{
        capture::CaptureContext,
        engine::{
            context::EmulationContext,
            interpreter::Interpreter,
            result::{EmulationOutcome, StepResult},
            trace::{TraceEvent, TraceWriter},
            EmulationError,
        },
        exception::{
            ExceptionClause, ExceptionInfo, HandlerMatch, InstructionLocation, ThreadExceptionState,
        },
        fakeobjects::SharedFakeObjects,
        memory::AddressSpace,
        process::{EmulationConfig, EmulationLimits, UnknownMethodBehavior},
        runtime::{get_bcl_static_field, HookContext, HookOutcome, RuntimeState},
        thread::{EmulationThread, ThreadCallFrame},
        EmValue, PointerTarget, SymbolicValue, TaintSource, ThreadId,
    },
    metadata::{
        signatures::TypeSignature,
        tables::{MemberRefSignature, StandAloneSignature, TableId},
        token::Token,
        typesystem::CilFlavor,
    },
    CilObject, Result,
};

/// High-level controller for CIL method emulation.
///
/// The `EmulationController` provides the main entry point for emulating .NET
/// methods. It manages:
/// - Method execution with proper call stack handling
/// - Method hook resolution for framework methods
/// - Exception handling
/// - Execution limits and timeouts
///
/// All memory operations go through the shared `AddressSpace`, which manages:
/// - Managed heap (shared across all executions)
/// - Static field storage
/// - Mapped memory regions (PE images, raw data)
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::emulation::{EmulationController, EmValue, ProcessBuilder};
/// use dotscope::CilObject;
/// use std::sync::Arc;
///
/// let assembly = Arc::new(CilObject::from_path("test.dll")?);
/// let process = ProcessBuilder::new()
///     .assembly_arc(assembly.clone())
///     .build()?;
///
/// // Use process.execute_method() instead of controller directly
/// let result = process.execute_method(method_token, vec![EmValue::I32(42)])?;
/// ```
pub struct EmulationController {
    /// Shared address space for all memory operations.
    address_space: Arc<AddressSpace>,

    /// Shared runtime state (for stubs).
    runtime: Arc<RwLock<RuntimeState>>,

    /// Capture context for collecting results during emulation.
    capture: Arc<CaptureContext>,

    /// Emulation configuration.
    config: Arc<EmulationConfig>,

    /// Assembly being emulated (provides metadata/type system access).
    assembly: Option<Arc<CilObject>>,

    /// Pre-allocated fake BCL objects shared across all threads.
    fake_objects: SharedFakeObjects,

    /// Optional trace writer for debugging execution.
    trace_writer: Option<Arc<TraceWriter>>,
}

impl EmulationController {
    /// Creates a new emulation controller with shared infrastructure.
    ///
    /// All infrastructure components are required:
    /// - `address_space` - Unified memory for heap, statics, and mapped regions
    /// - `runtime` - Stub registry and runtime state
    /// - `capture` - Context for capturing execution results
    /// - `config` - Emulation configuration and limits
    /// - `assembly` - Optional assembly for metadata access in stubs
    /// - `fake_objects` - Pre-allocated fake BCL objects for consistent references
    /// - `trace_writer` - Optional trace writer for debugging
    #[must_use]
    pub fn new(
        address_space: Arc<AddressSpace>,
        runtime: Arc<RwLock<RuntimeState>>,
        capture: Arc<CaptureContext>,
        config: Arc<EmulationConfig>,
        assembly: Option<Arc<CilObject>>,
        fake_objects: SharedFakeObjects,
        trace_writer: Option<Arc<TraceWriter>>,
    ) -> Self {
        EmulationController {
            address_space,
            runtime,
            capture,
            config,
            assembly,
            fake_objects,
            trace_writer,
        }
    }

    /// Returns a reference to the shared fake objects.
    #[must_use]
    pub fn fake_objects(&self) -> &SharedFakeObjects {
        &self.fake_objects
    }

    /// Returns a reference to the address space.
    #[must_use]
    pub fn address_space(&self) -> &Arc<AddressSpace> {
        &self.address_space
    }

    /// Returns a reference to the runtime state.
    #[must_use]
    pub fn runtime(&self) -> &Arc<RwLock<RuntimeState>> {
        &self.runtime
    }

    /// Returns a reference to the capture context.
    #[must_use]
    pub fn capture(&self) -> &Arc<CaptureContext> {
        &self.capture
    }

    /// Returns a reference to the emulation config.
    #[must_use]
    pub fn config(&self) -> &Arc<EmulationConfig> {
        &self.config
    }

    /// Returns a reference to the assembly being emulated.
    ///
    /// This provides stubs access to metadata, type information, and PE data.
    #[must_use]
    pub fn assembly(&self) -> Option<&Arc<CilObject>> {
        self.assembly.as_ref()
    }

    /// Returns the execution limits.
    #[must_use]
    pub fn limits(&self) -> &EmulationLimits {
        &self.config.limits
    }

    /// Creates a synthetic CLR exception object from an emulation error.
    ///
    /// This allocates an exception object on the managed heap with the appropriate
    /// type token. The exception can then be thrown and caught by exception handlers.
    fn create_clr_exception(&self, error: &EmulationError) -> Result<EmValue> {
        let type_token = error.to_exception_token();
        let heap_ref = self.address_space.alloc_object(type_token)?;
        Ok(EmValue::ObjectRef(heap_ref))
    }

    /// Writes a trace event if tracing is enabled.
    #[inline]
    fn trace(&self, event: TraceEvent) {
        if let Some(ref writer) = self.trace_writer {
            writer.write(event);
        }
    }

    /// Checks if instruction tracing is enabled.
    #[inline]
    fn trace_instructions_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.config.tracing.trace_instructions
    }

    /// Checks if call tracing is enabled.
    #[inline]
    fn trace_calls_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.config.tracing.trace_calls
    }

    /// Checks if exception tracing is enabled.
    #[inline]
    fn trace_exceptions_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.config.tracing.trace_exceptions
    }

    /// Checks if array operation tracing is enabled.
    #[inline]
    fn trace_array_ops_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.config.tracing.trace_array_ops
    }

    /// Emulates a method with the given arguments.
    ///
    /// This is the main entry point for method emulation. It sets up the
    /// execution context and runs the method to completion.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method to emulate
    /// * `args` - Arguments to pass to the method
    /// * `assembly` - The loaded assembly containing the method
    ///
    /// # Errors
    ///
    /// Returns an error if method setup fails, an unrecoverable error occurs,
    /// or an internal invariant is violated (e.g., empty call stack).
    pub fn emulate_method(
        &mut self,
        method_token: Token,
        args: Vec<EmValue>,
        assembly: Arc<CilObject>,
    ) -> Result<EmulationOutcome> {
        let context = EmulationContext::new(assembly);

        // Create interpreter
        let mut interpreter = Interpreter::new(
            self.config.limits.clone(),
            Arc::clone(&self.address_space),
            self.config.pointer_size,
        );
        interpreter.start();

        // Create emulation thread with initial call frame
        let mut thread = self.create_thread_for_method(&context, method_token, args)?;

        // Set interpreter to the method
        interpreter.set_method(method_token);

        // Run the execution loop
        self.run_execution_loop(&mut interpreter, &mut thread, &context)
    }

    /// Emulates a method until a specific condition is met.
    ///
    /// Useful for patterns like "emulate until ldstr" for string decryption.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method to emulate
    /// * `args` - Arguments to pass to the method
    /// * `assembly` - The loaded assembly containing the method
    /// * `condition` - A closure that returns `true` when emulation should stop
    ///
    /// # Errors
    ///
    /// Returns an error if method setup fails, an unrecoverable error occurs,
    /// or an internal invariant is violated (e.g., empty call stack).
    pub fn emulate_until<F>(
        &mut self,
        method_token: Token,
        args: Vec<EmValue>,
        assembly: Arc<CilObject>,
        condition: F,
    ) -> Result<EmulationOutcome>
    where
        F: Fn(&StepResult, &EmulationThread) -> bool,
    {
        let context = EmulationContext::new(assembly);

        // Create interpreter
        let mut interpreter = Interpreter::new(
            self.config.limits.clone(),
            Arc::clone(&self.address_space),
            self.config.pointer_size,
        );
        interpreter.start();

        // Create emulation thread with initial call frame
        let mut thread = self.create_thread_for_method(&context, method_token, args)?;

        // Set interpreter to the method
        interpreter.set_method(method_token);

        // Run with condition check
        self.run_execution_loop_with_condition(&mut interpreter, &mut thread, &context, condition)
    }

    /// Creates an emulation thread for a method.
    ///
    /// This creates a thread with the initial call frame set up based on the method's
    /// local variables and the provided arguments. The thread shares the controller's
    /// address space.
    ///
    /// # Arguments
    ///
    /// * `context` - The emulation context providing method metadata
    /// * `method_token` - Token of the method to create a thread for
    /// * `args` - Arguments to pass to the method
    ///
    /// # Returns
    ///
    /// A new [`EmulationThread`] configured to execute the specified method.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method metadata lookup fails
    /// - Local variable type resolution fails
    fn create_thread_for_method(
        &self,
        context: &EmulationContext,
        method_token: Token,
        args: Vec<EmValue>,
    ) -> Result<EmulationThread> {
        // Get method info
        let is_instance = !context.is_static_method(method_token)?;
        let local_types = context.get_local_types(method_token)?;

        // Local types are already Vec<CilFlavor>
        let local_cil_flavors = local_types;

        // Get argument types from method signature
        let param_types = context.get_parameter_types(method_token)?;
        let arg_types: Vec<CilFlavor> = if is_instance {
            // Instance methods have 'this' as first argument
            let mut types = vec![CilFlavor::Object];
            types.extend(param_types);
            types
        } else {
            param_types
        };

        // Create the thread with shared address space, capture context, assembly, and fake objects
        let mut thread = EmulationThread::new(
            ThreadId::MAIN,
            Arc::clone(&self.address_space),
            Arc::clone(&self.capture),
            self.assembly.clone(),
            self.fake_objects.clone(),
        );

        // Combine args with their types
        let args_with_types: Vec<(EmValue, CilFlavor)> = args.into_iter().zip(arg_types).collect();

        // Start the method - this pushes the initial ThreadCallFrame
        thread.start_method(method_token, local_cil_flavors, args_with_types, false);

        Ok(thread)
    }

    /// Runs the main execution loop until completion or limit reached.
    ///
    /// This is a convenience wrapper around [`run_execution_loop_with_condition`](Self::run_execution_loop_with_condition)
    /// that runs without any early stopping condition.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter for executing instructions
    /// * `thread` - The emulation thread with call stack and evaluation stack
    /// * `context` - The emulation context providing method metadata
    ///
    /// # Returns
    ///
    /// The outcome of execution - completion, limit reached, or error.
    ///
    /// # Errors
    ///
    /// Returns an error if instruction fetch or execution fails.
    fn run_execution_loop(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
    ) -> Result<EmulationOutcome> {
        self.run_execution_loop_with_condition(
            interpreter,
            thread,
            context,
            |_, _| false, // Never stop early
        )
    }

    /// Runs the execution loop with an optional early stopping condition.
    ///
    /// This is the core execution loop that fetches and executes instructions,
    /// handles branching, method calls, returns, and exception handling.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter for executing instructions
    /// * `thread` - The emulation thread with call stack and evaluation stack
    /// * `context` - The emulation context providing method metadata
    /// * `condition` - A closure that returns `true` to stop execution early.
    ///   Called after each step with the result and thread state.
    ///
    /// # Returns
    ///
    /// The outcome of execution:
    /// - [`EmulationOutcome::Completed`] - Method finished normally
    /// - [`EmulationOutcome::Stopped`] - Condition triggered early stop
    /// - [`EmulationOutcome::LimitReached`] - Execution limit hit
    /// - [`EmulationOutcome::Faulted`] - Unhandled exception
    ///
    /// # Errors
    ///
    /// Returns an error if instruction fetch or execution fails.
    fn run_execution_loop_with_condition<F>(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        condition: F,
    ) -> Result<EmulationOutcome>
    where
        F: Fn(&StepResult, &EmulationThread) -> bool,
    {
        // Clear any previous exception state at the start of the execution loop
        thread.exception_state_mut().clear();

        loop {
            // Check all limits (instruction count, call depth, timeout)
            if let Some(limit_exceeded) = interpreter
                .stats()
                .check_limits(&self.config.limits, thread.call_depth())
            {
                return Ok(EmulationOutcome::LimitReached {
                    limit: limit_exceeded,
                    partial_state: None,
                });
            }

            // Get current method
            let current_method = match thread.current_frame() {
                Some(frame) => frame.method(),
                None => {
                    // Stack is empty - we've returned from the entry method
                    return Ok(EmulationOutcome::Completed {
                        return_value: None,
                        instructions: interpreter.stats().instructions_executed,
                    });
                }
            };

            // Get the instruction at current offset
            let instruction =
                context.get_instruction_at(current_method, interpreter.ip().offset())?;

            // Trace instruction if enabled
            if self.trace_instructions_enabled() {
                let offset = interpreter.ip().offset();
                let opcode = if instruction.prefix == 0xFE {
                    u16::from(instruction.prefix) << 8 | u16::from(instruction.opcode)
                } else {
                    u16::from(instruction.opcode)
                };

                self.trace(TraceEvent::Instruction {
                    method: current_method,
                    offset,
                    opcode,
                    mnemonic: instruction.mnemonic.to_string(),
                    operand: instruction.operand.as_string(),
                    stack_depth: thread.stack().depth(),
                });
            }

            // Capture array store info before execution if tracing
            // stelem opcodes: 0x9B-0xA2 (no prefix) or 0xA4 (FE prefix)
            let array_store_info = if self.trace_array_ops_enabled() {
                let is_stelem = matches!(instruction.opcode, 0x9B..=0xA2)
                    || (instruction.prefix == 0xFE && instruction.opcode == 0xA4);
                if is_stelem && thread.stack().depth() >= 3 {
                    // Stack: [array_ref, index, value] - peek all three
                    let value = thread.stack().peek_at(0).ok().cloned();
                    let index = thread.stack().peek_at(1).ok().cloned();
                    let array_ref = thread.stack().peek_at(2).ok().cloned();
                    Some((array_ref, index, value, interpreter.ip().offset()))
                } else {
                    None
                }
            } else {
                None
            };

            // Execute the instruction, converting certain runtime errors to exceptions
            let step_result = match interpreter.step(thread, &instruction) {
                Ok(result) => result,
                Err(err) => {
                    // Check if this is a runtime error that should be a CLR exception
                    if let crate::Error::Emulation(ref emu_err) = err {
                        if emu_err.is_clr_exception() {
                            // Trace the runtime exception if enabled
                            if self.trace_exceptions_enabled() {
                                let offset = interpreter.ip().offset();
                                // Get a simple type name for the error
                                let error_type = match &**emu_err {
                                    EmulationError::ArrayIndexOutOfBounds { .. } => {
                                        "ArrayIndexOutOfBounds"
                                    }
                                    EmulationError::NullReference => "NullReference",
                                    EmulationError::DivisionByZero => "DivisionByZero",
                                    EmulationError::ArithmeticOverflow => "ArithmeticOverflow",
                                    EmulationError::InvalidCast { .. } => "InvalidCast",
                                    _ => "RuntimeException",
                                };
                                self.trace(TraceEvent::RuntimeException {
                                    method: current_method,
                                    offset,
                                    error_type: error_type.to_string(),
                                    description: emu_err.description(),
                                });
                            }

                            // Convert emulation error to a CLR exception and search for handlers
                            let exception = self.create_clr_exception(emu_err)?;
                            let exception_type = emu_err.to_exception_token();

                            let current_offset = interpreter.ip().offset();
                            let throw_location =
                                InstructionLocation::new(current_method, current_offset);

                            // Set up exception state
                            if let Some(heap_ref) = exception.as_object_ref() {
                                let exception_info =
                                    ExceptionInfo::new(heap_ref, exception_type, throw_location);
                                thread.exception_state_mut().set_exception(exception_info);
                            }

                            // Search for exception handler in current method
                            if let Some(handler_match) = Self::find_exception_handler(
                                context,
                                current_method,
                                current_offset,
                                Some(exception_type),
                                thread.exception_state_mut(),
                                None,
                            )? {
                                // Found handler - transfer control
                                thread.stack_mut().clear();
                                let target_offset = Self::apply_handler_match(
                                    &handler_match,
                                    exception,
                                    current_offset,
                                    thread,
                                )?;
                                interpreter.set_offset(target_offset);
                                continue; // Continue execution at handler
                            }

                            // No handler in current method - unwind call stack
                            loop {
                                // Check for pending finally blocks
                                if let Some(pending) = thread.exception_state_mut().pop_finally() {
                                    interpreter.set_method(pending.method);
                                    interpreter.set_offset(pending.handler_offset);
                                    thread
                                        .exception_state_mut()
                                        .set_leave_target(pending.leave_target);
                                    break;
                                }

                                // Pop call frame
                                thread.pop_frame();

                                if thread.call_depth() == 0 {
                                    // Unhandled exception
                                    return Ok(EmulationOutcome::UnhandledException {
                                        exception: thread
                                            .exception_state_mut()
                                            .take_exception_as_value()
                                            .unwrap_or(exception),
                                        instructions: interpreter.stats().instructions_executed,
                                    });
                                }

                                // Search for handler in caller
                                let caller_frame = thread.current_frame().ok_or(
                                    EmulationError::InternalError {
                                        description: "call stack empty during exception unwinding"
                                            .to_string(),
                                    },
                                )?;
                                let caller_method = caller_frame.method();
                                let caller_offset = caller_frame.return_offset();

                                if let Some(handler_match) = Self::find_exception_handler(
                                    context,
                                    caller_method,
                                    caller_offset,
                                    Some(exception_type),
                                    thread.exception_state_mut(),
                                    None,
                                )? {
                                    // Found handler in caller
                                    let exc = thread
                                        .exception_state_mut()
                                        .take_exception_as_value()
                                        .unwrap_or(EmValue::Null);
                                    thread.stack_mut().clear();
                                    let target_offset = Self::apply_handler_match(
                                        &handler_match,
                                        exc,
                                        caller_offset,
                                        thread,
                                    )?;
                                    interpreter.set_method(caller_method);
                                    interpreter.set_offset(target_offset);
                                    break;
                                }
                            }
                            continue; // Continue execution at handler or finally
                        }
                    }
                    // Not a convertible error - propagate it
                    return Err(err);
                }
            };

            // Check condition before handling result
            if condition(&step_result, thread) {
                return Ok(EmulationOutcome::Stopped {
                    reason: "Condition met".to_string(),
                    instructions: interpreter.stats().instructions_executed,
                });
            }

            // Emit array store trace event if we captured one
            if let Some((Some(EmValue::ObjectRef(href)), Some(index), Some(value), offset)) =
                array_store_info
            {
                // Convert index to usize
                let idx = match index {
                    EmValue::I32(i) => Some(i.cast_unsigned() as usize),
                    #[allow(clippy::cast_possible_truncation)]
                    EmValue::NativeInt(i) => Some(i.cast_unsigned() as usize),
                    _ => None,
                };
                if let Some(idx) = idx {
                    self.trace(TraceEvent::ArrayStore {
                        method: current_method,
                        offset,
                        heap_ref: href.id(),
                        index: idx,
                        value: format!("{value:?}"),
                    });
                }
            }

            // Handle the step result
            match step_result {
                StepResult::Continue => {
                    // IP was already advanced by interpreter
                }

                StepResult::Branch { target } => {
                    // Convert RVA to method-relative offset
                    let method_offset = context.rva_to_method_offset(current_method, target)?;

                    // Trace branch if enabled
                    if self.trace_instructions_enabled() {
                        self.trace(TraceEvent::Branch {
                            method: current_method,
                            from_offset: interpreter.ip().offset(),
                            to_offset: method_offset,
                            conditional: true, // Could be refined based on opcode
                        });
                    }

                    interpreter.set_offset(method_offset);
                }

                StepResult::Return { value: _ } => {
                    // Get return value from stack if method returns value
                    let return_value = if context.method_returns_value(current_method)? {
                        Some(thread.pop()?)
                    } else {
                        None
                    };

                    // Trace return if enabled
                    if self.trace_calls_enabled() {
                        self.trace(TraceEvent::MethodReturn {
                            method: current_method,
                            has_return_value: return_value.is_some(),
                            call_depth: thread.call_depth(),
                        });
                    }

                    // Pop the call frame (this is the callee's frame)
                    let mut popped_frame = thread.pop_frame();

                    if thread.call_depth() == 0 {
                        // Returned from entry method
                        return Ok(EmulationOutcome::Completed {
                            return_value,
                            instructions: interpreter.stats().instructions_executed,
                        });
                    }

                    // Restore caller's state
                    if let Some(callee_frame) = &mut popped_frame {
                        // Restore caller's evaluation stack (saved in the callee's frame)
                        let caller_stack = callee_frame.take_caller_stack();
                        thread.restore_stack(caller_stack);

                        // Restore instruction pointer
                        if let Some(return_method) = callee_frame.return_method() {
                            interpreter.set_method(return_method);
                            interpreter.set_offset(callee_frame.return_offset());
                        }
                    }

                    // Push return value onto caller's stack
                    if let Some(value) = return_value {
                        thread.push(value)?;
                    }
                }

                StepResult::Call {
                    method,
                    args: _,
                    is_virtual,
                } => {
                    self.handle_call(interpreter, thread, context, method, is_virtual)?;
                }

                StepResult::CallIndirect {
                    signature,
                    function_pointer,
                } => {
                    self.handle_calli(interpreter, thread, context, signature, &function_pointer)?;
                }

                StepResult::NewObj {
                    constructor,
                    args: _,
                } => {
                    self.handle_newobj(interpreter, thread, context, constructor)?;
                }

                StepResult::NewArray {
                    element_type,
                    length,
                } => {
                    Self::handle_newarr(thread, context, element_type, length)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::LoadString { token } => {
                    Self::handle_ldstr(thread, context, token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::LoadStaticField { field } => {
                    // Check if we need to initialize the field's owner type first
                    if self.maybe_run_type_cctor(interpreter, thread, context, field) {
                        // .cctor was pushed - don't advance IP so ldsfld re-executes after .cctor returns
                        continue;
                    }
                    self.handle_ldsfld(thread, context, field)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::StoreStaticField { field, value } => {
                    // Check if we need to initialize the field's owner type first
                    // IMPORTANT: Push the value back BEFORE calling maybe_run_type_cctor
                    // because maybe_run_type_cctor saves the caller's stack. If we push
                    // after, we'd be pushing onto the .cctor's stack instead.
                    thread.push(value.clone())?;
                    if self.maybe_run_type_cctor(interpreter, thread, context, field) {
                        // .cctor was pushed - the value is already on the saved caller stack
                        // stsfld will re-execute after .cctor returns and pop it again
                        continue;
                    }
                    // No .cctor needed - pop the value we just pushed and store it
                    let _ = thread.pop()?;
                    self.address_space.set_static(field, value);
                    interpreter.ip_mut().advance_current();
                }

                StepResult::Throw { exception } => {
                    // Set the exception in our state and try to find a handler
                    let current_offset = interpreter.ip().offset();

                    // Resolve exception type and create exception info
                    let exception_type = Self::resolve_exception_type(&exception, thread);
                    let throw_location = InstructionLocation::new(current_method, current_offset);

                    // Trace exception throw if enabled
                    if self.trace_exceptions_enabled() {
                        self.trace(TraceEvent::ExceptionThrow {
                            method: current_method,
                            offset: current_offset,
                            exception_type,
                            description: format!("{exception:?}"),
                        });
                    }

                    // In valid CIL, only object references can be thrown
                    // We need both the heap reference and the resolved type
                    match (exception.as_object_ref(), exception_type) {
                        (Some(heap_ref), Some(type_token)) => {
                            let exception_info =
                                ExceptionInfo::new(heap_ref, type_token, throw_location);
                            thread.exception_state_mut().set_exception(exception_info);
                        }
                        (None, _) => {
                            // Non-object throws are invalid CIL
                            return Err(EmulationError::InvalidOperand {
                                instruction: "throw",
                                expected: "object reference",
                            }
                            .into());
                        }
                        (Some(_), None) => {
                            // Could not resolve exception type
                            return Err(EmulationError::TypeMismatch {
                                operation: "throw",
                                expected: "resolvable exception type",
                                found: "unresolved type",
                            }
                            .into());
                        }
                    }
                    // Try to find an exception handler in the current method
                    if let Some(handler_match) = Self::find_exception_handler(
                        context,
                        current_method,
                        current_offset,
                        exception_type,
                        thread.exception_state_mut(),
                        None, // No handler to skip on initial throw
                    )? {
                        // Found a handler - transfer control to it
                        thread.stack_mut().clear();

                        // Apply handler and get target offset
                        let target_offset = Self::apply_handler_match(
                            &handler_match,
                            exception,
                            current_offset,
                            thread,
                        )?;
                        interpreter.set_offset(target_offset);
                    } else {
                        // No handler found - unwind the call stack
                        loop {
                            // Check for pending finally blocks
                            if let Some(pending) = thread.exception_state_mut().pop_finally() {
                                // Execute the finally block
                                interpreter.set_method(pending.method);
                                interpreter.set_offset(pending.handler_offset);
                                thread
                                    .exception_state_mut()
                                    .set_leave_target(pending.leave_target);
                                break;
                            }

                            // Pop the current frame
                            thread.pop_frame();

                            if thread.call_depth() == 0 {
                                // No more frames - exception is unhandled
                                return Ok(EmulationOutcome::UnhandledException {
                                    exception: thread
                                        .exception_state_mut()
                                        .take_exception_as_value()
                                        .unwrap_or(EmValue::Null),
                                    instructions: interpreter.stats().instructions_executed,
                                });
                            }

                            // Try to find a handler in the caller
                            let caller_frame =
                                thread
                                    .current_frame()
                                    .ok_or(EmulationError::InternalError {
                                        description: "call stack empty during exception unwinding"
                                            .to_string(),
                                    })?;
                            let caller_method = caller_frame.method();
                            let caller_offset = caller_frame.return_offset();

                            // Get exception to avoid borrow conflict
                            let exc_clone = thread
                                .exception_state_mut()
                                .get_exception_value()
                                .ok_or(EmulationError::InternalError {
                                    description: "exception state empty during exception handling"
                                        .to_string(),
                                })?;

                            // Resolve exception type for the cloned exception
                            let exc_type = Self::resolve_exception_type(&exc_clone, thread);

                            if let Some(handler_match) = Self::find_exception_handler(
                                context,
                                caller_method,
                                caller_offset,
                                exc_type,
                                thread.exception_state_mut(),
                                None, // No handler to skip when unwinding to caller
                            )? {
                                // Found a handler in caller
                                let exc = thread
                                    .exception_state_mut()
                                    .take_exception_as_value()
                                    .unwrap_or(EmValue::Null);
                                thread.stack_mut().clear();

                                // Apply handler and get target offset
                                let target_offset = Self::apply_handler_match(
                                    &handler_match,
                                    exc,
                                    caller_offset,
                                    thread,
                                )?;

                                interpreter.set_method(caller_method);
                                interpreter.set_offset(target_offset);
                                break;
                            }
                        }
                    }
                }

                StepResult::Leave { target } => {
                    // Leave is used to exit a protected region (try/catch/finally).
                    // It clears the evaluation stack and schedules finally blocks.
                    thread.stack_mut().clear();

                    // If leaving a catch handler normally, clear exception tracking
                    if thread
                        .exception_state_mut()
                        .current_handler_offset()
                        .is_some()
                    {
                        thread.exception_state_mut().leave_catch_handler();
                    }

                    // Convert RVA target to method-relative offset
                    let method_target = context.rva_to_method_offset(current_method, target)?;

                    // Find and schedule any finally blocks between current offset and target
                    let current_offset = interpreter.ip().offset();
                    Self::schedule_finally_blocks(
                        context,
                        current_method,
                        current_offset,
                        method_target,
                        thread.exception_state_mut(),
                    )?;

                    // If there are pending finally blocks, execute them first
                    if let Some(pending) = thread.exception_state_mut().pop_finally() {
                        // Trace branch to finally handler
                        if self.trace_instructions_enabled() {
                            self.trace(TraceEvent::FinallyEnter {
                                method: pending.method,
                                handler_offset: pending.handler_offset,
                            });
                        }
                        interpreter.set_method(pending.method);
                        interpreter.set_offset(pending.handler_offset);
                        thread
                            .exception_state_mut()
                            .set_leave_target(pending.leave_target);
                    } else {
                        // No finally blocks - go directly to target
                        // Trace branch to leave target
                        if self.trace_instructions_enabled() {
                            self.trace(TraceEvent::Branch {
                                method: current_method,
                                from_offset: current_offset,
                                to_offset: method_target,
                                conditional: false,
                            });
                        }
                        interpreter.set_offset(method_target);
                    }
                }

                StepResult::EndFinally => {
                    // EndFinally marks the end of a finally or fault handler.
                    let from_offset = interpreter.ip().offset();
                    if thread.exception_state_mut().has_exception() {
                        // Exception is propagating - continue unwinding
                        if let Some(pending) = thread.exception_state_mut().pop_finally() {
                            // Trace branch to next finally
                            if self.trace_instructions_enabled() {
                                self.trace(TraceEvent::FinallyEnter {
                                    method: pending.method,
                                    handler_offset: pending.handler_offset,
                                });
                            }
                            // More finally blocks to execute
                            interpreter.set_method(pending.method);
                            interpreter.set_offset(pending.handler_offset);
                            thread
                                .exception_state_mut()
                                .set_leave_target(pending.leave_target);
                        } else {
                            // No more finally blocks - check for handlers in caller
                            thread.pop_frame();
                            if thread.call_depth() == 0 {
                                return Ok(EmulationOutcome::UnhandledException {
                                    exception: thread
                                        .exception_state_mut()
                                        .take_exception_as_value()
                                        .unwrap_or(EmValue::Null),
                                    instructions: interpreter.stats().instructions_executed,
                                });
                            }
                            // Continue unwinding in caller
                            let caller_frame =
                                thread
                                    .current_frame()
                                    .ok_or(EmulationError::InternalError {
                                        description: "call stack empty during finally unwinding"
                                            .to_string(),
                                    })?;
                            interpreter.set_method(caller_frame.method());
                        }
                    } else if let Some(target) = thread.exception_state_mut().take_leave_target() {
                        // Normal leave - continue to leave target
                        if let Some(pending) = thread.exception_state_mut().pop_finally() {
                            // Trace branch to next finally
                            if self.trace_instructions_enabled() {
                                self.trace(TraceEvent::FinallyEnter {
                                    method: pending.method,
                                    handler_offset: pending.handler_offset,
                                });
                            }
                            // More finally blocks before reaching target
                            interpreter.set_method(pending.method);
                            interpreter.set_offset(pending.handler_offset);
                            thread
                                .exception_state_mut()
                                .set_leave_target(pending.leave_target);
                        } else {
                            // Trace branch to leave target
                            if self.trace_instructions_enabled() {
                                self.trace(TraceEvent::Branch {
                                    method: current_method,
                                    from_offset,
                                    to_offset: target,
                                    conditional: false,
                                });
                            }
                            // All finally blocks done - go to leave target
                            interpreter.set_offset(target);
                        }
                    }
                    // If neither exception nor leave, just continue (shouldn't happen)
                }

                StepResult::EndFilter { value } => {
                    // EndFilter ends an exception filter with a result.
                    // A non-zero value means the filter accepts and we enter the handler.
                    let should_handle = match value {
                        EmValue::I32(v) => v != 0,
                        _ => false,
                    };

                    thread
                        .exception_state_mut()
                        .set_filter_result(Some(should_handle));

                    if should_handle {
                        // Filter accepted - transfer control to the handler
                        if let Some(handler_offset) =
                            thread.exception_state_mut().filter_handler_offset()
                        {
                            // Get origin offset for entering catch handler
                            let origin_offset = thread
                                .exception_state_mut()
                                .exception_origin_offset()
                                .unwrap_or(interpreter.ip().offset());

                            // Clear filter state and enter catch mode
                            thread.exception_state_mut().set_in_filter(false);
                            thread
                                .exception_state_mut()
                                .enter_catch_handler(origin_offset, handler_offset);

                            // Transfer control to the handler
                            interpreter.set_offset(handler_offset);
                        } else {
                            // No handler offset stored - shouldn't happen but clear filter state
                            thread.exception_state_mut().set_in_filter(false);
                        }
                    } else {
                        // Filter rejected - clear filter state and continue searching
                        thread.exception_state_mut().set_in_filter(false);

                        if thread.exception_state_mut().has_exception() {
                            // Continue searching for another handler
                            // For now, report as unhandled - a full implementation would
                            // continue the handler search from the next clause
                            return Ok(EmulationOutcome::UnhandledException {
                                exception: thread
                                    .exception_state_mut()
                                    .take_exception_as_value()
                                    .unwrap_or(EmValue::Null),
                                instructions: interpreter.stats().instructions_executed,
                            });
                        }
                    }
                }

                StepResult::Rethrow => {
                    // Rethrow re-raises the current exception within a catch handler.
                    if let Some(exception) = thread.exception_state_mut().get_exception_value() {
                        // Get the origin offset and current handler for searching
                        let origin_offset = thread.exception_state_mut().exception_origin_offset();
                        let skip_handler = thread.exception_state_mut().current_handler_offset();

                        // Resolve exception type for find_exception_handler
                        let exception_type = Self::resolve_exception_type(&exception, thread);

                        // First, try to find another handler in the current method
                        // by searching at the original exception offset and skipping
                        // handlers at or before the current one
                        if let Some(origin) = origin_offset {
                            if let Some(handler_match) = Self::find_exception_handler(
                                context,
                                current_method,
                                origin,
                                exception_type,
                                thread.exception_state_mut(),
                                skip_handler,
                            )? {
                                // Found another handler in current method
                                thread.stack_mut().clear();

                                // Apply handler and get target offset
                                let target_offset = Self::apply_handler_match(
                                    &handler_match,
                                    exception,
                                    origin,
                                    thread,
                                )?;

                                interpreter.set_offset(target_offset);
                                continue;
                            }
                        }

                        // No handler in current method - unwind to caller
                        thread.pop_frame();
                        if thread.call_depth() == 0 {
                            return Ok(EmulationOutcome::UnhandledException {
                                exception,
                                instructions: interpreter.stats().instructions_executed,
                            });
                        }

                        let caller_frame =
                            thread
                                .current_frame()
                                .ok_or(EmulationError::InternalError {
                                    description: "call stack empty during rethrow".to_string(),
                                })?;
                        let caller_method = caller_frame.method();
                        let caller_offset = caller_frame.return_offset();

                        // Resolve exception type for caller search
                        let exc_type = Self::resolve_exception_type(&exception, thread);

                        if let Some(handler_match) = Self::find_exception_handler(
                            context,
                            caller_method,
                            caller_offset,
                            exc_type,
                            thread.exception_state_mut(),
                            None, // No handler to skip in caller
                        )? {
                            thread.stack_mut().clear();

                            // Apply handler and get target offset
                            let target_offset = Self::apply_handler_match(
                                &handler_match,
                                exception,
                                caller_offset,
                                thread,
                            )?;

                            interpreter.set_method(caller_method);
                            interpreter.set_offset(target_offset);
                        } else {
                            return Ok(EmulationOutcome::UnhandledException {
                                exception: thread
                                    .exception_state_mut()
                                    .take_exception_as_value()
                                    .unwrap_or(EmValue::Null),
                                instructions: interpreter.stats().instructions_executed,
                            });
                        }
                    } else {
                        // No current exception - this is an error condition
                        return Ok(EmulationOutcome::UnhandledException {
                            exception: EmValue::Null,
                            instructions: interpreter.stats().instructions_executed,
                        });
                    }
                }

                StepResult::Breakpoint => {
                    return Ok(EmulationOutcome::Breakpoint {
                        offset: interpreter.ip().offset(),
                        instructions: interpreter.stats().instructions_executed,
                    });
                }

                StepResult::TailCall { method, args: _ } => {
                    // Tail call replaces current frame - pop arguments first while stack is valid
                    let target_method = context.get_method(method)?;
                    let param_count = target_method.signature.params.len();
                    let is_instance = !context.is_static_method(method)?;
                    let total_args = if is_instance {
                        param_count + 1
                    } else {
                        param_count
                    };

                    // Pop arguments from stack (in reverse order)
                    let arg_values = thread.pop_args(total_args)?;

                    // Get argument types
                    let param_types = context.get_parameter_types(method)?;
                    let arg_types: Vec<CilFlavor> = if is_instance {
                        let mut types = vec![CilFlavor::Object];
                        types.extend(param_types);
                        types
                    } else {
                        param_types
                    };

                    // Combine args with types
                    let args_with_types: Vec<(EmValue, CilFlavor)> =
                        arg_values.into_iter().zip(arg_types).collect();

                    // Get local types for the target method
                    let local_cil_flavors = context.get_local_types(method)?;

                    // Pop current frame (tail call replaces it)
                    thread.pop_frame();

                    // Create and push new frame for the tail call target
                    let frame = ThreadCallFrame::new(
                        method,
                        None, // No return method - tail call returns directly to caller's caller
                        0,
                        local_cil_flavors,
                        args_with_types,
                        false,
                    );
                    thread.push_frame(frame);

                    // Trace tail call
                    if self.trace_calls_enabled() {
                        self.trace(TraceEvent::MethodCall {
                            target: method,
                            is_virtual: false,
                            arg_count: total_args,
                            call_depth: thread.call_depth(),
                            caller: None, // Tail call has no return point
                            caller_offset: None,
                        });
                    }

                    interpreter.set_method(method);
                    interpreter.set_offset(0);
                }

                StepResult::Box { type_token } => {
                    Self::handle_box(thread, type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::Unbox { type_token } | StepResult::UnboxAny { type_token } => {
                    Self::handle_unbox(thread, Some(context), type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::CastClass { type_token } => {
                    Self::handle_castclass(thread, context, type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::IsInst { type_token } => {
                    Self::handle_isinst(thread, context, type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::SizeOf { type_token } => {
                    self.handle_sizeof(thread, context, type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::LoadToken { token } => {
                    // ldtoken pushes a RuntimeHandle for the metadata token.
                    // The handle type depends on the token table:
                    // - TypeDef/TypeRef/TypeSpec -> RuntimeTypeHandle
                    // - MethodDef/MethodRef -> RuntimeMethodHandle
                    // - FieldDef -> RuntimeFieldHandle
                    // We represent all as NativeInt containing the token value,
                    // which can be used with Type.GetTypeFromHandle, etc.
                    thread.push(EmValue::NativeInt(i64::from(token.value())))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::LoadFunctionPointer { method } => {
                    // Push function pointer as unmanaged pointer
                    thread.push(EmValue::UnmanagedPtr(u64::from(method.value())))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::LoadVirtualFunctionPointer { method } => {
                    // Push virtual function pointer
                    thread.push(EmValue::UnmanagedPtr(u64::from(method.value())))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::InitObj { type_token } => {
                    Self::handle_initobj(thread, Some(context), type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::CopyObject { type_token } => {
                    self.handle_cpobj(thread, Some(context), type_token)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::LocalAlloc { size } => {
                    // localloc allocates stack space in unmanaged memory
                    let size_bytes = size.as_size()?;
                    let ptr = thread.address_space().alloc_unmanaged(size_bytes)?;
                    thread.push(EmValue::UnmanagedPtr(ptr))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::CopyBlock { dest, src, size } => {
                    Self::handle_cpblk(thread, &dest, &src, &size)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::InitBlock { addr, value, size } => {
                    Self::handle_initblk(thread, &addr, &value, &size)?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::RefAnyVal { type_token: _ } => {
                    // Extract address from typed reference - return symbolic
                    let _typed_ref = thread.pop()?;
                    thread.push(EmValue::Symbolic(SymbolicValue::new(
                        CilFlavor::ByRef,
                        TaintSource::Unknown,
                    )))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::MkRefAny { type_token: _ } => {
                    // Make typed reference from address - return symbolic
                    let _addr = thread.pop()?;
                    thread.push(EmValue::Symbolic(SymbolicValue::new(
                        CilFlavor::ValueType,
                        TaintSource::Unknown,
                    )))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::RefAnyType => {
                    // Get type from typed reference - return symbolic
                    let _typed_ref = thread.pop()?;
                    thread.push(EmValue::NativeInt(0))?;
                    interpreter.ip_mut().advance_current();
                }

                StepResult::ArgList => {
                    // Return a handle to the argument list
                    thread.push(EmValue::NativeInt(0))?;
                    interpreter.ip_mut().advance_current();
                }
            }
        }
    }

    /// Handles a method call instruction (`call` or `callvirt`).
    ///
    /// This is the central dispatch point for all method calls. It:
    /// 1. Attempts to resolve the call to a registered stub
    /// 2. If no stub matches, pushes a new call frame for the target method
    /// 3. Handles virtual dispatch for `callvirt` instructions
    /// 4. Handles reflection invoke requests from stubs like `MethodBase.Invoke`
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter (for IP management)
    /// * `thread` - The emulation thread (for stack and frame management)
    /// * `context` - The emulation context (for method metadata lookup)
    /// * `method_token` - The target method's metadata token
    /// * `is_virtual` - Whether this is a virtual call (`callvirt` vs `call`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method lookup fails
    /// - Stack underflow when popping arguments
    /// - Virtual dispatch resolution fails
    fn handle_call(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        method_token: Token,
        is_virtual: bool,
    ) -> Result<()> {
        // First, try to resolve via hooks (highest priority)
        if let Some(result) = self.try_hook_call(context, method_token, thread)? {
            // Check if the hook requested a reflection invoke
            if let Some(reflection_request) = thread.take_pending_reflection_invoke() {
                // Handle the reflection invoke by recursively calling the target method

                // If a value was returned as placeholder, pop it
                if result.is_some() {
                    let _ = thread.pop();
                }

                // Now handle the reflected method call
                let target_token = reflection_request.method_token;

                // Check if this is a valid MethodDef token
                if target_token.is_table(TableId::MethodDef) {
                    // Push the arguments for the reflected method
                    if let Some(this_val) = reflection_request.this_ref {
                        if !matches!(this_val, EmValue::Null) {
                            thread.push(this_val)?;
                        }
                    }

                    for arg in reflection_request.args {
                        thread.push(arg)?;
                    }

                    return self.handle_call(interpreter, thread, context, target_token, false);
                }

                interpreter.ip_mut().advance_current();
                return Ok(());
            }

            if let Some(value) = result {
                thread.push(value)?;
            }
            interpreter.ip_mut().advance_current();
            return Ok(());
        }

        // Then try native stubs for P/Invoke methods
        if let Some(result) = self.try_native_call(context, method_token, thread)? {
            if let Some(value) = result {
                thread.push(value)?;
            }
            interpreter.ip_mut().advance_current();
            return Ok(());
        }

        // Handle MethodSpec tokens (generic method instantiations)
        // Resolve to the underlying method token and recurse
        if method_token.is_table(TableId::MethodSpec) {
            if let Some(method_spec) = context.get_method_spec(method_token) {
                if let Some(underlying_token) =
                    EmulationContext::resolve_method_spec_to_token(&method_spec)
                {
                    return self.handle_call(
                        interpreter,
                        thread,
                        context,
                        underlying_token,
                        is_virtual,
                    );
                }
            }

            return Err(EmulationError::MethodNotFound {
                token: method_token,
            }
            .into());
        }

        // Handle MemberRef tokens (external methods) without stubs
        if method_token.is_table(TableId::MemberRef) {
            // MemberRef with no stub - return symbolic value
            // Look up the MemberRef to get return type info and pop args
            if let Some(member_ref) = context.get_member_ref(method_token) {
                if let MemberRefSignature::Method(method_sig) = &member_ref.signature {
                    let total_args = if method_sig.has_this {
                        method_sig.param_count as usize + 1
                    } else {
                        method_sig.param_count as usize
                    };

                    // Pop arguments from stack
                    for _ in 0..total_args {
                        thread.pop()?;
                    }

                    // Return symbolic value if the method has a return type
                    if !matches!(method_sig.return_type.base, TypeSignature::Void) {
                        let return_type = CilFlavor::from(&method_sig.return_type.base);
                        thread.push(EmValue::Symbolic(SymbolicValue::new(
                            return_type,
                            TaintSource::MethodReturn(method_token.value()),
                        )))?;
                    }

                    interpreter.ip_mut().advance_current();
                    return Ok(());
                }
            }

            // Couldn't resolve MemberRef - fail
            return Err(EmulationError::MethodNotFound {
                token: method_token,
            }
            .into());
        }

        // Get method signature for internal method
        let method = context.get_method(method_token)?;

        // Get argument count from the signature blob (authoritative source).
        // The Param table may have fewer entries than the actual parameter count
        // (e.g., ConfuserEx native stubs have signatures with params but no Param rows).
        let param_count = method.signature.params.len();
        let is_instance = !context.is_static_method(method_token)?;
        let total_args = if is_instance {
            param_count + 1
        } else {
            param_count
        };

        // Pop arguments from stack (in correct order)
        let arg_values = thread.pop_args(total_args)?;

        // Resolve virtual dispatch if this is a callvirt instruction
        let resolved_method_token = if is_virtual && is_instance && !arg_values.is_empty() {
            // For virtual calls, resolve the actual method to call based on the
            // runtime type of the 'this' object (first argument for instance methods)
            Self::resolve_virtual_dispatch(context, thread, method_token, &arg_values[0])
        } else {
            method_token
        };

        // Re-fetch method if we resolved to a different one
        let method = if resolved_method_token == method_token {
            method
        } else {
            context.get_method(resolved_method_token)?
        };

        // Check if this is a native method (x86 code, not IL)
        // Native methods with the Native+Unmanaged impl flags contain machine code
        // that our IL emulator cannot execute. These need to be converted to CIL
        // during the byte-level deobfuscation stage before emulation.
        if method.is_code_native() && method.is_code_unmanaged() {
            return Err(EmulationError::InternalError {
                description: format!(
                    "Cannot emulate native x86 method 0x{:08x} '{}'. \
                     Native methods must be converted to CIL during deobfuscation.",
                    resolved_method_token.value(),
                    method.name
                ),
            }
            .into());
        }

        // Check if we should emulate or return symbolic
        // Also verify method has actual instructions (not just a body with encrypted/empty code)
        let has_instructions = method.instructions().next().is_some();
        let default_behavior = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime lock poisoned",
            })?
            .unknown_method_behavior();
        match default_behavior {
            UnknownMethodBehavior::Emulate => {
                // Check if method has a body with actual instructions
                if method.has_body() && has_instructions {
                    // Get return info from current frame
                    let return_method = thread.current_frame().map(ThreadCallFrame::method);
                    let return_offset = interpreter.ip().next_offset();

                    // Save caller's evaluation stack before entering new method
                    let caller_stack = thread.take_stack();

                    // Get local types for the callee
                    let local_cil_flavors = context.get_local_types(resolved_method_token)?;

                    // Get argument types
                    let callee_is_instance = !context.is_static_method(resolved_method_token)?;
                    let param_types = context.get_parameter_types(resolved_method_token)?;
                    let arg_types: Vec<CilFlavor> = if callee_is_instance {
                        let mut types = vec![CilFlavor::Object];
                        types.extend(param_types);
                        types
                    } else {
                        param_types
                    };

                    // Combine args with types
                    let args_with_types: Vec<(EmValue, CilFlavor)> =
                        arg_values.into_iter().zip(arg_types).collect();

                    // Determine if the method returns a value
                    let expects_return = context.method_returns_value(resolved_method_token)?;

                    // Create new call frame
                    let mut frame = ThreadCallFrame::new(
                        resolved_method_token,
                        return_method,
                        return_offset,
                        local_cil_flavors,
                        args_with_types,
                        expects_return,
                    );
                    frame.save_caller_stack(caller_stack);

                    // Push the frame to the thread's call stack
                    thread.push_frame(frame);

                    // Trace call if enabled
                    if self.trace_calls_enabled() {
                        self.trace(TraceEvent::MethodCall {
                            target: resolved_method_token,
                            is_virtual,
                            arg_count: total_args,
                            call_depth: thread.call_depth(),
                            caller: return_method,
                            caller_offset: Some(return_offset),
                        });
                    }

                    // Update interpreter to new method
                    interpreter.set_method(resolved_method_token);
                    interpreter.set_offset(0);
                } else {
                    // No body - likely a P/Invoke, return symbolic with proper return type
                    let return_flavor = context
                        .get_return_type(resolved_method_token)?
                        .unwrap_or(CilFlavor::Object);
                    let symbolic = EmValue::Symbolic(SymbolicValue::new(
                        return_flavor,
                        TaintSource::MethodReturn(resolved_method_token.value()),
                    ));
                    thread.push(symbolic)?;
                    interpreter.ip_mut().advance_current();
                }
            }

            UnknownMethodBehavior::Symbolic => {
                // Return a symbolic value that can be tracked through data flow
                let return_flavor = context
                    .get_return_type(resolved_method_token)?
                    .unwrap_or(CilFlavor::Object);
                let symbolic = EmValue::Symbolic(SymbolicValue::new(
                    return_flavor,
                    TaintSource::MethodReturn(resolved_method_token.value()),
                ));
                thread.push(symbolic)?;
                interpreter.ip_mut().advance_current();
            }

            UnknownMethodBehavior::Fail => {
                return Err(EmulationError::UnsupportedMethod {
                    token: resolved_method_token,
                    reason: "No hook registered and Fail behavior configured",
                }
                .into());
            }

            UnknownMethodBehavior::Default => {
                // Return a default value based on the return type
                let return_flavor = context.get_return_type(resolved_method_token)?;
                if let Some(flavor) = return_flavor {
                    let default_value = match flavor {
                        CilFlavor::Void => None,
                        CilFlavor::Boolean
                        | CilFlavor::I1
                        | CilFlavor::U1
                        | CilFlavor::I2
                        | CilFlavor::U2
                        | CilFlavor::I4
                        | CilFlavor::U4
                        | CilFlavor::Char => Some(EmValue::I32(0)),
                        CilFlavor::I8 | CilFlavor::U8 => Some(EmValue::I64(0)),
                        CilFlavor::R4 => Some(EmValue::F32(0.0)),
                        CilFlavor::R8 => Some(EmValue::F64(0.0)),
                        CilFlavor::I | CilFlavor::U => Some(EmValue::NativeInt(0)),
                        _ => Some(EmValue::Null), // Reference types return null
                    };
                    if let Some(value) = default_value {
                        thread.push(value)?;
                    }
                }
                interpreter.ip_mut().advance_current();
            }

            UnknownMethodBehavior::Skip => {
                // Skip the call entirely - don't push any value
                // Warning: This may cause stack imbalance if return value is expected
                interpreter.ip_mut().advance_current();
            }
        }

        Ok(())
    }

    /// Handles the `calli` instruction - indirect call through a function pointer.
    ///
    /// The `calli` instruction calls a method through a function pointer that was
    /// previously loaded onto the stack (typically via `ldftn` or `ldvirtftn`).
    /// The call site signature is specified as a StandAloneSig token.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The interpreter for instruction pointer management
    /// * `thread` - The emulation thread for stack operations
    /// * `context` - The emulation context for metadata lookup
    /// * `sig_token` - StandAloneSig token containing the call site signature
    /// * `function_pointer` - The function pointer value (contains method token)
    fn handle_calli(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        sig_token: Token,
        function_pointer: &EmValue,
    ) -> Result<()> {
        // Get the call site signature from the StandAloneSig table
        let standalone_sig = context.get_standalone_signature(sig_token).ok_or(
            EmulationError::InvalidMethodMetadata {
                token: sig_token,
                reason: "StandAloneSig not found for calli",
            },
        )?;

        // Extract method signature - calli requires a method signature, not locals
        let StandAloneSignature::Method(method_sig) = standalone_sig else {
            return Err(EmulationError::TypeMismatch {
                operation: "calli",
                expected: "method signature",
                found: "non-method signature",
            }
            .into());
        };

        // Calculate argument count from signature
        let param_count = method_sig.param_count as usize;
        let has_this = method_sig.has_this;
        let total_args = if has_this {
            param_count + 1
        } else {
            param_count
        };

        // Pop arguments from stack (in reverse order - first pushed is last popped)
        let arg_values = thread.pop_args(total_args)?;

        // Extract the method token from the function pointer
        // Function pointers are stored as UnmanagedPtr containing the method token value
        let method_token = match *function_pointer {
            EmValue::UnmanagedPtr(ptr) =>
            {
                #[allow(clippy::cast_possible_truncation)]
                Token::new(ptr as u32)
            }
            EmValue::NativeInt(val) =>
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Token::new(val as u32)
            }
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "calli",
                    expected: "function pointer (UnmanagedPtr or NativeInt)",
                    found: "invalid value type",
                }
                .into())
            }
        };

        // Check if the resolved token points to a valid method
        // Table 0x06 = MethodDef
        if method_token.table() != 0x06 {
            // Not a MethodDef - might be an unresolved or invalid pointer
            // Return symbolic result based on the signature return type
            if !matches!(method_sig.return_type.base, TypeSignature::Void) {
                let return_flavor = CilFlavor::from(&method_sig.return_type.base);
                thread.push(EmValue::Symbolic(SymbolicValue::new(
                    return_flavor,
                    TaintSource::MethodReturn(method_token.value()),
                )))?;
            }
            interpreter.ip_mut().advance_current();
            return Ok(());
        }

        // Delegate to handle_call for the actual method invocation
        // First push args back onto stack (handle_call will pop them)
        for arg in arg_values {
            thread.push(arg)?;
        }

        // Now call the method (not virtual since we have the exact method token)
        self.handle_call(interpreter, thread, context, method_token, false)
    }

    /// Resolves virtual dispatch to find the actual method to call.
    ///
    /// For virtual method calls (callvirt), this resolves the declared method
    /// to the actual implementation based on the runtime type of the 'this' object.
    ///
    /// # Arguments
    ///
    /// * `context` - The emulation context providing type system access
    /// * `thread` - Emulation thread to look up heap object types
    /// * `declared_method` - The declared method token from the instruction
    /// * `this_arg` - The 'this' argument (first argument for instance methods)
    ///
    /// # Returns
    ///
    /// The resolved method token to actually call. If virtual dispatch cannot
    /// be resolved (type unknown, method not virtual, not overridden), returns
    /// the original declared method token.
    fn resolve_virtual_dispatch(
        context: &EmulationContext,
        thread: &EmulationThread,
        declared_method: Token,
        this_arg: &EmValue,
    ) -> Token {
        // Get the runtime type of the 'this' object
        let runtime_type = match this_arg {
            EmValue::ObjectRef(heap_ref) => {
                match thread.heap().get_type_token(*heap_ref) {
                    Ok(token) => token,
                    Err(_) => return declared_method, // Can't get type, use declared
                }
            }
            _ => return declared_method, // Null or other non-object type
        };

        // Use the context's virtual dispatch resolution
        context.resolve_virtual_call(declared_method, runtime_type)
    }

    /// Tries to execute a method call via a stub.
    ///
    /// Looks up the method in the stub registry and executes the matching stub if found.
    /// For P/Invoke methods, also checks native stubs. This method handles both MethodDef
    /// and MemberRef tokens.
    ///
    /// # Arguments
    ///
    /// * `context` - The emulation context for method metadata lookup
    /// * `method_token` - Token of the method to look up
    /// * `thread` - The emulation thread for stack operations
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Some(value)))` - Stub matched and returned a value
    /// - `Ok(Some(None))` - Stub matched and returned void
    /// - `Ok(None)` - No matching stub found
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack underflow when popping arguments
    /// - Native stub execution fails
    #[allow(clippy::option_option)] // None = no hook, Some(None) = void return, Some(Some) = value
    fn try_native_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<Option<Option<EmValue>>> {
        // Only MethodDef tokens can be P/Invoke - MemberRefs are handled via hooks
        if method_token.table() != 0x06 {
            return Ok(None);
        }

        // Get method info
        let Ok(method) = context.get_method(method_token) else {
            return Ok(None);
        };

        // Check if this is a P/Invoke (no method body)
        if method.has_body() {
            return Ok(None);
        }

        // For P/Invoke methods, look up the real import name from CilImports
        // This handles obfuscated method names where the actual import name differs
        let (function_name, dll_name): (String, Option<String>) =
            if let Some(import) = context.find_import_by_method(method_token) {
                let dll = context.get_import_dll_name(&import);
                (import.name.clone(), dll)
            } else {
                (method.name.clone(), None)
            };

        // Try native hooks for P/Invoke
        if let Some(dll) = &dll_name {
            // Get argument count - P/Invoke methods are always static
            let param_count = method.signature.params.len();

            // Pop arguments from stack
            let args = thread.pop_args(param_count)?;

            // Create native hook context
            let hook_context =
                HookContext::native(method_token, dll, &function_name, self.config.pointer_size)
                    .with_args(&args);

            let guard = self
                .runtime
                .read()
                .map_err(|_| EmulationError::LockPoisoned {
                    description: "runtime lock poisoned",
                })?;
            // P/Invoke calls are always bypassed - no "original" to execute
            match guard.hooks().execute(&hook_context, thread, |_| None)? {
                HookOutcome::NoMatch => {
                    // No hook found - push args back and return None
                    // (caller will decide how to handle unhandled P/Invoke)
                    for arg in args.into_iter().rev() {
                        thread.push(arg)?;
                    }
                    return Ok(None);
                }
                HookOutcome::Handled(result) => {
                    return Ok(Some(result));
                }
            }
        }

        Ok(None)
    }

    /// Tries to execute a method call via a hook.
    ///
    /// Hooks provide flexible method interception with matching criteria and
    /// bypass capabilities. This method creates a [`HookContext`] and checks
    /// registered hooks in priority order.
    ///
    /// # Arguments
    ///
    /// * `context` - The emulation context for method metadata lookup
    /// * `method_token` - Token of the method to look up
    /// * `thread` - The emulation thread for stack operations
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Some(value)))` - Hook matched and returned a value (bypass)
    /// - `Ok(Some(None))` - Hook matched and returned void (bypass)
    /// - `Ok(None)` - No matching hook, or hook returned Continue
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack underflow when popping arguments
    /// - Hook execution fails
    #[allow(clippy::option_option)]
    fn try_hook_call(
        &self,
        context: &EmulationContext,
        method_token: Token,
        thread: &mut EmulationThread,
    ) -> Result<Option<Option<EmValue>>> {
        // Extract method info - we use owned Strings to handle both MemberRef and MethodDef
        let (namespace, type_name, method_name, is_internal, param_count, has_this): (
            String,
            String,
            String,
            bool,
            usize,
            bool,
        ) = if method_token.is_table(TableId::MemberRef) {
            // MemberRef (external method)
            let Some(member_ref) = context.get_member_ref(method_token) else {
                return Ok(None);
            };

            let (ns, tn) = EmulationContext::get_member_ref_type_info(&member_ref)
                .unwrap_or_else(|| (String::new(), String::new()));

            let (count, has_this) = match &member_ref.signature {
                MemberRefSignature::Method(sig) => (sig.param_count as usize, sig.has_this),
                MemberRefSignature::Field(_) => return Ok(None),
            };

            (ns, tn, member_ref.name.clone(), false, count, has_this)
        } else {
            // MethodDef (internal method)
            let Ok(method) = context.get_method(method_token) else {
                return Ok(None);
            };

            let (ns, tn) = if let Some(dt) = context.get_declaring_type(method_token) {
                (dt.namespace.clone(), dt.name.clone())
            } else {
                (String::new(), String::new())
            };

            let has_this = !context.is_static_method(method_token).unwrap_or(true);
            (
                ns,
                tn,
                method.name.clone(),
                true,
                method.signature.params.len(),
                has_this,
            )
        };

        let total_args = if has_this {
            param_count + 1
        } else {
            param_count
        };

        // Peek at arguments without popping (we may not match a hook)
        let args = thread.peek_args(total_args)?;

        // Get parameter types if available
        let param_types = context.get_parameter_types(method_token).ok();
        let param_types_ref: Option<&[CilFlavor]> = param_types.as_deref();

        // Get return type
        let return_type = context.get_return_type(method_token).ok().flatten();

        // Split into this and method args
        let (this_ref, method_args): (Option<&EmValue>, &[EmValue]) =
            if has_this && !args.is_empty() {
                (Some(&args[0]), &args[1..])
            } else {
                (None, &args[..])
            };

        // Build hook context - use references to our owned strings
        let hook_context = HookContext::new(
            method_token,
            &namespace,
            &type_name,
            &method_name,
            self.config.pointer_size,
        )
        .with_this(this_ref)
        .with_args(method_args)
        .with_internal(is_internal)
        .with_param_types(param_types_ref)
        .with_return_type(return_type);

        // Try to execute via hooks
        let guard = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime lock poisoned",
            })?;
        let outcome = guard.hooks().execute(&hook_context, thread, |_| {
            // Original method execution callback - for now, we don't execute
            // the original here since the controller handles stubs/internal
            // methods separately. Post-hooks that depend on the original
            // result won't work in this mode.
            None
        })?;

        match outcome {
            HookOutcome::Handled(value) => {
                // Hook handled the call (pre-hook bypassed or post-hook returned)
                thread.pop_args(total_args)?;
                Ok(Some(value))
            }
            HookOutcome::NoMatch => Ok(None),
        }
    }

    /// Handles `newobj` instruction - creates a new object instance.
    ///
    /// Allocates memory for a new object on the managed heap, then invokes
    /// the specified constructor. The resulting object reference is pushed
    /// onto the evaluation stack.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter (for IP management)
    /// * `thread` - The emulation thread (for stack and heap access)
    /// * `context` - The emulation context (for type/method metadata)
    /// * `constructor_token` - Token of the constructor to invoke
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Constructor lookup fails
    /// - Stack underflow when popping arguments
    /// - Heap allocation fails
    fn handle_newobj(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        constructor_token: Token,
    ) -> Result<()> {
        // Handle MemberRef tokens (external constructors)
        if constructor_token.is_table(TableId::MemberRef) {
            return self.handle_newobj_memberref(interpreter, thread, context, constructor_token);
        }

        // Get constructor info for MethodDef tokens
        let method = context.get_method(constructor_token)?;
        let param_count = method.signature.params.len();

        // Pop constructor arguments
        let arg_values = thread.pop_args(param_count)?;

        // Allocate the object on the heap.
        // The constructor token is a MethodDef/MethodRef; we need the declaring type.
        // Use the type system to resolve the declaring type from the method's owning type.
        let declaring_type = context.get_declaring_type(constructor_token);
        let type_token = declaring_type.as_ref().map_or_else(
            || {
                // External method reference without resolvable declaring type.
                // Use the token's row index as type identifier for heap tracking.
                Token::new(constructor_token.value() & 0x00FF_FFFF)
            },
            |t| t.token,
        );

        // Get field types for proper initialization. Instance fields need default values.
        // Static fields (flags & 0x0010) are not part of object instances.
        let field_types: Vec<(Token, CilFlavor)> = declaring_type
            .as_ref()
            .map(|t| {
                t.fields
                    .iter()
                    .filter(|(_, f)| f.flags & 0x0010 == 0) // Not static
                    .map(|(_, f)| (f.token, CilFlavor::from(&f.signature.base)))
                    .collect()
            })
            .unwrap_or_default();

        let obj_ref = thread
            .heap_mut()
            .alloc_object_with_fields(type_token, &field_types)?;

        // Try to find a constructor hook using the hook system
        let mut hook_handled = false;
        if let Some(ref decl_type) = declaring_type {
            let this_value = EmValue::ObjectRef(obj_ref);
            let hook_context = HookContext::new(
                constructor_token,
                &decl_type.namespace,
                &decl_type.name,
                ".ctor",
                self.config.pointer_size,
            )
            .with_this(Some(&this_value))
            .with_args(&arg_values)
            .with_internal(constructor_token.is_table(TableId::MethodDef));

            let guard = self
                .runtime
                .read()
                .map_err(|_| EmulationError::LockPoisoned {
                    description: "runtime lock poisoned",
                })?;
            // Constructors don't return values, so we pass a no-op callback
            match guard.hooks().execute(&hook_context, thread, |_| None)? {
                HookOutcome::NoMatch => {}
                HookOutcome::Handled(_) => {
                    hook_handled = true;
                }
            }
        }

        // Check that the method has a body AND has decoded instructions
        // Some methods may have bodies but empty instructions (e.g., encrypted methods)
        let has_instructions = method.instructions().next().is_some();
        if !hook_handled && method.has_body() && has_instructions {
            // Emulate the constructor if it has a body.
            // Insert 'this' as first argument (instance methods receive 'this' in arg 0).
            let mut full_args = vec![EmValue::ObjectRef(obj_ref)];
            full_args.extend(arg_values);

            // Get return info from current frame
            let return_method = thread.current_frame().map(ThreadCallFrame::method);
            let return_offset = interpreter.ip().next_offset();

            // The caller expects the new object on the stack after newobj completes.
            // Since we're emulating the constructor, we need to add obj_ref to the
            // caller's stack before saving it (it will be restored on constructor return).
            thread.push(EmValue::ObjectRef(obj_ref))?;
            let caller_stack = thread.take_stack();

            // Get local types for the constructor
            let local_cil_flavors = context.get_local_types(constructor_token)?;

            // Get argument types (constructor is always instance, so 'this' + params)
            let param_types = context.get_parameter_types(constructor_token)?;
            let mut arg_types = vec![CilFlavor::Object]; // 'this'
            arg_types.extend(param_types);

            // Combine args with types
            let args_with_types: Vec<(EmValue, CilFlavor)> =
                full_args.into_iter().zip(arg_types).collect();

            // Create frame for constructor (constructors don't return values)
            let mut frame = ThreadCallFrame::new(
                constructor_token,
                return_method,
                return_offset,
                local_cil_flavors,
                args_with_types,
                false, // constructors don't return values
            );
            frame.save_caller_stack(caller_stack);

            // Push the frame to the thread's call stack
            thread.push_frame(frame);

            // Trace constructor call if enabled
            if self.trace_calls_enabled() {
                self.trace(TraceEvent::MethodCall {
                    target: constructor_token,
                    is_virtual: false,
                    arg_count: param_count + 1, // +1 for 'this'
                    call_depth: thread.call_depth(),
                    caller: return_method,
                    caller_offset: Some(return_offset),
                });
            }

            // Update interpreter to execute constructor
            interpreter.set_method(constructor_token);
            interpreter.set_offset(0);

            // Return early - obj_ref was already added to caller's saved stack
            return Ok(());
        }

        // Push the new object reference onto the stack (stub case or no constructor body)
        thread.push(EmValue::ObjectRef(obj_ref))?;
        // Advance IP past the newobj instruction
        interpreter.ip_mut().advance_current();

        Ok(())
    }

    /// Handles `newobj` instruction for MemberRef tokens (external constructors).
    ///
    /// MemberRef tokens reference constructors in external assemblies. This method
    /// looks up the reference, allocates the object, and attempts to find a
    /// matching constructor stub.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter (for IP management)
    /// * `thread` - The emulation thread (for stack and heap access)
    /// * `context` - The emulation context (for MemberRef lookup)
    /// * `constructor_token` - MemberRef token of the external constructor
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - MemberRef lookup fails
    /// - Signature is not a method signature
    /// - Stack underflow when popping arguments
    fn handle_newobj_memberref(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        constructor_token: Token,
    ) -> Result<()> {
        // Look up the MemberRef using the context
        let member_ref =
            context
                .get_member_ref(constructor_token)
                .ok_or(EmulationError::MethodNotFound {
                    token: constructor_token,
                })?;

        // Get parameter count from signature
        let param_count = if let MemberRefSignature::Method(method_sig) = &member_ref.signature {
            method_sig.param_count as usize
        } else {
            return Err(EmulationError::InvalidOperand {
                instruction: "newobj",
                expected: "method signature in MemberRef",
            }
            .into());
        };

        // Pop constructor arguments
        let args = thread.pop_args(param_count)?;

        // Get the declaring type info for hook lookup
        let (namespace, type_name_only) = EmulationContext::get_member_ref_type_info(&member_ref)
            .unwrap_or_else(|| (String::new(), String::from("Unknown")));

        // Allocate an object on the heap using the declaring type token
        let type_token = EmulationContext::get_member_ref_type_token(&member_ref)
            .unwrap_or_else(|| Token::new(constructor_token.value() & 0x00FF_FFFF));

        // Get field types for proper initialization if the type is available
        let field_types: Vec<(Token, CilFlavor)> = context
            .get_type(type_token)
            .map(|t| {
                t.fields
                    .iter()
                    .filter(|(_, f)| f.flags & 0x0010 == 0) // Not static
                    .map(|(_, f)| (f.token, CilFlavor::from(&f.signature.base)))
                    .collect()
            })
            .unwrap_or_default();

        let obj_ref = thread
            .heap_mut()
            .alloc_object_with_fields(type_token, &field_types)?;

        // Try to find a constructor hook using the hook system
        let this_value = EmValue::ObjectRef(obj_ref);
        let hook_context = HookContext::new(
            constructor_token,
            &namespace,
            &type_name_only,
            ".ctor",
            self.config.pointer_size,
        )
        .with_this(Some(&this_value))
        .with_args(&args)
        .with_internal(false); // MemberRef is external

        let guard = self
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime lock poisoned",
            })?;
        // Constructors don't return values, so we pass a no-op callback
        match guard.hooks().execute(&hook_context, thread, |_| None)? {
            HookOutcome::NoMatch => {}
            HookOutcome::Handled(_) => {
                thread.push(EmValue::ObjectRef(obj_ref))?;
                interpreter.ip_mut().advance_current();
                return Ok(());
            }
        }
        drop(guard);

        // No hook found - just return the allocated object
        // (external constructors without hooks get a default-initialized object)
        thread.push(EmValue::ObjectRef(obj_ref))?;
        interpreter.ip_mut().advance_current();

        Ok(())
    }

    /// Handles `newarr` instruction - creates a new array.
    ///
    /// Allocates a single-dimension zero-based array on the managed heap
    /// with the specified element type and length.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread (for heap access and stack push)
    /// * `context` - The emulation context (for type resolution)
    /// * `element_type` - Token of the array element type
    /// * `length` - Number of elements in the array
    ///
    /// # Errors
    ///
    /// Returns an error if type resolution or heap allocation fails.
    fn handle_newarr(
        thread: &mut EmulationThread,
        context: &EmulationContext,
        element_type: Token,
        length: usize,
    ) -> Result<()> {
        // Resolve element type from the type token
        let cil_flavor = context.type_token_to_cil_flavor(element_type)?;

        let array_ref = thread.heap_mut().alloc_array(cil_flavor, length)?;
        thread.push(EmValue::ObjectRef(array_ref))?;

        Ok(())
    }

    /// Handles `ldstr` instruction - loads a string literal.
    ///
    /// Retrieves a string from the assembly's user string heap and allocates
    /// it on the managed heap. The string reference is pushed onto the stack.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread (for heap and stack access)
    /// * `context` - The emulation context (for user string lookup)
    /// * `token` - User string token (0x70XXXXXX format)
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not found or heap allocation fails.
    fn handle_ldstr(
        thread: &mut EmulationThread,
        context: &EmulationContext,
        token: Token,
    ) -> Result<()> {
        // Extract user string index from token
        // User string tokens have the format 0x70XXXXXX
        let index = token.value() & 0x00FF_FFFF;

        let string = context.get_user_string(index)?;
        let str_ref = thread.heap_mut().alloc_string(&string)?;
        thread.push(EmValue::ObjectRef(str_ref))?;

        Ok(())
    }

    /// Handles `ldsfld` instruction - loads a static field value.
    ///
    /// Retrieves the value of a static field from the address space's static
    /// field storage. For known BCL static fields accessed via MemberRef (external
    /// assemblies), returns appropriate concrete values. Unknown fields return a
    /// symbolic value for tracking.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread (for stack push)
    /// * `context` - The emulation context for MemberRef lookup
    /// * `field` - Token of the static field to load
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    fn handle_ldsfld(
        &self,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        field: Token,
    ) -> Result<()> {
        // First check if we have the field in storage
        if let Some(value) = self.address_space.get_static(field) {
            thread.push(value)?;
            return Ok(());
        }

        // For MemberRef tokens, check if this is a known BCL static field
        if field.is_table(TableId::MemberRef) {
            if let Some(member_ref) = context.get_member_ref(field) {
                if let Some((namespace, type_name)) =
                    EmulationContext::get_member_ref_type_info(&member_ref)
                {
                    if let Some(value) =
                        get_bcl_static_field(&namespace, &type_name, &member_ref.name)
                    {
                        thread.push(value)?;
                        return Ok(());
                    }
                }
            }
        }

        // Unknown field - return symbolic
        thread.push(EmValue::Symbolic(SymbolicValue::new(
            CilFlavor::Object,
            TaintSource::Field(field.value()),
        )))?;
        Ok(())
    }

    /// Checks if a type needs initialization and runs its .cctor if needed.
    ///
    /// This implements lazy type initialization as per ECMA-335: before accessing
    /// a type's static members, its static constructor must be run exactly once.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The interpreter for pushing frames
    /// * `thread` - The emulation thread
    /// * `context` - The emulation context for type lookups
    /// * `field` - The static field being accessed
    ///
    /// # Returns
    ///
    /// * `true` - A .cctor was pushed and needs to run first
    /// * `false` - Type is already initialized or has no .cctor
    fn maybe_run_type_cctor(
        &mut self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        field: Token,
    ) -> bool {
        // Only process Field table tokens (0x04)
        if field.table() != 0x04 {
            return false;
        }

        // Find the type that owns this field
        let Some(type_token) = context.get_declaring_type_token_of_field(field) else {
            return false;
        };

        // Check if already initialized
        if self.address_space.statics().is_type_initialized(type_token) {
            return false;
        }

        // Find the .cctor for this type
        let Some(cctor_token) = context.find_type_cctor(type_token) else {
            // No .cctor - mark as initialized and proceed
            self.address_space
                .statics()
                .mark_type_initialized(type_token);
            return false;
        };

        // Get method info for .cctor and check if it has a body
        let Ok(method) = context.get_method(cctor_token) else {
            // Can't get method - mark as initialized and skip
            self.address_space
                .statics()
                .mark_type_initialized(type_token);
            return false;
        };

        // Check if .cctor has a body (it might be extern/P/Invoke)
        if !method.has_body() {
            // No body - mark as initialized and skip
            self.address_space
                .statics()
                .mark_type_initialized(type_token);
            return false;
        }

        // Mark type as initialized BEFORE running .cctor to prevent infinite recursion
        // (e.g., .cctor accessing its own static fields)
        self.address_space
            .statics()
            .mark_type_initialized(type_token);

        // .cctor takes no arguments and returns void
        let local_types = context.get_local_types(cctor_token).unwrap_or_default();

        // Save current stack state
        let caller_stack = thread.take_stack();

        // Current method and offset for return
        let return_method = interpreter.ip().method();
        let return_offset = interpreter.ip().offset();

        // .cctor has no arguments (it's always static and parameterless)
        let args_with_types: Vec<(EmValue, CilFlavor)> = vec![];

        // Create new call frame - .cctor never returns a value
        let mut frame = ThreadCallFrame::new(
            cctor_token,
            Some(return_method),
            return_offset,
            local_types,
            args_with_types,
            false, // .cctor returns void
        );
        frame.save_caller_stack(caller_stack);

        // Push the frame and set up interpreter
        thread.push_frame(frame);
        interpreter.set_method(cctor_token);
        interpreter.set_offset(0);

        true
    }

    /// Handles `box` instruction - boxes a value type.
    ///
    /// Converts a value type to an object reference by allocating a boxed
    /// container on the managed heap.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread (for heap/stack access)
    /// * `type_token` - Token of the value type being boxed
    ///
    /// # Errors
    ///
    /// Returns an error if stack underflow or heap allocation fails.
    fn handle_box(thread: &mut EmulationThread, type_token: Token) -> Result<()> {
        let value = thread.pop()?;

        // Create a boxed object containing the value
        let boxed_ref = thread.heap_mut().alloc_boxed(type_token, value.clone())?;
        thread.push(EmValue::ObjectRef(boxed_ref))?;

        Ok(())
    }

    /// Handles `unbox` and `unbox.any` instructions.
    ///
    /// Extracts the value from a boxed object. For `unbox.any`, the value is copied
    /// directly onto the stack. Verifies type compatibility when context is available.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for heap/stack access
    /// * `context` - Optional emulation context for type verification
    /// * `type_token` - Expected type of the unboxed value
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack underflow occurs
    /// - Null reference is unboxed
    /// - Type mismatch when context is provided
    fn handle_unbox(
        thread: &mut EmulationThread,
        context: Option<&EmulationContext>,
        type_token: Token,
    ) -> Result<()> {
        let obj = thread.pop()?;

        match obj {
            EmValue::ObjectRef(href) => {
                // Verify the boxed value's type matches the expected type (when context is available)
                if let Some(ctx) = context {
                    if let Ok(source_type) = thread.heap().get_type_token(href) {
                        if !ctx.is_type_compatible(source_type, type_token) {
                            let from_type = ctx.format_type_token(source_type);
                            let to_type = ctx.format_type_token(type_token);
                            return Err(EmulationError::InvalidCast { from_type, to_type }.into());
                        }
                    }
                }

                // Get the boxed value
                if let Ok(value) = thread.heap().get_boxed_value(href) {
                    thread.push(value)?;
                } else {
                    // Not a BoxedValue HeapObject.
                    // For unbox.any:
                    // - Reference types: returning ObjectRef is correct (castclass behavior)
                    // - Value types: this is an InvalidCast (should have been BoxedValue)
                    if let Some(ctx) = context {
                        if ctx.is_value_type(type_token) {
                            // Target is a value type but object is not a BoxedValue
                            let from_type = thread.heap().get_type_token(href).map_or_else(
                                |_| "unknown object".to_string(),
                                |t| ctx.format_type_token(t),
                            );
                            let to_type = ctx.format_type_token(type_token);
                            return Err(EmulationError::InvalidCast { from_type, to_type }.into());
                        }
                    }
                    // Reference type or unknown context - return the reference
                    thread.push(EmValue::ObjectRef(href))?;
                }
            }
            EmValue::Null => {
                return Err(EmulationError::NullReference.into());
            }
            other => {
                // Already unboxed
                thread.push(other)?;
            }
        }

        Ok(())
    }

    /// Handles `castclass` instruction.
    ///
    /// Attempts to cast an object reference to the specified type. Throws
    /// `InvalidCastException` (mapped to `EmulationError::InvalidCast`) if the
    /// cast fails. Null passes through unchanged per ECMA-335 III.4.3.
    ///
    /// Uses the type system infrastructure to perform proper type compatibility
    /// checking when type information is available.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for heap/stack access
    /// * `context` - The emulation context for type compatibility checking
    /// * `target_type` - Token of the type to cast to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack underflow occurs
    /// - Cast fails due to type incompatibility
    fn handle_castclass(
        thread: &mut EmulationThread,
        context: &EmulationContext,
        target_type: Token,
    ) -> Result<()> {
        let value = thread.pop()?;

        match &value {
            // Null always passes castclass (ECMA-335 III.4.3)
            EmValue::Null => {
                thread.push(EmValue::Null)?;
            }

            EmValue::ObjectRef(heap_ref) => {
                // Get the runtime type of the object
                let source_type = thread.heap().get_type_token(*heap_ref)?;

                // Check type compatibility using the type system
                if context.is_type_compatible(source_type, target_type) {
                    // Cast succeeds - push unchanged reference
                    thread.push(value)?;
                } else {
                    // Cast fails - throw InvalidCastException
                    let from_type = context.format_type_token(source_type);
                    let to_type = context.format_type_token(target_type);
                    return Err(EmulationError::InvalidCast { from_type, to_type }.into());
                }
            }

            // Non-object types cannot be cast
            _ => {
                let from_type = value.cil_flavor().as_str().to_string();
                let to_type = context.format_type_token(target_type);
                return Err(EmulationError::InvalidCast { from_type, to_type }.into());
            }
        }

        Ok(())
    }

    /// Handles `isinst` instruction.
    ///
    /// Tests if an object reference is an instance of the specified type.
    /// Returns the object reference if compatible, or null if not.
    /// Unlike `castclass`, this never throws an exception per ECMA-335 III.4.6.
    ///
    /// Uses the type system infrastructure to perform proper type compatibility
    /// checking when type information is available.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for heap/stack access
    /// * `context` - The emulation context for type compatibility checking
    /// * `target_type` - Token of the type to check against
    ///
    /// # Errors
    ///
    /// Returns an error if stack underflow or heap lookup fails.
    fn handle_isinst(
        thread: &mut EmulationThread,
        context: &EmulationContext,
        target_type: Token,
    ) -> Result<()> {
        let value = thread.pop()?;

        match &value {
            EmValue::ObjectRef(heap_ref) => {
                // Get the runtime type of the object
                let source_type = thread.heap().get_type_token(*heap_ref)?;

                // Check type compatibility using the context's type system
                if context.is_type_compatible(source_type, target_type) {
                    // Type is compatible - return the object reference
                    thread.push(value)?;
                } else {
                    // Not compatible - return null
                    thread.push(EmValue::Null)?;
                }
            }

            // Null always returns null (ECMA-335 III.4.6), non-object types also return null
            _ => {
                thread.push(EmValue::Null)?;
            }
        }

        Ok(())
    }

    /// Handles `sizeof` instruction - gets the size of a value type.
    ///
    /// Uses the context's type system to look up the size of the type
    /// and pushes it as an `I32` value onto the evaluation stack.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread (for stack push)
    /// * `context` - The emulation context (for type size lookup)
    /// * `type_token` - Token of the type to get the size of
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    fn handle_sizeof(
        &self,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        type_token: Token,
    ) -> Result<()> {
        let size = context.get_type_size(type_token, self.config.pointer_size);

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        thread.push(EmValue::I32(size as i32))?; // Size bounded by type system
        Ok(())
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
    /// - `Ok(Some(HandlerMatch))` - A matching handler was found
    /// - `Ok(None)` - No handler matches (exception should propagate)
    ///
    /// # Errors
    ///
    /// Returns an error if the method lookup fails.
    #[allow(clippy::too_many_arguments)] // Exception handling requires all these parameters
    fn find_exception_handler(
        context: &EmulationContext,
        method_token: Token,
        current_offset: u32,
        exception_type: Option<Token>,
        exception_state: &mut ThreadExceptionState,
        skip_handler_offset: Option<u32>,
    ) -> Result<Option<HandlerMatch>> {
        // Get the method's exception handlers
        let method = context.get_method(method_token)?;
        let Some(body) = method.body.get() else {
            return Ok(None);
        };

        // Convert metadata handlers to exception clauses
        let clauses = ExceptionClause::from_metadata_handlers(&body.exception_handlers);

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
                    // Also return as cleanup handler so caller knows cleanup is needed
                    // But we continue searching for a catch handler
                    // Don't return - continue searching
                    _ = handler_length; // Suppress unused warning
                }

                ExceptionClause::Fault { handler_length, .. } => {
                    // Fault handler - like finally but only on exception path
                    exception_state.push_finally(method_token, clause.handler_offset(), None);
                    // Don't return - continue searching for a catch handler
                    _ = handler_length; // Suppress unused warning
                }
            }
        }

        Ok(None)
    }

    /// Schedules finally blocks to execute when leaving a protected region.
    ///
    /// This finds all finally handlers between the current offset and the leave target,
    /// and schedules them for execution. Finally blocks are executed in innermost-first
    /// order per ECMA-335.
    ///
    /// # Arguments
    ///
    /// * `context` - The emulation context for method metadata
    /// * `method_token` - Token of the method containing the finally blocks
    /// * `current_offset` - Current instruction offset (where the leave originates)
    /// * `leave_target` - Target offset of the leave instruction
    /// * `exception_state` - Mutable exception state to record pending finally blocks
    ///
    /// # Errors
    ///
    /// Returns an error if method lookup fails.
    fn schedule_finally_blocks(
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
        finally_blocks.sort_by(|a, b| b.1.cmp(&a.1));

        // Schedule finally blocks in order (innermost first)
        // The last one scheduled will be popped first
        for (i, (handler_offset, _)) in finally_blocks.iter().enumerate() {
            // The last finally should have the actual leave target
            let target = if i == finally_blocks.len() - 1 {
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
    /// * `exception` - The exception value to resolve
    /// * `thread` - The emulation thread for heap lookups
    ///
    /// # Returns
    ///
    /// - `Some(Token)` for `ObjectRef` (from heap), `ValueType`, or `TypedRef`
    /// - `None` for primitive types or unresolvable values
    fn resolve_exception_type(exception: &EmValue, thread: &EmulationThread) -> Option<Token> {
        match exception {
            EmValue::ObjectRef(href) => thread.heap().get_type_token(*href).ok(),
            EmValue::ValueType { type_token, .. } | EmValue::TypedRef { type_token, .. } => {
                Some(*type_token)
            }
            _ => None,
        }
    }

    /// Applies a handler match result, pushing exception if needed and returning target offset.
    ///
    /// For catch/filter handlers, pushes the exception onto the stack.
    /// For catch handlers, also enters the catch handler state for proper rethrow handling.
    ///
    /// # Arguments
    ///
    /// * `handler_match` - The matched handler (catch, filter, finally, or fault)
    /// * `exception` - The exception value being handled
    /// * `origin_offset` - The original instruction offset where the exception was thrown
    /// * `thread` - The emulation thread for stack operations
    ///
    /// # Returns
    ///
    /// The instruction offset to jump to for handler execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full when pushing the exception.
    fn apply_handler_match(
        handler_match: &HandlerMatch,
        exception: EmValue,
        origin_offset: u32,
        thread: &mut EmulationThread,
    ) -> Result<u32> {
        match handler_match {
            HandlerMatch::Catch { handler_offset, .. } => {
                thread.push(exception)?;
                thread
                    .exception_state_mut()
                    .enter_catch_handler(origin_offset, *handler_offset);
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

    /// Handles `initobj` instruction - initializes value type at address to default.
    ///
    /// Writes a default-initialized value type to the address on the stack.
    /// Supports managed pointers to locals, arguments, array elements, and object fields.
    ///
    /// For TypeSpec tokens representing generic type parameters (like `!!0` in a generic
    /// method), this function attempts to determine the appropriate default value based
    /// on the type signature. Reference types default to null, while value types get
    /// an empty `ValueType` placeholder.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for stack and memory access
    /// * `context` - Optional emulation context for resolving TypeSpec signatures
    /// * `type_token` - Token of the value type to initialize
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack underflow occurs
    /// - Null reference is passed
    /// - Address is not a valid managed pointer
    fn handle_initobj(
        thread: &mut EmulationThread,
        context: Option<&EmulationContext>,
        type_token: Token,
    ) -> Result<()> {
        let addr = thread.pop()?;

        match addr {
            EmValue::ManagedPtr(ptr) => {
                // Determine the appropriate default value based on the type
                let default_value = Self::get_initobj_default_value(context, type_token);

                // Write the default value to the pointer target
                match &ptr.target {
                    PointerTarget::Local(idx) => {
                        thread
                            .current_frame_mut()
                            .ok_or_else(|| EmulationError::InternalError {
                                description: "empty call stack".into(),
                            })?
                            .locals_mut()
                            .set(usize::from(*idx), default_value)?;
                    }
                    PointerTarget::Argument(idx) => {
                        thread
                            .current_frame_mut()
                            .ok_or_else(|| EmulationError::InternalError {
                                description: "empty call stack".into(),
                            })?
                            .arguments_mut()
                            .set(usize::from(*idx), default_value)?;
                    }
                    PointerTarget::ArrayElement { array, index } => {
                        thread
                            .heap_mut()
                            .set_array_element(*array, *index, default_value)?;
                    }
                    PointerTarget::ObjectField { object, field } => {
                        thread
                            .heap_mut()
                            .set_field(*object, *field, default_value)?;
                    }
                    PointerTarget::StaticField(_) => {
                        // Static fields are handled separately
                    }
                }
            }
            EmValue::UnmanagedPtr(_) => {
                // For unmanaged pointers, we can't safely initialize
                // In a real emulator, this would write to raw memory
            }
            EmValue::Null => {
                return Err(EmulationError::NullReference.into());
            }
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "initobj",
                    expected: "managed pointer",
                    found: addr.cil_flavor().as_str(),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Gets the appropriate default value for an `initobj` instruction based on the type.
    ///
    /// For TypeSpec tokens (table 0x1B), this resolves the signature to determine
    /// if the type is a reference type (defaults to null) or a value type (defaults
    /// to a `ValueType` with empty fields).
    ///
    /// Generic type parameters (`!!0`, `!0`) are treated as reference types since
    /// without knowing the actual instantiation, we can't determine the correct
    /// default. This is safe because reference type default (null) will work for
    /// most deobfuscation scenarios where the actual value gets assigned later.
    fn get_initobj_default_value(context: Option<&EmulationContext>, type_token: Token) -> EmValue {
        // Try to resolve TypeSpec tokens to get more precise default values
        if type_token.is_table(TableId::TypeSpec) {
            if let Some(ctx) = context {
                if let Some(typespec_sig) = ctx.get_typespec_signature(type_token) {
                    // Check what kind of type this TypeSpec represents
                    return match &typespec_sig.base {
                        // Primitive types - use appropriate defaults
                        TypeSignature::Boolean => EmValue::Bool(false),
                        TypeSignature::Char => EmValue::Char('\0'),
                        TypeSignature::I1
                        | TypeSignature::U1
                        | TypeSignature::I2
                        | TypeSignature::U2
                        | TypeSignature::I4
                        | TypeSignature::U4 => EmValue::I32(0),
                        TypeSignature::I8 | TypeSignature::U8 => EmValue::I64(0),
                        TypeSignature::R4 => EmValue::F32(0.0),
                        TypeSignature::R8 => EmValue::F64(0.0),
                        TypeSignature::I | TypeSignature::U => EmValue::NativeInt(0),

                        // Pointer types
                        TypeSignature::Ptr(_) => EmValue::UnmanagedPtr(0),

                        // Generic type parameters, reference types, and by-ref - default to null
                        TypeSignature::GenericParamType(_)
                        | TypeSignature::GenericParamMethod(_)
                        | TypeSignature::String
                        | TypeSignature::Object
                        | TypeSignature::Class(_)
                        | TypeSignature::SzArray(_)
                        | TypeSignature::Array(_)
                        | TypeSignature::ByRef(_) => EmValue::Null,

                        // Generic instantiation - check if the base type is a value type
                        TypeSignature::GenericInst(base_type, _) => {
                            if matches!(base_type.as_ref(), TypeSignature::ValueType(_)) {
                                EmValue::ValueType {
                                    type_token,
                                    fields: Vec::new(),
                                }
                            } else {
                                EmValue::Null
                            }
                        }

                        // Value types and other types - default to ValueType for safety
                        _ => EmValue::ValueType {
                            type_token,
                            fields: Vec::new(),
                        },
                    };
                }
            }
        }

        // Default behavior: ValueType with empty fields
        EmValue::ValueType {
            type_token,
            fields: Vec::new(),
        }
    }

    /// Handles `cpobj` instruction - copies a value type from source to destination.
    ///
    /// Reads a value type from the source address and writes it to the destination
    /// address. Both addresses must be managed pointers pointing to value types.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for stack and memory access
    /// * `context` - Optional emulation context for type verification
    /// * `type_token` - Token of the value type being copied
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Stack underflow occurs
    /// - Either address is null
    /// - Source value is not a value type
    /// - Destination is not a valid managed pointer
    fn handle_cpobj(
        &self,
        thread: &mut EmulationThread,
        context: Option<&EmulationContext>,
        type_token: Token,
    ) -> Result<()> {
        let src_addr = thread.pop()?;
        let dest_addr = thread.pop()?;

        // Read value from source
        let value = match src_addr {
            EmValue::ManagedPtr(ptr) => match &ptr.target {
                PointerTarget::Local(idx) => thread
                    .current_frame()
                    .ok_or_else(|| EmulationError::InternalError {
                        description: "empty call stack".into(),
                    })?
                    .locals()
                    .get(usize::from(*idx))?
                    .clone(),
                PointerTarget::Argument(idx) => thread
                    .current_frame()
                    .ok_or_else(|| EmulationError::InternalError {
                        description: "empty call stack".into(),
                    })?
                    .arguments()
                    .get(usize::from(*idx))?
                    .clone(),
                PointerTarget::ArrayElement { array, index } => {
                    thread.heap().get_array_element(*array, *index)?.clone()
                }
                PointerTarget::ObjectField { object, field } => {
                    thread.heap().get_field(*object, *field)?.clone()
                }
                PointerTarget::StaticField(field) => self
                    .address_space
                    .get_static(*field)
                    .unwrap_or(EmValue::Null),
            },
            EmValue::Null => {
                return Err(EmulationError::NullReference.into());
            }
            other => other, // If not a pointer, use the value directly
        };

        // Verify value type is a value type (cpobj is for copying value types)
        let _ = (context, type_token); // Available for future enhanced type resolution
        let value_flavor = value.cil_flavor();
        let is_value_type = value_flavor.is_value_type();
        if !is_value_type {
            return Err(EmulationError::TypeMismatch {
                operation: "cpobj",
                expected: "value type",
                found: format!("{value_flavor:?}").leak(),
            }
            .into());
        }

        // Write value to destination
        match dest_addr {
            EmValue::ManagedPtr(ptr) => {
                match &ptr.target {
                    PointerTarget::Local(idx) => {
                        thread
                            .current_frame_mut()
                            .ok_or_else(|| EmulationError::InternalError {
                                description: "empty call stack".into(),
                            })?
                            .locals_mut()
                            .set(usize::from(*idx), value)?;
                    }
                    PointerTarget::Argument(idx) => {
                        thread
                            .current_frame_mut()
                            .ok_or_else(|| EmulationError::InternalError {
                                description: "empty call stack".into(),
                            })?
                            .arguments_mut()
                            .set(usize::from(*idx), value)?;
                    }
                    PointerTarget::ArrayElement { array, index } => {
                        thread.heap_mut().set_array_element(*array, *index, value)?;
                    }
                    PointerTarget::ObjectField { object, field } => {
                        thread.heap_mut().set_field(*object, *field, value)?;
                    }
                    PointerTarget::StaticField(_) => {
                        // Static fields handled separately
                    }
                }
            }
            EmValue::Null => {
                return Err(EmulationError::NullReference.into());
            }
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "cpobj",
                    expected: "managed pointer",
                    found: dest_addr.cil_flavor().as_str(),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Handles `cpblk` instruction - copies a block of memory.
    ///
    /// Copies `size` bytes from the source address to the destination address.
    /// Operates on unmanaged memory through the address space.
    ///
    /// Stack: ..., dest, src, size -> ...
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for address space access
    /// * `dest` - Destination pointer value
    /// * `src` - Source pointer value
    /// * `size` - Number of bytes to copy
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Pointer extraction fails
    /// - Size extraction fails
    /// - Memory copy operation fails
    fn handle_cpblk(
        thread: &mut EmulationThread,
        dest: &EmValue,
        src: &EmValue,
        size: &EmValue,
    ) -> Result<()> {
        // Extract destination address
        let dest_addr = dest.as_pointer_address()?;

        // Extract source address
        let src_addr = src.as_pointer_address()?;

        // Extract size
        let size_bytes = size.as_size()?;

        // Perform the block copy in unmanaged memory
        thread
            .address_space()
            .copy_block(dest_addr, src_addr, size_bytes)
    }

    /// Handles `initblk` instruction - initializes a block of memory.
    ///
    /// Sets `size` bytes at the target address to the specified byte value.
    /// Operates on unmanaged memory through the address space.
    ///
    /// Stack: ..., addr, value, size -> ...
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread for address space access
    /// * `addr` - Target pointer value
    /// * `value` - Byte value to fill with (only low 8 bits used)
    /// * `size` - Number of bytes to initialize
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Pointer extraction fails
    /// - Value is not an integer type
    /// - Size extraction fails
    /// - Memory initialization fails
    #[allow(clippy::cast_sign_loss)] // Intentional byte truncation
    fn handle_initblk(
        thread: &mut EmulationThread,
        addr: &EmValue,
        value: &EmValue,
        size: &EmValue,
    ) -> Result<()> {
        // Extract address
        let address = addr.as_pointer_address()?;

        // Extract the byte value to initialize with
        // On the CIL stack, all small integers are widened to I32
        #[allow(clippy::match_same_arms)]
        let byte_value = match *value {
            EmValue::I32(n) => (n & 0xFF) as u8,
            EmValue::I64(n) => (n & 0xFF) as u8,
            EmValue::NativeInt(n) => (n & 0xFF) as u8,
            EmValue::NativeUInt(n) => (n & 0xFF) as u8,
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "initblk",
                    expected: "integer value",
                    found: value.type_name(),
                }
                .into());
            }
        };

        // Extract size
        let size_bytes = size.as_size()?;

        // Perform the block initialization in unmanaged memory
        thread
            .address_space()
            .init_block(address, byte_value, size_bytes)
    }
}

impl Default for EmulationController {
    fn default() -> Self {
        let address_space = Arc::new(AddressSpace::new());
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let capture = Arc::new(CaptureContext::default());
        let config = Arc::new(EmulationConfig::default());
        let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
        Self::new(
            address_space,
            runtime,
            capture,
            config,
            None,
            fake_objects,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test::emulation::create_test_thread, CilObject};

    /// Helper function to create a controller for testing with default infrastructure.
    fn create_test_controller() -> EmulationController {
        EmulationController::default()
    }

    /// Helper function to create a controller with custom runtime.
    fn create_test_controller_with_runtime(
        runtime: Arc<RwLock<RuntimeState>>,
    ) -> EmulationController {
        let address_space = Arc::new(AddressSpace::new());
        let capture = Arc::new(CaptureContext::default());
        let config = Arc::new(EmulationConfig::default());
        let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
        EmulationController::new(
            address_space,
            runtime,
            capture,
            config,
            None,
            fake_objects,
            None,
        )
    }

    /// Creates a minimal [`EmulationContext`] for unit tests.
    ///
    /// Uses crafted_2.exe as a test assembly.
    fn create_test_context() -> EmulationContext {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/samples/crafted_2.exe");
        let assembly = CilObject::from_path(&path).expect("Failed to load test assembly");
        EmulationContext::new(Arc::new(assembly))
    }

    #[test]
    fn test_controller_creation() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let controller = create_test_controller_with_runtime(runtime);
        // RuntimeState::new() initializes with default hooks
        assert!(!controller.runtime().read().unwrap().hooks().is_empty());
    }

    #[test]
    fn test_controller_with_custom_limits() {
        // Use default controller and verify limits from config
        let controller = create_test_controller();

        // Default config has default limits
        assert!(controller.limits().max_instructions > 0);
        assert!(controller.limits().max_call_depth > 0);
    }

    #[test]
    fn test_controller_with_runtime() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let controller = create_test_controller_with_runtime(runtime);

        // Verify runtime is set and hooks are accessible
        // RuntimeState::new() initializes with default hooks
        let guard = controller.runtime().read().unwrap();
        assert!(
            !guard.hooks().is_empty(),
            "RuntimeState should have default hooks"
        );
    }

    // Note: Static field tests are in addressspace.rs and statics.rs
    // Note: Type size tests are in context.rs (get_type_size and flavor_to_size)

    #[test]
    fn test_hook_registration() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let _controller = create_test_controller_with_runtime(runtime.clone());
        let initial_count = runtime.read().unwrap().hooks().len();

        // RuntimeState::new() should have default hooks registered (BCL + native)
        assert!(initial_count > 0, "Should have default hooks registered");

        // Set unknown method behavior
        runtime
            .write()
            .unwrap()
            .set_unknown_method_behavior(UnknownMethodBehavior::Fail);

        // Hook count should remain the same
        assert_eq!(runtime.read().unwrap().hooks().len(), initial_count);

        // Verify behavior was set
        assert_eq!(
            runtime.read().unwrap().unknown_method_behavior(),
            UnknownMethodBehavior::Fail
        );
    }

    #[test]
    fn test_limits_accessors() {
        // Limits come from EmulationConfig via the Default implementation
        let controller = create_test_controller();

        // Default config has reasonable limits
        assert!(controller.limits().max_instructions > 0);
        assert!(controller.limits().max_call_depth > 0);
    }

    // Note: ExceptionState tests were moved to exception/state.rs with ThreadExceptionState

    #[test]
    fn test_handle_box() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        // Push a value to box
        thread.push(EmValue::I32(42)).unwrap();

        // Box it
        EmulationController::handle_box(&mut thread, type_token).unwrap();

        // Should have a boxed reference on stack
        let result = thread.pop().unwrap();
        assert!(matches!(result, EmValue::ObjectRef(_)));

        // Verify the boxed value
        if let EmValue::ObjectRef(href) = result {
            let unboxed = thread.heap().get_boxed_value(href).unwrap();
            assert_eq!(unboxed, EmValue::I32(42));
        }
    }

    #[test]
    fn test_handle_unbox() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        // Allocate a boxed value
        let boxed_ref = thread
            .heap_mut()
            .alloc_boxed(type_token, EmValue::I64(100))
            .unwrap();
        thread.push(EmValue::ObjectRef(boxed_ref)).unwrap();

        // Unbox it
        EmulationController::handle_unbox(&mut thread, None, type_token).unwrap();

        // Should have the unboxed value
        let result = thread.pop().unwrap();
        assert_eq!(result, EmValue::I64(100));
    }

    #[test]
    fn test_handle_unbox_null_fails() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        thread.push(EmValue::Null).unwrap();

        let result = EmulationController::handle_unbox(&mut thread, None, type_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_unbox_already_unboxed() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        // Push an already unboxed value
        thread.push(EmValue::F64(std::f64::consts::PI)).unwrap();

        // Unbox should pass it through
        EmulationController::handle_unbox(&mut thread, None, type_token).unwrap();

        let result = thread.pop().unwrap();
        assert_eq!(result, EmValue::F64(std::f64::consts::PI));
    }

    // Note: sizeof tests are in context.rs (get_type_size, flavor_to_size)
    // handle_sizeof requires an EmulationContext for type size lookup

    #[test]
    fn test_handle_ldsfld_known_field() {
        let controller = EmulationController::default();
        let context = create_test_context();
        let field = Token::new(0x04000001);
        let mut thread = create_test_thread();

        // Set a static field value via AddressSpace
        controller
            .address_space()
            .set_static(field, EmValue::I32(999));

        controller
            .handle_ldsfld(&mut thread, &context, field)
            .unwrap();

        let result = thread.pop().unwrap();
        assert_eq!(result, EmValue::I32(999));
    }

    #[test]
    fn test_handle_ldsfld_unknown_returns_symbolic() {
        let controller = EmulationController::default();
        let context = create_test_context();
        let field = Token::new(0x04000099); // Unknown field
        let mut thread = create_test_thread();

        controller
            .handle_ldsfld(&mut thread, &context, field)
            .unwrap();

        let result = thread.pop().unwrap();
        assert!(matches!(result, EmValue::Symbolic(_)));
    }

    #[test]
    fn test_heap_array_creation() {
        let mut thread = create_test_thread();

        // Test array creation directly via heap - this is what handle_newarr does internally
        let array_ref = thread.heap_mut().alloc_array(CilFlavor::I4, 5).unwrap();
        thread.push(EmValue::ObjectRef(array_ref)).unwrap();

        // Verify array was created
        let result = thread.pop().unwrap();
        if let EmValue::ObjectRef(href) = result {
            let len = thread.heap().get_array_length(href).unwrap();
            assert_eq!(len, 5);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_heap_array_element_access() {
        let thread = create_test_thread();

        // Create array and set elements
        let array_ref = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();

        // Set elements
        thread
            .heap_mut()
            .set_array_element(array_ref, 0, EmValue::I32(10))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(array_ref, 1, EmValue::I32(20))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(array_ref, 2, EmValue::I32(30))
            .unwrap();

        // Verify elements
        assert_eq!(
            thread.heap().get_array_element(array_ref, 0).unwrap(),
            EmValue::I32(10)
        );
        assert_eq!(
            thread.heap().get_array_element(array_ref, 1).unwrap(),
            EmValue::I32(20)
        );
        assert_eq!(
            thread.heap().get_array_element(array_ref, 2).unwrap(),
            EmValue::I32(30)
        );
    }

    #[test]
    fn test_heap_string_creation() {
        let thread = create_test_thread();

        // Create string on heap
        let str_ref = thread.heap().alloc_string("Hello, World!").unwrap();

        // Verify string content
        let content = thread.heap().get_string(str_ref).unwrap();
        assert_eq!(&*content, "Hello, World!");
    }
}
