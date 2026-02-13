//! Emulation thread implementation.
//!
//! This module provides the per-thread execution state for .NET emulation,
//! including the call stack, evaluation stack, instruction pointer, and
//! exception handling state.
//!
//! # Thread Structure
//!
//! Each emulation thread maintains:
//!
//! - **Call Stack**: Stack of [`ThreadCallFrame`]s representing method calls
//! - **Evaluation Stack**: The CIL evaluation stack for intermediate values
//! - **Exception State**: Current exception handling context
//! - **Thread-Local Storage**: Per-thread data storage
//!
//! # Call Frame Layout
//!
//! Each call frame ([`ThreadCallFrame`]) contains:
//!
//! - Method token identifying the executing method
//! - Local variables storage
//! - Argument storage
//! - Instruction pointer (current offset in method body)
//! - Saved caller stack for method returns
//!
//! # Thread States
//!
//! Threads transition through [`ThreadState`]:
//!
//! 1. `Ready` - Created but not yet running
//! 2. `Running` - Actively executing instructions
//! 3. `Waiting` - Blocked on synchronization ([`WaitReason`] specifies why)
//! 4. Terminal: `Completed`, `Faulted`, or `Aborted`
//!
//! # Example
//!
//! ```ignore
//! use dotscope::emulation::thread::{EmulationThread, ThreadCallFrame};
//!
//! // Create a thread
//! let mut thread = EmulationThread::new(thread_id, address_space, capture, assembly);
//!
//! // Start executing a method
//! thread.start_method(method_token, locals, args, expects_return);
//!
//! // Push/pop values on evaluation stack
//! thread.push(EmValue::I32(42))?;
//! let value = thread.pop()?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::{
    emulation::{
        capture::CaptureContext,
        engine::EmulationError,
        exception::ThreadExceptionState,
        fakeobjects::SharedFakeObjects,
        memory::{HeapObject, ManagedHeap},
        value::PointerTarget,
        AddressSpace, ArgumentStorage, EmValue, EvaluationStack, HeapRef, LocalVariables,
        ManagedPointer, ThreadId,
    },
    metadata::{token::Token, typesystem::CilFlavor},
    CilObject, Error, Result,
};

/// Thread execution state.
///
/// Represents the current lifecycle stage of an emulation thread. Threads
/// progress through these states during their lifetime, with `Completed`,
/// `Faulted`, and `Aborted` being terminal states.
///
/// # State Transitions
///
/// ```text
/// Ready -> Running -> Completed
///            |           ^
///            v           |
///       Waiting --------'
///            |
///            v
///       Faulted / Aborted
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ThreadState {
    /// Thread is ready to execute but not currently running.
    ///
    /// Threads start in this state and return to it when preempted or
    /// after being woken from a wait.
    #[default]
    Ready,

    /// Thread is currently executing instructions.
    ///
    /// Only one thread can be in this state at a time within a single
    /// scheduler context.
    Running,

    /// Thread is blocked waiting for a condition.
    ///
    /// The [`WaitReason`] specifies what the thread is waiting for.
    Waiting(WaitReason),

    /// Thread completed execution normally.
    ///
    /// The return value (if any) can be retrieved from the thread.
    Completed,

    /// Thread terminated with an unhandled exception.
    ///
    /// The exception details can be retrieved from the thread's exception state.
    Faulted,

    /// Thread was explicitly aborted.
    ///
    /// This occurs when `Thread.Abort()` is called or during forced termination.
    Aborted,
}

/// Reason a thread is blocked in the [`ThreadState::Waiting`] state.
///
/// This enum provides context about what synchronization primitive or
/// condition the thread is waiting for. The scheduler uses this information
/// to determine when to wake the thread.
///
/// Most variants include a [`HeapRef`] identifying the specific synchronization
/// object being waited on. This allows the scheduler to correctly wake threads
/// when the corresponding object is signaled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitReason {
    /// Waiting to acquire a monitor lock (`Monitor.Enter` / `lock`).
    ///
    /// Contains the heap reference of the object being used as a monitor.
    Monitor(HeapRef),

    /// Waiting for an event to be signaled (`WaitHandle.WaitOne`).
    ///
    /// Contains the heap reference of the event object.
    Event(HeapRef),

    /// Waiting for another thread to complete (`Thread.Join`).
    ///
    /// Contains the ID of the thread being waited on.
    Thread(ThreadId),

    /// Sleeping for a specified duration (`Thread.Sleep`).
    ///
    /// The thread should wake when the virtual instruction count reaches
    /// or exceeds `until_instruction`.
    Sleep {
        /// Virtual instruction count at which to wake the thread.
        until_instruction: u64,
    },

    /// Waiting to acquire a mutex (`Mutex.WaitOne`).
    ///
    /// Contains the heap reference of the mutex object.
    Mutex(HeapRef),

    /// Waiting to acquire a semaphore slot (`Semaphore.WaitOne`).
    ///
    /// Contains the heap reference of the semaphore object.
    Semaphore(HeapRef),
}

/// Thread priority levels for scheduling.
///
/// Higher priority threads are scheduled before lower priority threads.
/// Within the same priority level, threads are scheduled in FIFO order.
///
/// These correspond to the .NET `ThreadPriority` enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ThreadPriority {
    /// Lowest scheduling priority.
    Lowest = 0,

    /// Below normal scheduling priority.
    BelowNormal = 1,

    /// Normal (default) scheduling priority.
    #[default]
    Normal = 2,

    /// Above normal scheduling priority.
    AboveNormal = 3,

    /// Highest scheduling priority.
    Highest = 4,
}

/// A call frame on the thread's call stack.
///
/// Each method invocation creates a new call frame that stores the method's
/// execution context: local variables, arguments, instruction pointer, and
/// information needed to return to the caller.
///
/// # Stack Management
///
/// When a method call occurs:
/// 1. A new frame is pushed with the callee's locals and arguments
/// 2. The caller's evaluation stack is saved in the new frame
/// 3. Execution continues in the callee
///
/// When a method returns:
/// 1. The frame is popped
/// 2. The caller's evaluation stack is restored
/// 3. Any return value is pushed onto the restored stack
#[derive(Clone, Debug)]
pub struct ThreadCallFrame {
    /// Metadata token of the method being executed.
    method: Token,

    /// Method token of the caller (used for return navigation).
    return_method: Option<Token>,

    /// Instruction offset in the caller to return to.
    return_offset: u32,

    /// Local variables storage for this method.
    locals: LocalVariables,

    /// Arguments passed to this method.
    arguments: ArgumentStorage,

    /// Current instruction pointer (byte offset in method body).
    instruction_offset: u32,

    /// Whether the caller expects a return value to be pushed.
    expects_return: bool,

    /// Saved evaluation stack from the caller (restored on return).
    caller_stack: Vec<EmValue>,
}

impl ThreadCallFrame {
    /// Creates a new call frame for a method invocation.
    ///
    /// # Arguments
    ///
    /// * `method` - Token of the method being called
    /// * `return_method` - Token of the caller method (for return navigation)
    /// * `return_offset` - Instruction offset to return to in the caller
    /// * `local_types` - Types of local variables declared in the method
    /// * `args` - Arguments passed to the method (value and type pairs)
    /// * `expects_return` - Whether the caller expects a return value
    #[must_use]
    pub fn new(
        method: Token,
        return_method: Option<Token>,
        return_offset: u32,
        local_types: Vec<CilFlavor>,
        args: Vec<(EmValue, CilFlavor)>,
        expects_return: bool,
    ) -> Self {
        let (arg_values, arg_types): (Vec<_>, Vec<_>) = args.into_iter().unzip();
        Self {
            method,
            return_method,
            return_offset,
            locals: LocalVariables::new(local_types),
            arguments: ArgumentStorage::new(arg_values, arg_types),
            instruction_offset: 0,
            expects_return,
            caller_stack: Vec::new(),
        }
    }

    /// Returns the method token for this frame.
    #[must_use]
    pub fn method(&self) -> Token {
        self.method
    }

    /// Returns the method token to return to (the caller).
    #[must_use]
    pub fn return_method(&self) -> Option<Token> {
        self.return_method
    }

    /// Returns the instruction offset to resume at in the caller.
    #[must_use]
    pub fn return_offset(&self) -> u32 {
        self.return_offset
    }

    /// Returns the current instruction pointer (byte offset in method body).
    #[must_use]
    pub fn ip(&self) -> u32 {
        self.instruction_offset
    }

    /// Sets the instruction pointer to a specific offset.
    ///
    /// Used for jumps, branches, and exception handling.
    pub fn set_ip(&mut self, offset: u32) {
        self.instruction_offset = offset;
    }

    /// Advances the instruction pointer by the given delta.
    ///
    /// Typically called after executing an instruction to move to the next one.
    pub fn advance_ip(&mut self, delta: u32) {
        self.instruction_offset += delta;
    }

    /// Returns whether the caller expects a return value.
    #[must_use]
    pub fn expects_return(&self) -> bool {
        self.expects_return
    }

    /// Returns the number of local variables in this frame.
    #[must_use]
    pub fn local_count(&self) -> usize {
        self.locals.count()
    }

    /// Gets a local variable by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_local(&self, index: u16) -> Option<&EmValue> {
        self.locals.get(index as usize).ok()
    }

    /// Sets a local variable by index.
    ///
    /// Returns `true` on success, `false` if the index is out of bounds.
    pub fn set_local(&mut self, index: u16, value: EmValue) -> bool {
        self.locals.set(index as usize, value).is_ok()
    }

    /// Returns the type of a local variable.
    #[must_use]
    pub fn local_type(&self, index: u16) -> Option<&CilFlavor> {
        self.locals.get_type(index as usize).ok()
    }

    /// Returns the number of arguments in this frame.
    #[must_use]
    pub fn argument_count(&self) -> usize {
        self.arguments.count()
    }

    /// Gets an argument by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_argument(&self, index: u16) -> Option<&EmValue> {
        self.arguments.get(index as usize).ok()
    }

    /// Sets an argument by index (for `starg` instruction).
    ///
    /// Returns `true` on success, `false` if the index is out of bounds.
    pub fn set_argument(&mut self, index: u16, value: EmValue) -> bool {
        self.arguments.set(index as usize, value).is_ok()
    }

    /// Returns the type of an argument.
    #[must_use]
    pub fn argument_type(&self, index: u16) -> Option<&CilFlavor> {
        self.arguments.get_type(index as usize).ok()
    }

    /// Saves the caller's evaluation stack for later restoration.
    ///
    /// Called when entering a new method to preserve the caller's stack state.
    pub fn save_caller_stack(&mut self, stack: Vec<EmValue>) {
        self.caller_stack = stack;
    }

    /// Takes the saved caller's stack, leaving an empty vector.
    ///
    /// Used when returning from a method to restore the caller's stack.
    pub fn take_caller_stack(&mut self) -> Vec<EmValue> {
        std::mem::take(&mut self.caller_stack)
    }

    /// Returns a reference to the saved caller's stack.
    #[must_use]
    pub fn caller_stack(&self) -> &[EmValue] {
        &self.caller_stack
    }

    /// Returns a reference to the local variables storage.
    #[must_use]
    pub fn locals(&self) -> &LocalVariables {
        &self.locals
    }

    /// Returns a mutable reference to the local variables storage.
    pub fn locals_mut(&mut self) -> &mut LocalVariables {
        &mut self.locals
    }

    /// Returns a reference to the arguments storage.
    #[must_use]
    pub fn arguments(&self) -> &ArgumentStorage {
        &self.arguments
    }

    /// Returns a mutable reference to the arguments storage.
    pub fn arguments_mut(&mut self) -> &mut ArgumentStorage {
        &mut self.arguments
    }
}

/// Per-thread execution state for .NET emulation.
///
/// `EmulationThread` represents a single managed thread in the emulated
/// .NET runtime. It maintains all thread-local state including:
///
/// - Call stack with method frames
/// - CIL evaluation stack
/// - Exception handling context
/// - Thread-local storage
///
/// # Shared State
///
/// Threads share access to:
/// - Address space (managed heap, statics, unmanaged memory)
/// - Capture context (for recording decrypted strings, etc.)
/// - Assembly metadata
///
/// # Example
///
/// ```ignore
/// // Create a new thread
/// let thread = EmulationThread::new(
///     ThreadId::new(1),
///     address_space,
///     capture,
///     Some(assembly),
/// );
///
/// // Or create the main thread with ID 1
/// let main = EmulationThread::main(address_space, capture, Some(assembly));
/// ```
pub struct EmulationThread {
    /// Unique identifier for this thread.
    id: ThreadId,

    /// Optional name for debugging (e.g., "Main", "Worker-1").
    name: Option<String>,

    /// Scheduling priority.
    priority: ThreadPriority,

    /// Current execution state.
    state: ThreadState,

    /// Call stack of method frames.
    call_stack: Vec<ThreadCallFrame>,

    /// CIL evaluation stack for intermediate values.
    eval_stack: EvaluationStack,

    /// Exception handling state (current exception, handler stack).
    exception_state: ThreadExceptionState,

    /// Thread-local storage (field token -> value).
    tls: HashMap<Token, EmValue>,

    /// Shared address space for heap and memory access.
    address_space: Arc<AddressSpace>,

    /// Shared capture context for recording emulation artifacts.
    capture: Arc<CaptureContext>,

    /// Assembly being emulated (for metadata access).
    assembly: Option<Arc<CilObject>>,

    /// Total instructions executed by this thread.
    instructions_executed: u64,

    /// Return value when thread completes.
    return_value: Option<EmValue>,

    /// Pending reflection invoke request from a stub.
    ///
    /// When a stub like `MethodBase.Invoke()` wants to invoke a reflected method,
    /// it sets this field. The emulation controller checks this after each stub
    /// call and handles the method invocation.
    pending_reflection_invoke: Option<ReflectionInvokeRequest>,

    /// Pre-allocated fake BCL objects shared with other threads.
    ///
    /// These objects ensure that BCL methods like `Assembly.GetExecutingAssembly()`
    /// return the same reference each time, which is critical for anti-tamper checks.
    fake_objects: SharedFakeObjects,
}

/// A request to invoke a method via reflection.
///
/// Used by stubs to signal that a reflected method should be invoked.
#[derive(Debug, Clone)]
pub struct ReflectionInvokeRequest {
    /// The method token to invoke.
    pub method_token: Token,
    /// The 'this' reference for instance methods (None for static).
    pub this_ref: Option<EmValue>,
    /// Arguments to pass to the method.
    pub args: Vec<EmValue>,
}

impl fmt::Debug for EmulationThread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmulationThread")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("state", &self.state)
            .field("call_stack", &self.call_stack)
            .field("eval_stack", &self.eval_stack)
            .field("exception_state", &self.exception_state)
            .field("tls", &self.tls)
            .field("address_space", &"...")
            .field("capture", &"...")
            .field("assembly", &self.assembly.as_ref().map(|_| "..."))
            .field("instructions_executed", &self.instructions_executed)
            .field("return_value", &self.return_value)
            .field("pending_reflection_invoke", &self.pending_reflection_invoke)
            .finish_non_exhaustive()
    }
}

impl EmulationThread {
    /// Creates a new thread with the given configuration.
    ///
    /// The thread starts in the [`ThreadState::Ready`] state with normal
    /// priority and an empty call stack.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this thread
    /// * `address_space` - Shared address space for memory operations
    /// * `capture` - Shared capture context for recording artifacts
    /// * `assembly` - Optional assembly for metadata access
    /// * `fake_objects` - Pre-allocated fake BCL objects for consistent references
    pub fn new(
        id: ThreadId,
        address_space: Arc<AddressSpace>,
        capture: Arc<CaptureContext>,
        assembly: Option<Arc<CilObject>>,
        fake_objects: SharedFakeObjects,
    ) -> Self {
        Self {
            id,
            name: None,
            priority: ThreadPriority::Normal,
            state: ThreadState::Ready,
            call_stack: Vec::new(),
            eval_stack: EvaluationStack::new(1000),
            exception_state: ThreadExceptionState::new(),
            tls: HashMap::new(),
            address_space,
            capture,
            assembly,
            instructions_executed: 0,
            return_value: None,
            pending_reflection_invoke: None,
            fake_objects,
        }
    }

    /// Creates the main thread (ID 1) with the name "Main".
    ///
    /// This is a convenience constructor for creating the primary thread
    /// that typically executes the program's entry point.
    pub fn main(
        address_space: Arc<AddressSpace>,
        capture: Arc<CaptureContext>,
        assembly: Option<Arc<CilObject>>,
        fake_objects: SharedFakeObjects,
    ) -> Self {
        let mut thread = Self::new(
            ThreadId::MAIN,
            address_space,
            capture,
            assembly,
            fake_objects,
        );
        thread.name = Some("Main".to_string());
        thread
    }

    /// Returns a reference to the shared fake BCL objects.
    ///
    /// BCL hooks use these pre-allocated objects to return consistent references
    /// for methods like `Assembly.GetExecutingAssembly()`.
    #[must_use]
    pub fn fake_objects(&self) -> &SharedFakeObjects {
        &self.fake_objects
    }

    /// Returns the capture context for recording emulation artifacts.
    ///
    /// Stubs can use this to capture decrypted strings, loaded assemblies,
    /// and other data discovered during emulation.
    #[must_use]
    pub fn capture(&self) -> &Arc<CaptureContext> {
        &self.capture
    }

    /// Returns the assembly being emulated.
    ///
    /// Stubs can use this to access metadata, type information, PE data,
    /// and other assembly-level data during emulation.
    #[must_use]
    pub fn assembly(&self) -> Option<&Arc<CilObject>> {
        self.assembly.as_ref()
    }

    /// Returns the thread's unique identifier.
    #[must_use]
    pub fn id(&self) -> ThreadId {
        self.id
    }

    /// Returns the thread's name, if set.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Sets the thread's name for debugging purposes.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Returns the thread's scheduling priority.
    #[must_use]
    pub fn priority(&self) -> ThreadPriority {
        self.priority
    }

    /// Sets the thread's scheduling priority.
    pub fn set_priority(&mut self, priority: ThreadPriority) {
        self.priority = priority;
    }

    /// Returns the thread's current execution state.
    #[must_use]
    pub fn state(&self) -> ThreadState {
        self.state
    }

    /// Sets the thread's execution state.
    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// Checks if the thread is ready to execute.
    ///
    /// Returns `true` if the thread is in `Ready` or `Running` state.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.state, ThreadState::Ready | ThreadState::Running)
    }

    /// Checks if the thread has reached a terminal state.
    ///
    /// Returns `true` if the thread is `Completed`, `Faulted`, or `Aborted`.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(
            self.state,
            ThreadState::Completed | ThreadState::Faulted | ThreadState::Aborted
        )
    }

    /// Returns the current (topmost) call frame, if any.
    #[must_use]
    pub fn current_frame(&self) -> Option<&ThreadCallFrame> {
        self.call_stack.last()
    }

    /// Returns a mutable reference to the current call frame.
    pub fn current_frame_mut(&mut self) -> Option<&mut ThreadCallFrame> {
        self.call_stack.last_mut()
    }

    /// Returns the current call stack depth (number of frames).
    #[must_use]
    pub fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Pushes a new call frame onto the call stack.
    ///
    /// Used when entering a method.
    pub fn push_frame(&mut self, frame: ThreadCallFrame) {
        self.call_stack.push(frame);
    }

    /// Pops and returns the current call frame.
    ///
    /// Used when returning from a method.
    pub fn pop_frame(&mut self) -> Option<ThreadCallFrame> {
        self.call_stack.pop()
    }

    /// Returns a reference to the evaluation stack.
    #[must_use]
    pub fn stack(&self) -> &EvaluationStack {
        &self.eval_stack
    }

    /// Returns a mutable reference to the evaluation stack.
    pub fn stack_mut(&mut self) -> &mut EvaluationStack {
        &mut self.eval_stack
    }

    /// Pushes a value onto the evaluation stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    pub fn push(&mut self, value: EmValue) -> Result<()> {
        self.eval_stack.push(value)
    }

    /// Pops a value from the evaluation stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty.
    pub fn pop(&mut self) -> Result<EmValue> {
        self.eval_stack.pop()
    }

    /// Pops multiple arguments from the evaluation stack in correct order.
    ///
    /// CIL method calls push arguments left-to-right, but they're popped in
    /// reverse order. This helper pops `count` values and returns them in
    /// the original left-to-right order (i.e., first parameter first).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of arguments to pop
    ///
    /// # Returns
    ///
    /// A vector of arguments in left-to-right order (first argument at index 0).
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than `count` values.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // For a method call like: Foo(arg1, arg2, arg3)
    /// // Stack before (top on right): [..., arg1, arg2, arg3]
    /// let args = thread.pop_args(3)?;
    /// // args = [arg1, arg2, arg3]
    /// ```
    pub fn pop_args(&mut self, count: usize) -> Result<Vec<EmValue>> {
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            args.push(self.eval_stack.pop()?);
        }
        args.reverse();
        Ok(args)
    }

    /// Peeks at multiple arguments on the evaluation stack without removing them.
    ///
    /// Similar to `pop_args`, but returns clones of the values without
    /// modifying the stack. Useful for hook matching where we need to
    /// inspect arguments before deciding whether to handle the call.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of arguments to peek at
    ///
    /// # Returns
    ///
    /// A vector of argument clones in left-to-right order.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than `count` values.
    pub fn peek_args(&self, count: usize) -> Result<Vec<EmValue>> {
        let mut args = Vec::with_capacity(count);
        // Arguments are pushed left-to-right, so arg0 is at depth (count-1)
        // and argN is at depth 0 (top of stack)
        for i in 0..count {
            args.push(self.eval_stack.peek_at(count - 1 - i)?.clone());
        }
        Ok(args)
    }

    /// Returns a reference to the exception handling state.
    #[must_use]
    pub fn exception_state(&self) -> &ThreadExceptionState {
        &self.exception_state
    }

    /// Returns a mutable reference to the exception handling state.
    pub fn exception_state_mut(&mut self) -> &mut ThreadExceptionState {
        &mut self.exception_state
    }

    /// Returns a reference to the shared address space.
    #[must_use]
    pub fn address_space(&self) -> &AddressSpace {
        &self.address_space
    }

    /// Gets a thread-local storage value by its field token.
    #[must_use]
    pub fn get_tls(&self, key: Token) -> Option<&EmValue> {
        self.tls.get(&key)
    }

    /// Sets a thread-local storage value.
    pub fn set_tls(&mut self, key: Token, value: EmValue) {
        self.tls.insert(key, value);
    }

    /// Returns the number of instructions executed by this thread.
    #[must_use]
    pub fn instructions_executed(&self) -> u64 {
        self.instructions_executed
    }

    /// Increments the instruction counter.
    ///
    /// Called by the interpreter after each instruction.
    pub fn increment_instructions(&mut self) {
        self.instructions_executed += 1;
    }

    /// Returns the method token of the currently executing method.
    #[must_use]
    pub fn current_method(&self) -> Option<Token> {
        self.current_frame().map(|f| f.method)
    }

    /// Returns the current instruction offset within the method body.
    #[must_use]
    pub fn current_offset(&self) -> Option<u32> {
        self.current_frame().map(|f| f.instruction_offset)
    }

    /// Sets the return value and marks the thread as completed.
    ///
    /// This transitions the thread to [`ThreadState::Completed`].
    pub fn set_return_value(&mut self, value: Option<EmValue>) {
        self.return_value = value;
        self.state = ThreadState::Completed;
    }

    /// Returns the return value, if the thread completed with one.
    #[must_use]
    pub fn return_value(&self) -> Option<&EmValue> {
        self.return_value.as_ref()
    }

    /// Takes and returns the return value, leaving `None`.
    pub fn take_return_value(&mut self) -> Option<EmValue> {
        self.return_value.take()
    }

    /// Returns any pending reflection invoke request.
    ///
    /// This is set by stubs like `MethodBase.Invoke()` when they need to
    /// invoke a reflected method. The controller should check this after
    /// each stub execution and handle the invocation.
    #[must_use]
    pub fn pending_reflection_invoke(&self) -> Option<&ReflectionInvokeRequest> {
        self.pending_reflection_invoke.as_ref()
    }

    /// Takes and returns any pending reflection invoke request.
    ///
    /// This clears the pending request, allowing the controller to handle it.
    pub fn take_pending_reflection_invoke(&mut self) -> Option<ReflectionInvokeRequest> {
        self.pending_reflection_invoke.take()
    }

    /// Sets a pending reflection invoke request.
    ///
    /// Called by stubs like `MethodBase.Invoke()` to request method invocation.
    pub fn set_pending_reflection_invoke(&mut self, request: ReflectionInvokeRequest) {
        self.pending_reflection_invoke = Some(request);
    }

    /// Marks the thread as faulted due to an unhandled exception.
    pub fn fault(&mut self) {
        self.state = ThreadState::Faulted;
    }

    /// Marks the thread as aborted.
    pub fn abort(&mut self) {
        self.state = ThreadState::Aborted;
    }

    /// Starts executing a method as the initial entry point.
    ///
    /// Creates a call frame for the method and transitions the thread to
    /// [`ThreadState::Running`].
    ///
    /// # Arguments
    ///
    /// * `method` - Token of the method to execute
    /// * `locals` - Types of local variables declared in the method
    /// * `args` - Arguments to pass (value and type pairs)
    /// * `expects_return` - Whether a return value is expected
    pub fn start_method(
        &mut self,
        method: Token,
        locals: Vec<CilFlavor>,
        args: Vec<(EmValue, CilFlavor)>,
        expects_return: bool,
    ) {
        let frame = ThreadCallFrame::new(method, None, 0, locals, args, expects_return);
        self.push_frame(frame);
        self.state = ThreadState::Running;
    }

    /// Gets a local variable from the current frame by index.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn get_local(&self, index: usize) -> Result<&EmValue> {
        self.current_frame()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .locals
            .get(index)
    }

    /// Sets a local variable in the current frame by index.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn set_local(&mut self, index: usize, value: EmValue) -> Result<()> {
        self.current_frame_mut()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .locals
            .set(index, value)
    }

    /// Gets an argument from the current frame by index.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn get_arg(&self, index: usize) -> Result<&EmValue> {
        self.current_frame()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .arguments
            .get(index)
    }

    /// Sets an argument in the current frame by index (for `starg` instruction).
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn set_arg(&mut self, index: usize, value: EmValue) -> Result<()> {
        self.current_frame_mut()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .arguments
            .set(index, value)
    }

    /// Returns a reference to the managed heap.
    #[must_use]
    pub fn heap(&self) -> &ManagedHeap {
        self.address_space.managed_heap()
    }

    /// Returns a reference to the managed heap for mutation.
    ///
    /// Note: `ManagedHeap` uses interior mutability (e.g., `RefCell`), so
    /// mutation is done through `&self` methods on `ManagedHeap`.
    #[must_use]
    pub fn heap_mut(&self) -> &ManagedHeap {
        self.address_space.managed_heap()
    }

    /// Gets an object from the heap.
    ///
    /// Returns a cloned `HeapObject`. For strings and other Arc-backed data,
    /// cloning is cheap (just incrementing a reference count).
    ///
    /// # Errors
    ///
    /// Returns error if reference is invalid.
    pub fn get_heap_object(&self, heap_ref: HeapRef) -> Result<HeapObject> {
        self.address_space.managed_heap().get(heap_ref)
    }

    /// Dereferences a managed pointer and returns the value at that location.
    ///
    /// # Errors
    ///
    /// Returns error if the pointer target is invalid or inaccessible.
    pub fn deref_pointer(&self, ptr: &ManagedPointer) -> Result<EmValue> {
        match &ptr.target {
            PointerTarget::Local(index) => {
                let idx = usize::from(*index);
                self.get_local(idx).cloned()
            }
            PointerTarget::Argument(index) => {
                let idx = usize::from(*index);
                self.get_arg(idx).cloned()
            }
            PointerTarget::ArrayElement { array, index } => self
                .address_space
                .managed_heap()
                .get_array_element(*array, *index),
            PointerTarget::ObjectField { object, field } => self
                .address_space
                .managed_heap()
                .get_field(*object, *field)
                .map_err(|_| {
                    EmulationError::TypeMismatch {
                        operation: "ldind",
                        expected: "valid field",
                        found: "unknown field",
                    }
                    .into()
                }),
            PointerTarget::StaticField(field_token) => self
                .address_space
                .statics()
                .get(*field_token)
                .ok_or_else(|| {
                    EmulationError::TypeMismatch {
                        operation: "ldind (static field)",
                        expected: "initialized static field",
                        found: "uninitialized static field",
                    }
                    .into()
                }),
        }
    }

    /// Stores a value through a managed pointer.
    ///
    /// # Errors
    ///
    /// Returns error if the pointer target is invalid or inaccessible.
    pub fn store_through_pointer(&mut self, ptr: &ManagedPointer, value: EmValue) -> Result<()> {
        match &ptr.target {
            PointerTarget::Local(index) => {
                let idx = usize::from(*index);
                self.set_local(idx, value)
            }
            PointerTarget::Argument(index) => {
                let idx = usize::from(*index);
                self.set_arg(idx, value)
            }
            PointerTarget::ArrayElement { array, index } => self
                .address_space
                .managed_heap()
                .set_array_element(*array, *index, value),
            PointerTarget::ObjectField { object, field } => self
                .address_space
                .managed_heap()
                .set_field(*object, *field, value),
            PointerTarget::StaticField(field_token) => {
                self.address_space.statics().set(*field_token, value);
                Ok(())
            }
        }
    }

    /// Reconfigures the current frame's local variables.
    ///
    /// This is used when returning from a call to restore the caller's
    /// local variable configuration.
    ///
    /// # Arguments
    ///
    /// * `local_types` - Types of local variables in the frame
    pub fn configure_locals(&mut self, local_types: Vec<CilFlavor>) {
        if let Some(frame) = self.current_frame_mut() {
            frame.locals = LocalVariables::new(local_types);
        }
    }

    /// Reconfigures the current frame's arguments.
    ///
    /// This is used when returning from a call to restore the caller's
    /// argument configuration.
    ///
    /// # Arguments
    ///
    /// * `arg_values` - Argument values
    /// * `arg_types` - Argument types
    pub fn configure_arguments(&mut self, arg_values: Vec<EmValue>, arg_types: Vec<CilFlavor>) {
        if let Some(frame) = self.current_frame_mut() {
            frame.arguments = ArgumentStorage::new(arg_values, arg_types);
        }
    }

    /// Restores the evaluation stack with the given values.
    ///
    /// Clears the current stack and pushes all provided values in order.
    /// Used when returning from a method to restore the caller's stack.
    pub fn restore_stack(&mut self, values: Vec<EmValue>) {
        self.eval_stack.clear();
        for value in values {
            let _ = self.eval_stack.push(value);
        }
    }

    /// Clears the evaluation stack.
    pub fn clear_stack(&mut self) {
        self.eval_stack.clear();
    }

    /// Takes all values from the evaluation stack and clears it.
    ///
    /// Returns a snapshot of the stack contents before clearing.
    pub fn take_stack(&mut self) -> Vec<EmValue> {
        let values = self.eval_stack.snapshot();
        self.eval_stack.clear();
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::emulation::create_test_thread;

    #[test]
    fn test_thread_creation() {
        let thread = create_test_thread();
        assert_eq!(thread.id(), ThreadId::MAIN);
        assert_eq!(thread.state(), ThreadState::Ready);
        assert!(thread.is_ready());
        assert!(!thread.is_completed());
    }

    #[test]
    fn test_thread_main() {
        let space = Arc::new(AddressSpace::new());
        let capture = Arc::new(CaptureContext::new());
        let fake_objects = SharedFakeObjects::new(space.managed_heap());
        let thread = EmulationThread::main(space, capture, None, fake_objects);
        assert_eq!(thread.id(), ThreadId::MAIN);
        assert_eq!(thread.name(), Some("Main"));
    }

    #[test]
    fn test_call_stack() {
        let mut thread = create_test_thread();

        assert_eq!(thread.call_depth(), 0);
        assert!(thread.current_frame().is_none());

        // Start a method
        thread.start_method(
            Token::new(0x06000001),
            vec![CilFlavor::I4],
            vec![(EmValue::I32(42), CilFlavor::I4)],
            true,
        );

        assert_eq!(thread.call_depth(), 1);
        assert!(thread.current_frame().is_some());
        assert_eq!(thread.current_method(), Some(Token::new(0x06000001)));

        // Push another frame
        let frame = ThreadCallFrame::new(
            Token::new(0x06000002),
            Some(Token::new(0x06000001)), // return to first method
            0x10,
            vec![],
            vec![],
            false,
        );
        thread.push_frame(frame);
        assert_eq!(thread.call_depth(), 2);

        // Pop frame
        let popped = thread.pop_frame().unwrap();
        assert_eq!(popped.method(), Token::new(0x06000002));
        assert_eq!(thread.call_depth(), 1);
    }

    #[test]
    fn test_evaluation_stack() {
        let mut thread = create_test_thread();

        thread.push(EmValue::I32(10)).unwrap();
        thread.push(EmValue::I32(20)).unwrap();

        assert_eq!(thread.stack().depth(), 2);

        let val = thread.pop().unwrap();
        assert_eq!(val, EmValue::I32(20));
    }

    #[test]
    fn test_thread_completion() {
        let mut thread = create_test_thread();

        thread.set_return_value(Some(EmValue::I32(42)));
        assert!(thread.is_completed());
        assert_eq!(thread.state(), ThreadState::Completed);

        let ret = thread.take_return_value();
        assert_eq!(ret, Some(EmValue::I32(42)));
    }

    #[test]
    fn test_thread_priority() {
        let mut thread = create_test_thread();
        assert_eq!(thread.priority(), ThreadPriority::Normal);

        thread.set_priority(ThreadPriority::Highest);
        assert_eq!(thread.priority(), ThreadPriority::Highest);
    }

    #[test]
    fn test_tls() {
        let mut thread = create_test_thread();
        let key = Token::new(0x04000001);

        assert!(thread.get_tls(key).is_none());

        thread.set_tls(key, EmValue::I32(100));
        assert_eq!(thread.get_tls(key), Some(&EmValue::I32(100)));
    }
}
