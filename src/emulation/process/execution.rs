//! Emulation process - main entry point for .NET emulation.
//!
//! This module provides [`EmulationProcess`], the central orchestrator for
//! .NET emulation. An `EmulationProcess` encapsulates all the state and
//! resources needed to emulate a .NET application, including:
//!
//! - The loaded assembly and its metadata
//! - The virtual address space with mapped PE images and data
//! - Runtime state including method stubs
//! - Capture context for collecting extracted data
//! - Execution limits and configuration
//!
//! # Creating a Process
//!
//! Use [`ProcessBuilder`](super::ProcessBuilder) to create an `EmulationProcess`:
//!
//! ```rust,no_run
//! use dotscope::emulation::ProcessBuilder;
//! use dotscope::CilObject;
//!
//! # fn main() -> Result<(), dotscope::Error> {
//! # let assembly = CilObject::from_path("sample.exe")?;
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .for_extraction()
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Executing Methods
//!
//! Once created, use [`execute_method`](EmulationProcess::execute_method) to
//! run specific methods:
//!
//! ```rust,ignore
//! # use dotscope::metadata::token::Token;
//! # let method_token = Token::new(0x06000001);
//! let outcome = process.execute_method(method_token, vec![])?;
//! ```
//!
//! # Retrieving Results
//!
//! After execution, retrieve captured data:
//!
//! ```rust,ignore
//! for asm in process.captured_assemblies() {
//!     println!("Captured: {} bytes", asm.data.len());
//! }
//! ```

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use crate::{
    emulation::{
        capture::{
            CaptureContext, CapturedAssembly, CapturedBuffer, CapturedString, FileOperation,
        },
        engine::{EmulationController, EmulationError, EmulationOutcome, TraceWriter},
        fakeobjects::SharedFakeObjects,
        loader::{LoadedImage, MappedRegionInfo},
        memory::AddressSpace,
        process::EmulationConfig,
        runtime::RuntimeState,
        EmValue, EmulationThread, StepResult, UnknownMethodBehavior,
    },
    metadata::token::Token,
    CilObject, Error, Result,
};

// Note: Use EmulationOutcome from crate::emulation::engine::result for execution outcomes.
// The types below are process-specific helper types.

/// Describes which execution limit was reached.
///
/// When emulation stops due to a limit being exceeded, this enum
/// indicates which specific limit caused the stop and provides
/// the relevant value.
///
/// # See Also
///
/// - [`EmulationLimits`](super::EmulationLimits) - Configuration for limits
/// - [`EmulationOutcome::LimitReached`](crate::emulation::engine::EmulationOutcome::LimitReached)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// Maximum instruction count was reached.
    ///
    /// Contains the number of instructions that were executed.
    Instructions(u64),

    /// Maximum call stack depth was reached.
    ///
    /// Contains the call depth when the limit was hit.
    CallDepth(usize),

    /// Maximum number of heap objects was reached.
    ///
    /// Contains the number of objects allocated.
    HeapObjects(usize),

    /// Maximum heap memory was reached.
    ///
    /// Contains the number of bytes allocated.
    HeapBytes(usize),

    /// Execution timeout was reached.
    Timeout,
}

/// Stack trace entry for exception and error reporting.
///
/// Represents a single frame in a call stack, providing information
/// about the method and instruction location. Used for debugging,
/// error reporting, and exception stack traces.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::emulation::StackTraceEntry;
/// use dotscope::metadata::token::Token;
///
/// let entry = StackTraceEntry {
///     method: Token::new(0x06000001),
///     method_name: Some("MyClass::MyMethod".to_string()),
///     offset: 0x0042,
/// };
/// println!("at {} (IL_{:04X})", entry.method_name.unwrap(), entry.offset);
/// ```
#[derive(Clone, Debug)]
pub struct StackTraceEntry {
    /// Metadata token of the method.
    ///
    /// This is the MethodDef or MemberRef token identifying the method.
    pub method: Token,

    /// Human-readable method name, if available.
    ///
    /// May be `None` if the method name could not be resolved from
    /// metadata.
    pub method_name: Option<String>,

    /// IL (Intermediate Language) offset within the method.
    ///
    /// The byte offset into the method's IL body where execution
    /// was at this stack frame.
    pub offset: u32,
}

/// Central emulation process orchestrating .NET execution.
///
/// `EmulationProcess` is the main entry point for .NET emulation. It
/// coordinates all components needed for emulation including the address
/// space, runtime state, and capture context. Processes are created using
/// [`ProcessBuilder`](super::ProcessBuilder).
///
/// # Components
///
/// An `EmulationProcess` manages:
///
/// - **Address Space**: Virtual memory with mapped PE images and data
/// - **Runtime State**: Method stubs, type information, and execution state
/// - **Capture Context**: Collects assemblies, strings, and other data
/// - **Configuration**: Limits, behavior settings, and options
///
/// # Thread Safety
///
/// `EmulationProcess` is designed to be shared across threads via `Arc`.
/// The address space and runtime state use internal synchronization.
/// However, method execution should typically be done from a single thread
/// to maintain deterministic behavior.
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::emulation::ProcessBuilder;
/// use dotscope::CilObject;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let assembly = CilObject::from_path("sample.exe")?;
/// // Create a process
/// let process = ProcessBuilder::new()
///     .assembly(assembly)
///     .for_extraction()
///     .capture_assemblies()
///     .build()?;
///
/// // Find entry point and execute
/// if let Some(entry) = process.find_entry_point() {
///     let outcome = process.execute_method(entry, vec![])?;
/// }
///
/// // Retrieve results
/// for captured in process.captured_assemblies() {
///     std::fs::write("unpacked.dll", &captured.data)?;
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Memory Management
///
/// The process manages memory through its address space. You can:
///
/// - Read/write memory directly via [`read_memory`](Self::read_memory)
///   and [`write_memory`](Self::write_memory)
/// - Access static fields via [`get_static`](Self::get_static) and
///   [`set_static`](Self::set_static)
/// - Check address validity via [`is_valid_address`](Self::is_valid_address)
pub struct EmulationProcess {
    /// Process name for identification and logging.
    pub(super) name: String,

    /// Primary .NET assembly being emulated.
    ///
    /// Provides metadata for type resolution and method lookup.
    pub(super) assembly: Option<Arc<CilObject>>,

    /// Emulation configuration (immutable after creation).
    pub(super) config: Arc<EmulationConfig>,

    /// Virtual address space containing all mapped memory.
    pub(super) address_space: Arc<AddressSpace>,

    /// Runtime state including stubs and type information.
    ///
    /// Protected by RwLock for thread-safe access.
    pub(super) runtime: Arc<RwLock<RuntimeState>>,

    /// Capture context for collecting runtime data.
    pub(super) capture: Arc<CaptureContext>,

    /// Loaded PE images (executables and DLLs).
    pub(super) loaded_images: Vec<LoadedImage>,

    /// Mapped raw data regions.
    pub(super) mapped_regions: Vec<MappedRegionInfo>,

    /// Total instructions executed across all method calls.
    ///
    /// Atomic for lock-free updates during execution.
    pub(super) instruction_count: AtomicU64,

    /// Pre-allocated fake BCL objects for consistent emulation behavior.
    ///
    /// These objects are allocated once and shared across all threads,
    /// ensuring that methods like `Assembly.GetExecutingAssembly()` return
    /// the same reference each time. This is critical for anti-tamper checks.
    pub(super) fake_objects: SharedFakeObjects,

    /// Trace writer for debugging emulation.
    ///
    /// When tracing is enabled via `TracingConfig`, this writer records
    /// execution events to a file or memory buffer for later analysis.
    pub(super) trace_writer: Option<Arc<TraceWriter>>,
}

impl EmulationProcess {
    /// Returns the process name.
    ///
    /// The name is set during process creation via [`ProcessBuilder::name`](super::ProcessBuilder::name)
    /// or defaults to the assembly name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if a primary assembly is loaded.
    pub fn has_assembly(&self) -> bool {
        self.assembly.is_some()
    }

    /// Returns a reference to the primary assembly, if one was loaded.
    ///
    /// The primary assembly provides metadata for type resolution and
    /// method lookup during emulation.
    pub fn assembly(&self) -> Option<&Arc<CilObject>> {
        self.assembly.as_ref()
    }

    /// Returns the emulation configuration.
    ///
    /// The configuration is immutable after process creation.
    pub fn config(&self) -> &EmulationConfig {
        &self.config
    }

    /// Returns the process address space.
    ///
    /// The address space contains all mapped memory regions, including
    /// PE images and raw data. Use for direct memory access when needed.
    pub fn address_space(&self) -> &Arc<AddressSpace> {
        &self.address_space
    }

    /// Returns the runtime state.
    ///
    /// The runtime state includes registered method stubs and type
    /// information. Access is synchronized via `RwLock`.
    pub fn runtime(&self) -> &Arc<RwLock<RuntimeState>> {
        &self.runtime
    }

    /// Returns the capture context.
    ///
    /// Use this for advanced capture operations. For common cases,
    /// prefer the convenience methods like [`captured_assemblies`](Self::captured_assemblies).
    pub fn capture(&self) -> &Arc<CaptureContext> {
        &self.capture
    }

    /// Returns the shared fake BCL objects.
    ///
    /// These pre-allocated objects ensure that BCL methods like
    /// `Assembly.GetExecutingAssembly()` return consistent references,
    /// which is critical for anti-tamper checks in obfuscated code.
    pub fn fake_objects(&self) -> &SharedFakeObjects {
        &self.fake_objects
    }

    /// Returns all loaded PE images.
    ///
    /// Images are listed in the order they were loaded, with the
    /// primary assembly's image typically first.
    pub fn loaded_images(&self) -> &[LoadedImage] {
        &self.loaded_images
    }

    /// Returns the number of loaded PE images.
    pub fn loaded_image_count(&self) -> usize {
        self.loaded_images.len()
    }

    /// Returns all mapped data regions.
    ///
    /// These are raw data regions mapped via [`ProcessBuilder::map_data`](super::ProcessBuilder::map_data)
    /// and similar methods.
    pub fn mapped_regions(&self) -> &[MappedRegionInfo] {
        &self.mapped_regions
    }

    /// Returns the number of mapped data regions.
    pub fn mapped_region_count(&self) -> usize {
        self.mapped_regions.len()
    }

    /// Returns the primary loaded PE image.
    ///
    /// The primary image is typically the first loaded image, usually
    /// from the primary assembly.
    pub fn primary_image(&self) -> Option<&LoadedImage> {
        self.loaded_images.first()
    }

    /// Finds a loaded image by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name used when loading the image
    ///
    /// # Returns
    ///
    /// Returns `Some(&LoadedImage)` if found, `None` otherwise.
    pub fn image_by_name(&self, name: &str) -> Option<&LoadedImage> {
        self.loaded_images.iter().find(|i| i.name == name)
    }

    /// Returns the total number of instructions executed.
    ///
    /// This count accumulates across all method calls and is not
    /// reset between calls to [`execute_method`](Self::execute_method).
    pub fn instruction_count(&self) -> u64 {
        self.instruction_count.load(Ordering::Relaxed)
    }

    /// Increments the instruction count and checks limits.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of instructions to add
    ///
    /// # Errors
    ///
    /// Returns an error if the instruction limit is exceeded.
    pub fn increment_instructions(&self, count: u64) -> Result<()> {
        let new_count = self.instruction_count.fetch_add(count, Ordering::Relaxed) + count;

        if self.config.limits.max_instructions > 0
            && new_count > self.config.limits.max_instructions
        {
            return Err(EmulationError::InstructionLimitExceeded {
                executed: new_count,
                limit: self.config.limits.max_instructions,
            }
            .into());
        }

        Ok(())
    }

    /// Resets the instruction count to zero.
    ///
    /// Use this to reset limits for a new execution phase.
    pub fn reset_instruction_count(&self) {
        self.instruction_count.store(0, Ordering::Relaxed);
    }

    /// Reads bytes from the virtual address space.
    ///
    /// # Arguments
    ///
    /// * `address` - Virtual address to read from
    /// * `len` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// Returns the read bytes on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid or the read crosses
    /// unmapped memory.
    pub fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>> {
        self.address_space.read(address, len)
    }

    /// Writes bytes to the virtual address space.
    ///
    /// # Arguments
    ///
    /// * `address` - Virtual address to write to
    /// * `data` - Bytes to write
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid or the region is
    /// not writable.
    pub fn write_memory(&self, address: u64, data: &[u8]) -> Result<()> {
        self.address_space.write(address, data)
    }

    /// Checks if a virtual address is valid (mapped and accessible).
    ///
    /// # Arguments
    ///
    /// * `address` - Virtual address to check
    pub fn is_valid_address(&self, address: u64) -> bool {
        self.address_space.is_valid(address)
    }

    /// Gets the value of a static field.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The field's metadata token
    ///
    /// # Returns
    ///
    /// Returns `Some(value)` if the field has been initialized,
    /// `None` otherwise.
    pub fn get_static(&self, field_token: Token) -> Option<EmValue> {
        self.address_space.get_static(field_token)
    }

    /// Sets the value of a static field.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The field's metadata token
    /// * `value` - The value to set
    pub fn set_static(&self, field_token: Token, value: EmValue) {
        self.address_space.set_static(field_token, value);
    }

    /// Returns `true` if any data has been captured during emulation.
    pub fn has_captures(&self) -> bool {
        self.capture.has_captures()
    }

    /// Returns all captured assemblies.
    ///
    /// Assemblies are captured when code calls `Assembly.Load` with
    /// byte array arguments and assembly capture is enabled.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # // process is an EmulationProcess instance
    /// for asm in process.captured_assemblies() {
    ///     std::fs::write(format!("extracted_{}.dll", asm.id), &asm.data)?;
    /// }
    /// ```
    pub fn captured_assemblies(&self) -> Vec<CapturedAssembly> {
        self.capture.assemblies()
    }

    /// Returns all captured strings.
    ///
    /// Strings are captured when string capture is enabled and strings
    /// are constructed or decrypted during emulation.
    pub fn captured_strings(&self) -> Vec<CapturedString> {
        self.capture.strings()
    }

    /// Returns all captured memory buffers.
    ///
    /// Buffers are captured when writes occur to monitored memory regions.
    pub fn captured_buffers(&self) -> Vec<CapturedBuffer> {
        self.capture.buffers()
    }

    /// Returns all captured file operations.
    ///
    /// File operations are captured when file operation capture is enabled.
    pub fn captured_file_operations(&self) -> Vec<FileOperation> {
        self.capture.file_operations()
    }

    /// Clears all captured data.
    ///
    /// Use this to reset capture state before a new execution phase.
    pub fn clear_captures(&self) {
        self.capture.clear();
    }

    /// Converts a Relative Virtual Address (RVA) to a Virtual Address (VA).
    ///
    /// Uses the primary image's base address for the conversion.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA to convert
    ///
    /// # Returns
    ///
    /// Returns `Some(va)` if a primary image is loaded, `None` otherwise.
    pub fn rva_to_va(&self, rva: u32) -> Option<u64> {
        self.primary_image().map(|img| img.rva_to_va(rva))
    }

    /// Returns the entry point virtual address of the primary image.
    ///
    /// This is the native entry point address, not the .NET entry point
    /// method token. For the .NET entry point, use [`find_entry_point`](Self::find_entry_point).
    pub fn entry_point(&self) -> Option<u64> {
        self.primary_image().and_then(LoadedImage::entry_point_va)
    }

    /// Returns the base address of the primary image.
    pub fn image_base(&self) -> Option<u64> {
        self.primary_image().map(|img| img.base_address)
    }

    /// Finds a method token by type and method name.
    ///
    /// Searches the primary assembly for a method matching the given names.
    /// The type name can be a full name, partial name, or just the class name.
    ///
    /// # Arguments
    ///
    /// * `type_name` - Type name (e.g., "MyClass" or "Namespace.MyClass")
    /// * `method_name` - Method name (e.g., "Decrypt")
    ///
    /// # Returns
    ///
    /// Returns `Some(Token)` if found, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use dotscope::emulation::EmValue;
    /// # // process is an EmulationProcess instance
    /// if let Some(token) = process.find_method("StringDecryptor", "Decrypt") {
    ///     process.execute_method(token, vec![EmValue::I32(42)])?;
    /// }
    /// ```
    pub fn find_method(&self, type_name: &str, method_name: &str) -> Option<Token> {
        let assembly = self.assembly.as_ref()?;
        let type_registry = assembly.types();

        // Search through all types
        for ciltype in type_registry.all_types() {
            let type_full_name = ciltype.fullname();
            if type_full_name.ends_with(type_name)
                || type_full_name == type_name
                || type_full_name.split('.').next_back() == Some(type_name)
            {
                // Iterate through methods
                for (_, method_ref) in ciltype.methods.iter() {
                    if let Some(method) = method_ref.upgrade() {
                        if method.name == method_name {
                            return Some(method.token);
                        }
                    }
                }
            }
        }

        None
    }

    /// Finds the static constructor (.cctor) for a type.
    ///
    /// Static constructors are called automatically before the first
    /// access to a type's static members.
    ///
    /// # Arguments
    ///
    /// * `type_name` - Type name to find the .cctor for
    ///
    /// # Returns
    ///
    /// Returns `Some(Token)` if the type has a static constructor.
    pub fn find_cctor(&self, type_name: &str) -> Option<Token> {
        self.find_method(type_name, ".cctor")
    }

    /// Finds the .NET entry point method token.
    ///
    /// The entry point is defined in the COR20 header and is typically
    /// the `Main` method.
    ///
    /// # Returns
    ///
    /// Returns `Some(Token)` if an entry point is defined, `None` otherwise.
    pub fn find_entry_point(&self) -> Option<Token> {
        let assembly = self.assembly.as_ref()?;
        let entry_token_value = assembly.cor20header().entry_point_token;
        if entry_token_value != 0 {
            Some(Token::new(entry_token_value))
        } else {
            None
        }
    }

    /// Execute a method with the given arguments.
    ///
    /// This is the primary entry point for method emulation. It creates an internal
    /// `EmulationController` with the process's shared infrastructure and executes
    /// the specified method.
    ///
    /// # Arguments
    ///
    /// * `method` - Token of the method to execute
    /// * `args` - Arguments to pass to the method
    ///
    /// # Returns
    ///
    /// Returns an `EmulationOutcome` indicating how execution completed (completed,
    /// limit reached, breakpoint, etc.) along with any return value.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No assembly is loaded
    /// - Method setup fails
    /// - An unrecoverable emulation error occurs
    pub fn execute_method(&self, method: Token, args: Vec<EmValue>) -> Result<EmulationOutcome> {
        let assembly = self
            .assembly
            .as_ref()
            .ok_or_else(|| Error::Other("No assembly loaded".into()))?;

        // Create controller with shared infrastructure
        let mut controller = EmulationController::new(
            Arc::clone(&self.address_space),
            Arc::clone(&self.runtime),
            Arc::clone(&self.capture),
            Arc::clone(&self.config),
            Some(Arc::clone(assembly)),
            self.fake_objects.clone(),
            self.trace_writer.clone(),
        );

        // Execute the method
        controller.emulate_method(method, args, Arc::clone(assembly))
    }

    /// Execute a method with a condition callback.
    ///
    /// This allows stopping emulation when a specific condition is met (e.g.,
    /// when a decrypted string is detected on the stack).
    ///
    /// # Arguments
    ///
    /// * `method` - Token of the method to execute
    /// * `args` - Arguments to pass to the method
    /// * `condition` - Callback that receives step results and memory state.
    ///   Return `true` to stop emulation.
    ///
    /// # Returns
    ///
    /// Returns an `EmulationOutcome::Stopped` if the condition triggered,
    /// or the normal outcome if execution completed.
    pub fn emulate_until<F>(
        &self,
        method: Token,
        args: Vec<EmValue>,
        condition: F,
    ) -> Result<EmulationOutcome>
    where
        F: Fn(&StepResult, &EmulationThread) -> bool,
    {
        let assembly = self
            .assembly
            .as_ref()
            .ok_or_else(|| Error::Other("No assembly loaded".into()))?;

        // Create controller with shared infrastructure
        let mut controller = EmulationController::new(
            Arc::clone(&self.address_space),
            Arc::clone(&self.runtime),
            Arc::clone(&self.capture),
            Arc::clone(&self.config),
            Some(Arc::clone(assembly)),
            self.fake_objects.clone(),
            self.trace_writer.clone(),
        );

        // Execute with condition
        controller.emulate_until(method, args, Arc::clone(assembly), condition)
    }

    /// Sets the default behavior for methods without registered hooks.
    ///
    /// This overrides the behavior specified in the configuration for
    /// any future method calls where no hook matches.
    ///
    /// # Arguments
    ///
    /// * `behavior` - How to handle unknown method calls
    ///
    /// # See Also
    ///
    /// - [`UnknownMethodBehavior`](crate::emulation::UnknownMethodBehavior)
    pub fn set_default_behavior(&self, behavior: UnknownMethodBehavior) -> Result<()> {
        self.runtime
            .write()
            .map_err(|e| Error::LockError(format!("runtime write lock: {e}")))?
            .set_unknown_method_behavior(behavior);
        Ok(())
    }

    /// Forks this process with full Copy-on-Write semantics.
    ///
    /// Creates an independent copy of the process that shares data with the
    /// original via structural sharing. Both the original and fork can be
    /// modified independently - only the modified data is actually copied.
    ///
    /// # What Gets Forked (CoW)
    ///
    /// - **Address space**: Memory regions, managed heap, and static fields
    ///   are forked with per-page/per-object CoW semantics
    ///
    /// # What Gets Shared (Immutable)
    ///
    /// - **Assembly**: Metadata is read-only, shared via `Arc`
    /// - **Configuration**: Immutable after creation, shared via `Arc`
    /// - **Runtime state**: Method stubs and type info, shared via `Arc`
    /// - **Loaded image metadata**: List of loaded images (shallow copy)
    /// - **Mapped region metadata**: List of mapped regions (shallow copy)
    ///
    /// # What Gets Fresh
    ///
    /// - **Capture context**: Each fork gets fresh captures so results don't mix
    /// - **Instruction count**: Reset to 0 for independent tracking
    ///
    /// # Performance
    ///
    /// This operation is O(1) for heap, statics, and protection overrides due
    /// to `imbl`'s structural sharing. Memory regions are O(n) in the number
    /// of regions, but each region's pages use CoW internally.
    ///
    /// # Use Case
    ///
    /// Ideal for running many parallel decryption operations from a single
    /// setup. The expensive emulator initialization (PE loading, type resolution,
    /// static initializers) happens once, then `fork()` creates lightweight
    /// copies for each decryptor call.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{ProcessBuilder, EmValue};
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// # let assembly = CilObject::from_path("sample.exe")?;
    /// # let cctor_token = Token::new(0x06000001);
    /// # let decryptor_calls: Vec<(Token, i32)> = vec![];
    /// // Set up template with assembly loaded and static constructors run
    /// let template = ProcessBuilder::new()
    ///     .assembly(assembly)
    ///     .build()?;
    ///
    /// // Run the static initializer once
    /// template.execute_method(cctor_token, vec![])?;
    ///
    /// // Now fork for each decryption call - very cheap!
    /// for (token, id) in decryptor_calls {
    ///     let forked = template.fork();
    ///     let result = forked.execute_method(token, vec![EmValue::I32(id)])?;
    ///     // Collect decrypted string from forked.captured_strings()
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            // Copy name (cheap)
            name: self.name.clone(),
            // Share assembly metadata (immutable, Arc clone is cheap)
            assembly: self.assembly.clone(),
            // Share config (immutable, Arc clone is cheap)
            config: Arc::clone(&self.config),
            // Fork address space with full CoW
            address_space: Arc::new(self.address_space.fork()),
            // Share runtime state (method stubs, type info)
            runtime: Arc::clone(&self.runtime),
            // Fresh capture context (same config, empty captures)
            capture: Arc::new(CaptureContext::with_config(self.capture.config().clone())),
            // Copy image/region metadata (shallow)
            loaded_images: self.loaded_images.clone(),
            mapped_regions: self.mapped_regions.clone(),
            // Fresh instruction count
            instruction_count: AtomicU64::new(0),
            // Share fake objects - HeapRefs remain valid in forked heap (CoW)
            fake_objects: self.fake_objects.clone(),
            // Share trace writer (if any)
            trace_writer: self.trace_writer.clone(),
        }
    }

    /// Forks this process, preserving captured data.
    ///
    /// Like [`fork`](Self::fork), but the capture context is also forked,
    /// preserving any assemblies, strings, or other data captured so far.
    /// Use this when you want the fork to inherit captures from the parent.
    ///
    /// # Note
    ///
    /// Captures are cloned, not shared via CoW. This means modifications to
    /// captures in the fork do not affect the original, and vice versa.
    #[must_use]
    pub fn fork_with_captures(&self) -> Self {
        // Clone all captured data
        let capture = CaptureContext::with_config(self.capture.config().clone());

        // Copy assemblies
        for asm in self.capture.assemblies() {
            capture.capture_assembly(asm.data, asm.source.clone(), asm.load_method, asm.name);
        }

        // Copy strings
        for s in self.capture.strings() {
            capture.capture_string_with_details(s.value, s.source.clone(), s.encrypted_data, s.key);
        }

        // Copy buffers
        for b in self.capture.buffers() {
            capture.capture_buffer(b.data, b.source.clone(), b.buffer_source.clone(), &b.label);
        }

        // Copy file operations
        for op in self.capture.file_operations() {
            capture.capture_file_operation(
                op.operation,
                op.path,
                op.destination,
                op.data,
                op.source.clone(),
                op.success,
            );
        }

        // Copy network operations
        for op in self.capture.network_operations() {
            capture.capture_network_operation(op);
        }

        Self {
            name: self.name.clone(),
            assembly: self.assembly.clone(),
            config: Arc::clone(&self.config),
            address_space: Arc::new(self.address_space.fork()),
            runtime: Arc::clone(&self.runtime),
            capture: Arc::new(capture),
            loaded_images: self.loaded_images.clone(),
            mapped_regions: self.mapped_regions.clone(),
            instruction_count: AtomicU64::new(self.instruction_count.load(Ordering::Relaxed)),
            // Share fake objects - HeapRefs remain valid in forked heap (CoW)
            fake_objects: self.fake_objects.clone(),
            // Share trace writer (if any)
            trace_writer: self.trace_writer.clone(),
        }
    }

    /// Returns a summary of the process state.
    ///
    /// The summary provides a snapshot of key metrics including memory
    /// mappings, execution counts, and capture statistics.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # // process is an EmulationProcess instance
    /// let summary = process.summary();
    /// println!("Executed {} instructions", summary.instruction_count);
    /// println!("Captured {} assemblies", summary.captured_assemblies);
    /// ```
    pub fn summary(&self) -> ProcessSummary {
        ProcessSummary {
            name: self.name.clone(),
            has_assembly: self.assembly.is_some(),
            loaded_images: self.loaded_images.len(),
            mapped_regions: self.mapped_regions.len(),
            instruction_count: self.instruction_count(),
            captured_assemblies: self.capture.assembly_count(),
            captured_strings: self.capture.string_count(),
            captured_buffers: self.capture.buffer_count(),
            captured_file_ops: self.capture.file_operation_count(),
            captured_network_ops: self.capture.network_operation_count(),
        }
    }
}

impl std::fmt::Debug for EmulationProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmulationProcess")
            .field("name", &self.name)
            .field("has_assembly", &self.assembly.is_some())
            .field("loaded_images", &self.loaded_images.len())
            .field("mapped_regions", &self.mapped_regions.len())
            .field("instruction_count", &self.instruction_count())
            .finish()
    }
}

/// Summary snapshot of an emulation process state.
///
/// `ProcessSummary` provides a lightweight, copyable snapshot of key
/// metrics from an [`EmulationProcess`]. Useful for logging, monitoring,
/// and debugging.
///
/// # Example
///
/// ```rust,ignore
/// # // process is an EmulationProcess instance
/// let summary = process.summary();
/// println!("Process: {}", summary.name);
/// println!("Instructions: {}", summary.instruction_count);
/// println!("Captured: {} assemblies, {} strings",
///     summary.captured_assemblies,
///     summary.captured_strings);
/// ```
#[derive(Clone, Debug)]
pub struct ProcessSummary {
    /// Display name of the process.
    pub name: String,

    /// Whether a primary assembly is loaded.
    pub has_assembly: bool,

    /// Number of PE images loaded into memory.
    pub loaded_images: usize,

    /// Number of raw data regions mapped.
    pub mapped_regions: usize,

    /// Total CIL instructions executed.
    pub instruction_count: u64,

    /// Number of assemblies captured during emulation.
    pub captured_assemblies: usize,

    /// Number of strings captured during emulation.
    pub captured_strings: usize,

    /// Number of memory buffers captured.
    pub captured_buffers: usize,

    /// Number of file operations recorded.
    pub captured_file_ops: usize,

    /// Number of network operations recorded.
    pub captured_network_ops: usize,
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            capture::CaptureSource,
            engine::{EmulationOutcome, LimitExceeded},
            process::{CaptureConfig, ProcessBuilder},
            EmValue, ThreadId,
        },
        metadata::token::Token,
    };

    #[test]
    fn test_process_creation() {
        let process = ProcessBuilder::new().name("test").build().unwrap();

        assert_eq!(process.name(), "test");
        assert!(!process.has_assembly());
        assert_eq!(process.instruction_count(), 0);
    }

    #[test]
    fn test_instruction_counting() {
        let process = ProcessBuilder::new().build().unwrap();

        process.increment_instructions(100).unwrap();
        assert_eq!(process.instruction_count(), 100);

        process.increment_instructions(50).unwrap();
        assert_eq!(process.instruction_count(), 150);

        process.reset_instruction_count();
        assert_eq!(process.instruction_count(), 0);
    }

    #[test]
    fn test_memory_operations() {
        let process = ProcessBuilder::new()
            .map_data(0x10000, vec![0xDE, 0xAD, 0xBE, 0xEF], "test")
            .build()
            .unwrap();

        let data = process.read_memory(0x10000, 4).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        process.write_memory(0x10000, &[0x01, 0x02]).unwrap();
        let data = process.read_memory(0x10000, 4).unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0xBE, 0xEF]);
    }

    #[test]
    fn test_static_fields() {
        let process = ProcessBuilder::new().build().unwrap();

        let token = Token::new(0x04000001);

        assert!(process.get_static(token).is_none());

        process.set_static(token, EmValue::I32(42));
        assert_eq!(process.get_static(token), Some(EmValue::I32(42)));
    }

    #[test]
    fn test_process_summary() {
        let process = ProcessBuilder::new()
            .name("summary_test")
            .map_data(0x10000, vec![0x01, 0x02], "region1")
            .build()
            .unwrap();

        let summary = process.summary();
        assert_eq!(summary.name, "summary_test");
        assert!(!summary.has_assembly);
        assert_eq!(summary.mapped_regions, 1);
        assert_eq!(summary.instruction_count, 0);
    }

    #[test]
    fn test_emulation_outcome() {
        let completed = EmulationOutcome::Completed {
            return_value: Some(EmValue::I32(42)),
            instructions: 100,
        };
        match completed {
            EmulationOutcome::Completed {
                return_value: Some(EmValue::I32(v)),
                ..
            } => assert_eq!(v, 42),
            _ => panic!("Expected Completed"),
        }

        let limit = EmulationOutcome::LimitReached {
            limit: LimitExceeded::Instructions {
                executed: 1000000,
                limit: 500000,
            },
            partial_state: None,
        };
        match limit {
            EmulationOutcome::LimitReached { limit, .. } => {
                assert!(matches!(limit, LimitExceeded::Instructions { .. }));
            }
            _ => panic!("Expected LimitReached"),
        }
    }

    #[test]
    fn test_fork_memory_isolation() {
        let process = ProcessBuilder::new()
            .name("original")
            .map_data(0x10000, vec![1, 2, 3, 4], "data")
            .build()
            .unwrap();

        // Fork
        let forked = process.fork();

        // Both see the same initial data
        assert_eq!(process.read_memory(0x10000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(forked.read_memory(0x10000, 4).unwrap(), vec![1, 2, 3, 4]);

        // Modify in forked
        forked.write_memory(0x10000, &[0xFF, 0xFE]).unwrap();

        // Original unchanged
        assert_eq!(process.read_memory(0x10000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(
            forked.read_memory(0x10000, 4).unwrap(),
            vec![0xFF, 0xFE, 3, 4]
        );
    }

    #[test]
    fn test_fork_statics_isolation() {
        let process = ProcessBuilder::new().build().unwrap();
        let field = Token::new(0x04000001);

        process.set_static(field, EmValue::I32(42));

        // Fork
        let forked = process.fork();

        // Both see the same static
        assert_eq!(process.get_static(field), Some(EmValue::I32(42)));
        assert_eq!(forked.get_static(field), Some(EmValue::I32(42)));

        // Modify in fork
        forked.set_static(field, EmValue::I32(100));

        // Original unchanged
        assert_eq!(process.get_static(field), Some(EmValue::I32(42)));
        assert_eq!(forked.get_static(field), Some(EmValue::I32(100)));
    }

    #[test]
    fn test_fork_captures_isolation() {
        // Enable assembly capture
        let capture_config = CaptureConfig {
            assemblies: true,
            ..Default::default()
        };
        let process = ProcessBuilder::new()
            .capture(capture_config)
            .build()
            .unwrap();

        // Fork gets fresh captures
        let forked = process.fork();

        // Capture in forked doesn't affect original
        forked.capture.capture_assembly_load_bytes(
            vec![0x4D, 0x5A],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0,
            0,
        );

        assert!(!process.has_captures());
        assert!(forked.has_captures());
    }

    #[test]
    fn test_fork_instruction_count_fresh() {
        let process = ProcessBuilder::new().build().unwrap();

        process.increment_instructions(100).unwrap();
        assert_eq!(process.instruction_count(), 100);

        // Fork starts fresh
        let forked = process.fork();
        assert_eq!(forked.instruction_count(), 0);

        // Modifying fork doesn't affect original
        forked.increment_instructions(50).unwrap();
        assert_eq!(process.instruction_count(), 100);
        assert_eq!(forked.instruction_count(), 50);
    }

    #[test]
    fn test_fork_with_captures() {
        // Enable assembly and string capture
        let capture_config = CaptureConfig {
            assemblies: true,
            strings: true,
            ..Default::default()
        };
        let process = ProcessBuilder::new()
            .capture(capture_config)
            .build()
            .unwrap();

        // Add capture to original
        process.capture.capture_assembly_load_bytes(
            vec![0x4D, 0x5A, 0x90, 0x00],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0,
            0,
        );

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0, 0);
        process
            .capture
            .capture_string("test string".to_string(), source);

        assert_eq!(process.captured_assemblies().len(), 1);
        assert_eq!(process.captured_strings().len(), 1);

        // Fork with captures - preserves existing captures
        let forked = process.fork_with_captures();
        assert_eq!(forked.captured_assemblies().len(), 1);
        assert_eq!(forked.captured_strings().len(), 1);

        // But adding to fork doesn't affect original
        forked.capture.capture_assembly_load_bytes(
            vec![0x4D, 0x5A, 0x90, 0x00, 0x03],
            Token::new(0x06000002),
            ThreadId::MAIN,
            0,
            0,
        );

        assert_eq!(process.captured_assemblies().len(), 1);
        assert_eq!(forked.captured_assemblies().len(), 2);
    }

    #[test]
    fn test_multiple_forks() {
        let process = ProcessBuilder::new()
            .map_data(0x10000, vec![0u8; 16], "data")
            .build()
            .unwrap();

        let field = Token::new(0x04000001);
        process.set_static(field, EmValue::I32(1));

        // Create multiple forks
        let fork1 = process.fork();
        let fork2 = process.fork();

        // Modify each independently
        fork1.set_static(field, EmValue::I32(10));
        fork1.write_memory(0x10000, &[0x11]).unwrap();

        fork2.set_static(field, EmValue::I32(20));
        fork2.write_memory(0x10000, &[0x22]).unwrap();

        // Each has its own state
        assert_eq!(process.get_static(field), Some(EmValue::I32(1)));
        assert_eq!(fork1.get_static(field), Some(EmValue::I32(10)));
        assert_eq!(fork2.get_static(field), Some(EmValue::I32(20)));

        assert_eq!(process.read_memory(0x10000, 1).unwrap(), vec![0]);
        assert_eq!(fork1.read_memory(0x10000, 1).unwrap(), vec![0x11]);
        assert_eq!(fork2.read_memory(0x10000, 1).unwrap(), vec![0x22]);
    }
}
