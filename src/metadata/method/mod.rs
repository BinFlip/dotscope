//! Method representation and analysis for .NET assemblies.
//!
//! This module provides comprehensive support for analyzing .NET methods, including
//! method metadata, IL code, exception handlers, and control flow structures.
//! It integrates closely with the disassembler to provide complete method analysis.
//!
//! # Architecture Overview
//!
//! The method analysis system uses a streamlined architecture centered around the
//! [`crate::metadata::method::Method`] struct with lazy-initialized basic blocks. Key design principles:
//!
//! - **Thread-safe lazy initialization**: Basic blocks are computed once and cached
//!   using `OnceLock<Vec<crate::assembly::BasicBlock>>` for efficient concurrent access
//! - **Zero-copy iteration**: The [`crate::metadata::method::InstructionIterator`] yields references to
//!   instructions without copying, enabling efficient analysis of large methods
//! - **Unified storage**: All instruction data is stored in basic blocks, eliminating
//!   redundant caching layers and simplifying the architecture
//!
//! # Key Components
//!
//! - [`crate::metadata::method::Method`] - Complete method representation with metadata and lazily-loaded IL code
//! - [`crate::metadata::method::MethodBody`] - Method body containing IL instructions and exception handlers
//! - [`crate::metadata::method::ExceptionHandler`] - Try/catch/finally exception handling regions
//! - [`crate::metadata::method::InstructionIterator`] - Efficient iterator over method instructions
//! - [`crate::metadata::method::MethodMap`] - Token-indexed collection of all methods in an assembly
//!
//! # Usage Patterns
//!
//! ## Basic Method Analysis
//!
//! ```rust,ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! for entry in assembly.methods().iter().take(10) {
//!     let method = entry.value();
//!     
//!     println!("Method: {} (Token: {:?})", method.name, method.token);
//!     println!("  Blocks: {}, Instructions: {}",
//!              method.block_count(), method.instruction_count());
//!     
//!     // Analyze control flow
//!     for (block_idx, block) in method.blocks() {
//!         println!("  Block {}: {} instructions at RVA 0x{:X}",
//!                  block_idx, block.instructions.len(), block.rva);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Instruction-Level Analysis
//!
//! ```rust,ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! for entry in assembly.methods().iter().take(5) {
//!     let method = entry.value();
//!     
//!     // Count different instruction types
//!     let mut call_count = 0;
//!     let mut branch_count = 0;
//!     
//!     for instruction in method.instructions() {
//!         match instruction.mnemonic {
//!             s if s.starts_with("call") => call_count += 1,
//!             s if s.contains("br") => branch_count += 1,
//!             _ => {}
//!         }
//!     }
//!     
//!     println!("{}: {} calls, {} branches", method.name, call_count, branch_count);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All method analysis operations are thread-safe:
//! - Methods can be safely shared across threads via `Arc<Method>`
//! - Basic block initialization uses `OnceLock` for thread-safe lazy loading
//! - Multiple threads can safely iterate over the same method simultaneously
//! - Iterator creation and consumption can happen concurrently

mod body;
mod encode;
mod exceptions;
mod iter;
mod types;

use crossbeam_skiplist::SkipMap;
use std::sync::{atomic::AtomicU32, Arc, OnceLock, Weak};

pub use body::*;
pub use encode::encode_method_body_header;
pub use exceptions::*;
pub use iter::InstructionIterator;
pub use types::*;

use crate::{
    assembly::{self, BasicBlock, VisitedMap},
    file::File,
    metadata::{
        customattributes::CustomAttributeValueList,
        security::Security,
        signatures::{parse_local_var_signature, SignatureMethod},
        streams::Blob,
        tables::{GenericParamList, MetadataTable, MethodSpecList, ParamList, StandAloneSigRaw},
        token::Token,
        typesystem::{TypeRegistry, TypeResolver},
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `Method`.
pub type MethodMap = SkipMap<Token, MethodRc>;
/// A vector that holds several parsed `Method`s.
pub type MethodList = Arc<boxcar::Vec<MethodRc>>;
/// A vector that holds `MethodRef` instances (weak references)
pub type MethodRefList = Arc<boxcar::Vec<MethodRef>>;
/// A reference-counted pointer to a `Method`.
pub type MethodRc = Arc<Method>;

/// A smart reference to a Method that automatically handles weak references
/// to prevent circular reference memory leaks while providing a clean API.
///
/// `MethodRef` provides a safe way to reference methods without creating strong
/// reference cycles that could lead to memory leaks. This is particularly useful
/// when methods reference other methods (e.g., through inheritance or interfaces)
/// where circular dependencies might occur.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Create weak references to avoid circular dependencies
/// for entry in assembly.methods().iter().take(5) {
///     let method = entry.value();
///     let weak_ref = dotscope::metadata::method::MethodRef::new(&method);
///     
///     // Check if the reference is still valid
///     if weak_ref.is_valid() {
///         if let Some(name) = weak_ref.name() {
///             println!("Referenced method: {}", name);
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct MethodRef {
    /// Weak reference to the actual method to avoid reference cycles
    weak_ref: Weak<Method>,
}

impl MethodRef {
    /// Create a new `MethodRef` from a strong reference.
    ///
    /// This method creates a weak reference to the provided method, allowing
    /// safe referencing without creating strong reference cycles.
    ///
    /// # Arguments
    ///
    /// * `strong_ref` - A strong reference (`Arc<Method>`) to the method
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     println!("Created weak reference to method: {}", method.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(strong_ref: &MethodRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Get a strong reference to the method, returning None if the method has been dropped.
    ///
    /// This method attempts to upgrade the weak reference to a strong reference.
    /// If the original method has been dropped, this returns `None`.
    ///
    /// # Returns
    ///
    /// - `Some(Arc<Method>)` if the method is still alive
    /// - `None` if the method has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     // Later, try to access the method
    ///     if let Some(method) = method_ref.upgrade() {
    ///         println!("Method is still available: {}", method.name);
    ///     } else {
    ///         println!("Method has been dropped");
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn upgrade(&self) -> Option<MethodRc> {
        self.weak_ref.upgrade()
    }

    /// Get a strong reference to the method, panicking if the method has been dropped.
    ///
    /// Use this when you're certain the method should still exist. This provides
    /// a convenient way to access the method without handling the `Option` case.
    ///
    /// # Arguments
    ///
    /// * `msg` - Error message to display if the method has been dropped
    ///
    /// # Panics
    ///
    /// Panics if the method has been dropped and the weak reference cannot be upgraded.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     // Use expect when you're certain the method should exist
    ///     let method = method_ref.expect("Method should still be available");
    ///     println!("Accessed method: {}", method.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn expect(&self, msg: &str) -> MethodRc {
        self.weak_ref.upgrade().expect(msg)
    }

    /// Check if the referenced method is still alive.
    ///
    /// This provides a quick way to test if the weak reference can still be
    /// upgraded to a strong reference without actually performing the upgrade.
    ///
    /// # Returns
    ///
    /// `true` if the method is still alive, `false` if it has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut method_refs = Vec::new();
    ///
    /// // Collect weak references
    /// for entry in assembly.methods().iter().take(10) {
    ///     let method = entry.value();
    ///     method_refs.push(dotscope::metadata::method::MethodRef::new(&method));
    /// }
    ///
    /// // Check which references are still valid
    /// let valid_count = method_refs.iter().filter(|r| r.is_valid()).count();
    /// println!("{} out of {} method references are still valid",
    ///          valid_count, method_refs.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.weak_ref.strong_count() > 0
    }

    /// Get the token of the referenced method (if still alive).
    ///
    /// This is a convenience method that upgrades the reference and extracts
    /// the method token in a single operation.
    ///
    /// # Returns
    ///
    /// - `Some(Token)` if the method is still alive
    /// - `None` if the method has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     if let Some(token) = method_ref.token() {
    ///         println!("Method token: {:?}", token);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        self.upgrade().map(|m| m.token)
    }

    /// Get the name of the referenced method (if still alive).
    ///
    /// This is a convenience method that upgrades the reference and extracts
    /// the method name in a single operation.
    ///
    /// # Returns
    ///
    /// - `Some(String)` containing the method name if the method is still alive
    /// - `None` if the method has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut method_names = Vec::new();
    ///
    /// for entry in assembly.methods().iter().take(5) {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     if let Some(name) = method_ref.name() {
    ///         method_names.push(name);
    ///     }
    /// }
    ///
    /// println!("Collected {} method names", method_names.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.upgrade().map(|m| m.name.clone())
    }

    /// Check if the referenced method is a constructor (.ctor or .cctor).
    ///
    /// This is a convenience method that upgrades the reference and checks
    /// if the method is a constructor in a single operation.
    ///
    /// # Returns
    ///
    /// `true` if the method is still alive and is a constructor, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut constructor_count = 0;
    ///
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     if method_ref.is_constructor() {
    ///         constructor_count += 1;
    ///     }
    /// }
    ///
    /// println!("Found {} constructors", constructor_count);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        if let Some(method) = self.upgrade() {
            method.is_constructor()
        } else {
            false
        }
    }
}

impl From<MethodRc> for MethodRef {
    fn from(strong_ref: MethodRc) -> Self {
        Self::new(&strong_ref)
    }
}

/// Represents all the information about a CIL method.
///
/// The `Method` struct contains all metadata, code, and analysis results for a single .NET method.
/// It includes method attributes, parameters, generic arguments, IL code, exception handlers, and analysis results.
pub struct Method {
    /// The row this method has in the `MetadataTable`
    pub rid: u32,
    /// The token of this method
    pub token: Token,
    /// The offset in the `MetadataTable`
    pub meta_offset: usize,
    /// This methods name
    pub name: String,
    /// `MethodImplAttributes`, §II.23.1.10
    pub impl_code_type: MethodImplCodeType,
    /// `MethodImplAttributes`, §II.23.1.10
    pub impl_management: MethodImplManagement,
    /// `MethodImplAttributes`, §II.23.1.10
    pub impl_options: MethodImplOptions,
    /// `MethodAttributes`, §II.23.1.10
    pub flags_access: MethodAccessFlags,
    /// `MethodAttributes`, §II.23.1.10
    pub flags_vtable: MethodVtableFlags,
    /// `MethodAttributes`, §II.23.1.10
    pub flags_modifiers: MethodModifiers,
    /// `PInvokeAttributes`, §II.23.1.8
    pub flags_pinvoke: AtomicU32,
    /// The parameters (from `Param` table, enhanced with information from the `SignatureMethod`)
    /// sequence 0, is the return value (if there is a count 0).
    pub params: ParamList,
    /// The vararg parameters of this method
    pub varargs: Arc<boxcar::Vec<VarArg>>,
    /// All generic parameters this type has (type information, not the instantiated version)
    pub generic_params: GenericParamList,
    /// `MethodSpec` instances that provide generic instantiations for this method
    pub generic_args: MethodSpecList,
    /// The signature of this method
    pub signature: SignatureMethod,
    /// The RVA of this method
    pub rva: Option<u32>,
    /// The `MethodBody`
    pub body: OnceLock<MethodBody>,
    /// The local variables
    pub local_vars: Arc<boxcar::Vec<LocalVariable>>,
    /// Overridden method if this is an override
    /// (from `MethodImpl` table where `MethodBody` points to this method)
    pub overrides: OnceLock<MethodRef>,
    /// Implemented interface methods
    /// (from `MethodImpl` table entries for this type)
    pub interface_impls: MethodRefList,
    /// The .NET CIL Security Information (if present)
    pub security: OnceLock<Security>,
    /// The basic blocks of this method, lazily initialized
    pub blocks: OnceLock<Vec<BasicBlock>>,
    /// Custom attributes attached to this method
    pub custom_attributes: CustomAttributeValueList,
    // /// The control flow graph of this method
    // pub cfg: RwLock<Option<ControlFlowGraph>>,
    // /// The SSA representation of this method
    // pub ssa: RwLock<Option<SSAForm>>,
}

impl Method {
    /// Returns an iterator over all instructions in this method.
    ///
    /// Instructions are yielded in execution order across all basic blocks, providing
    /// a linear view of the method's IL code. This method handles uninitialized state
    /// gracefully by returning an empty iterator if blocks haven't been decoded yet.
    ///
    /// The iterator implements efficient traversal without copying instruction data,
    /// making it suitable for analysis of large methods. Each instruction maintains
    /// its original metadata including RVA, operands, and flow control information.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. If the method hasn't
    /// been disassembled yet, all threads will receive an empty iterator.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(3) {
    ///     let method = entry.value();
    ///     println!("Method: {} ({} instructions)",
    ///              method.name, method.instruction_count());
    ///
    ///     for (i, instruction) in method.instructions().enumerate() {
    ///         println!("  [{}] {} {:?}", i, instruction.mnemonic, instruction.operand);
    ///         if i >= 10 { break; } // Limit output for readability
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn instructions(&self) -> InstructionIterator<'_> {
        if let Some(blocks) = self.blocks.get() {
            InstructionIterator::new(blocks.as_slice())
        } else {
            InstructionIterator::new(&[])
        }
    }

    /// Returns an iterator over all basic blocks containing the instructions.
    ///
    /// This method provides access to the control flow structure of the method by yielding
    /// each basic block along with its sequential index. Basic blocks represent straight-line
    /// sequences of instructions with a single entry point and single exit point.
    ///
    /// The iterator yields tuples of `(block_index, &BasicBlock)` where `block_index` is the
    /// zero-based position in the blocks vector. Returns an empty iterator if the method
    /// hasn't been disassembled yet.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and handles the `OnceLock` access pattern internally.
    /// Multiple threads can safely iterate over blocks simultaneously.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(3) {
    ///     let method = entry.value();
    ///     println!("Method: {} has {} basic blocks",
    ///              method.name, method.block_count());
    ///     
    ///     for (block_index, block) in method.blocks() {
    ///         println!("  Block {}: RVA 0x{:X}, {} instructions, {} exceptions",
    ///                 block_index, block.rva, block.instructions.len(), block.exceptions.len());
    ///         
    ///         // Show control flow information
    ///         if !block.instructions.is_empty() {
    ///             let last_instr = &block.instructions[block.instructions.len() - 1];
    ///             println!("    Ends with: {} (flow: {:?})",
    ///                     last_instr.mnemonic, last_instr.flow_type);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Control Flow Analysis
    ///
    /// Each basic block contains:
    /// - Sequential instructions with no internal jumps
    /// - Exception handler associations
    /// - RVA and offset information for debugging
    /// - Flow control termination (branch, return, throw, etc.)
    pub fn blocks(&self) -> Box<dyn Iterator<Item = (usize, &BasicBlock)> + '_> {
        if let Some(blocks) = self.blocks.get() {
            Box::new(blocks.iter().enumerate())
        } else {
            Box::new([].iter().enumerate())
        }
    }

    /// Returns the number of basic blocks in this method.
    ///
    /// This provides an efficient way to get the block count without iterating through
    /// all blocks. Returns 0 if the method hasn't been disassembled yet or contains
    /// no executable code.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and handles the `OnceLock` access pattern internally.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(10) {
    ///     let method = entry.value();
    ///     let block_count = method.block_count();
    ///     let instr_count = method.instruction_count();
    ///     
    ///     println!("Method: {} - {} blocks, {} instructions (avg {:.1} instr/block)",
    ///              method.name, block_count, instr_count,
    ///              if block_count > 0 { instr_count as f64 / block_count as f64 } else { 0.0 });
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn block_count(&self) -> usize {
        if let Some(blocks) = self.blocks.get() {
            blocks.len()
        } else {
            0
        }
    }

    /// Returns the total number of instructions across all basic blocks.
    ///
    /// This method efficiently calculates the total instruction count by summing
    /// the length of instruction vectors in each basic block. This is more efficient
    /// than calling `method.instructions().count()` as it avoids creating and
    /// consuming the iterator.
    ///
    /// Returns 0 if the method hasn't been disassembled yet or contains no executable code.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and handles the `OnceLock` access pattern internally.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut total_instructions = 0;
    /// let mut method_count = 0;
    ///
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     let count = method.instruction_count();
    ///     total_instructions += count;
    ///     method_count += 1;
    ///     
    ///     if count > 100 {
    ///         println!("Large method: {} with {} instructions", method.name, count);
    ///     }
    /// }
    ///
    /// println!("Assembly has {} methods with {} total instructions",
    ///          method_count, total_instructions);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn instruction_count(&self) -> usize {
        if let Some(blocks) = self.blocks.get() {
            blocks.iter().map(|block| block.instructions.len()).sum()
        } else {
            0
        }
    }

    /// Returns true if the method has IL code.
    ///
    /// This checks the `MethodImplCodeType::IL` flag in the method's implementation
    /// attributes to determine if the method contains Common Intermediate Language (CIL)
    /// instructions that can be disassembled and analyzed.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(10) {
    ///     let method = entry.value();
    ///     if method.is_code_il() {
    ///         println!("Method '{}' contains IL code", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_il(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::IL)
    }

    /// Returns true if the method has native code (P/Invoke).
    ///
    /// This checks the `MethodImplCodeType::NATIVE` flag to determine if the method
    /// is implemented in native code rather than IL. This is typical for P/Invoke
    /// methods that call into unmanaged libraries.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let native_methods: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_code_native())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("Found {} native methods", native_methods.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_native(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::NATIVE)
    }

    /// Returns true if the method has optimized IL code.
    ///
    /// This checks the `MethodImplCodeType::OPTIL` flag to determine if the method
    /// contains optimized Common Intermediate Language that may have been transformed
    /// by the runtime or tools for better performance.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_code_opt_il() {
    ///         println!("Method '{}' has optimized IL code", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_opt_il(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::OPTIL)
    }

    /// Returns true if the method is implemented in the runtime.
    ///
    /// This checks the `MethodImplCodeType::RUNTIME` flag to determine if the method
    /// is implemented directly by the .NET runtime rather than containing user code.
    /// This is common for intrinsic methods and runtime-provided functionality.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let runtime_methods: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_code_runtime())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("Found {} runtime-implemented methods", runtime_methods.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_runtime(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::RUNTIME)
    }

    /// Returns true if the method is unmanaged.
    ///
    /// This checks the `MethodImplManagement::UNMANAGED` flag to determine if the
    /// method runs outside the managed execution environment, typically for P/Invoke
    /// methods or COM interop scenarios.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_code_unmanaged() {
    ///         println!("Unmanaged method: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_unmanaged(&self) -> bool {
        self.impl_management
            .contains(MethodImplManagement::UNMANAGED)
    }

    /// Returns true if the method is a forward reference (used in merge scenarios).
    ///
    /// This checks the `MethodImplOptions::FORWARD_REF` flag to determine if the
    /// method is declared but not yet defined, which can occur during incremental
    /// compilation or when working with incomplete assemblies.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let forward_refs: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_forward_ref())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// if !forward_refs.is_empty() {
    ///     println!("Found {} forward reference methods", forward_refs.len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_forward_ref(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::FORWARD_REF)
    }

    /// Returns true if the method is synchronized.
    ///
    /// This checks the `MethodImplOptions::SYNCHRONIZED` flag to determine if the
    /// method automatically acquires a lock before execution, providing thread-safe
    /// access to the method body. This is equivalent to marking a method with the
    /// `synchronized` keyword in some languages.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_synchronized() {
    ///         println!("Synchronized method: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_synchronized(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::SYNCHRONIZED)
    }

    /// Returns true if the method preserves signature for P/Invoke.
    ///
    /// This checks the `MethodImplOptions::PRESERVE_SIG` flag to determine if the
    /// method signature should be preserved exactly as declared when calling into
    /// unmanaged code, rather than applying standard .NET marshalling transformations.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_pinvoke() {
    ///         println!("P/Invoke method with preserved signature: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_pinvoke(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::PRESERVE_SIG)
    }

    /// Returns true if the method is an internal call.
    ///
    /// This checks the `MethodImplOptions::INTERNAL_CALL` flag to determine if the
    /// method is implemented internally by the runtime with special handling for
    /// parameter type checking and validation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let internal_methods: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_internal_call())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("Found {} internal call methods", internal_methods.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_internal_call(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::INTERNAL_CALL)
    }

    /// Returns true if the method implementation is forwarded through P/Invoke.
    ///
    /// This checks the `MethodImplOptions::MAX_METHOD_IMPL_VAL` flag to determine
    /// if the method implementation is forwarded to an external library through
    /// the Platform Invoke (P/Invoke) mechanism.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_forarded_pinvoke() {
    ///         println!("Forwarded P/Invoke method: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_forarded_pinvoke(&self) -> bool {
        self.impl_options
            .contains(MethodImplOptions::MAX_METHOD_IMPL_VAL)
    }

    /// Returns true if the method is a constructor (.ctor or .cctor).
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name.starts_with(".ctor") || self.name.starts_with(".cctor")
    }

    /// Parse provided data, and extract additional information from the binary. e.g. Disassembly,
    /// method body, local variables, exception handlers, etc.
    ///
    /// # Arguments
    /// * `file`    - The input file
    /// * `blobs`   - The processed Blobs
    /// * `sigs`    - The table of signatures
    /// * `types`   - The type registry
    ///
    /// # Errors
    /// Returns an error if parsing fails or if referenced types/signatures cannot be resolved.
    pub fn parse(
        &self,
        file: &File,
        blobs: &Blob,
        sigs: &MetadataTable<StandAloneSigRaw>,
        types: &Arc<TypeRegistry>,
        shared_visited: Arc<VisitedMap>,
    ) -> Result<()> {
        if let Some(rva) = self.rva {
            let method_offset = file.rva_to_offset(rva as usize)?;
            if method_offset == 0 || method_offset >= file.data().len() {
                return Err(malformed_error!(
                    "Method offset is invalid - {}",
                    method_offset
                ));
            }

            let mut body = MethodBody::from(&file.data()[method_offset..])?;
            if body.local_var_sig_token != 0 {
                let local_var_sig_data = match sigs.get(body.local_var_sig_token & 0x00FF_FFFF) {
                    Some(var_sig_row) => blobs.get(var_sig_row.signature as usize)?,
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve signature - {}",
                            body.local_var_sig_token & 0x00FF_FFFF
                        ))
                    }
                };

                let mut resolver = TypeResolver::new(types.clone());
                let local_var_sig = parse_local_var_signature(local_var_sig_data)?;
                for local_var in &local_var_sig.locals {
                    let modifiers = Arc::new(boxcar::Vec::with_capacity(local_var.modifiers.len()));
                    for var_mod in &local_var.modifiers {
                        match types.get(&var_mod.modifier_type) {
                            Some(var_mod_type) => _ = modifiers.push(var_mod_type.into()),
                            None => {
                                return Err(malformed_error!(
                                    "Failed to resolve type - {}",
                                    var_mod.modifier_type.value()
                                ))
                            }
                        }
                    }

                    self.local_vars.push(LocalVariable {
                        modifiers,
                        is_byref: local_var.is_byref,
                        is_pinned: local_var.is_pinned,
                        base: resolver.resolve(&local_var.base)?.into(),
                    });
                }
            }

            for exception_handler in &mut body.exception_handlers {
                if exception_handler.flags == ExceptionHandlerFlags::EXCEPTION {
                    let Some(handler) = types.get(&Token::new(exception_handler.filter_offset))
                    else {
                        return Err(malformed_error!(
                            "Failed to resolve exception handler type - {}",
                            exception_handler.filter_offset
                        ));
                    };

                    exception_handler.handler = Some(handler);
                    exception_handler.filter_offset = 0;
                }
            }

            self.body.set(body).ok();
        }

        // Resolve the parameters
        let method_param_count = Some(self.signature.params.len());
        for (_, parameter) in self.params.iter() {
            if parameter.sequence == 0 {
                parameter.apply_signature(
                    &self.signature.return_type,
                    types.clone(),
                    method_param_count,
                )?;
            } else {
                let index = (parameter.sequence - 1) as usize;
                if let Some(param_signature) = self.signature.params.get(index) {
                    parameter.apply_signature(
                        param_signature,
                        types.clone(),
                        method_param_count,
                    )?;
                }
            }
        }

        // Parse varargs
        for vararg in &self.signature.varargs {
            let modifiers = Arc::new(boxcar::Vec::with_capacity(vararg.modifiers.len()));
            for modifier in &vararg.modifiers {
                match types.get(&modifier.modifier_type) {
                    Some(new_mod) => _ = modifiers.push(new_mod.into()),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve modifier type - {}",
                            modifier.modifier_type.value()
                        ))
                    }
                }
            }

            let mut resolver = TypeResolver::new(types.clone());
            self.varargs.push(VarArg {
                modifiers,
                by_ref: vararg.by_ref,
                base: resolver.resolve(&vararg.base)?.into(),
            });
        }

        // Last step, disassemble the whole method and generate analysis
        assembly::decode_method(self, file, shared_visited)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::{
        BasicBlock, FlowType, Instruction, InstructionCategory, Operand, StackBehavior,
    };
    use crate::test::builders::MethodBuilder;

    #[test]
    fn test_instructions_iterator_empty_method() {
        // Create a method with no basic blocks
        let blocks = Vec::new();
        let method = create_test_method(blocks);

        let mut instruction_count = 0;
        for _instruction in method.instructions() {
            instruction_count += 1;
        }

        assert_eq!(instruction_count, 0);
        assert_eq!(method.instruction_count(), 0);
    }

    #[test]
    fn test_instructions_iterator_single_block() {
        // Create a method with one basic block containing multiple instructions
        let block = BasicBlock {
            id: 0,
            rva: 0x1000,
            offset: 0,
            size: 10,
            instructions: vec![
                create_test_instruction(0x00, "nop"),     // nop
                create_test_instruction(0x02, "ldarg.0"), // ldarg.0
                create_test_instruction(0x2A, "ret"),     // ret
            ],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
        };

        let blocks = vec![block];
        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 3);
        assert_eq!(method.instruction_count(), 3);

        // Verify the instructions are returned in order
        assert_eq!(instructions[0].mnemonic, "nop");
        assert_eq!(instructions[1].mnemonic, "ldarg.0");
        assert_eq!(instructions[2].mnemonic, "ret");
    }

    #[test]
    fn test_instructions_iterator_multiple_blocks() {
        // Create a method with multiple basic blocks
        let block1 = BasicBlock {
            id: 0,
            rva: 0x1000,
            offset: 0,
            size: 5,
            instructions: vec![
                create_test_instruction(0x02, "ldarg.0"),
                create_test_instruction(0x03, "ldarg.1"),
            ],
            predecessors: vec![],
            successors: vec![1],
            exceptions: vec![],
        };

        let block2 = BasicBlock {
            id: 1,
            rva: 0x1010,
            offset: 5,
            size: 5,
            instructions: vec![
                create_test_instruction(0x58, "add"),
                create_test_instruction(0x2A, "ret"),
            ],
            predecessors: vec![0],
            successors: vec![],
            exceptions: vec![],
        };

        let blocks = vec![block1, block2];
        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 4);
        assert_eq!(method.instruction_count(), 4);

        // Verify the instructions are returned in block order
        assert_eq!(instructions[0].mnemonic, "ldarg.0");
        assert_eq!(instructions[1].mnemonic, "ldarg.1");
        assert_eq!(instructions[2].mnemonic, "add");
        assert_eq!(instructions[3].mnemonic, "ret");
    }

    #[test]
    fn test_instruction_iterator_size_hint() {
        let block = BasicBlock {
            id: 0,
            rva: 0x1000,
            offset: 0,
            size: 3,
            instructions: vec![
                create_test_instruction(0x00, "nop"),
                create_test_instruction(0x00, "nop"),
                create_test_instruction(0x2A, "ret"),
            ],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
        };

        let blocks = vec![block];
        let method = create_test_method(blocks);
        let mut iter = method.instructions();

        // Initial size hint should be (3, Some(3))
        assert_eq!(iter.size_hint(), (3, Some(3)));

        // After consuming one instruction
        iter.next();
        assert_eq!(iter.size_hint(), (2, Some(2)));

        // After consuming all instructions
        iter.next();
        iter.next();
        assert_eq!(iter.size_hint(), (0, Some(0)));
    }

    // Helper function to create a test method with the given blocks
    fn create_test_method(blocks: Vec<BasicBlock>) -> MethodRc {
        let method = MethodBuilder::new().with_name("TestMethod").build();

        // Set the blocks in the method (this is test-specific setup)
        method.blocks.set(blocks).ok();

        method
    }

    // Helper function to create a test instruction
    fn create_test_instruction(opcode: u8, mnemonic: &'static str) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode,
            prefix: 0,
            mnemonic,
            category: InstructionCategory::Misc,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        }
    }
}
