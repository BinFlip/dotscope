//! Method type flags, attributes, and supporting types for .NET CIL methods.
//!
//! This module defines all bitflags, constants, and supporting types used to represent and extract
//! method implementation flags, attributes, vtable layout, and local variable/vararg information for CIL methods.
//! It provides a comprehensive set of flags and types that correspond to the .NET metadata specifications
//! in ECMA-335 for method attributes and implementation details.
//!
//! # Architecture Overview
//!
//! The flag types in this module are organized hierarchically to match the .NET metadata structure:
//! - **Implementation Flags**: Control how methods are implemented (IL, native, runtime)
//! - **Access Flags**: Define method visibility and accessibility
//! - **Modifier Flags**: Specify method behavior (static, virtual, abstract, etc.)
//! - **Body Flags**: Control method body format and initialization
//!
//! Each flag group provides extraction methods that parse raw metadata values according to
//! the official bitmask specifications.
//!
//! # Key Types
//!
//! ## Implementation Attributes
//! - [`MethodImplCodeType`] - Method implementation type (IL, native, runtime)
//! - [`MethodImplManagement`] - Managed vs unmanaged execution
//! - [`MethodImplOptions`] - Additional implementation options (inlining, synchronization, etc.)
//!
//! ## Method Attributes  
//! - [`MethodAccessFlags`] - Visibility and accessibility controls
//! - [`MethodVtableFlags`] - Virtual table layout behavior
//! - [`MethodModifiers`] - Method behavior modifiers (static, virtual, abstract, etc.)
//!
//! ## Body and Section Attributes
//! - [`MethodBodyFlags`] - Method body format and initialization flags
//! - [`SectionFlags`] - Exception handling and data section flags
//!
//! ## Variable Types
//! - [`LocalVariable`] - Resolved local variable with type information
//! - [`VarArg`] - Variable argument parameter with type information
//!
//! # Usage Patterns
//!
//! ## Flag Extraction from Raw Metadata
//!
//! ```rust,ignore
//! // Extract different flag categories from raw method attributes
//! let raw_impl_flags = 0x0001_2080; // Example implementation flags
//! let raw_method_flags = 0x0086; // Example method attribute flags
//!
//! let code_type = MethodImplCodeType::from_impl_flags(raw_impl_flags);
//! let management = MethodImplManagement::from_impl_flags(raw_impl_flags);
//! let options = MethodImplOptions::from_impl_flags(raw_impl_flags);
//!
//! let access = MethodAccessFlags::from_method_flags(raw_method_flags);
//! let vtable = MethodVtableFlags::from_method_flags(raw_method_flags);
//! let modifiers = MethodModifiers::from_method_flags(raw_method_flags);
//! ```
//!
//! ## Flag Testing and Analysis
//!
//! ```rust,ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! for entry in assembly.methods().iter().take(20) {
//!     let method = entry.value();
//!     
//!     // Analyze method characteristics
//!     if method.flags_access.contains(MethodAccessFlags::PUBLIC) {
//!         println!("Public method: {}", method.name);
//!     }
//!     
//!     if method.flags_modifiers.contains(MethodModifiers::STATIC) {
//!         println!("Static method: {}", method.name);
//!     }
//!     
//!     if method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
//!         println!("Virtual method: {}", method.name);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Flag Relationships
//!
//! Many flags have logical relationships and constraints:
//! - Methods marked `ABSTRACT` must also be `VIRTUAL`
//! - `STATIC` methods cannot be `VIRTUAL` or `ABSTRACT`  
//! - `PINVOKE_IMPL` methods typically have `PRESERVE_SIG` option
//! - `RUNTIME` code type often paired with `INTERNAL_CALL` option
//!
//! # Thread Safety
//!
//! All flag types are `Copy` and thread-safe. LocalVariable and VarArg use `Arc`-based
//! reference counting for safe sharing across threads.

use bitflags::bitflags;

use crate::metadata::typesystem::{CilTypeRef, CilTypeRefList};

/// Bitmask for `CODE_TYPE` extraction
pub const METHOD_IMPL_CODE_TYPE_MASK: u32 = 0x0003;
/// Bitmask for `MANAGED` state extraction
pub const METHOD_IMPL_MANAGED_MASK: u32 = 0x0004;
/// Bitmask for `ACCESS` state extraction
pub const METHOD_ACCESS_MASK: u32 = 0x0007;
/// Bitmask for `VTABLE_LAYOUT` information extraction
pub const METHOD_VTABLE_LAYOUT_MASK: u32 = 0x0100;

// Method implementation flags split into logical groups
bitflags! {
    #[derive(PartialEq)]
    /// Method implementation code type flags
    pub struct MethodImplCodeType: u32 {
        /// Method impl is IL
        const IL = 0x0000;
        /// Method impl is native
        const NATIVE = 0x0001;
        /// Method impl is OPTIL
        const OPTIL = 0x0002;
        /// Method impl is provided by the runtime
        const RUNTIME = 0x0003;
    }
}

// Methods to extract flags from raw values
impl MethodImplCodeType {
    /// Extract code type from raw implementation flags
    #[must_use]
    pub fn from_impl_flags(flags: u32) -> Self {
        let code_type = flags & METHOD_IMPL_CODE_TYPE_MASK;
        Self::from_bits_truncate(code_type)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method implementation management flags
    pub struct MethodImplManagement: u32 {
        /// Method impl is unmanaged, otherwise managed
        const UNMANAGED = 0x0004;
    }
}

impl MethodImplManagement {
    /// Extract management type from raw implementation flags
    #[must_use]
    pub fn from_impl_flags(flags: u32) -> Self {
        let management = flags & METHOD_IMPL_MANAGED_MASK;
        Self::from_bits_truncate(management)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method implementation additional options
    pub struct MethodImplOptions: u32 {
        /// Method cannot be inlined
        const NO_INLINING = 0x0008;
        /// Method is defined; used primarily in merge scenarios
        const FORWARD_REF = 0x0010;
        /// Method is a synchronized method
        const SYNCHRONIZED = 0x0020;
        /// Method is a P/Invoke
        const PRESERVE_SIG = 0x0080;
        /// Runtime shall check all types of parameters
        const INTERNAL_CALL = 0x1000;
        /// Method implementation is forwarded through PInvoke
        const MAX_METHOD_IMPL_VAL = 0xFFFF;
    }
}

impl MethodImplOptions {
    /// Extract implementation options from raw implementation flags
    #[must_use]
    pub fn from_impl_flags(flags: u32) -> Self {
        let options = flags & !(METHOD_IMPL_CODE_TYPE_MASK | METHOD_IMPL_MANAGED_MASK);
        Self::from_bits_truncate(options)
    }
}

// Method attributes split into logical groups
bitflags! {
    #[derive(PartialEq)]
    /// Method access flags
    pub struct MethodAccessFlags: u32 {
        /// Member not referenceable
        const COMPILER_CONTROLLED = 0x0000;
        /// Accessible only by the parent type
        const PRIVATE = 0x0001;
        /// Accessible by sub-types only in this Assembly
        const FAM_AND_ASSEM = 0x0002;
        /// Accessibly by anyone in the Assembly
        const ASSEM = 0x0003;
        /// Accessible only by type and sub-types
        const FAMILY = 0x0004;
        /// Accessibly by sub-types anywhere, plus anyone in assembly
        const FAM_OR_ASSEM = 0x0005;
        /// Accessibly by anyone who has visibility to this scope
        const PUBLIC = 0x0006;
    }
}

impl MethodAccessFlags {
    /// Extract access flags from raw method attributes
    #[must_use]
    pub fn from_method_flags(flags: u32) -> Self {
        let access = flags & METHOD_ACCESS_MASK;
        Self::from_bits_truncate(access)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method vtable layout flags
    pub struct MethodVtableFlags: u32 {
        /// Method reuses existing slot in vtable
        const REUSE_SLOT = 0x0000;
        /// Method always gets a new slot in the vtable
        const NEW_SLOT = 0x0100;
    }
}

impl MethodVtableFlags {
    /// Extract vtable layout flags from raw method attributes
    #[must_use]
    pub fn from_method_flags(flags: u32) -> Self {
        let vtable = flags & METHOD_VTABLE_LAYOUT_MASK;
        Self::from_bits_truncate(vtable)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method modifiers and properties
    pub struct MethodModifiers: u32 {
        /// Defined on type, else per instance
        const STATIC = 0x0010;
        /// Method cannot be overridden
        const FINAL = 0x0020;
        /// Method is virtual
        const VIRTUAL = 0x0040;
        /// Method hides by name+sig, else just by name
        const HIDE_BY_SIG = 0x0080;
        /// Method can only be overriden if also accessible
        const STRICT = 0x0200;
        /// Method does not provide an implementation
        const ABSTRACT = 0x0400;
        /// Method is special
        const SPECIAL_NAME = 0x0800;
        /// CLI provides 'special' behavior, dpending upon the name of the method
        const RTSPECIAL_NAME = 0x1000;
        /// Implementation is forwarded through PInvoke
        const PINVOKE_IMPL = 0x2000;
        /// Method has security associate with it
        const HAS_SECURITY = 0x4000;
        /// Method calls another method containing security code
        const REQUIRE_SEC_OBJECT = 0x8000;
        /// Reserved: shall be zero for conforming implementations
        const UNMANAGED_EXPORT = 0x0008;
    }
}

impl MethodModifiers {
    /// Extract method modifiers from raw method attributes
    #[must_use]
    pub fn from_method_flags(flags: u32) -> Self {
        let modifiers = flags & !METHOD_ACCESS_MASK & !METHOD_VTABLE_LAYOUT_MASK;
        Self::from_bits_truncate(modifiers)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Flags that a method body can have
    pub struct MethodBodyFlags: u16 {
        /// Tiny method header format
        const TINY_FORMAT = 0x2;
        /// Fat method header format
        const FAT_FORMAT = 0x3;
        /// Flag of the fat method header, showing that there are more data sections appended to the header
        const MORE_SECTS = 0x8;
        /// Flag to indicate that this method should call the default constructor on all local variables
        const INIT_LOCALS = 0x10;
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Flags that a method body section can have
    pub struct SectionFlags: u8 {
        /// Indicates that this section contains exception handling data
        const EHTABLE = 0x1;
        /// Reserved, shall be 0
        const OPT_ILTABLE = 0x2;
        /// Indicates that the data section format is far
        const FAT_FORMAT = 0x40;
        /// Indicates that the data section is followed by another one
        const MORE_SECTS = 0x80;
    }
}

/// Represents a local variable in a method with resolved type information.
///
/// `LocalVariable` provides a fully resolved representation of a local variable within a
/// method body, including its type signature, custom modifiers, and special attributes
/// like reference passing and pinning. This is the resolved form of signature local
/// variables, with all type tokens converted to concrete type references.
///
/// # Type Resolution
///
/// Unlike signature-based representations, `LocalVariable` contains resolved type
/// references that can be directly used for analysis without additional lookups.
/// This makes it efficient for runtime analysis and code generation scenarios.
///
/// # Pinning and References
///
/// Local variables can have special memory management attributes:
/// - **By Reference**: The variable stores a reference rather than a value
/// - **Pinned**: The variable's memory location is fixed (prevents GC movement)
///
/// These attributes are crucial for interop scenarios and unsafe code analysis.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// for entry in assembly.methods().iter().take(10) {
///     let method = entry.value();
///     
///     if !method.local_vars.is_empty() {
///         println!("Method '{}' has {} local variables:",
///                  method.name, method.local_vars.len());
///         
///         for (i, local_var) in method.local_vars.iter().enumerate() {
///             let var_info = format!("  [{}] Type: {}, ByRef: {}, Pinned: {}, Modifiers: {}",
///                                   i,
///                                   local_var.base.name(),
///                                   local_var.is_byref,
///                                   local_var.is_pinned,
///                                   local_var.modifiers.len());
///             println!("{}", var_info);
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Memory Management
///
/// - **Type References**: Use `Arc` for efficient sharing across thread boundaries
/// - **Modifiers**: Stored in reference-counted vectors for minimal memory overhead
/// - **Flags**: Stored as boolean values for fast access
///
/// # Thread Safety
///
/// `LocalVariable` is thread-safe through its use of `Arc`-based type references.
/// Multiple threads can safely access local variable information concurrently.
pub struct LocalVariable {
    /// Custom modifiers applied to the variable type.
    ///
    /// These are optional and required modifiers that change the semantic meaning
    /// of the base type, such as `const`, `volatile`, or custom attribute-based
    /// modifiers. Each modifier is a resolved type reference.
    pub modifiers: CilTypeRefList,

    /// Whether the variable is passed by reference.
    ///
    /// When `true`, the variable stores a reference to the actual data rather than
    /// the data itself. This is equivalent to `ref` or `out` parameters in C#.
    pub is_byref: bool,

    /// Whether the variable is pinned in memory.
    ///
    /// When `true`, the garbage collector will not move this variable's memory
    /// location, allowing safe use with unmanaged code pointers. This is typically
    /// used in unsafe code scenarios and P/Invoke operations.
    pub is_pinned: bool,

    /// The resolved base type of the variable.
    ///
    /// This is the primary type of the local variable after all type tokens have
    /// been resolved to concrete type references. The type includes full namespace
    /// and assembly qualification for unambiguous identification.
    pub base: CilTypeRef,
}

/// Variable argument parameter used in method signatures to describe vararg parameters.
///
/// `VarArg` represents a single parameter in the variable-length argument list of a
/// method that uses varargs (...) calling convention. Each vararg parameter has its
/// own type signature and modifiers, allowing for type-safe variable argument processing.
///
/// # Varargs in .NET
///
/// Variable arguments in .NET are less common than in C/C++ but are still supported
/// for scenarios like P/Invoke to C libraries that use varargs, or for implementing
/// methods like `String.Format` with variable parameter counts.
///
/// # Type Resolution
///
/// Like `LocalVariable`, `VarArg` contains fully resolved type references rather than
/// raw signature data, making it efficient for analysis and code generation without
/// requiring additional type lookups.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// for entry in assembly.methods().iter() {
///     let method = entry.value();
///     
///     if !method.varargs.is_empty() {
///         println!("Method '{}' has {} vararg parameters:",
///                  method.name, method.varargs.len());
///         
///         for (i, vararg) in method.varargs.iter().enumerate() {
///             let arg_info = format!("  VarArg[{}] Type: {}, ByRef: {}, Modifiers: {}",
///                                   i,
///                                   vararg.base.name(),
///                                   vararg.by_ref,
///                                   vararg.modifiers.len());
///             println!("{}", arg_info);
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Memory Management
///
/// - **Type References**: Use `Arc` for efficient sharing and thread safety
/// - **Modifiers**: Reference-counted vectors for minimal memory overhead  
/// - **Flags**: Simple boolean values for fast access
///
/// # Thread Safety
///
/// `VarArg` is thread-safe through its use of `Arc`-based type references.
/// Multiple threads can safely access vararg parameter information concurrently.
pub struct VarArg {
    /// Custom modifiers applied to the parameter type.
    ///
    /// These are optional and required modifiers that change the semantic meaning
    /// of the base parameter type. Common modifiers include `const`, `volatile`,
    /// or custom attribute-based type modifications.
    pub modifiers: CilTypeRefList,

    /// Whether the parameter is passed by reference.
    ///
    /// When `true`, the parameter is passed by reference rather than by value.
    /// This allows the called method to modify the original value in the caller's
    /// context, similar to `ref` or `out` parameters in C#.
    pub by_ref: bool,

    /// The resolved base type of the parameter.
    ///
    /// This is the primary type of the vararg parameter after all type tokens
    /// have been resolved to concrete type references. The type includes full
    /// namespace and assembly qualification for unambiguous identification.
    pub base: CilTypeRef,
}
