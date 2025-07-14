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
//! # Key Components
//!
//! ## Implementation Attributes
//! - [`crate::metadata::method::MethodImplCodeType`] - Method implementation type (IL, native, runtime)
//! - [`crate::metadata::method::MethodImplManagement`] - Managed vs unmanaged execution
//! - [`crate::metadata::method::MethodImplOptions`] - Additional implementation options (inlining, synchronization, etc.)
//!
//! ## Method Attributes  
//! - [`crate::metadata::method::MethodAccessFlags`] - Visibility and accessibility controls
//! - [`crate::metadata::method::MethodVtableFlags`] - Virtual table layout behavior
//! - [`crate::metadata::method::MethodModifiers`] - Method behavior modifiers (static, virtual, abstract, etc.)
//!
//! ## Body and Section Attributes
//! - [`crate::metadata::method::MethodBodyFlags`] - Method body format and initialization flags
//! - [`crate::metadata::method::SectionFlags`] - Exception handling and data section flags
//!
//! ## Variable Types
//! - [`crate::metadata::method::LocalVariable`] - Resolved local variable with type information
//! - [`crate::metadata::method::VarArg`] - Variable argument parameter with type information
//!
//! # Usage Patterns
//!
//! ## Flag Extraction from Raw Metadata
//!
//! ```rust,ignore
//! use dotscope::metadata::method::{
//!     MethodImplCodeType, MethodImplManagement, MethodImplOptions,
//!     MethodAccessFlags, MethodVtableFlags, MethodModifiers
//! };
//!
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
//! use dotscope::{CilObject, metadata::method::{MethodAccessFlags, MethodModifiers}};
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
//! ## Variable Analysis
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
//!     // Analyze local variables
//!     if !method.local_vars.is_empty() {
//!         println!("Method '{}' has {} local variables:", method.name, method.local_vars.len());
//!         for (i, local) in method.local_vars.iter().enumerate() {
//!             println!("  [{}] {} (by_ref: {}, pinned: {})",
//!                      i, local.base.name(), local.is_byref, local.is_pinned);
//!         }
//!     }
//!     
//!     // Analyze varargs
//!     if !method.varargs.is_empty() {
//!         println!("Method '{}' has {} varargs:", method.name, method.varargs.len());
//!         for (i, vararg) in method.varargs.iter().enumerate() {
//!             println!("  VarArg[{}] {} (by_ref: {})",
//!                      i, vararg.base.name(), vararg.by_ref);
//!         }
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
//! # ECMA-335 Compliance
//!
//! The flag definitions and extraction methods conform to:
//! - **Partition II, Section 23.1.10**: MethodImplAttributes and MethodAttributes
//! - **Partition II, Section 25.4.1**: Method header format flags
//! - **Partition II, Section 23.2.6**: Local variable signature format
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access:
//! - **Flag Types**: All bitflag types are [`std::marker::Copy`] and immutable, making them inherently thread-safe
//! - **Variable Types**: [`crate::metadata::method::LocalVariable`] and [`crate::metadata::method::VarArg`] use [`std::sync::Arc`]-based reference counting for safe sharing
//! - **Constants**: All mask constants are immutable and safe for concurrent access
//! - **Extraction Methods**: All flag extraction methods are pure functions without shared state
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::method`] - Method analysis and representation infrastructure
//! - [`crate::metadata::typesystem`] - Type resolution for local variables and varargs
//! - [`crate::metadata::signatures`] - Signature parsing for variable type extraction
//! - [`crate::metadata::tables`] - Raw metadata table parsing and token resolution

use bitflags::bitflags;

use crate::metadata::typesystem::{CilTypeRef, CilTypeRefList};

/// Bitmask for extracting code type from [`crate::metadata::method::MethodImplCodeType`] implementation flags.
///
/// This mask isolates the lower 2 bits (0x0003) that determine how a method is implemented:
/// IL, native, optimized IL, or runtime-provided implementation.
pub const METHOD_IMPL_CODE_TYPE_MASK: u32 = 0x0003;

/// Bitmask for extracting managed/unmanaged state from [`crate::metadata::method::MethodImplManagement`] implementation flags.
///
/// This mask isolates bit 2 (0x0004) that determines whether a method runs in the
/// managed execution environment or executes as unmanaged code.
pub const METHOD_IMPL_MANAGED_MASK: u32 = 0x0004;

/// Bitmask for extracting access level from [`crate::metadata::method::MethodAccessFlags`] method attributes.
///
/// This mask isolates the lower 3 bits (0x0007) that determine method visibility:
/// private, public, assembly, family, etc.
pub const METHOD_ACCESS_MASK: u32 = 0x0007;

/// Bitmask for extracting vtable layout from [`crate::metadata::method::MethodVtableFlags`] method attributes.
///
/// This mask isolates bit 8 (0x0100) that determines whether a virtual method
/// reuses an existing vtable slot or creates a new slot.
pub const METHOD_VTABLE_LAYOUT_MASK: u32 = 0x0100;

// Method implementation flags split into logical groups
bitflags! {
    #[derive(PartialEq)]
    /// Method implementation code type flags as defined in ECMA-335 II.23.1.10.
    ///
    /// These flags specify how a method is implemented and where its code originates.
    /// The flags are mutually exclusive - each method has exactly one implementation type.
    ///
    /// # ECMA-335 Reference
    ///
    /// From Partition II, Section 23.1.10 (MethodImplAttributes):
    /// > The CodeTypeMask sub-field of the Flags field in the MethodImpl table can hold any
    /// > of the values specified in the enumeration below. These values indicate the kind
    /// > of implementation the method has.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodImplCodeType;
    ///
    /// // Extract from raw implementation flags
    /// let raw_flags = 0x0001; // Native implementation
    /// let code_type = MethodImplCodeType::from_impl_flags(raw_flags);
    /// assert!(code_type.contains(MethodImplCodeType::NATIVE));
    /// ```
    pub struct MethodImplCodeType: u32 {
        /// Method implementation is Common Intermediate Language (CIL).
        ///
        /// The method contains IL bytecode that will be just-in-time compiled
        /// by the runtime. This is the default and most common implementation type
        /// for managed methods.
        const IL = 0x0000;

        /// Method implementation is native machine code.
        ///
        /// The method is implemented as pre-compiled native code rather than IL.
        /// This is typically used for P/Invoke methods that call into unmanaged
        /// libraries or for methods marked with `[MethodImpl(MethodImplOptions.Unmanaged)]`.
        const NATIVE = 0x0001;

        /// Method implementation is optimized Common Intermediate Language.
        ///
        /// The method contains IL that has been optimized by development tools
        /// or runtime optimizers. This is less common and typically indicates
        /// special handling by the runtime.
        const OPTIL = 0x0002;

        /// Method implementation is provided directly by the runtime.
        ///
        /// The runtime provides the implementation internally without IL or native code.
        /// This is used for intrinsic methods, runtime helpers, and methods marked
        /// with `[MethodImpl(MethodImplOptions.InternalCall)]`.
        const RUNTIME = 0x0003;
    }
}

// Methods to extract flags from raw values
impl MethodImplCodeType {
    /// Extract code type from raw implementation flags.
    ///
    /// This method applies the [`METHOD_IMPL_CODE_TYPE_MASK`] to isolate the code type
    /// bits from a complete MethodImplAttributes value and converts them to the
    /// appropriate [`crate::metadata::method::MethodImplCodeType`] flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - Raw MethodImplAttributes value from the metadata table
    ///
    /// # Returns
    ///
    /// The extracted code type flags, with unknown bits truncated to ensure
    /// only valid combinations are returned.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodImplCodeType;
    ///
    /// let raw_flags = 0x1001; // RUNTIME + some other flags
    /// let code_type = MethodImplCodeType::from_impl_flags(raw_flags);
    /// assert!(code_type.contains(MethodImplCodeType::RUNTIME));
    /// ```
    #[must_use]
    pub fn from_impl_flags(flags: u32) -> Self {
        let code_type = flags & METHOD_IMPL_CODE_TYPE_MASK;
        Self::from_bits_truncate(code_type)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method implementation management flags as defined in ECMA-335 II.23.1.10.
    ///
    /// These flags determine whether a method executes in the managed or unmanaged
    /// execution environment. Most .NET methods are managed, but some special methods
    /// like P/Invoke targets execute as unmanaged code.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodImplManagement;
    ///
    /// // Extract from raw implementation flags
    /// let raw_flags = 0x0004; // Unmanaged method
    /// let management = MethodImplManagement::from_impl_flags(raw_flags);
    /// assert!(management.contains(MethodImplManagement::UNMANAGED));
    /// ```
    pub struct MethodImplManagement: u32 {
        /// Method implementation executes as unmanaged code.
        ///
        /// When set, the method runs outside the managed execution environment,
        /// typically for P/Invoke methods that call into native libraries.
        /// When not set (default), the method runs as managed code under
        /// the control of the .NET runtime.
        const UNMANAGED = 0x0004;
    }
}

impl MethodImplManagement {
    /// Extract management type from raw implementation flags.
    ///
    /// This method applies the [`METHOD_IMPL_MANAGED_MASK`] to isolate the management
    /// bit from a complete MethodImplAttributes value and converts it to the
    /// appropriate [`crate::metadata::method::MethodImplManagement`] flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - Raw MethodImplAttributes value from the metadata table
    ///
    /// # Returns
    ///
    /// The extracted management flags. If the bit is clear, returns empty flags
    /// (indicating managed execution). If set, returns [`UNMANAGED`](Self::UNMANAGED).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodImplManagement;
    ///
    /// // Managed method (default)
    /// let managed_flags = 0x0000;
    /// let management = MethodImplManagement::from_impl_flags(managed_flags);
    /// assert!(management.is_empty()); // Managed is the default
    ///
    /// // Unmanaged method
    /// let unmanaged_flags = 0x0004;
    /// let management = MethodImplManagement::from_impl_flags(unmanaged_flags);
    /// assert!(management.contains(MethodImplManagement::UNMANAGED));
    /// ```
    #[must_use]
    pub fn from_impl_flags(flags: u32) -> Self {
        let management = flags & METHOD_IMPL_MANAGED_MASK;
        Self::from_bits_truncate(management)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method implementation additional options as defined in ECMA-335 II.23.1.10.
    ///
    /// These flags provide additional control over method implementation behavior,
    /// covering aspects like inlining, synchronization, P/Invoke semantics, and
    /// runtime-provided implementations.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodImplOptions;
    ///
    /// // Extract from raw implementation flags
    /// let raw_flags = 0x0020; // Synchronized method
    /// let options = MethodImplOptions::from_impl_flags(raw_flags);
    /// assert!(options.contains(MethodImplOptions::SYNCHRONIZED));
    /// ```
    pub struct MethodImplOptions: u32 {
        /// Method cannot be inlined by the runtime or JIT compiler.
        ///
        /// This flag prevents the runtime from inlining the method call,
        /// which can be important for debugging, profiling, or when the
        /// method has side effects that must be preserved.
        const NO_INLINING = 0x0008;

        /// Method is a forward reference used primarily in merge scenarios.
        ///
        /// This indicates that the method is declared but not yet defined,
        /// which can occur during incremental compilation or when working
        /// with incomplete assemblies.
        const FORWARD_REF = 0x0010;

        /// Method is automatically synchronized with a lock.
        ///
        /// The runtime will automatically acquire a lock before executing
        /// the method and release it afterwards, providing thread-safe
        /// access. This is equivalent to the `synchronized` keyword.
        const SYNCHRONIZED = 0x0020;

        /// Method signature should be preserved exactly for P/Invoke.
        ///
        /// When calling into unmanaged code, this flag prevents the runtime
        /// from applying standard .NET marshalling transformations, preserving
        /// the exact signature as declared.
        const PRESERVE_SIG = 0x0080;

        /// Runtime should check all parameter types for internal calls.
        ///
        /// This flag indicates that the method is implemented internally by
        /// the runtime and requires special parameter type checking and
        /// validation during calls.
        const INTERNAL_CALL = 0x1000;

        /// Maximum valid value for method implementation attributes.
        ///
        /// This constant defines the upper bound for valid MethodImplAttributes
        /// values and can be used for validation and range checking.
        const MAX_METHOD_IMPL_VAL = 0xFFFF;
    }
}

impl MethodImplOptions {
    /// Extract implementation options from raw implementation flags.
    ///
    /// This method removes the code type and management bits from the raw flags
    /// and converts the remaining bits to [`crate::metadata::method::MethodImplOptions`] flags.
    /// This allows extraction of all additional implementation options while
    /// excluding the basic type and management information.
    ///
    /// # Arguments
    ///
    /// * `flags` - Raw MethodImplAttributes value from the metadata table
    ///
    /// # Returns
    ///
    /// The extracted implementation option flags, with code type and management
    /// bits masked out and unknown bits truncated.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodImplOptions;
    ///
    /// // Synchronized P/Invoke method
    /// let raw_flags = 0x00A1; // SYNCHRONIZED + PRESERVE_SIG + IL
    /// let options = MethodImplOptions::from_impl_flags(raw_flags);
    /// assert!(options.contains(MethodImplOptions::SYNCHRONIZED));
    /// assert!(options.contains(MethodImplOptions::PRESERVE_SIG));
    /// // Code type and management bits are excluded
    /// ```
    #[must_use]
    pub fn from_impl_flags(flags: u32) -> Self {
        let options = flags & !(METHOD_IMPL_CODE_TYPE_MASK | METHOD_IMPL_MANAGED_MASK);
        Self::from_bits_truncate(options)
    }
}

// Method attributes split into logical groups
bitflags! {
    #[derive(PartialEq, Eq, Debug)]
    /// Method accessibility flags as defined in ECMA-335 II.23.1.10.
    ///
    /// These flags control the visibility and accessibility of methods, determining
    /// which code can call or reference the method. The access levels follow the
    /// standard .NET visibility model with support for assembly-level and
    /// inheritance-based access control.
    ///
    /// # Access Hierarchy
    ///
    /// The access levels form a hierarchy from most restrictive to least restrictive:
    /// 1. [`COMPILER_CONTROLLED`](Self::COMPILER_CONTROLLED) - No external access
    /// 2. [`PRIVATE`](Self::PRIVATE) - Only within the same type
    /// 3. [`FAM_AND_ASSEM`](Self::FAM_AND_ASSEM) - Family within assembly
    /// 4. [`ASSEM`](Self::ASSEM) - Assembly-level access
    /// 5. [`FAMILY`](Self::FAMILY) - Inheritance-based access
    /// 6. [`FAM_OR_ASSEM`](Self::FAM_OR_ASSEM) - Family or assembly access
    /// 7. [`PUBLIC`](Self::PUBLIC) - Universal access
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodAccessFlags;
    ///
    /// // Extract from raw method attributes
    /// let raw_flags = 0x0006; // Public method
    /// let access = MethodAccessFlags::from_method_flags(raw_flags);
    /// assert!(access.contains(MethodAccessFlags::PUBLIC));
    /// ```
    pub struct MethodAccessFlags: u32 {
        /// Member not referenceable by external code.
        ///
        /// The method is controlled by the compiler and cannot be accessed
        /// by user code. This is the most restrictive access level.
        const COMPILER_CONTROLLED = 0x0000;

        /// Accessible only by the parent type.
        ///
        /// The method can only be called from within the same type that
        /// declares it. This corresponds to `private` in C#.
        const PRIVATE = 0x0001;

        /// Accessible by sub-types only within this Assembly.
        ///
        /// The method can be accessed by derived types, but only when those
        /// types are in the same assembly. This combines family and assembly access.
        const FAMILY_AND_ASSEMBLY = 0x0002;

        /// Accessible by anyone in the Assembly.
        ///
        /// The method can be called by any code within the same assembly,
        /// regardless of type relationships. This corresponds to `internal` in C#.
        const ASSEMBLY = 0x0003;

        /// Accessible only by type and sub-types.
        ///
        /// The method can be accessed by the declaring type and any derived types,
        /// regardless of assembly boundaries. This corresponds to `protected` in C#.
        const FAMILY = 0x0004;

        /// Accessible by sub-types anywhere, plus anyone in assembly.
        ///
        /// The method can be accessed by derived types in any assembly, or by
        /// any code within the same assembly. This corresponds to `protected internal` in C#.
        const FAMILY_OR_ASSEMBLY = 0x0005;

        /// Accessible by anyone who has visibility to this scope.
        ///
        /// The method can be called by any code that can see the declaring type.
        /// This is the least restrictive access level and corresponds to `public` in C#.
        const PUBLIC = 0x0006;
    }
}

impl MethodAccessFlags {
    /// Extract access flags from raw method attributes.
    ///
    /// This method applies the [`METHOD_ACCESS_MASK`] to isolate the access control
    /// bits from a complete MethodAttributes value and converts them to the
    /// appropriate [`crate::metadata::method::MethodAccessFlags`] flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - Raw MethodAttributes value from the metadata table
    ///
    /// # Returns
    ///
    /// The extracted access control flags, with unknown bits truncated to ensure
    /// only valid access levels are returned.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodAccessFlags;
    ///
    /// // Public method
    /// let public_flags = 0x0006;
    /// let access = MethodAccessFlags::from_method_flags(public_flags);
    /// assert!(access.contains(MethodAccessFlags::PUBLIC));
    ///
    /// // Private method with other flags
    /// let private_flags = 0x0091; // PRIVATE + other flags
    /// let access = MethodAccessFlags::from_method_flags(private_flags);
    /// assert!(access.contains(MethodAccessFlags::PRIVATE));
    /// ```
    #[must_use]
    pub fn from_method_flags(flags: u32) -> Self {
        let access = flags & METHOD_ACCESS_MASK;
        Self::from_bits_truncate(access)
    }
}

impl PartialOrd for MethodAccessFlags {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MethodAccessFlags {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by accessibility level: higher values = more accessible
        // COMPILER_CONTROLLED(0) < PRIVATE(1) < FAMILY_AND_ASSEMBLY(2) < ASSEMBLY(3) < FAMILY(4) < FAMILY_OR_ASSEMBLY(5) < PUBLIC(6)
        self.bits().cmp(&other.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_access_flags_ordering() {
        // Test the accessibility hierarchy ordering
        assert!(MethodAccessFlags::COMPILER_CONTROLLED < MethodAccessFlags::PRIVATE);
        assert!(MethodAccessFlags::PRIVATE < MethodAccessFlags::FAMILY_AND_ASSEMBLY);
        assert!(MethodAccessFlags::FAMILY_AND_ASSEMBLY < MethodAccessFlags::ASSEMBLY);
        assert!(MethodAccessFlags::ASSEMBLY < MethodAccessFlags::FAMILY);
        assert!(MethodAccessFlags::FAMILY < MethodAccessFlags::FAMILY_OR_ASSEMBLY);
        assert!(MethodAccessFlags::FAMILY_OR_ASSEMBLY < MethodAccessFlags::PUBLIC);

        // Test some specific comparisons useful for method override validation
        assert!(MethodAccessFlags::PUBLIC >= MethodAccessFlags::PRIVATE);
        assert!(MethodAccessFlags::FAMILY >= MethodAccessFlags::PRIVATE);
        assert!(MethodAccessFlags::PRIVATE < MethodAccessFlags::PUBLIC);

        // Test equality
        assert_eq!(MethodAccessFlags::PUBLIC, MethodAccessFlags::PUBLIC);
        assert!(MethodAccessFlags::PUBLIC >= MethodAccessFlags::PUBLIC);
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method virtual table layout flags as defined in ECMA-335 II.23.1.10.
    ///
    /// These flags control how virtual methods are assigned slots in the virtual method table (vtable).
    /// Virtual methods can either reuse an existing slot (for method overrides) or require a new
    /// slot (for new virtual methods or methods with `new` modifier in C#).
    ///
    /// # Virtual Table Mechanics
    ///
    /// In .NET's virtual dispatch system:
    /// - **Method Overrides**: Use [`REUSE_SLOT`](Self::REUSE_SLOT) to replace the base method's implementation
    /// - **Method Hiding**: Use [`NEW_SLOT`](Self::NEW_SLOT) to create a new vtable entry that shadows the base method
    /// - **Interface Methods**: Typically use [`NEW_SLOT`](Self::NEW_SLOT) unless explicitly overriding
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodVtableFlags;
    ///
    /// // Extract from raw method attributes
    /// let override_flags = 0x0000; // Method override (reuses slot)
    /// let vtable = MethodVtableFlags::from_method_flags(override_flags);
    /// assert!(vtable.contains(MethodVtableFlags::REUSE_SLOT));
    ///
    /// let new_method_flags = 0x0100; // New virtual method
    /// let vtable = MethodVtableFlags::from_method_flags(new_method_flags);
    /// assert!(vtable.contains(MethodVtableFlags::NEW_SLOT));
    /// ```
    pub struct MethodVtableFlags: u32 {
        /// Method reuses existing slot in vtable.
        ///
        /// This is the default behavior for method overrides where the method
        /// replaces the implementation of a base class virtual method. The method
        /// uses the same vtable slot as the method it overrides, maintaining
        /// polymorphic behavior.
        const REUSE_SLOT = 0x0000;

        /// Method always gets a new slot in the vtable.
        ///
        /// This flag indicates that the method should receive its own vtable slot
        /// rather than reusing an existing one. This is used for new virtual methods
        /// and methods that hide (rather than override) base class methods.
        const NEW_SLOT = 0x0100;
    }
}

impl MethodVtableFlags {
    /// Extract vtable layout flags from raw method attributes.
    ///
    /// This method applies the [`METHOD_VTABLE_LAYOUT_MASK`] to isolate the vtable layout
    /// bit from a complete MethodAttributes value and converts it to the
    /// appropriate [`crate::metadata::method::MethodVtableFlags`] flags.
    ///
    /// # Arguments
    ///
    /// * `flags` - Raw MethodAttributes value from the metadata table
    ///
    /// # Returns
    ///
    /// The extracted vtable layout flags. If the bit is clear, returns [`REUSE_SLOT`](Self::REUSE_SLOT).
    /// If set, returns [`NEW_SLOT`](Self::NEW_SLOT).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodVtableFlags;
    ///
    /// // Method override (reuses existing vtable slot)
    /// let override_flags = 0x0040; // VIRTUAL without NEW_SLOT
    /// let vtable = MethodVtableFlags::from_method_flags(override_flags);
    /// assert!(vtable.contains(MethodVtableFlags::REUSE_SLOT));
    ///
    /// // New virtual method (gets new vtable slot)
    /// let new_virtual_flags = 0x0140; // VIRTUAL + NEW_SLOT
    /// let vtable = MethodVtableFlags::from_method_flags(new_virtual_flags);
    /// assert!(vtable.contains(MethodVtableFlags::NEW_SLOT));
    /// ```
    #[must_use]
    pub fn from_method_flags(flags: u32) -> Self {
        let vtable = flags & METHOD_VTABLE_LAYOUT_MASK;
        Self::from_bits_truncate(vtable)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method behavior modifiers and properties as defined in ECMA-335 II.23.1.10.
    ///
    /// These flags define various behavioral aspects of methods including inheritance patterns,
    /// security requirements, and special runtime handling. They work in combination with
    /// access flags and vtable flags to fully specify method characteristics.
    ///
    /// # Flag Categories
    ///
    /// ## Inheritance and Overriding
    /// - [`STATIC`](Self::STATIC) - Method belongs to type, not instance
    /// - [`VIRTUAL`](Self::VIRTUAL) - Method supports polymorphic dispatch
    /// - [`ABSTRACT`](Self::ABSTRACT) - Method has no implementation (must be overridden)
    /// - [`FINAL`](Self::FINAL) - Method cannot be overridden in derived classes
    ///
    /// ## Method Resolution
    /// - [`HIDE_BY_SIG`](Self::HIDE_BY_SIG) - Method hiding considers full signature
    /// - [`STRICT`](Self::STRICT) - Override checking considers accessibility
    ///
    /// ## Special Handling
    /// - [`SPECIAL_NAME`](Self::SPECIAL_NAME) - Method has special meaning to tools
    /// - [`RTSPECIAL_NAME`](Self::RTSPECIAL_NAME) - Method has special meaning to runtime
    /// - [`PINVOKE_IMPL`](Self::PINVOKE_IMPL) - Method implemented via P/Invoke
    ///
    /// ## Security
    /// - [`HAS_SECURITY`](Self::HAS_SECURITY) - Method has security attributes
    /// - [`REQUIRE_SEC_OBJECT`](Self::REQUIRE_SEC_OBJECT) - Method requires security context
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodModifiers;
    ///
    /// // Abstract virtual method
    /// let abstract_flags = 0x0440; // VIRTUAL + ABSTRACT
    /// let modifiers = MethodModifiers::from_method_flags(abstract_flags);
    /// assert!(modifiers.contains(MethodModifiers::VIRTUAL));
    /// assert!(modifiers.contains(MethodModifiers::ABSTRACT));
    ///
    /// // Static method with special name
    /// let static_flags = 0x0810; // STATIC + SPECIAL_NAME
    /// let modifiers = MethodModifiers::from_method_flags(static_flags);
    /// assert!(modifiers.contains(MethodModifiers::STATIC));
    /// assert!(modifiers.contains(MethodModifiers::SPECIAL_NAME));
    /// ```
    pub struct MethodModifiers: u32 {
        /// Method is defined on the type rather than per instance.
        ///
        /// Static methods belong to the type itself and do not require an instance
        /// to be called. They cannot access instance members directly and cannot
        /// be virtual, abstract, or final.
        const STATIC = 0x0010;

        /// Method cannot be overridden in derived classes.
        ///
        /// Final methods prevent further overriding in the inheritance chain.
        /// This is equivalent to the `sealed` modifier in C#. Final methods
        /// must also be virtual to have any effect.
        const FINAL = 0x0020;

        /// Method supports polymorphic dispatch through virtual table.
        ///
        /// Virtual methods can be overridden in derived classes and support
        /// runtime polymorphism. The actual method called is determined by
        /// the runtime type of the instance.
        const VIRTUAL = 0x0040;

        /// Method hiding considers full signature, not just name.
        ///
        /// When set, method resolution uses the complete signature (name + parameters)
        /// for hiding decisions. When clear, only the method name is considered.
        /// This affects how methods in derived classes hide base class methods.
        const HIDE_BY_SIG = 0x0080;

        /// Method can only be overridden if it is also accessible.
        ///
        /// This flag enforces that method overrides must have appropriate
        /// accessibility. It prevents overriding methods that would not
        /// normally be accessible in the overriding context.
        const STRICT = 0x0200;

        /// Method does not provide an implementation.
        ///
        /// Abstract methods must be implemented by derived classes. They can
        /// only exist in abstract classes and must also be virtual. The method
        /// has no method body and serves as a contract for derived classes.
        const ABSTRACT = 0x0400;

        /// Method has special meaning to development tools.
        ///
        /// Special name methods include property accessors (get/set), event
        /// handlers (add/remove), operator overloads, and constructors.
        /// Tools may provide special handling for these methods.
        const SPECIAL_NAME = 0x0800;

        /// Runtime provides special behavior based on method name.
        ///
        /// Runtime special methods include constructors (.ctor, .cctor),
        /// finalizers (Finalize), and other methods with intrinsic runtime
        /// behavior. The runtime interprets these methods specially.
        const RTSPECIAL_NAME = 0x1000;

        /// Method implementation is forwarded through Platform Invoke.
        ///
        /// P/Invoke methods call into unmanaged libraries. The method has no
        /// IL implementation and instead forwards calls to native code based
        /// on DllImport attributes and marshalling specifications.
        const PINVOKE_IMPL = 0x2000;

        /// Method has security attributes associated with it.
        ///
        /// Methods with this flag have declarative security attributes that
        /// specify permission requirements or security actions. The security
        /// system checks these attributes before method execution.
        const HAS_SECURITY = 0x4000;

        /// Method calls another method containing security code.
        ///
        /// This flag indicates that the method requires a security object
        /// to be present on the stack, typically for security-critical
        /// operations or when calling security-sensitive methods.
        const REQUIRE_SEC_OBJECT = 0x8000;

        /// Reserved flag for unmanaged export scenarios.
        ///
        /// This flag is reserved by the ECMA-335 specification and should
        /// be zero in conforming implementations. It may be used in future
        /// extensions or for specific runtime scenarios.
        const UNMANAGED_EXPORT = 0x0008;
    }
}

impl MethodModifiers {
    /// Extract method modifier flags from raw method attributes.
    ///
    /// This method removes the access control and vtable layout bits from the raw flags
    /// and converts the remaining bits to [`crate::metadata::method::MethodModifiers`] flags.
    /// This allows extraction of all behavioral modifiers while excluding the basic
    /// access and vtable information.
    ///
    /// # Arguments
    ///
    /// * `flags` - Raw MethodAttributes value from the metadata table
    ///
    /// # Returns
    ///
    /// The extracted method modifier flags, with access and vtable bits masked out
    /// and unknown bits truncated.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodModifiers;
    ///
    /// // Virtual abstract method with special name
    /// let raw_flags = 0x0C46; // PUBLIC + VIRTUAL + ABSTRACT + SPECIAL_NAME
    /// let modifiers = MethodModifiers::from_method_flags(raw_flags);
    /// assert!(modifiers.contains(MethodModifiers::VIRTUAL));
    /// assert!(modifiers.contains(MethodModifiers::ABSTRACT));
    /// assert!(modifiers.contains(MethodModifiers::SPECIAL_NAME));
    /// // Access bits are excluded from the result
    ///
    /// // Static method with P/Invoke
    /// let pinvoke_flags = 0x2016; // PUBLIC + STATIC + PINVOKE_IMPL
    /// let modifiers = MethodModifiers::from_method_flags(pinvoke_flags);
    /// assert!(modifiers.contains(MethodModifiers::STATIC));
    /// assert!(modifiers.contains(MethodModifiers::PINVOKE_IMPL));
    /// ```
    #[must_use]
    pub fn from_method_flags(flags: u32) -> Self {
        let modifiers = flags & !METHOD_ACCESS_MASK & !METHOD_VTABLE_LAYOUT_MASK;
        Self::from_bits_truncate(modifiers)
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method body header flags as defined in ECMA-335 II.25.4.1.
    ///
    /// These flags control the format and behavior of method body headers in the IL stream.
    /// Method bodies can use either tiny or fat header formats, and can have additional
    /// configuration for local variable initialization and exception handling sections.
    ///
    /// # Header Formats
    ///
    /// The .NET runtime supports two method header formats:
    /// - **Tiny Format**: Single-byte header for simple methods (≤63 bytes, no locals, no exceptions)
    /// - **Fat Format**: Multi-byte header for complex methods with full metadata
    ///
    /// # Flag Relationships
    ///
    /// - [`TINY_FORMAT`](Self::TINY_FORMAT) and [`FAT_FORMAT`](Self::FAT_FORMAT) are mutually exclusive format indicators
    /// - [`MORE_SECTS`](Self::MORE_SECTS) is only valid with [`FAT_FORMAT`](Self::FAT_FORMAT)
    /// - [`INIT_LOCALS`](Self::INIT_LOCALS) is only valid with [`FAT_FORMAT`](Self::FAT_FORMAT)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::MethodBodyFlags;
    ///
    /// // Simple method with tiny header
    /// let tiny_flags = 0x02;
    /// let body_flags = MethodBodyFlags::from_bits_truncate(tiny_flags);
    /// assert!(body_flags.contains(MethodBodyFlags::TINY_FORMAT));
    ///
    /// // Complex method with fat header, local initialization, and exception sections
    /// let fat_flags = 0x1B; // FAT_FORMAT + MORE_SECTS + INIT_LOCALS
    /// let body_flags = MethodBodyFlags::from_bits_truncate(fat_flags);
    /// assert!(body_flags.contains(MethodBodyFlags::FAT_FORMAT));
    /// assert!(body_flags.contains(MethodBodyFlags::MORE_SECTS));
    /// assert!(body_flags.contains(MethodBodyFlags::INIT_LOCALS));
    /// ```
    pub struct MethodBodyFlags: u16 {
        /// Method uses tiny header format (single byte).
        ///
        /// Tiny headers are used for simple methods with:
        /// - Code size ≤ 63 bytes
        /// - No local variables
        /// - No exception handling sections
        /// - Maximum evaluation stack depth ≤ 8
        const TINY_FORMAT = 0x2;

        /// Method uses fat header format (12-byte header).
        ///
        /// Fat headers support:
        /// - Code size up to 2^32 bytes
        /// - Local variable signatures
        /// - Exception handling sections
        /// - Arbitrary maximum evaluation stack depth
        /// - Local variable initialization flags
        const FAT_FORMAT = 0x3;

        /// Method header indicates additional data sections follow.
        ///
        /// When set, one or more data sections (typically exception handling tables)
        /// follow the method body. This flag is only valid with fat format headers
        /// and indicates the parser should continue reading section headers.
        const MORE_SECTS = 0x8;

        /// Runtime should zero-initialize all local variables.
        ///
        /// When set, the runtime automatically initializes all local variables
        /// to their default values before method execution begins. This is
        /// equivalent to the C# compiler's behavior and ensures predictable
        /// initial state for local variables.
        const INIT_LOCALS = 0x10;
    }
}

bitflags! {
    #[derive(PartialEq)]
    /// Method body data section flags as defined in ECMA-335 II.25.4.5.
    ///
    /// These flags control the format and content of data sections that can follow method bodies.
    /// Data sections typically contain exception handling tables, but the specification allows
    /// for other types of method-associated data.
    ///
    /// # Section Types
    ///
    /// The most common section type is exception handling tables ([`EHTABLE`](Self::EHTABLE)),
    /// which contain try/catch/finally/fault handlers for the method. Other section types
    /// are reserved for future use.
    ///
    /// # Format Control
    ///
    /// Sections can use either small or fat format headers:
    /// - **Small Format**: Compact representation for simple exception tables
    /// - **Fat Format**: Extended representation for complex exception handling scenarios
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::method::SectionFlags;
    ///
    /// // Simple exception handling section
    /// let eh_flags = 0x01;
    /// let section_flags = SectionFlags::from_bits_truncate(eh_flags);
    /// assert!(section_flags.contains(SectionFlags::EHTABLE));
    ///
    /// // Complex exception section with fat format and continuation
    /// let complex_flags = 0xC1; // EHTABLE + FAT_FORMAT + MORE_SECTS
    /// let section_flags = SectionFlags::from_bits_truncate(complex_flags);
    /// assert!(section_flags.contains(SectionFlags::EHTABLE));
    /// assert!(section_flags.contains(SectionFlags::FAT_FORMAT));
    /// assert!(section_flags.contains(SectionFlags::MORE_SECTS));
    /// ```
    pub struct SectionFlags: u8 {
        /// Section contains exception handling data.
        ///
        /// When set, the section contains exception handling tables that define
        /// try/catch/finally/fault regions for the method. This is the most common
        /// type of data section and contains structured exception handling metadata.
        const EHTABLE = 0x1;

        /// Reserved section type for optional IL tables.
        ///
        /// This flag is reserved by the ECMA-335 specification and shall be zero
        /// in conforming implementations. It may be used in future specification
        /// versions for optional IL-related data structures.
        const OPT_ILTABLE = 0x2;

        /// Section uses fat format for extended capabilities.
        ///
        /// Fat format sections use larger field sizes to support:
        /// - Larger exception handler counts
        /// - Extended offset ranges for large methods
        /// - Additional metadata fields for complex exception scenarios
        /// When clear, the section uses small format with compact representations.
        const FAT_FORMAT = 0x40;

        /// Additional data sections follow this one.
        ///
        /// When set, the parser should continue reading section headers after
        /// processing the current section. This allows methods to have multiple
        /// data sections, though exception handling sections are typically sufficient.
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
