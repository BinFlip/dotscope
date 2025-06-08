//! Method type flags, attributes, and supporting types for .NET CIL methods.
//!
//! This module defines all bitflags, constants, and supporting types used to represent and extract
//! method implementation flags, attributes, vtable layout, and local variable/vararg information for CIL methods.
//!
//! # Key Types
//! - [`MethodImplCodeType`], [`MethodImplManagement`], [`MethodImplOptions`]: Implementation flags
//! - [`MethodAccessFlags`], [`MethodVtableFlags`], [`MethodModifiers`]: Attribute flags
//! - [`MethodBodyFlags`], [`SectionFlags`]: Method body and section flags
//! - [`LocalVariable`], [`VarArg`]: Local variable and vararg parameter representations

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

/// Represents a local variable in a method. Similar to `SignatureLocalVariable`, but with resolved indexes and owned data.
pub struct LocalVariable {
    /// Custom modifiers
    pub modifiers: CilTypeRefList,
    /// Is passed by reference
    pub is_byref: bool,
    /// This variable is pinned
    pub is_pinned: bool,
    /// The signature of this variable
    pub base: CilTypeRef,
}

/// Variable Argument used in `SignatureMethod` to describe vararg parameters of `Method`
pub struct VarArg {
    /// Custom modifiers of the parameter
    pub modifiers: CilTypeRefList,
    /// Parameter is passed by reference
    pub by_ref: bool,
    /// The type of the parameter
    pub base: CilTypeRef,
}
