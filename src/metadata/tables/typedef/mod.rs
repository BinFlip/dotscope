//! TypeDef table support for .NET metadata.
//!
//! This module provides comprehensive support for the TypeDef metadata table (ID 0x02), which
//! defines all types (classes, interfaces, value types, enums, delegates) within the current
//! assembly. The TypeDef table is fundamental to the .NET type system and serves as the primary
//! source of type definitions for metadata consumers.
//!
//! ## Table Structure
//!
//! The TypeDef table contains the following columns as specified in ECMA-335:
//! - **Flags** (4-byte bitmask): [`TypeAttributes`] controlling visibility, layout, and semantics
//! - **TypeName** (string heap index): Simple name of the type (without namespace)
//! - **TypeNamespace** (string heap index): Namespace containing the type (empty for global types)
//! - **Extends** (coded index): Base type reference (TypeDef, TypeRef, or TypeSpec)
//! - **FieldList** (Field table index): First field belonging to this type
//! - **MethodList** (MethodDef table index): First method belonging to this type
//!
//! ## Type System Integration
//!
//! TypeDef entries are processed and converted into [`crate::metadata::typesystem::CilType`]
//! instances that provide high-level type system operations:
//! - Type hierarchy navigation and inheritance resolution
//! - Member enumeration (fields, methods, properties, events)
//! - Generic type parameter and constraint handling
//! - Custom attribute association and retrieval
//!
//! ## Member Organization
//!
//! Types own contiguous ranges of fields and methods in their respective tables.
//! The range for each type is determined by comparing its field_list/method_list
//! values with the next type's values:
//! ```text
//! // Type A owns fields [A.field_list .. B.field_list)
//! // Type A owns methods [A.method_list .. B.method_list)
//! ```
//!
//! ## Type Attributes
//!
//! The [`TypeAttributes`] module provides constants for all possible type flags:
//! - **Visibility**: Public, private, nested with various access levels
//! - **Layout**: Auto, sequential, or explicit field layout
//! - **Semantics**: Class vs interface, abstract/sealed modifiers
//! - **Special**: Import, serializable, special name attributes
//! - **Interop**: String format handling for native interoperability
//!
//! ## Module Components
//!
//! - [`TypeDefRaw`] - Raw table entry representation
//! - [`crate::metadata::tables::typedef::loader::TypeDefLoader`] - Table loading functionality  
//! - [`TypeAttributes`] - Type attribute flag constants
//!
//! ## ECMA-335 Reference
//!
//! See ECMA-335, Partition II, Section 22.37 for the complete TypeDef table specification.
//!
//! **Table ID**: `0x02`

mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;

#[allow(non_snake_case)]
/// Type attribute flag constants for TypeDef entries.
///
/// This module provides all the flag constants used in the TypeDef.Flags field
/// to control type visibility, layout, semantics, and interoperability characteristics.
/// The flags are organized into logical groups with corresponding mask constants
/// for efficient bit manipulation.
///
/// ## Visibility Flags
/// Control type accessibility and nested type visibility:
/// - [`TypeAttributes::NOT_PUBLIC`] / [`TypeAttributes::PUBLIC`] - Top-level type visibility
/// - [`TypeAttributes::NESTED_PUBLIC`], [`TypeAttributes::NESTED_PRIVATE`], etc. - Nested type accessibility levels
///
/// ## Layout Flags  
/// Control how type fields are arranged in memory:
/// - [`TypeAttributes::AUTO_LAYOUT`] - Runtime-determined field layout (default)
/// - [`TypeAttributes::SEQUENTIAL_LAYOUT`] - Fields laid out in declaration order
/// - [`TypeAttributes::EXPLICIT_LAYOUT`] - Explicit field offsets specified
///
/// ## Semantic Flags
/// Control type behavior and characteristics:
/// - [`TypeAttributes::CLASS`] / [`TypeAttributes::INTERFACE`] - Type category
/// - [`TypeAttributes::ABSTRACT`] / [`TypeAttributes::SEALED`] - Inheritance modifiers
/// - [`TypeAttributes::SPECIAL_NAME`] / [`TypeAttributes::IMPORT`] / [`TypeAttributes::SERIALIZABLE`] - Special attributes
///
/// ## Interop Flags
/// Control string handling for native interoperability:
/// - [`TypeAttributes::ANSI_CLASS`] / [`TypeAttributes::UNICODE_CLASS`] / [`TypeAttributes::AUTO_CLASS`] - String encoding
/// - [`TypeAttributes::CUSTOM_FORMAT_CLASS`] - Custom string format
pub mod TypeAttributes {
    /// Mask for extracting type visibility information.
    ///
    /// Use this mask with bitwise AND to isolate the 3 visibility bits,
    /// then compare with specific visibility constants.
    pub const VISIBILITY_MASK: u32 = 0x0000_0007;

    /// Type has no public scope (internal to assembly).
    ///
    /// This is the default visibility for top-level types that are not
    /// explicitly declared as public.
    pub const NOT_PUBLIC: u32 = 0x0000_0000;

    /// Type has public scope (visible outside assembly).
    ///
    /// Public types can be accessed from other assemblies and form
    /// part of the assembly's public API surface.
    pub const PUBLIC: u32 = 0x0000_0001;

    /// Nested type with public visibility.
    ///
    /// The nested type is accessible wherever the enclosing type is accessible,
    /// providing unrestricted access within that scope.
    pub const NESTED_PUBLIC: u32 = 0x0000_0002;

    /// Nested type with private visibility.
    ///
    /// The nested type is only accessible within the enclosing type,
    /// providing the most restrictive access level.
    pub const NESTED_PRIVATE: u32 = 0x0000_0003;

    /// Nested type with family (protected) visibility.
    ///
    /// The nested type is accessible within the enclosing type and
    /// types that inherit from the enclosing type.
    pub const NESTED_FAMILY: u32 = 0x0000_0004;

    /// Nested type with assembly (internal) visibility.
    ///
    /// The nested type is accessible within the same assembly as
    /// the enclosing type, but not from other assemblies.
    pub const NESTED_ASSEMBLY: u32 = 0x0000_0005;

    /// Nested type with family AND assembly visibility.
    ///
    /// The nested type is accessible only to derived types within
    /// the same assembly (intersection of family and assembly).
    pub const NESTED_FAM_AND_ASSEM: u32 = 0x0000_0006;

    /// Nested type with family OR assembly visibility.
    ///
    /// The nested type is accessible to derived types OR types within
    /// the same assembly (union of family and assembly).
    pub const NESTED_FAM_OR_ASSEM: u32 = 0x0000_0007;

    /// Mask for extracting class layout information.
    ///
    /// Use this mask with bitwise AND to isolate the 2 layout bits,
    /// then compare with specific layout constants.
    pub const LAYOUT_MASK: u32 = 0x0000_0018;

    /// Class fields are automatically laid out by the runtime.
    ///
    /// The runtime determines the most efficient field arrangement,
    /// which may not match declaration order. This is the default layout.
    pub const AUTO_LAYOUT: u32 = 0x0000_0000;

    /// Class fields are laid out sequentially in declaration order.
    ///
    /// Fields appear in memory in the same order they are declared
    /// in source code, enabling predictable layout for interop scenarios.
    pub const SEQUENTIAL_LAYOUT: u32 = 0x0000_0008;

    /// Field layout is explicitly specified using field offsets.
    ///
    /// Each field's position is explicitly controlled using
    /// [`crate::metadata::tables::FieldLayout`] entries, providing
    /// complete control over type layout.
    pub const EXPLICIT_LAYOUT: u32 = 0x0000_0010;

    /// Mask for extracting class semantics information.
    ///
    /// Use this mask to determine if the type is a class or interface.
    pub const CLASS_SEMANTICS_MASK: u32 = 0x0000_0020;

    /// Type is a class (reference or value type).
    ///
    /// Classes can contain fields, methods, properties, and events.
    /// This includes both reference types and value types (structs).
    pub const CLASS: u32 = 0x0000_0000;

    /// Type is an interface definition.
    ///
    /// Interfaces define contracts with method signatures, properties,
    /// and events, but cannot contain fields or implementation.
    pub const INTERFACE: u32 = 0x0000_0020;

    /// Class is abstract and cannot be instantiated directly.
    ///
    /// Abstract classes may contain abstract methods that must be
    /// implemented by derived classes.
    pub const ABSTRACT: u32 = 0x0000_0080;

    /// Class is sealed and cannot be inherited from.
    ///
    /// Sealed classes represent final implementations that cannot
    /// be extended through inheritance.
    pub const SEALED: u32 = 0x0000_0100;

    /// Class name has special meaning to the runtime.
    ///
    /// Types with special names follow specific naming conventions
    /// and may receive special treatment from the runtime.
    pub const SPECIAL_NAME: u32 = 0x0000_0400;

    /// Class/Interface is imported from external metadata.
    ///
    /// Imported types are defined in other assemblies or modules
    /// and referenced within this assembly.
    pub const IMPORT: u32 = 0x0000_1000;

    /// Type is serializable (legacy attribute).
    ///
    /// This flag indicates the type supports binary serialization.
    /// Modern .NET uses attributes for serialization control.
    pub const SERIALIZABLE: u32 = 0x0000_2000;

    /// Mask for extracting string format information for native interop.
    ///
    /// Use this mask to determine how string parameters are marshaled
    /// when calling native (unmanaged) code.
    pub const STRING_FORMAT_MASK: u32 = 0x0003_0000;

    /// String parameters are marshaled as ANSI (single-byte) strings.
    ///
    /// LPSTR parameters use single-byte character encoding, typically
    /// the system's default ANSI code page.
    pub const ANSI_CLASS: u32 = 0x0000_0000;

    /// String parameters are marshaled as Unicode (UTF-16) strings.
    ///
    /// LPSTR parameters use UTF-16 encoding with 2-byte characters,
    /// which is the native .NET string format.
    pub const UNICODE_CLASS: u32 = 0x0001_0000;

    /// String parameter marshaling is determined automatically.
    ///
    /// The runtime selects ANSI or Unicode marshaling based on the
    /// target platform and API requirements.
    pub const AUTO_CLASS: u32 = 0x0002_0000;

    /// String parameters use a custom marshaling format.
    ///
    /// Custom string marshaling behavior is defined by additional
    /// metadata or runtime-specific handling.
    pub const CUSTOM_FORMAT_CLASS: u32 = 0x0003_0000;

    /// Mask for custom string format encoding information.
    ///
    /// These bits provide additional encoding details when using
    /// [`CUSTOM_FORMAT_CLASS`]. The specific meaning is implementation-defined.
    pub const CUSTOM_STRING_FORMAT_MASK: u32 = 0x00C0_0000;
}
