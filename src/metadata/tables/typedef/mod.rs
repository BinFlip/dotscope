//! `TypeDef` table support for .NET metadata.
//!
//! The `TypeDef` table defines types (classes, interfaces, value types, enums) in the current module.
//! Each row represents a type definition with its attributes, name, namespace, base type, and
//! ranges indicating which fields and methods belong to this type.
//!
//! ## ECMA-335 Specification
//! From ECMA-335, Partition II, Section 22.37:
//! > The TypeDef table has the following columns:
//! > - Flags (a 4-byte bitmask of type TypeAttributes)
//! > - TypeName (an index into the String heap)
//! > - TypeNamespace (an index into the String heap)
//! > - Extends (an index into the TypeDef, TypeRef, or TypeSpec table)
//! > - FieldList (an index into the Field table)
//! > - MethodList (an index into the MethodDef table)

mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;

#[allow(non_snake_case)]
/// All possible flags for `TypeAttributes`
pub mod TypeAttributes {
    /// Use this mask to retrieve visibility information. These 3 bits contain one of the following values:
    pub const VISIBILITY_MASK: u32 = 0x0000_0007;
    /// Class has no public scope
    pub const NOT_PUBLIC: u32 = 0x0000_0000;
    /// Class has public scope
    pub const PUBLIC: u32 = 0x0000_0001;
    /// Class is nested with public visibility
    pub const NESTED_PUBLIC: u32 = 0x0000_0002;
    /// Class is nested with private visibility
    pub const NESTED_PRIVATE: u32 = 0x0000_0003;
    /// Class is nested with family visibility
    pub const NESTED_FAMILY: u32 = 0x0000_0004;
    /// Class is nested with assembly visibility
    pub const NESTED_ASSEMBLY: u32 = 0x0000_0005;
    /// Class is nested with family and assembly visibility
    pub const NESTED_FAM_AND_ASSEM: u32 = 0x0000_0006;
    /// Class is nested with family or assemblyvisibility
    pub const NESTED_FAM_OR_ASSEM: u32 = 0x0000_0007;
    //
    /// Use this mask to retrieve class layout information. These 2 bits contain one of the following values:
    pub const LAYOUT_MASK: u32 = 0x0000_0018;
    /// Class fields are auto-laid out
    pub const AUTO_LAYOUT: u32 = 0x0000_0000;
    /// Class fields are laid out sequentially
    pub const SEQUENTIAL_LAYOUT: u32 = 0x0000_0008;
    /// Layout is supplied explicitly
    pub const EXPLICIT_LAYOUT: u32 = 0x0000_0010;
    //
    /// Use this mask to retrive class semantics information. This bit contains one of the following values:
    pub const CLASS_SEMANTICS_MASK: u32 = 0x0000_0020;
    /// Type is a class
    pub const CLASS: u32 = 0x0000_0000;
    /// Type is an interface
    pub const INTERFACE: u32 = 0x0000_0020;
    /// Class is abstract
    pub const ABSTRACT: u32 = 0x0000_0080;
    /// Class cannot be extended
    pub const SEALED: u32 = 0x0000_0100;
    /// Class name is special
    pub const SPECIAL_NAME: u32 = 0x0000_0400;
    /// Class/Interface is imported
    pub const IMPORT: u32 = 0x0000_1000;
    /// Reserved (Class is serializable)
    pub const SERIALIZABLE: u32 = 0x0000_2000;
    //
    /// Use this mask to retrieve string information for native interop. These 2 bits contain one of the following values:
    pub const STRING_FORMAT_MASK: u32 = 0x0003_0000;
    /// LPSTR is interpreted as ANSI
    pub const ANSI_CLASS: u32 = 0x0000_0000;
    /// LPSTR is interpreted as Unicode
    pub const UNICODE_CLASS: u32 = 0x0001_0000;
    /// LPSTR is interpreted automatically
    pub const AUTO_CLASS: u32 = 0x0002_0000;
    /// A non-standard encoding specified by
    pub const CUSTOM_FORMAT_CLASS: u32 = 0x0003_0000;
    //
    /// Use this mask to retrieve non-standard encoding information for native interop. The meaning of the values of these 2 bits is unspecified.
    pub const CUSTOM_STRING_FORMAT_MASK: u32 = 0x00C0_0000;
}
