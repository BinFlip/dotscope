//! CustomAttribute-specific types and data structures.
//!
//! This module contains all the types used for representing parsed custom attribute data,
//! including argument values, named arguments, and the overall custom attribute value structure.
//! These types are designed to be self-contained and follow ECMA-335 II.23.3 specification.

use std::sync::Arc;

/// A reference-counted pointer to a `CustomAttributeValue`
pub type CustomAttributeValueRc = Arc<CustomAttributeValue>;
/// A vector that holds a list of `CustomAttributeValue` instances for storage on parent objects
pub type CustomAttributeValueList = Arc<boxcar::Vec<CustomAttributeValueRc>>;

/// Represents a parsed custom attribute value with arguments and named arguments
#[derive(Debug, Clone)]
pub struct CustomAttributeValue {
    /// Fixed arguments from the constructor signature  
    pub fixed_args: Vec<CustomAttributeArgument>,
    /// Named arguments (fields and properties)
    pub named_args: Vec<CustomAttributeNamedArgument>,
}

/// Represents a single custom attribute argument value
#[derive(Debug, Clone)]
pub enum CustomAttributeArgument {
    /// Void type (for completeness, rarely used in custom attributes)
    Void,
    /// Boolean value
    Bool(bool),
    /// Character value (16-bit Unicode)
    Char(char),
    /// Signed 8-bit integer
    I1(i8),
    /// Unsigned 8-bit integer  
    U1(u8),
    /// Signed 16-bit integer
    I2(i16),
    /// Unsigned 16-bit integer
    U2(u16),
    /// Signed 32-bit integer
    I4(i32),
    /// Unsigned 32-bit integer
    U4(u32),
    /// Signed 64-bit integer
    I8(i64),
    /// Unsigned 64-bit integer
    U8(u64),
    /// 32-bit floating point
    R4(f32),
    /// 64-bit floating point
    R8(f64),
    /// Native signed integer (platform-dependent size)
    I(isize),
    /// Native unsigned integer (platform-dependent size)
    U(usize),
    /// UTF-8 string
    String(String),
    /// Type reference (as string)
    Type(String),
    /// Array of arguments
    Array(Vec<CustomAttributeArgument>),
    /// Enum value (base type + value)
    Enum(String, Box<CustomAttributeArgument>),
}

/// Represents a named argument (field or property) in a custom attribute
#[derive(Debug, Clone)]
pub struct CustomAttributeNamedArgument {
    /// Whether this is a field (true) or property (false)
    pub is_field: bool,
    /// Name of the field or property
    pub name: String,
    /// Type of the argument
    pub arg_type: String,
    /// Value of the argument
    pub value: CustomAttributeArgument,
}

/// .NET `CorSerializationType` constants as defined in corhdr.h
#[allow(non_snake_case, missing_docs)]
pub mod SERIALIZATION_TYPE {
    pub const BOOLEAN: u8 = 0x02;
    pub const CHAR: u8 = 0x03;
    pub const I1: u8 = 0x04;
    pub const U1: u8 = 0x05;
    pub const I2: u8 = 0x06;
    pub const U2: u8 = 0x07;
    pub const I4: u8 = 0x08;
    pub const U4: u8 = 0x09;
    pub const I8: u8 = 0x0A;
    pub const U8: u8 = 0x0B;
    pub const R4: u8 = 0x0C;
    pub const R8: u8 = 0x0D;
    pub const STRING: u8 = 0x0E;
    pub const TYPE: u8 = 0x50;
    pub const TAGGED_OBJECT: u8 = 0x51;
    pub const ENUM: u8 = 0x55;
    pub const SZARRAY: u8 = 0x1D;
}
