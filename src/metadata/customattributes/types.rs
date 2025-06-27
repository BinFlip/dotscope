//! Custom attribute types and data structures for .NET metadata parsing.
//!
//! This module provides the complete type system for representing parsed custom attribute data
//! according to ECMA-335 II.23.3 specification. It includes argument values, named arguments,
//! and serialization type constants used throughout the custom attribute parsing pipeline.
//!
//! # Architecture
//!
//! The module implements a hierarchical type system that mirrors the .NET custom attribute
//! specification, providing complete coverage of all supported argument types and structures.
//!
//! ## Core Data Structures
//!
//! - **Value Container**: [`crate::metadata::customattributes::types::CustomAttributeValue`] - Complete attribute representation
//! - **Argument Types**: [`crate::metadata::customattributes::types::CustomAttributeArgument`] - Type-safe value storage
//! - **Named Arguments**: [`crate::metadata::customattributes::types::CustomAttributeNamedArgument`] - Field/property assignments
//! - **Type Constants**: [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] - Binary format constants
//!
//! ## Memory Management
//!
//! Uses efficient reference counting and concurrent collections:
//! - [`crate::metadata::customattributes::types::CustomAttributeValueRc`] - Shared ownership
//! - [`crate::metadata::customattributes::types::CustomAttributeValueList`] - Thread-safe collections
//!
//! # Key Components
//!
//! ## Type Hierarchy Overview
//!
//! ```text
//! CustomAttributeValue
//! ├── fixed_args: Vec<CustomAttributeArgument>
//! └── named_args: Vec<CustomAttributeNamedArgument>
//!     ├── name: String
//!     ├── arg_type: String  
//!     └── value: CustomAttributeArgument
//! ```
//!
//! ## Supported Argument Types
//!
//! - **Primitive Types**: All .NET primitive types (bool, integers, floats, char)
//! - **Reference Types**: String, Type references, multi-dimensional arrays
//! - **Complex Types**: Enum values with type names and underlying values
//! - **Platform Types**: Native integers with platform-dependent sizing
//!
//! # Usage Examples
//!
//! ## Creating Custom Attribute Values
//!
//! ```rust,ignore
//! use dotscope::metadata::customattributes::{
//!     CustomAttributeValue, CustomAttributeArgument, CustomAttributeNamedArgument
//! };
//!
//! // Example: Create a custom attribute value programmatically
//! let custom_attr = CustomAttributeValue {
//!     fixed_args: vec![
//!         CustomAttributeArgument::String("Hello".to_string()),
//!         CustomAttributeArgument::I4(42),
//!     ],
//!     named_args: vec![
//!         CustomAttributeNamedArgument {
//!             is_field: false,  // property
//!             name: "Name".to_string(),
//!             arg_type: "String".to_string(),
//!             value: CustomAttributeArgument::String("Value".to_string()),
//!         }
//!     ],
//! };
//!
//! println!("Custom attribute has {} fixed args", custom_attr.fixed_args.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Working with Different Argument Types
//!
//! ```rust,ignore
//! use dotscope::metadata::customattributes::CustomAttributeArgument;
//!
//! // Different argument types
//! let bool_arg = CustomAttributeArgument::Bool(true);
//! let string_arg = CustomAttributeArgument::String("Hello".to_string());
//! let int_arg = CustomAttributeArgument::I4(42);
//! let array_arg = CustomAttributeArgument::Array(vec![
//!     CustomAttributeArgument::I4(1),
//!     CustomAttributeArgument::I4(2),
//! ]);
//!
//! // Enum with underlying value
//! let enum_arg = CustomAttributeArgument::Enum(
//!     "System.AttributeTargets".to_string(),
//!     Box::new(CustomAttributeArgument::I4(1)),
//! );
//!
//! // Pattern matching on argument types
//! match &string_arg {
//!     CustomAttributeArgument::String(s) => println!("String value: {}", s),
//!     CustomAttributeArgument::I4(i) => println!("Integer value: {}", i),
//!     _ => println!("Other argument type"),
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement [`std::marker::Send`] and [`std::marker::Sync`].
//! The custom attribute value types contain only owned data, and the reference-counted types
//! ([`crate::metadata::customattributes::types::CustomAttributeValueRc`] and
//! [`crate::metadata::customattributes::types::CustomAttributeValueList`]) provide safe concurrent access.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customattributes::parser`] - Parsing implementation using these types
//! - [`crate::metadata::typesystem`] - Type system integration for `CilFlavor` mapping
//! - [`crate::metadata::tables`] - Metadata table storage and retrieval
//! - [`crate::metadata::streams`] - Blob and string heap access
//!
//! # Binary Format Compatibility
//!
//! The types directly correspond to the .NET runtime's internal representation:
//! - **Fixed arguments** parsed using constructor parameter types
//! - **Named arguments** parsed using embedded [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] tags
//! - **Values** stored in little-endian binary format as per ECMA-335
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with custom attribute specification (II.23.3)
//! - **Type Safety**: Strongly typed argument values prevent runtime errors
//! - **Memory Efficiency**: Reference counting and concurrent collections minimize overhead
//! - **.NET Compatibility**: Direct mapping to runtime `CorSerializationType` enumeration

use std::sync::Arc;

/// A reference-counted pointer to a [`CustomAttributeValue`] for efficient sharing.
///
/// Enables safe sharing of custom attribute data across multiple metadata consumers
/// without copying or blocking. Used throughout the metadata subsystem for
/// attaching custom attributes to types, methods, fields, and other metadata elements.
pub type CustomAttributeValueRc = Arc<CustomAttributeValue>;

/// A concurrent vector storing multiple [`CustomAttributeValueRc`] instances.
///
/// Provides thread-safe storage for custom attribute collections on metadata objects.
/// Uses [`boxcar::Vec`] for lock-free concurrent access and [`Arc`] for reference counting,
/// enabling efficient metadata processing in multi-threaded scenarios.
pub type CustomAttributeValueList = Arc<boxcar::Vec<CustomAttributeValueRc>>;

/// Represents a complete parsed custom attribute with fixed and named arguments.
///
/// This is the top-level structure for custom attribute data parsed from .NET metadata.
/// It contains both constructor arguments (`fixed_args`) and field/property assignments
/// (`named_args`) as specified in ECMA-335 II.23.3.
///
/// # Structure
/// - **Fixed Arguments**: Parsed using constructor method parameter types, appear in declaration order
/// - **Named Arguments**: Field/property assignments with embedded type information
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::customattributes::{CustomAttributeValue, CustomAttributeArgument};
///
/// let custom_attr = CustomAttributeValue {
///     fixed_args: vec![
///         CustomAttributeArgument::String("Debug".to_string()),
///         CustomAttributeArgument::Bool(true),
///     ],
///     named_args: vec![], // No named arguments in this example
/// };
///
/// // Access constructor arguments
/// if let CustomAttributeArgument::String(name) = &custom_attr.fixed_args[0] {
///     println!("Attribute name: {}", name);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`CustomAttributeValue`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone)]
pub struct CustomAttributeValue {
    /// Fixed arguments from the constructor signature, parsed using parameter type information
    pub fixed_args: Vec<CustomAttributeArgument>,
    /// Named arguments (fields and properties) with embedded type tags
    pub named_args: Vec<CustomAttributeNamedArgument>,
}

/// Represents a single custom attribute argument value with full .NET type support.
///
/// This enum covers all argument types supported by the .NET custom attribute system
/// according to ECMA-335. Each variant corresponds to a specific [`crate::metadata::typesystem::CilFlavor`]
/// or [`SERIALIZATION_TYPE`] in the binary format.
///
/// # Type Categories
///
/// **Primitive Types**: Bool, Char, I1-I8, U1-U8, R4, R8, I, U
/// **Reference Types**: String, Type, Array
/// **Complex Types**: Enum (with type name + underlying value)
/// **Special**: Void (for completeness)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::customattributes::CustomAttributeArgument;
///
/// // Different argument types
/// let bool_arg = CustomAttributeArgument::Bool(true);
/// let string_arg = CustomAttributeArgument::String("Hello".to_string());
/// let int_arg = CustomAttributeArgument::I4(42);
/// let array_arg = CustomAttributeArgument::Array(vec![
///     CustomAttributeArgument::I4(1),
///     CustomAttributeArgument::I4(2),
/// ]);
///
/// // Enum with underlying value
/// let enum_arg = CustomAttributeArgument::Enum(
///     "System.AttributeTargets".to_string(),
///     Box::new(CustomAttributeArgument::I4(1)),
/// );
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`CustomAttributeArgument`] is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
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

/// Represents a named argument (field or property assignment) in a custom attribute.
///
/// Named arguments appear after fixed arguments in the custom attribute binary format.
/// They contain explicit type information via [`SERIALIZATION_TYPE`] tags, allowing
/// the parser to handle them without external type resolution.
///
/// # Format in Binary
/// 1. Field/Property indicator: 0x53 (FIELD) or 0x54 (PROPERTY)
/// 2. Type tag: [`SERIALIZATION_TYPE`] enumeration value
/// 3. Name: Compressed length + UTF-8 string
/// 4. Value: Type-specific binary data
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::customattributes::{CustomAttributeNamedArgument, CustomAttributeArgument};
///
/// // Property assignment
/// let named_arg = CustomAttributeNamedArgument {
///     is_field: false,  // This is a property
///     name: "Name".to_string(),
///     arg_type: "String".to_string(),
///     value: CustomAttributeArgument::String("MyName".to_string()),
/// };
///
/// println!("Setting {} property '{}' to {:?}",
///          if named_arg.is_field { "field" } else { "property" },
///          named_arg.name, named_arg.value);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`CustomAttributeNamedArgument`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
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

/// .NET `CorSerializationType` enumeration constants from the runtime.
///
/// These constants define the binary format for custom attribute argument types
/// as specified in ECMA-335 and implemented in the .NET runtime. They are used
/// in named argument type tags to enable self-describing argument parsing.
///
/// # Usage
///
/// Used by the custom attribute parser to parse named arguments that contain
/// explicit type information in their binary representation.
///
/// # References
///
/// - ECMA-335 II.23.3 `CustomAttribute` specification
/// - .NET Runtime corhdr.h `CorSerializationType` enumeration
/// - CLI Standard Partition II Metadata definition
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::customattributes::SERIALIZATION_TYPE;
///
/// // Check type tags during parsing
/// let type_tag = SERIALIZATION_TYPE::STRING;
/// match type_tag {
///     SERIALIZATION_TYPE::STRING => println!("String type"),
///     SERIALIZATION_TYPE::I4 => println!("I4 type"),
///     SERIALIZATION_TYPE::ENUM => println!("Enum type"),
///     _ => println!("Other type"),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[allow(non_snake_case)]
pub mod SERIALIZATION_TYPE {
    /// Boolean type (System.Boolean) - stored as single byte (0 = false, non-zero = true)
    pub const BOOLEAN: u8 = 0x02;
    /// Character type (System.Char) - stored as 16-bit Unicode value
    pub const CHAR: u8 = 0x03;
    /// Signed 8-bit integer (System.SByte)
    pub const I1: u8 = 0x04;
    /// Unsigned 8-bit integer (System.Byte)
    pub const U1: u8 = 0x05;
    /// Signed 16-bit integer (System.Int16)
    pub const I2: u8 = 0x06;
    /// Unsigned 16-bit integer (System.UInt16)
    pub const U2: u8 = 0x07;
    /// Signed 32-bit integer (System.Int32)
    pub const I4: u8 = 0x08;
    /// Unsigned 32-bit integer (System.UInt32)
    pub const U4: u8 = 0x09;
    /// Signed 64-bit integer (System.Int64)
    pub const I8: u8 = 0x0A;
    /// Unsigned 64-bit integer (System.UInt64)
    pub const U8: u8 = 0x0B;
    /// 32-bit floating point (System.Single)
    pub const R4: u8 = 0x0C;
    /// 64-bit floating point (System.Double)
    pub const R8: u8 = 0x0D;
    /// String type (System.String) - compressed length + UTF-8 data
    pub const STRING: u8 = 0x0E;
    /// Type reference (System.Type) - stored as string containing type name
    pub const TYPE: u8 = 0x50;
    /// Tagged object - followed by another type tag for the actual value
    pub const TAGGED_OBJECT: u8 = 0x51;
    /// Enum type - type name string followed by underlying value (usually I4)
    pub const ENUM: u8 = 0x55;
    /// Single-dimensional array - element type tag + length + elements
    pub const SZARRAY: u8 = 0x1D;
}
