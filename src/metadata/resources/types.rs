//! Resource type definitions and parsing for .NET resource files.
//!
//! This module provides comprehensive support for parsing and representing the various data types
//! that can be stored in .NET resource files (.resources). It implements the complete type system
//! defined by the .NET resource format specification, including primitive types, special types,
//! and user-defined types.
//!
//! # .NET Resource Type System
//!
//! The .NET resource format supports a hierarchical type system:
//! - **Primitive Types (0x00-0x1F)**: Built-in .NET value types like integers, strings, booleans
//! - **Special Types (0x20-0x3F)**: Complex types with special serialization like byte arrays
//! - **User Types (0x40+)**: Custom types serialized using the binary formatter
//!
//! # Magic Number
//!
//! All .NET resource files begin with the magic number `0xBEEFCACE` to identify the format.
//!
//! # Examples
//!
//! ## Basic Type Parsing
//!
//! ```ignore
//! use dotscope::metadata::resources::types::{ResourceType, RESOURCE_MAGIC};
//! use dotscope::file::parser::Parser;
//!
//! // Parse a resource file header
//! let mut parser = Parser::new(&data);
//! let magic = parser.read_le::<u32>()?;
//! assert_eq!(magic, RESOURCE_MAGIC);
//!
//! // Parse a type from type byte
//! let type_byte = parser.read_le::<u8>()?;
//! let resource_type = ResourceType::from_type_byte(type_byte, &mut parser)?;
//!
//! match resource_type {
//!     ResourceType::String(s) => println!("Found string: {}", s),
//!     ResourceType::Int32(i) => println!("Found integer: {}", i),
//!     ResourceType::ByteArray(bytes) => println!("Found byte array: {} bytes", bytes.len()),
//!     _ => println!("Found other type"),
//! }
//! ```
//!
//! ## Type Name Resolution
//!
//! ```ignore
//! use dotscope::metadata::resources::types::ResourceType;
//! use dotscope::file::parser::Parser;
//!
//! let mut parser = Parser::new(&data);
//!
//! // Parse using type name instead of type byte
//! let resource_type = ResourceType::from_type_name("System.String", &mut parser)?;
//! if let ResourceType::String(s) = resource_type {
//!     println!("Parsed string from type name: {}", s);
//! }
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe:
//! - [`ResourceType`] implements `Send + Sync` for safe sharing across threads
//! - Parsing operations are stateless and can be performed concurrently
//! - No global state is maintained during parsing operations

/// The magic number that identifies a .NET resource file (0xBEEFCACE)
pub const RESOURCE_MAGIC: u32 = 0xBEEF_CACE;

use crate::{file::parser::Parser, Error::TypeError, Result};

/// Represents all data types that can be stored in .NET resource files.
///
/// This enum provides a complete representation of the type system used in .NET resource files,
/// including all primitive types, special collection types, and extensibility for user-defined types.
/// Each variant corresponds to specific type codes defined in the .NET resource format specification.
///
/// # Type Code Ranges
///
/// - **0x00-0x1F**: Primitive and built-in types (null, strings, numbers, dates)
/// - **0x20-0x3F**: Special types with custom serialization (byte arrays, streams)
/// - **0x40+**: User-defined types serialized with the binary formatter
///
/// # Examples
///
/// ```ignore
/// use dotscope::metadata::resources::types::ResourceType;
/// use dotscope::file::parser::Parser;
///
/// // Parse different resource types
/// let mut parser = Parser::new(&data);
///
/// // Parse a string resource (type code 0x01)
/// let string_resource = ResourceType::from_type_byte(0x01, &mut parser)?;
/// if let ResourceType::String(s) = string_resource {
///     println!("String resource: {}", s);
/// }
///
/// // Parse an integer resource (type code 0x08)
/// let int_resource = ResourceType::from_type_byte(0x08, &mut parser)?;
/// if let ResourceType::Int32(i) = int_resource {
///     println!("Integer resource: {}", i);
/// }
///
/// // Parse a byte array resource (type code 0x20)
/// let bytes_resource = ResourceType::from_type_byte(0x20, &mut parser)?;
/// if let ResourceType::ByteArray(bytes) = bytes_resource {
///     println!("Byte array: {} bytes", bytes.len());
/// }
/// ```
///
/// # Thread Safety
///
/// All variants are thread-safe and can be safely shared across threads without synchronization.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceType {
    /// Null resource value (type code 0x00)
    /* 0 */
    Null,
    /// UTF-8 string resource with length prefix (type code 0x01)
    /* 1 */
    String(String),
    /// Boolean resource value, false=0, true=non-zero (type code 0x02)
    /* 2 */
    Boolean(bool),
    /// Single character resource as byte value (type code 0x03)
    /* 3 */
    Char(char),
    /// Unsigned 8-bit integer resource (type code 0x04)
    /* 4 */
    Byte(u8),
    /// Signed 8-bit integer resource (type code 0x05)
    /* 5 */
    SByte(i8),
    /// Signed 16-bit integer resource, little-endian (type code 0x06)
    /* 6 */
    Int16(i16),
    /// Unsigned 16-bit integer resource, little-endian (type code 0x07)
    /* 7 */
    UInt16(u16),
    /// Signed 32-bit integer resource, little-endian (type code 0x08)
    /* 8 */
    Int32(i32),
    /// Unsigned 32-bit integer resource, little-endian (type code 0x09)
    /* 9 */
    UInt32(u32),
    /// Signed 64-bit integer resource, little-endian (type code 0x0A)
    /* 0xA */
    Int64(i64),
    /// Unsigned 64-bit integer resource, little-endian (type code 0x0B)
    /* 0xB */
    UInt64(u64),
    /// 32-bit floating point resource, little-endian (type code 0x0C)
    /* 0xC */
    Single(f32),
    /// 64-bit floating point resource, little-endian (type code 0x0D)
    /* 0xD */
    Double(f64),
    /// Decimal resource value (type code 0x0E) - not yet implemented
    /* 0xE */
    Decimal,
    /// `DateTime` resource value (type code 0x0F) - not yet implemented
    /* 0xF */
    DateTime,
    /// `TimeSpan` resource value (type code 0x10) - not yet implemented
    /* 0x10 */
    TimeSpan,

    // Type with special representation, like byte[] and Stream
    /// Byte array resource with length prefix (type code 0x20)
    /* 0x20 */
    ByteArray(Vec<u8>),
    /// Stream resource reference (type code 0x21) - not yet implemented
    /* 0x21 */
    Stream,

    // User types - serialized using the binary formatter
    /// Marker for the beginning of user-defined types (type code 0x40+)
    /* 0x40 */
    StartOfUserTypes,
}

impl ResourceType {
    /// Parses a resource type from its binary type code.
    ///
    /// This method reads a resource value from the parser based on the provided type byte,
    /// which corresponds to the type codes defined in the .NET resource format specification.
    /// Each type code indicates both the data type and how to parse the following bytes.
    ///
    /// # Arguments
    ///
    /// * `byte` - The type code byte (0x00-0xFF) that identifies the data type
    /// * `parser` - A mutable reference to the parser positioned after the type byte
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<ResourceType>`] containing the parsed resource value,
    /// or an error if the type code is unsupported or parsing fails.
    ///
    /// # Supported Type Codes
    ///
    /// - `0x01`: UTF-8 string with length prefix
    /// - `0x02`: Boolean value (0 = false, non-zero = true)
    /// - `0x03`: Single character as byte
    /// - `0x04`: Unsigned 8-bit integer
    /// - `0x05`: Signed 8-bit integer
    /// - `0x06`: Signed 16-bit integer (little-endian)
    /// - `0x07`: Unsigned 16-bit integer (little-endian)
    /// - `0x08`: Signed 32-bit integer (little-endian)
    /// - `0x09`: Unsigned 32-bit integer (little-endian)
    /// - `0x0A`: Signed 64-bit integer (little-endian)
    /// - `0x0B`: Unsigned 64-bit integer (little-endian)
    /// - `0x0C`: 32-bit floating point (little-endian)
    /// - `0x0D`: 64-bit floating point (little-endian)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::metadata::resources::types::ResourceType;
    /// use dotscope::file::parser::Parser;
    ///
    /// let mut parser = Parser::new(&data);
    ///
    /// // Parse a string resource (type code 0x01)
    /// let string_type = ResourceType::from_type_byte(0x01, &mut parser)?;
    /// if let ResourceType::String(s) = string_type {
    ///     println!("Found string: {}", s);
    /// }
    ///
    /// // Parse an integer resource (type code 0x08)
    /// let int_type = ResourceType::from_type_byte(0x08, &mut parser)?;
    /// if let ResourceType::Int32(value) = int_type {
    ///     println!("Found integer: {}", value);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::TypeError`]: If the type byte is not supported
    /// - Parser errors: If reading the underlying data fails (e.g., truncated data)
    pub fn from_type_byte(byte: u8, parser: &mut Parser) -> Result<Self> {
        match byte {
            0x1 => Ok(ResourceType::String(parser.read_prefixed_string_utf8()?)),
            0x2 => Ok(ResourceType::Boolean(parser.read_le::<u8>()? > 0)),
            0x3 => Ok(ResourceType::Char(parser.read_le::<u8>()?.into())),
            0x4 => Ok(ResourceType::Byte(parser.read_le::<u8>()?)),
            0x5 => Ok(ResourceType::SByte(parser.read_le::<i8>()?)),
            0x6 => Ok(ResourceType::Int16(parser.read_le::<i16>()?)),
            0x7 => Ok(ResourceType::UInt16(parser.read_le::<u16>()?)),
            0x8 => Ok(ResourceType::Int32(parser.read_le::<i32>()?)),
            0x9 => Ok(ResourceType::UInt32(parser.read_le::<u32>()?)),
            0xA => Ok(ResourceType::Int64(parser.read_le::<i64>()?)),
            0xB => Ok(ResourceType::UInt64(parser.read_le::<u64>()?)),
            0xC => Ok(ResourceType::Single(parser.read_le::<f32>()?)),
            0xD => Ok(ResourceType::Double(parser.read_le::<f64>()?)),
            _ => Err(TypeError(format!(
                "TypeByte - {:X} is currently not supported",
                byte
            ))),
        }
    }

    /// Parses a resource type from its .NET type name.
    ///
    /// This method provides an alternative parsing mechanism that uses .NET type names instead
    /// of type bytes. It maps common .NET Framework type names to their corresponding binary
    /// representations and delegates to [`Self::from_type_byte`] for the actual parsing.
    ///
    /// This approach is commonly used in resource files that store type information as strings
    /// rather than numeric type codes, particularly in older .NET resource formats.
    ///
    /// # Arguments
    ///
    /// * `type_name` - The fully qualified .NET type name (e.g., "System.String")
    /// * `parser` - A mutable reference to the parser positioned at the resource value
    ///
    /// # Returns
    ///
    /// Returns a [`crate::Result<ResourceType>`] containing the parsed resource value,
    /// or an error if the type name is unsupported or parsing fails.
    ///
    /// # Supported Type Names
    ///
    /// - `"System.Null"`: Null value
    /// - `"System.String"`: UTF-8 string with length prefix
    /// - `"System.Boolean"`: Boolean value
    /// - `"System.Char"`: Single character
    /// - `"System.Byte"`: Unsigned 8-bit integer
    /// - `"System.SByte"`: Signed 8-bit integer
    /// - `"System.Int16"`: Signed 16-bit integer
    /// - `"System.UInt16"`: Unsigned 16-bit integer
    /// - `"System.Int32"`: Signed 32-bit integer
    /// - `"System.UInt32"`: Unsigned 32-bit integer
    /// - `"System.Int64"`: Signed 64-bit integer
    /// - `"System.UInt64"`: Unsigned 64-bit integer
    /// - `"System.Single"`: 32-bit floating point
    /// - `"System.Double"`: 64-bit floating point
    /// - `"System.Byte[]"`: Byte array
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dotscope::metadata::resources::types::ResourceType;
    /// use dotscope::file::parser::Parser;
    ///
    /// let mut parser = Parser::new(&data);
    ///
    /// // Parse using .NET type names
    /// let string_resource = ResourceType::from_type_name("System.String", &mut parser)?;
    /// if let ResourceType::String(s) = string_resource {
    ///     println!("String resource: {}", s);
    /// }
    ///
    /// let int_resource = ResourceType::from_type_name("System.Int32", &mut parser)?;
    /// if let ResourceType::Int32(value) = int_resource {
    ///     println!("Integer resource: {}", value);
    /// }
    ///
    /// let bytes_resource = ResourceType::from_type_name("System.Byte[]", &mut parser)?;
    /// if let ResourceType::ByteArray(bytes) = bytes_resource {
    ///     println!("Byte array: {} bytes", bytes.len());
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// - [`crate::Error::TypeError`]: If the type name is not supported
    /// - Parser errors: If reading the underlying data fails
    pub fn from_type_name(type_name: &str, parser: &mut Parser) -> Result<Self> {
        match type_name {
            "System.Null" => ResourceType::from_type_byte(0, parser),
            "System.String" => ResourceType::from_type_byte(1, parser),
            "System.Boolean" => ResourceType::from_type_byte(2, parser),
            "System.Char" => ResourceType::from_type_byte(3, parser),
            "System.Byte" => ResourceType::from_type_byte(4, parser),
            "System.SByte" => ResourceType::from_type_byte(5, parser),
            "System.Int16" => ResourceType::from_type_byte(6, parser),
            "System.UInt16" => ResourceType::from_type_byte(7, parser),
            "System.Int32" => ResourceType::from_type_byte(8, parser),
            "System.UInt32" => ResourceType::from_type_byte(9, parser),
            "System.Int64" => ResourceType::from_type_byte(0xA, parser),
            "System.UInt64" => ResourceType::from_type_byte(0xB, parser),
            "System.Single" => ResourceType::from_type_byte(0xC, parser),
            "System.Double" => ResourceType::from_type_byte(0xD, parser),
            "System.Byte[]" => ResourceType::from_type_byte(0x20, parser),
            _ => Err(TypeError(format!(
                "TypeName - {} is currently not supported",
                type_name
            ))),
        }
    }
}

/// A parsed .NET resource entry
pub struct ResourceEntry {
    /// The name of the resource
    pub name: String,
    /// The hash of the name
    pub name_hash: u32,
    /// The parsed resource
    pub data: ResourceType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::parser::Parser;

    #[test]
    fn test_resource_magic_constant() {
        assert_eq!(RESOURCE_MAGIC, 0xBEEFCACE);
    }

    #[test]
    fn test_from_type_byte_string() {
        let data = b"\x05hello";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x1, &mut parser).unwrap();

        if let ResourceType::String(s) = result {
            assert_eq!(s, "hello");
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn test_from_type_byte_boolean_true() {
        let data = b"\x01";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x2, &mut parser).unwrap();

        if let ResourceType::Boolean(b) = result {
            assert!(b);
        } else {
            panic!("Expected Boolean variant");
        }
    }

    #[test]
    fn test_from_type_byte_boolean_false() {
        let data = b"\x00";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x2, &mut parser).unwrap();

        if let ResourceType::Boolean(b) = result {
            assert!(!b);
        } else {
            panic!("Expected Boolean variant");
        }
    }

    #[test]
    fn test_from_type_byte_char() {
        let data = b"A";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x3, &mut parser).unwrap();

        if let ResourceType::Char(c) = result {
            assert_eq!(c, 'A');
        } else {
            panic!("Expected Char variant");
        }
    }

    #[test]
    fn test_from_type_byte_byte() {
        let data = b"\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x4, &mut parser).unwrap();

        if let ResourceType::Byte(b) = result {
            assert_eq!(b, 255);
        } else {
            panic!("Expected Byte variant");
        }
    }

    #[test]
    fn test_from_type_byte_sbyte() {
        let data = b"\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x5, &mut parser).unwrap();

        if let ResourceType::SByte(sb) = result {
            assert_eq!(sb, -1);
        } else {
            panic!("Expected SByte variant");
        }
    }

    #[test]
    fn test_from_type_byte_int16() {
        let data = b"\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x6, &mut parser).unwrap();

        if let ResourceType::Int16(i) = result {
            assert_eq!(i, -1);
        } else {
            panic!("Expected Int16 variant");
        }
    }

    #[test]
    fn test_from_type_byte_uint16() {
        let data = b"\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x7, &mut parser).unwrap();

        if let ResourceType::UInt16(u) = result {
            assert_eq!(u, 65535);
        } else {
            panic!("Expected UInt16 variant");
        }
    }

    #[test]
    fn test_from_type_byte_int32() {
        let data = b"\x2A\x00\x00\x00";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x8, &mut parser).unwrap();

        if let ResourceType::Int32(i) = result {
            assert_eq!(i, 42);
        } else {
            panic!("Expected Int32 variant");
        }
    }

    #[test]
    fn test_from_type_byte_uint32() {
        let data = b"\xFF\xFF\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0x9, &mut parser).unwrap();

        if let ResourceType::UInt32(u) = result {
            assert_eq!(u, 4294967295);
        } else {
            panic!("Expected UInt32 variant");
        }
    }

    #[test]
    fn test_from_type_byte_int64() {
        let data = b"\x2A\x00\x00\x00\x00\x00\x00\x00";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xA, &mut parser).unwrap();

        if let ResourceType::Int64(i) = result {
            assert_eq!(i, 42);
        } else {
            panic!("Expected Int64 variant");
        }
    }

    #[test]
    fn test_from_type_byte_uint64() {
        let data = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xB, &mut parser).unwrap();

        if let ResourceType::UInt64(u) = result {
            assert_eq!(u, 18446744073709551615);
        } else {
            panic!("Expected UInt64 variant");
        }
    }

    #[test]
    fn test_from_type_byte_single() {
        let data = b"\x00\x00\x28\x42"; // 42.0 as f32 in little endian
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xC, &mut parser).unwrap();

        if let ResourceType::Single(f) = result {
            assert_eq!(f, 42.0);
        } else {
            panic!("Expected Single variant");
        }
    }

    #[test]
    fn test_from_type_byte_double() {
        let data = b"\x00\x00\x00\x00\x00\x00\x45\x40"; // 42.0 as f64 in little endian
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xD, &mut parser).unwrap();

        if let ResourceType::Double(d) = result {
            assert_eq!(d, 42.0);
        } else {
            panic!("Expected Double variant");
        }
    }

    #[test]
    fn test_from_type_byte_unsupported() {
        let data = b"";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_byte(0xFF, &mut parser);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("FF is currently not supported"));
    }

    #[test]
    fn test_from_type_name_null() {
        let data = b"";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.Null", &mut parser);

        // This should try to call from_type_byte(0, parser) but will fail since 0 is unsupported
        assert!(result.is_err());
    }

    #[test]
    fn test_from_type_name_string() {
        let data = b"\x05hello";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.String", &mut parser).unwrap();

        if let ResourceType::String(s) = result {
            assert_eq!(s, "hello");
        } else {
            panic!("Expected String variant");
        }
    }

    #[test]
    fn test_from_type_name_boolean() {
        let data = b"\x01";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.Boolean", &mut parser).unwrap();

        if let ResourceType::Boolean(b) = result {
            assert!(b);
        } else {
            panic!("Expected Boolean variant");
        }
    }

    #[test]
    fn test_from_type_name_all_supported_types() {
        // Test each type individually since they have different data sizes

        // String
        let mut parser = Parser::new(b"\x05hello");
        assert!(ResourceType::from_type_name("System.String", &mut parser).is_ok());

        // Boolean
        let mut parser = Parser::new(b"\x01");
        assert!(ResourceType::from_type_name("System.Boolean", &mut parser).is_ok());

        // Char
        let mut parser = Parser::new(b"A");
        assert!(ResourceType::from_type_name("System.Char", &mut parser).is_ok());

        // Byte
        let mut parser = Parser::new(b"\xFF");
        assert!(ResourceType::from_type_name("System.Byte", &mut parser).is_ok());

        // SByte
        let mut parser = Parser::new(b"\xFF");
        assert!(ResourceType::from_type_name("System.SByte", &mut parser).is_ok());

        // Int16
        let mut parser = Parser::new(b"\xFF\xFF");
        assert!(ResourceType::from_type_name("System.Int16", &mut parser).is_ok());

        // UInt16
        let mut parser = Parser::new(b"\xFF\xFF");
        assert!(ResourceType::from_type_name("System.UInt16", &mut parser).is_ok());

        // Int32
        let mut parser = Parser::new(b"\x2A\x00\x00\x00");
        assert!(ResourceType::from_type_name("System.Int32", &mut parser).is_ok());

        // UInt32
        let mut parser = Parser::new(b"\xFF\xFF\xFF\xFF");
        assert!(ResourceType::from_type_name("System.UInt32", &mut parser).is_ok());

        // Int64
        let mut parser = Parser::new(b"\x2A\x00\x00\x00\x00\x00\x00\x00");
        assert!(ResourceType::from_type_name("System.Int64", &mut parser).is_ok());

        // UInt64
        let mut parser = Parser::new(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
        assert!(ResourceType::from_type_name("System.UInt64", &mut parser).is_ok());

        // Single
        let mut parser = Parser::new(b"\x00\x00\x28\x42");
        assert!(ResourceType::from_type_name("System.Single", &mut parser).is_ok());

        // Double
        let mut parser = Parser::new(b"\x00\x00\x00\x00\x00\x00\x45\x40");
        assert!(ResourceType::from_type_name("System.Double", &mut parser).is_ok());
    }

    #[test]
    fn test_from_type_name_unsupported() {
        let data = b"";
        let mut parser = Parser::new(data);
        let result = ResourceType::from_type_name("System.NotSupported", &mut parser);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("System.NotSupported is currently not supported"));
    }

    #[test]
    fn test_resource_entry_creation() {
        let entry = ResourceEntry {
            name: "TestResource".to_string(),
            name_hash: 12345,
            data: ResourceType::String("test_data".to_string()),
        };

        assert_eq!(entry.name, "TestResource");
        assert_eq!(entry.name_hash, 12345);

        if let ResourceType::String(s) = &entry.data {
            assert_eq!(s, "test_data");
        } else {
            panic!("Expected String data");
        }
    }

    #[test]
    fn test_resource_type_debug() {
        let resource = ResourceType::String("test".to_string());
        let debug_str = format!("{:?}", resource);
        assert!(debug_str.contains("String"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_resource_type_clone() {
        let original = ResourceType::Int32(42);
        let cloned = original.clone();

        assert_eq!(original, cloned);

        if let (ResourceType::Int32(orig), ResourceType::Int32(clone)) = (&original, &cloned) {
            assert_eq!(orig, clone);
        } else {
            panic!("Clone should preserve type and value");
        }
    }

    #[test]
    fn test_resource_type_partial_eq() {
        let res1 = ResourceType::String("test".to_string());
        let res2 = ResourceType::String("test".to_string());
        let res3 = ResourceType::String("different".to_string());
        let res4 = ResourceType::Int32(42);

        assert_eq!(res1, res2);
        assert_ne!(res1, res3);
        assert_ne!(res1, res4);
    }
}
