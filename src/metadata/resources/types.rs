/// The magic number that identifies a .NET resource file (0xBEEFCACE)
pub const RESOURCE_MAGIC: u32 = 0xBEEF_CACE;

use crate::{file::parser::Parser, Error::TypeError, Result};

/// Represents the common types that can be stored in .NET resources
///
/// ```rust,ignore
/// An internal implementation detail for .resources files, describing
/// what type an object is.
///
/// Ranges:
///     0 - 0x1F     Primitives and reserved values
///     0x20 - 0x3F  Specially recognized types, like byte[] and Streams
///
/// Note this data must be included in any documentation describing the
/// internals of .resources files.
/// ```
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceType {
    /* 0 */ Null,
    /* 1 */ String(String),
    /* 2 */ Boolean(bool),
    /* 3 */ Char(char),
    /* 4 */ Byte(u8),
    /* 5 */ SByte(i8),
    /* 6 */ Int16(i16),
    /* 7 */ UInt16(u16),
    /* 8 */ Int32(i32),
    /* 9 */ UInt32(u32),
    /* 0xA */ Int64(i64),
    /* 0xB */ UInt64(u64),
    /* 0xC */ Single(f32),
    /* 0xD */ Double(f64),
    /* 0xE */ Decimal,
    /* 0xF */ DateTime,
    /* 0x10 */ TimeSpan,

    // Type with special representation, like byte[] and Stream
    /* 0x20 */
    ByteArray(Vec<u8>),
    /* 0x21 */ Stream,

    // User types - serialized using the binary formatter
    /* 0x40 */ StartOfUserTypes,
}

impl ResourceType {
    /// Convert a .NET type byte into a `ResourceType`
    ///
    /// # Arguments
    /// * `byte` - The type byte
    /// * `parser` - Instance of the parser to read the underlying value
    ///
    /// # Errors
    /// Returns an error if the type byte is invalid or parsing fails.
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

    /// Convert a .NET type name to a `ResourceType`
    ///
    /// # Arguments
    /// * `type_name` - The name of the type to produce
    /// * `parser` - Instance of the parser to read the underlying value
    ///
    /// # Errors
    /// Returns an error if the type name is invalid or parsing fails.
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
