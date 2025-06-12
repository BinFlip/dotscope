use std::{convert::TryFrom, fmt};

use crate::{
    file::io::read_le,
    metadata::{
        token::Token,
        typesystem::{CilFlavor, ELEMENT_TYPE},
    },
    Error::{self, OutOfBounds, TypeConversionInvalid, TypeNotPrimitive},
    Result,
};

/// Type for raw constant data (used in various primitive types)
#[derive(Debug, Clone, PartialEq, Default)]
pub enum CilPrimitiveData {
    /// No data (for void, null, etc.)
    #[default]
    None,
    /// Boolean value
    Boolean(bool),
    /// Character value
    Char(char),
    /// 8-bit signed integer
    I1(i8),
    /// 8-bit unsigned integer
    U1(u8),
    /// 16-bit signed integer
    I2(i16),
    /// 16-bit unsigned integer
    U2(u16),
    /// 32-bit signed integer
    I4(i32),
    /// 32-bit unsigned integer
    U4(u32),
    /// 64-bit signed integer
    I8(i64),
    /// 64-bit unsigned integer
    U8(u64),
    /// platform usize
    U(usize),
    /// platform isize
    I(isize),
    /// 32-bit floating point
    R4(f32),
    /// 64-bit floating point
    R8(f64),
    /// String value
    String(String),
    /// Raw bytes (for complex types)
    Bytes(Vec<u8>),
}

impl CilPrimitiveData {
    /// Try to convert to a boolean value
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(*value),
            CilPrimitiveData::I4(value) => Some(*value != 0),
            CilPrimitiveData::U4(value) => Some(*value != 0),
            CilPrimitiveData::I8(value) => Some(*value != 0),
            CilPrimitiveData::U8(value) => Some(*value != 0),
            _ => None,
        }
    }

    /// Try to convert to an integer value
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(i32::from(*value)),
            CilPrimitiveData::I1(value) => Some(i32::from(*value)),
            CilPrimitiveData::U1(value) => Some(i32::from(*value)),
            CilPrimitiveData::I2(value) => Some(i32::from(*value)),
            CilPrimitiveData::U2(value) => Some(i32::from(*value)),
            CilPrimitiveData::I4(value) => Some(*value),
            CilPrimitiveData::U4(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::I8(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::U8(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::I(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::U(value) => i32::try_from(*value).ok(),
            CilPrimitiveData::R4(value) => {
                #[allow(clippy::cast_precision_loss)]
                if value.is_finite() && *value >= i32::MIN as f32 && *value <= i32::MAX as f32 {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i32)
                } else {
                    None
                }
            }
            CilPrimitiveData::R8(value) => {
                #[allow(clippy::cast_possible_truncation)]
                if value.is_finite()
                    && *value >= f64::from(i32::MIN)
                    && *value <= f64::from(i32::MAX)
                {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i32)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Try to convert to a 64-bit integer value
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(i64::from(*value)),
            CilPrimitiveData::I1(value) => Some(i64::from(*value)),
            CilPrimitiveData::U1(value) => Some(i64::from(*value)),
            CilPrimitiveData::I2(value) => Some(i64::from(*value)),
            CilPrimitiveData::U2(value) => Some(i64::from(*value)),
            CilPrimitiveData::I4(value) => Some(i64::from(*value)),
            CilPrimitiveData::U4(value) => Some(i64::from(*value)),
            CilPrimitiveData::I8(value) => Some(*value),
            CilPrimitiveData::U8(value) => i64::try_from(*value).ok(),
            CilPrimitiveData::I(value) => i64::try_from(*value).ok(),
            CilPrimitiveData::U(value) => i64::try_from(*value).ok(),
            CilPrimitiveData::R4(value) => {
                #[allow(clippy::cast_precision_loss)]
                if value.is_finite() && *value >= i64::MIN as f32 && *value <= i64::MAX as f32 {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i64)
                } else {
                    None
                }
            }
            CilPrimitiveData::R8(value) => {
                #[allow(clippy::cast_precision_loss)]
                if value.is_finite() && *value >= i64::MIN as f64 && *value <= i64::MAX as f64 {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(*value as i64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Try to convert to a floating point value
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            CilPrimitiveData::Boolean(value) => Some(f64::from(*value)),
            CilPrimitiveData::I1(value) => Some(f64::from(*value)),
            CilPrimitiveData::U1(value) => Some(f64::from(*value)),
            CilPrimitiveData::I2(value) => Some(f64::from(*value)),
            CilPrimitiveData::U2(value) => Some(f64::from(*value)),
            CilPrimitiveData::I4(value) => Some(f64::from(*value)),
            CilPrimitiveData::U4(value) => Some(f64::from(*value)),
            #[allow(clippy::cast_precision_loss)]
            CilPrimitiveData::I8(value) => Some(*value as f64),
            #[allow(clippy::cast_precision_loss)]
            CilPrimitiveData::U8(value) => Some(*value as f64),
            CilPrimitiveData::R4(value) => Some(f64::from(*value)),
            CilPrimitiveData::R8(value) => Some(*value),
            _ => None,
        }
    }

    /// Try to convert to a string value
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        match self {
            CilPrimitiveData::String(value) => Some(value.clone()),
            CilPrimitiveData::Boolean(value) => Some(value.to_string()),
            CilPrimitiveData::Char(value) => Some(value.to_string()),
            CilPrimitiveData::I1(value) => Some(value.to_string()),
            CilPrimitiveData::U1(value) => Some(value.to_string()),
            CilPrimitiveData::I2(value) => Some(value.to_string()),
            CilPrimitiveData::U2(value) => Some(value.to_string()),
            CilPrimitiveData::I4(value) => Some(value.to_string()),
            CilPrimitiveData::U4(value) => Some(value.to_string()),
            CilPrimitiveData::I8(value) => Some(value.to_string()),
            CilPrimitiveData::U8(value) => Some(value.to_string()),
            CilPrimitiveData::R4(value) => Some(value.to_string()),
            CilPrimitiveData::R8(value) => Some(value.to_string()),
            _ => None,
        }
    }

    /// Parse from raw bytes based on primitive type
    ///
    /// ## Arguments
    /// * `type_byte`   - The type byte to convert for
    /// * `data`        - The data blob to parse for the value
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if the data is too short for the specified type.
    /// Returns [`Error`] for invalid string data or other parsing errors.
    pub fn from_bytes(type_byte: u8, data: &[u8]) -> Result<Self> {
        match type_byte {
            ELEMENT_TYPE::BOOLEAN => {
                if data.is_empty() {
                    Err(OutOfBounds)
                } else {
                    Ok(CilPrimitiveData::Boolean(data[0] != 0))
                }
            }
            ELEMENT_TYPE::CHAR => {
                if data.is_empty() {
                    Err(OutOfBounds)
                } else {
                    Ok(CilPrimitiveData::Char(char::from(data[0])))
                }
            }
            ELEMENT_TYPE::I1 => Ok(CilPrimitiveData::I1(read_le::<i8>(data)?)),
            ELEMENT_TYPE::U1 => Ok(CilPrimitiveData::U1(read_le::<u8>(data)?)),
            ELEMENT_TYPE::I2 => Ok(CilPrimitiveData::I2(read_le::<i16>(data)?)),
            ELEMENT_TYPE::U2 => Ok(CilPrimitiveData::U2(read_le::<u16>(data)?)),
            ELEMENT_TYPE::I4 => Ok(CilPrimitiveData::I4(read_le::<i32>(data)?)),
            ELEMENT_TYPE::U4 => Ok(CilPrimitiveData::U4(read_le::<u32>(data)?)),
            ELEMENT_TYPE::I8 => Ok(CilPrimitiveData::I8(read_le::<i64>(data)?)),
            ELEMENT_TYPE::U8 => Ok(CilPrimitiveData::U8(read_le::<u64>(data)?)),
            ELEMENT_TYPE::R4 => Ok(CilPrimitiveData::R4(read_le::<f32>(data)?)),
            ELEMENT_TYPE::R8 => Ok(CilPrimitiveData::R8(read_le::<f64>(data)?)),
            ELEMENT_TYPE::U => Ok(CilPrimitiveData::U(read_le::<usize>(data)?)),
            ELEMENT_TYPE::I => Ok(CilPrimitiveData::I(read_le::<isize>(data)?)),
            ELEMENT_TYPE::STRING => {
                if data.is_empty() {
                    return Ok(CilPrimitiveData::String(String::new()));
                }

                if data.len() % 2 != 0 {
                    return Err(malformed_error!(
                        "Invalid UTF-16 string length: {} (must be even)",
                        data.len()
                    ));
                }

                let utf16_chars: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();

                match String::from_utf16(&utf16_chars) {
                    Ok(utf_string) => Ok(CilPrimitiveData::String(utf_string)),
                    Err(_) => Err(malformed_error!(
                        "Invalid UTF-16 sequence in primitive string"
                    )),
                }
            }
            _ => Ok(CilPrimitiveData::Bytes(data.to_vec())),
        }
    }
}

/// Represents all primitive types in CIL/.NET with optional data
#[derive(Debug, Clone, PartialEq)]
pub struct CilPrimitive {
    /// The type of primitive
    pub kind: CilPrimitiveKind,
    /// The actual data (if available)
    pub data: CilPrimitiveData,
}

/// Represents all primitive types in CIL/.NET (without data)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CilPrimitiveKind {
    /// System.Void - represents no value
    Void,
    /// System.Boolean - true/false value
    Boolean,
    /// System.Char - Unicode 16-bit character
    Char,
    /// System.SByte - signed 8-bit integer
    I1,
    /// System.Byte - unsigned 8-bit integer
    U1,
    /// System.Int16 - signed 16-bit integer
    I2,
    /// System.UInt16 - unsigned 16-bit integer
    U2,
    /// System.Int32 - signed 32-bit integer
    I4,
    /// System.UInt32 - unsigned 32-bit integer
    U4,
    /// System.Int64 - signed 64-bit integer
    I8,
    /// System.UInt64 - unsigned 64-bit integer
    U8,
    /// System.Single - 32-bit floating point
    R4,
    /// System.Double - 64-bit floating point
    R8,
    /// System.IntPtr - native sized signed integer
    I,
    /// System.UIntPtr - native sized unsigned integer
    U,
    /// System.Object - base class for all reference types
    Object,
    /// System.String - immutable string of Unicode characters
    String,
    /// Special value for null reference in constants
    Null,
    /// System.TypedReference - type-safe pointer (used by compiler)
    TypedReference,
    /// System.ValueType - base class for value types
    ValueType,
    /// Generic type parameter
    Var,
    /// Generic method parameter
    MVar,
    /// A class object
    Class,
}

impl CilPrimitiveKind {
    /// Get the token for this type
    #[must_use]
    pub fn token(&self) -> Token {
        Token::new(match self {
            CilPrimitiveKind::Void => 0xF000_0001,
            CilPrimitiveKind::Boolean => 0xF000_0002,
            CilPrimitiveKind::Char => 0xF000_0003,
            CilPrimitiveKind::I1 => 0xF000_0004,
            CilPrimitiveKind::U1 => 0xF000_0005,
            CilPrimitiveKind::I2 => 0xF000_0006,
            CilPrimitiveKind::U2 => 0xF000_0007,
            CilPrimitiveKind::I4 => 0xF000_0008,
            CilPrimitiveKind::U4 => 0xF000_0009,
            CilPrimitiveKind::I8 => 0xF000_000A,
            CilPrimitiveKind::U8 => 0xF000_000B,
            CilPrimitiveKind::R4 => 0xF000_000C,
            CilPrimitiveKind::R8 => 0xF000_000D,
            CilPrimitiveKind::I => 0xF000_000E,
            CilPrimitiveKind::U => 0xF000_000F,
            CilPrimitiveKind::Object => 0xF000_0010,
            CilPrimitiveKind::String => 0xF000_0011,
            CilPrimitiveKind::TypedReference => 0xF000_0012,
            CilPrimitiveKind::ValueType => 0xF000_0013,
            CilPrimitiveKind::Var => 0xF000_0014,
            CilPrimitiveKind::MVar => 0xF000_0015,
            CilPrimitiveKind::Null => 0xF000_0016,
            CilPrimitiveKind::Class => 0xF000_0017,
        })
    }

    /// Parse from raw bytes based on primitive type
    ///
    /// ## Arguments
    /// * `type_byte` - The byte to convert from
    ///
    /// # Errors
    /// Returns [`TypeNotPrimitive`] if the byte does not represent a valid primitive type.
    pub fn from_byte(type_byte: u8) -> Result<Self> {
        match type_byte {
            ELEMENT_TYPE::BOOLEAN => Ok(CilPrimitiveKind::Boolean),
            ELEMENT_TYPE::CHAR => Ok(CilPrimitiveKind::Char),
            ELEMENT_TYPE::I1 => Ok(CilPrimitiveKind::I1),
            ELEMENT_TYPE::U1 => Ok(CilPrimitiveKind::U1),
            ELEMENT_TYPE::I2 => Ok(CilPrimitiveKind::I2),
            ELEMENT_TYPE::U2 => Ok(CilPrimitiveKind::U2),
            ELEMENT_TYPE::I4 => Ok(CilPrimitiveKind::I4),
            ELEMENT_TYPE::U4 => Ok(CilPrimitiveKind::U4),
            ELEMENT_TYPE::I8 => Ok(CilPrimitiveKind::I8),
            ELEMENT_TYPE::U8 => Ok(CilPrimitiveKind::U8),
            ELEMENT_TYPE::R4 => Ok(CilPrimitiveKind::R4),
            ELEMENT_TYPE::R8 => Ok(CilPrimitiveKind::R8),
            ELEMENT_TYPE::U => Ok(CilPrimitiveKind::U),
            ELEMENT_TYPE::I => Ok(CilPrimitiveKind::I),
            ELEMENT_TYPE::STRING => Ok(CilPrimitiveKind::String),
            ELEMENT_TYPE::CLASS => Ok(CilPrimitiveKind::Class),
            _ => Err(TypeNotPrimitive),
        }
    }
}

impl CilPrimitive {
    /// Create a new primitive with the default value
    ///
    /// ## Arguments
    /// * `kind` - The type or primitive to create
    #[must_use]
    pub fn new(kind: CilPrimitiveKind) -> Self {
        CilPrimitive {
            kind,
            data: CilPrimitiveData::None,
        }
    }

    /// Create a primitive with specific data
    ///
    /// ## Arguments
    /// * `kind` - Set the kind of primitive
    /// * `data` - Set the data for the primitive
    #[must_use]
    pub fn with_data(kind: CilPrimitiveKind, data: CilPrimitiveData) -> Self {
        CilPrimitive { kind, data }
    }

    /// Create a boolean primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn boolean(value: bool) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Boolean,
            data: CilPrimitiveData::Boolean(value),
        }
    }

    /// Create a character primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn char(value: char) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Char,
            data: CilPrimitiveData::Char(value),
        }
    }

    /// Create an i8 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i1(value: i8) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I1,
            data: CilPrimitiveData::I1(value),
        }
    }

    /// Create a u8 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u1(value: u8) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U1,
            data: CilPrimitiveData::U1(value),
        }
    }

    /// Create an i16 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i2(value: i16) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I2,
            data: CilPrimitiveData::I2(value),
        }
    }

    /// Create a u16 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u2(value: u16) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U2,
            data: CilPrimitiveData::U2(value),
        }
    }

    /// Create an i32 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i4(value: i32) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I4,
            data: CilPrimitiveData::I4(value),
        }
    }

    /// Create a u32 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u4(value: u32) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U4,
            data: CilPrimitiveData::U4(value),
        }
    }

    /// Create an i64 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i8(value: i64) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I8,
            data: CilPrimitiveData::I8(value),
        }
    }

    /// Create a u64 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u8(value: u64) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U8,
            data: CilPrimitiveData::U8(value),
        }
    }

    /// Create an f32 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn r4(value: f32) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::R4,
            data: CilPrimitiveData::R4(value),
        }
    }

    /// Create an f64 primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn r8(value: f64) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::R8,
            data: CilPrimitiveData::R8(value),
        }
    }

    /// Create an usize primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn u(value: usize) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::U,
            data: CilPrimitiveData::U(value),
        }
    }

    /// Create an isize primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn i(value: isize) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::I,
            data: CilPrimitiveData::I(value),
        }
    }

    /// Create a string primitive
    ///
    /// ## Arguments
    /// * `value` - The initial value for the requested primitive
    #[must_use]
    pub fn string(value: &str) -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::String,
            data: CilPrimitiveData::String(value.to_string()),
        }
    }

    /// Create a null primitive
    #[must_use]
    pub fn null() -> Self {
        CilPrimitive {
            kind: CilPrimitiveKind::Null,
            data: CilPrimitiveData::None,
        }
    }

    /// Get the token for this primitive type
    #[must_use]
    pub fn token(&self) -> Token {
        self.kind.token()
    }

    /// Get the byte representation in type signatures (per ECMA-335 spec)
    #[must_use]
    pub fn as_byte(&self) -> u8 {
        match self.kind {
            CilPrimitiveKind::Void => ELEMENT_TYPE::VOID,
            CilPrimitiveKind::Boolean => ELEMENT_TYPE::BOOLEAN,
            CilPrimitiveKind::Char => ELEMENT_TYPE::CHAR,
            CilPrimitiveKind::I1 => ELEMENT_TYPE::I1,
            CilPrimitiveKind::U1 => ELEMENT_TYPE::U1,
            CilPrimitiveKind::I2 => ELEMENT_TYPE::I2,
            CilPrimitiveKind::U2 => ELEMENT_TYPE::U2,
            CilPrimitiveKind::I4 => ELEMENT_TYPE::I4,
            CilPrimitiveKind::U4 => ELEMENT_TYPE::U4,
            CilPrimitiveKind::I8 => ELEMENT_TYPE::I8,
            CilPrimitiveKind::U8 => ELEMENT_TYPE::U8,
            CilPrimitiveKind::R4 => ELEMENT_TYPE::R4,
            CilPrimitiveKind::R8 => ELEMENT_TYPE::R8,
            CilPrimitiveKind::I => ELEMENT_TYPE::I,
            CilPrimitiveKind::U => ELEMENT_TYPE::U,
            CilPrimitiveKind::Object => ELEMENT_TYPE::OBJECT,
            CilPrimitiveKind::String => ELEMENT_TYPE::STRING,
            CilPrimitiveKind::TypedReference => ELEMENT_TYPE::TYPEDBYREF,
            CilPrimitiveKind::ValueType => ELEMENT_TYPE::VALUETYPE, // Used for VALUETYPE signature
            CilPrimitiveKind::Var => ELEMENT_TYPE::VAR,             // Used for VAR signature
            CilPrimitiveKind::MVar => ELEMENT_TYPE::MVAR,           // Used for MVAR signature
            CilPrimitiveKind::Null => 0xFF,                         // Not used in signatures
            CilPrimitiveKind::Class => ELEMENT_TYPE::CLASS,
        }
    }

    /// Try to parse a primitive type from a signature byte
    ///
    /// ## Arguments
    /// * `byte` - The kind byte to convert
    ///
    /// # Errors
    /// Returns [`TypeNotPrimitive`] if the byte does not represent a valid primitive type.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            ELEMENT_TYPE::VOID => Ok(Self::new(CilPrimitiveKind::Void)),
            ELEMENT_TYPE::BOOLEAN => Ok(Self::new(CilPrimitiveKind::Boolean)),
            ELEMENT_TYPE::CHAR => Ok(Self::new(CilPrimitiveKind::Char)),
            ELEMENT_TYPE::I1 => Ok(Self::new(CilPrimitiveKind::I1)),
            ELEMENT_TYPE::U1 => Ok(Self::new(CilPrimitiveKind::U1)),
            ELEMENT_TYPE::I2 => Ok(Self::new(CilPrimitiveKind::I2)),
            ELEMENT_TYPE::U2 => Ok(Self::new(CilPrimitiveKind::U2)),
            ELEMENT_TYPE::I4 => Ok(Self::new(CilPrimitiveKind::I4)),
            ELEMENT_TYPE::U4 => Ok(Self::new(CilPrimitiveKind::U4)),
            ELEMENT_TYPE::I8 => Ok(Self::new(CilPrimitiveKind::I8)),
            ELEMENT_TYPE::U8 => Ok(Self::new(CilPrimitiveKind::U8)),
            ELEMENT_TYPE::R4 => Ok(Self::new(CilPrimitiveKind::R4)),
            ELEMENT_TYPE::R8 => Ok(Self::new(CilPrimitiveKind::R8)),
            ELEMENT_TYPE::STRING => Ok(Self::new(CilPrimitiveKind::String)),
            ELEMENT_TYPE::TYPEDBYREF => Ok(Self::new(CilPrimitiveKind::TypedReference)),
            ELEMENT_TYPE::I => Ok(Self::new(CilPrimitiveKind::I)),
            ELEMENT_TYPE::U => Ok(Self::new(CilPrimitiveKind::U)),
            ELEMENT_TYPE::OBJECT => Ok(Self::new(CilPrimitiveKind::Object)),
            ELEMENT_TYPE::CLASS => Ok(Self::new(CilPrimitiveKind::Class)),
            // Note: 0x11 (VALUETYPE), 0x13 (VAR), and 0x1E (MVAR) are handled separately
            // in signature parsing as they require additional parameters
            _ => Err(TypeNotPrimitive),
        }
    }

    /// Get the CLR full type name (with namespace)
    #[must_use]
    pub fn clr_full_name(&self) -> &'static str {
        match self.kind {
            CilPrimitiveKind::Void => "System.Void",
            CilPrimitiveKind::Boolean => "System.Boolean",
            CilPrimitiveKind::Char => "System.Char",
            CilPrimitiveKind::I1 => "System.SByte",
            CilPrimitiveKind::U1 => "System.Byte",
            CilPrimitiveKind::I2 => "System.Int16",
            CilPrimitiveKind::U2 => "System.UInt16",
            CilPrimitiveKind::I4 => "System.Int32",
            CilPrimitiveKind::U4 => "System.UInt32",
            CilPrimitiveKind::I8 => "System.Int64",
            CilPrimitiveKind::U8 => "System.UInt64",
            CilPrimitiveKind::R4 => "System.Single",
            CilPrimitiveKind::R8 => "System.Double",
            CilPrimitiveKind::I => "System.IntPtr",
            CilPrimitiveKind::U => "System.UIntPtr",
            CilPrimitiveKind::Object => "System.Object",
            CilPrimitiveKind::String => "System.String",
            CilPrimitiveKind::TypedReference => "System.TypedReference",
            CilPrimitiveKind::ValueType => "System.ValueType",
            CilPrimitiveKind::Var => "<Generic Parameter>",
            CilPrimitiveKind::MVar => "<Generic Method Parameter>",
            CilPrimitiveKind::Null => "<null>",
            CilPrimitiveKind::Class => "",
        }
    }

    /// Get the namespace of this type
    #[must_use]
    pub fn namespace(&self) -> &'static str {
        match self.kind {
            CilPrimitiveKind::Var | CilPrimitiveKind::MVar | CilPrimitiveKind::Null => "",
            _ => "System",
        }
    }

    /// Get the short name (without namespace)
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.kind {
            CilPrimitiveKind::Void => "Void",
            CilPrimitiveKind::Boolean => "Boolean",
            CilPrimitiveKind::Char => "Char",
            CilPrimitiveKind::I1 => "SByte",
            CilPrimitiveKind::U1 => "Byte",
            CilPrimitiveKind::I2 => "Int16",
            CilPrimitiveKind::U2 => "UInt16",
            CilPrimitiveKind::I4 => "Int32",
            CilPrimitiveKind::U4 => "UInt32",
            CilPrimitiveKind::I8 => "Int64",
            CilPrimitiveKind::U8 => "UInt64",
            CilPrimitiveKind::R4 => "Single",
            CilPrimitiveKind::R8 => "Double",
            CilPrimitiveKind::I => "IntPtr",
            CilPrimitiveKind::U => "UIntPtr",
            CilPrimitiveKind::Object => "Object",
            CilPrimitiveKind::String => "String",
            CilPrimitiveKind::TypedReference => "TypedReference",
            CilPrimitiveKind::ValueType => "ValueType",
            CilPrimitiveKind::Var => "<Generic Parameter>",
            CilPrimitiveKind::MVar => "<Generic Method Parameter>",
            CilPrimitiveKind::Null => "<null>",
            CilPrimitiveKind::Class => "Class",
        }
    }

    /// Convert to `CilFlavor`
    #[must_use]
    pub fn to_flavor(&self) -> CilFlavor {
        match self.kind {
            CilPrimitiveKind::Void => CilFlavor::Void,
            CilPrimitiveKind::Boolean => CilFlavor::Boolean,
            CilPrimitiveKind::Char => CilFlavor::Char,
            CilPrimitiveKind::I1 => CilFlavor::I1,
            CilPrimitiveKind::U1 => CilFlavor::U1,
            CilPrimitiveKind::I2 => CilFlavor::I2,
            CilPrimitiveKind::U2 => CilFlavor::U2,
            CilPrimitiveKind::I4 => CilFlavor::I4,
            CilPrimitiveKind::U4 => CilFlavor::U4,
            CilPrimitiveKind::I8 => CilFlavor::I8,
            CilPrimitiveKind::U8 => CilFlavor::U8,
            CilPrimitiveKind::R4 => CilFlavor::R4,
            CilPrimitiveKind::R8 => CilFlavor::R8,
            CilPrimitiveKind::I => CilFlavor::I,
            CilPrimitiveKind::U => CilFlavor::U,
            CilPrimitiveKind::Object => CilFlavor::Object,
            CilPrimitiveKind::String => CilFlavor::String,
            CilPrimitiveKind::TypedReference | CilPrimitiveKind::Null => CilFlavor::Unknown,
            CilPrimitiveKind::ValueType => CilFlavor::ValueType,
            CilPrimitiveKind::Var => CilFlavor::GenericParameter {
                index: 0,
                method: false,
            },
            CilPrimitiveKind::MVar => CilFlavor::GenericParameter {
                index: 0,
                method: true,
            },
            CilPrimitiveKind::Class => CilFlavor::Class,
        }
    }

    /// Is this a value type
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        matches!(
            self.kind,
            CilPrimitiveKind::Boolean
                | CilPrimitiveKind::Char
                | CilPrimitiveKind::I1
                | CilPrimitiveKind::U1
                | CilPrimitiveKind::I2
                | CilPrimitiveKind::U2
                | CilPrimitiveKind::I4
                | CilPrimitiveKind::U4
                | CilPrimitiveKind::I8
                | CilPrimitiveKind::U8
                | CilPrimitiveKind::R4
                | CilPrimitiveKind::R8
                | CilPrimitiveKind::I
                | CilPrimitiveKind::U
                | CilPrimitiveKind::ValueType
        )
    }

    /// Is this a reference type
    #[must_use]
    pub fn is_reference_type(&self) -> bool {
        matches!(
            self.kind,
            CilPrimitiveKind::Object | CilPrimitiveKind::String
        )
    }

    /// Parse a primitive value from a blob of data
    ///
    /// ## Arguments
    /// * `p_type`  - The primitive byte to determine the kind of
    /// * `blob`    - The data blob to parse for the value
    ///
    /// # Errors
    /// Returns [`TypeNotPrimitive`] if the primitive type is invalid.
    /// Returns [`OutOfBounds`] or other errors if the blob data is insufficient or invalid.
    pub fn from_blob(p_type: u8, blob: &[u8]) -> Result<Self> {
        Ok(CilPrimitive {
            kind: CilPrimitiveKind::from_byte(p_type)?,
            data: CilPrimitiveData::from_bytes(p_type, blob)?,
        })
    }

    /// Try to get as boolean value
    #[must_use]
    pub fn as_boolean(&self) -> Option<bool> {
        self.data.as_boolean()
    }

    /// Try to get as i32 value
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        self.data.as_i32()
    }

    /// Try to get as i64 value
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.data.as_i64()
    }

    /// Try to get as f64 value
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        self.data.as_f64()
    }

    /// Try to get as string value
    #[must_use]
    pub fn as_string(&self) -> Option<String> {
        self.data.as_string()
    }

    /// Serialize this primitive to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.data {
            CilPrimitiveData::None => Vec::new(),
            CilPrimitiveData::Boolean(value) => vec![u8::from(*value)],
            CilPrimitiveData::Char(value) => {
                let code = *value as u16;
                vec![(code & 0xFF) as u8, ((code >> 8) & 0xFF) as u8]
            }
            CilPrimitiveData::I1(value) => vec![{
                #[allow(clippy::cast_sign_loss)]
                {
                    *value as u8
                }
            }],
            CilPrimitiveData::U1(value) => vec![*value],
            CilPrimitiveData::I2(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U2(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::I4(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U4(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::I8(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U8(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::R4(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::R8(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::U(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::I(value) => value.to_le_bytes().to_vec(),
            CilPrimitiveData::String(value) => value.as_bytes().to_vec(),
            CilPrimitiveData::Bytes(value) => value.clone(),
        }
    }
}

impl fmt::Display for CilPrimitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.data {
            CilPrimitiveData::None => write!(f, "{}", self.clr_full_name()),
            CilPrimitiveData::Boolean(value) => write!(f, "{}", value),
            CilPrimitiveData::Char(value) => write!(f, "'{}'", value),
            CilPrimitiveData::I1(value) => write!(f, "{}", value),
            CilPrimitiveData::U1(value) => write!(f, "{}", value),
            CilPrimitiveData::I2(value) => write!(f, "{}", value),
            CilPrimitiveData::U2(value) => write!(f, "{}", value),
            CilPrimitiveData::I4(value) => write!(f, "{}", value),
            CilPrimitiveData::U4(value) => write!(f, "{}", value),
            CilPrimitiveData::I8(value) => write!(f, "{}", value),
            CilPrimitiveData::U8(value) => write!(f, "{}", value),
            CilPrimitiveData::R4(value) => write!(f, "{}", value),
            CilPrimitiveData::R8(value) => write!(f, "{}", value),
            CilPrimitiveData::U(value) => write!(f, "{}", value),
            CilPrimitiveData::I(value) => write!(f, "{}", value),
            CilPrimitiveData::String(value) => write!(f, "\"{}\"", value),
            CilPrimitiveData::Bytes(value) => {
                write!(f, "Bytes[")?;
                for (i, byte) in value.iter().enumerate().take(8) {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02X}", byte)?;
                }
                if value.len() > 8 {
                    write!(f, "...")?;
                }
                write!(f, "]")
            }
        }
    }
}

impl From<bool> for CilPrimitive {
    fn from(value: bool) -> Self {
        CilPrimitive::boolean(value)
    }
}

impl From<char> for CilPrimitive {
    fn from(value: char) -> Self {
        CilPrimitive::char(value)
    }
}

impl From<i8> for CilPrimitive {
    fn from(value: i8) -> Self {
        CilPrimitive::i1(value)
    }
}

impl From<u8> for CilPrimitive {
    fn from(value: u8) -> Self {
        CilPrimitive::u1(value)
    }
}

impl From<i16> for CilPrimitive {
    fn from(value: i16) -> Self {
        CilPrimitive::i2(value)
    }
}

impl From<u16> for CilPrimitive {
    fn from(value: u16) -> Self {
        CilPrimitive::u2(value)
    }
}

impl From<i32> for CilPrimitive {
    fn from(value: i32) -> Self {
        CilPrimitive::i4(value)
    }
}

impl From<u32> for CilPrimitive {
    fn from(value: u32) -> Self {
        CilPrimitive::u4(value)
    }
}

impl From<i64> for CilPrimitive {
    fn from(value: i64) -> Self {
        CilPrimitive::i8(value)
    }
}

impl From<u64> for CilPrimitive {
    fn from(value: u64) -> Self {
        CilPrimitive::u8(value)
    }
}

impl From<f32> for CilPrimitive {
    fn from(value: f32) -> Self {
        CilPrimitive::r4(value)
    }
}

impl From<f64> for CilPrimitive {
    fn from(value: f64) -> Self {
        CilPrimitive::r8(value)
    }
}

impl From<&str> for CilPrimitive {
    fn from(value: &str) -> Self {
        CilPrimitive::string(value)
    }
}

impl From<String> for CilPrimitive {
    fn from(value: String) -> Self {
        CilPrimitive::string(&value)
    }
}

impl TryFrom<CilPrimitive> for bool {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_boolean().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for i32 {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_i32().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for i64 {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_i64().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for f64 {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_f64().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilPrimitive> for String {
    type Error = Error;

    fn try_from(value: CilPrimitive) -> Result<Self> {
        value.as_string().ok_or(TypeConversionInvalid)
    }
}

impl TryFrom<CilFlavor> for CilPrimitive {
    type Error = Error;

    fn try_from(flavor: CilFlavor) -> Result<Self> {
        match flavor.to_primitive_kind() {
            Some(kind) => Ok(CilPrimitive::new(kind)),
            None => Err(TypeNotPrimitive),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_primitive_creation() {
        let bool_primitive = CilPrimitive::boolean(true);
        assert_eq!(bool_primitive.kind, CilPrimitiveKind::Boolean);
        assert_eq!(bool_primitive.data, CilPrimitiveData::Boolean(true));

        let int_primitive = CilPrimitive::i4(42);
        assert_eq!(int_primitive.kind, CilPrimitiveKind::I4);
        assert_eq!(int_primitive.data, CilPrimitiveData::I4(42));

        let string_primitive = CilPrimitive::string("Hello");
        assert_eq!(string_primitive.kind, CilPrimitiveKind::String);
        assert_eq!(
            string_primitive.data,
            CilPrimitiveData::String("Hello".to_string())
        );

        let void_primitive = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_primitive.kind, CilPrimitiveKind::Void);
        assert_eq!(void_primitive.data, CilPrimitiveData::None);

        let char_primitive =
            CilPrimitive::with_data(CilPrimitiveKind::Char, CilPrimitiveData::Char('A'));
        assert_eq!(char_primitive.kind, CilPrimitiveKind::Char);
        assert_eq!(char_primitive.data, CilPrimitiveData::Char('A'));
    }

    #[test]
    fn test_data_conversion() {
        let int_primitive = CilPrimitive::i4(42);
        assert_eq!(int_primitive.as_i32(), Some(42));
        assert_eq!(int_primitive.as_i64(), Some(42i64));
        assert_eq!(int_primitive.as_f64(), Some(42.0));
        assert_eq!(int_primitive.as_boolean(), Some(true));
        assert_eq!(int_primitive.as_string(), Some("42".to_string()));

        let bool_primitive = CilPrimitive::boolean(true);
        assert_eq!(bool_primitive.as_i32(), Some(1));
        assert_eq!(bool_primitive.as_boolean(), Some(true));

        let string_primitive = CilPrimitive::string("123");
        assert_eq!(string_primitive.as_string(), Some("123".to_string()));
        assert_eq!(string_primitive.as_i32(), None); // Can't convert string to int

        // Test data conversion for more types
        let i1_primitive = CilPrimitive::i1(-42);
        assert_eq!(i1_primitive.as_i32(), Some(-42));

        let u1_primitive = CilPrimitive::u1(42);
        assert_eq!(u1_primitive.as_i32(), Some(42));

        let i2_primitive = CilPrimitive::i2(-1000);
        assert_eq!(i2_primitive.as_i32(), Some(-1000));

        let u2_primitive = CilPrimitive::u2(1000);
        assert_eq!(u2_primitive.as_i32(), Some(1000));

        let i8_primitive = CilPrimitive::i8(-1_000_000_000_000);
        assert_eq!(i8_primitive.as_i64(), Some(-1_000_000_000_000));

        let u8_primitive = CilPrimitive::u8(1_000_000_000_000);
        assert_eq!(u8_primitive.as_i64(), Some(1_000_000_000_000));

        let r4_primitive = CilPrimitive::r4(3.01);
        assert!((r4_primitive.as_f64().unwrap() - 3.01).abs() < 0.001);

        let r8_primitive = CilPrimitive::r8(3.00009);
        assert!((r8_primitive.as_f64().unwrap() - 3.00009).abs() < 0.000001);

        let i_primitive = CilPrimitive::i(42);
        assert_eq!(i_primitive.as_i32(), Some(42));

        let u_primitive = CilPrimitive::u(42);
        assert_eq!(u_primitive.as_i32(), Some(42));
    }

    #[test]
    fn test_primitive_from_blob() {
        let bool_blob = vec![1]; // true
        let bool_prim = CilPrimitive::from_blob(ELEMENT_TYPE::BOOLEAN, &bool_blob).unwrap();
        assert_eq!(bool_prim.kind, CilPrimitiveKind::Boolean);
        assert_eq!(bool_prim.as_boolean(), Some(true));

        let int_blob = vec![42, 0, 0, 0]; // 42 as i32
        let int_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I4, &int_blob).unwrap();
        assert_eq!(int_prim.kind, CilPrimitiveKind::I4);
        assert_eq!(int_prim.as_i32(), Some(42));

        let float_blob = vec![0, 0, 0x20, 0x41]; // 10.0 as f32
        let float_prim = CilPrimitive::from_blob(ELEMENT_TYPE::R4, &float_blob).unwrap();
        assert_eq!(float_prim.kind, CilPrimitiveKind::R4);
        assert!((float_prim.as_f64().unwrap() - 10.0).abs() < 0.001);

        let i1_blob = vec![0xFF]; // -1 as i8
        let i1_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I1, &i1_blob).unwrap();
        assert_eq!(i1_prim.kind, CilPrimitiveKind::I1);
        assert_eq!(i1_prim.as_i32(), Some(-1));

        let u1_blob = vec![0xFF]; // 255 as u8
        let u1_prim = CilPrimitive::from_blob(ELEMENT_TYPE::U1, &u1_blob).unwrap();
        assert_eq!(u1_prim.kind, CilPrimitiveKind::U1);
        assert_eq!(u1_prim.as_i32(), Some(255));

        let i2_blob = vec![0xFF, 0xFF]; // -1 as i16
        let i2_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I2, &i2_blob).unwrap();
        assert_eq!(i2_prim.kind, CilPrimitiveKind::I2);
        assert_eq!(i2_prim.as_i32(), Some(-1));

        let u2_blob = vec![0xFF, 0xFF]; // 65535 as u16
        let u2_prim = CilPrimitive::from_blob(ELEMENT_TYPE::U2, &u2_blob).unwrap();
        assert_eq!(u2_prim.kind, CilPrimitiveKind::U2);
        assert_eq!(u2_prim.as_i32(), Some(65535));

        let i8_blob = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // -1 as i64
        let i8_prim = CilPrimitive::from_blob(ELEMENT_TYPE::I8, &i8_blob).unwrap();
        assert_eq!(i8_prim.kind, CilPrimitiveKind::I8);
        assert_eq!(i8_prim.as_i64(), Some(-1));

        let u8_blob = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // max u64
        let u8_prim = CilPrimitive::from_blob(ELEMENT_TYPE::U8, &u8_blob).unwrap();
        assert_eq!(u8_prim.kind, CilPrimitiveKind::U8);
        assert_eq!(u8_prim.as_i64(), None);

        let char_blob = vec![65]; // 'A'
        let char_prim = CilPrimitive::from_blob(ELEMENT_TYPE::CHAR, &char_blob).unwrap();
        assert_eq!(char_prim.kind, CilPrimitiveKind::Char);
        assert_eq!(char_prim.data, CilPrimitiveData::Char('A'));
    }

    #[test]
    fn test_to_flavor() {
        let bool_prim = CilPrimitive::boolean(true);
        let flavor = bool_prim.to_flavor();
        assert!(matches!(flavor, CilFlavor::Boolean));

        let int_prim = CilPrimitive::i4(42);
        let flavor = int_prim.to_flavor();
        assert!(matches!(flavor, CilFlavor::I4));

        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert!(matches!(void_prim.to_flavor(), CilFlavor::Void));

        let char_prim = CilPrimitive::char('A');
        assert!(matches!(char_prim.to_flavor(), CilFlavor::Char));

        let i1_prim = CilPrimitive::i1(42);
        assert!(matches!(i1_prim.to_flavor(), CilFlavor::I1));

        let u1_prim = CilPrimitive::u1(42);
        assert!(matches!(u1_prim.to_flavor(), CilFlavor::U1));

        let i2_prim = CilPrimitive::i2(42);
        assert!(matches!(i2_prim.to_flavor(), CilFlavor::I2));

        let u2_prim = CilPrimitive::u2(42);
        assert!(matches!(u2_prim.to_flavor(), CilFlavor::U2));

        let u4_prim = CilPrimitive::u4(42);
        assert!(matches!(u4_prim.to_flavor(), CilFlavor::U4));

        let i8_prim = CilPrimitive::i8(42);
        assert!(matches!(i8_prim.to_flavor(), CilFlavor::I8));

        let u8_prim = CilPrimitive::u8(42);
        assert!(matches!(u8_prim.to_flavor(), CilFlavor::U8));

        let r4_prim = CilPrimitive::r4(3.04);
        assert!(matches!(r4_prim.to_flavor(), CilFlavor::R4));

        let r8_prim = CilPrimitive::r8(3.04);
        assert!(matches!(r8_prim.to_flavor(), CilFlavor::R8));

        let i_prim = CilPrimitive::i(42);
        assert!(matches!(i_prim.to_flavor(), CilFlavor::I));

        let u_prim = CilPrimitive::u(42);
        assert!(matches!(u_prim.to_flavor(), CilFlavor::U));

        let obj_prim = CilPrimitive::new(CilPrimitiveKind::Object);
        assert!(matches!(obj_prim.to_flavor(), CilFlavor::Object));

        let str_prim = CilPrimitive::string("Hello");
        assert!(matches!(str_prim.to_flavor(), CilFlavor::String));

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        if let CilFlavor::GenericParameter { index, method } = var_prim.to_flavor() {
            assert_eq!(index, 0);
            assert!(!method);
        } else {
            panic!("Expected GenericParameter flavor");
        }

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        if let CilFlavor::GenericParameter { index, method } = mvar_prim.to_flavor() {
            assert_eq!(index, 0);
            assert!(method);
        } else {
            panic!("Expected GenericParameter flavor");
        }
    }

    #[test]
    fn test_from_conversions() {
        let bool_prim: CilPrimitive = true.into();
        assert_eq!(bool_prim.kind, CilPrimitiveKind::Boolean);
        assert_eq!(bool_prim.as_boolean(), Some(true));

        let int_prim: CilPrimitive = 42i32.into();
        assert_eq!(int_prim.kind, CilPrimitiveKind::I4);
        assert_eq!(int_prim.as_i32(), Some(42));

        let string_prim: CilPrimitive = "Hello".into();
        assert_eq!(string_prim.kind, CilPrimitiveKind::String);
        assert_eq!(string_prim.as_string(), Some("Hello".to_string()));

        let i8_prim: CilPrimitive = 42i8.into();
        assert_eq!(i8_prim.kind, CilPrimitiveKind::I1);
        assert_eq!(i8_prim.as_i32(), Some(42));

        let u8_prim: CilPrimitive = 42u8.into();
        assert_eq!(u8_prim.kind, CilPrimitiveKind::U1);
        assert_eq!(u8_prim.as_i32(), Some(42));

        let i16_prim: CilPrimitive = 42i16.into();
        assert_eq!(i16_prim.kind, CilPrimitiveKind::I2);
        assert_eq!(i16_prim.as_i32(), Some(42));

        let u16_prim: CilPrimitive = 42u16.into();
        assert_eq!(u16_prim.kind, CilPrimitiveKind::U2);
        assert_eq!(u16_prim.as_i32(), Some(42));

        let u32_prim: CilPrimitive = 42u32.into();
        assert_eq!(u32_prim.kind, CilPrimitiveKind::U4);
        assert_eq!(u32_prim.as_i32(), Some(42));

        let i64_prim: CilPrimitive = 42i64.into();
        assert_eq!(i64_prim.kind, CilPrimitiveKind::I8);
        assert_eq!(i64_prim.as_i64(), Some(42));

        let u64_prim: CilPrimitive = 42u64.into();
        assert_eq!(u64_prim.kind, CilPrimitiveKind::U8);
        assert_eq!(u64_prim.as_i64(), Some(42));

        let f32_prim: CilPrimitive = 3.01f32.into();
        assert_eq!(f32_prim.kind, CilPrimitiveKind::R4);
        assert!((f32_prim.as_f64().unwrap() - 3.01).abs() < 0.001);

        let f64_prim: CilPrimitive = 3.00002f64.into();
        assert_eq!(f64_prim.kind, CilPrimitiveKind::R8);
        assert!((f64_prim.as_f64().unwrap() - 3.00002).abs() < 0.00001);

        let char_prim: CilPrimitive = 'A'.into();
        assert_eq!(char_prim.kind, CilPrimitiveKind::Char);

        let string_owned_prim: CilPrimitive = "Hello".to_string().into();
        assert_eq!(string_owned_prim.kind, CilPrimitiveKind::String);
        assert_eq!(string_owned_prim.as_string(), Some("Hello".to_string()));
    }

    #[test]
    fn test_try_into_conversions() {
        let bool_prim = CilPrimitive::boolean(true);
        let bool_val: bool = bool_prim.try_into().unwrap();
        assert!(bool_val);

        let int_prim = CilPrimitive::i4(42);
        let int_val: i32 = int_prim.try_into().unwrap();
        assert_eq!(int_val, 42);

        let string_prim = CilPrimitive::string("Hello");
        let string_val: String = string_prim.try_into().unwrap();
        assert_eq!(string_val, "Hello");

        let string_prim = CilPrimitive::string("Hello");
        let int_result: Result<i32> = string_prim.try_into();
        assert!(int_result.is_err());
        assert!(matches!(int_result, Err(Error::TypeConversionInvalid)));

        let i64_prim = CilPrimitive::i8(42);
        let i64_val: i64 = i64_prim.try_into().unwrap();
        assert_eq!(i64_val, 42);

        let f64_prim = CilPrimitive::r8(3.0);
        let f64_val: f64 = f64_prim.try_into().unwrap();
        assert!((f64_val - 3.0).abs() < 0.00001);

        let large_i64 = CilPrimitive::i8(i64::MAX);
        let i32_result: Result<i32> = large_i64.try_into();
        assert!(i32_result.is_err());

        let large_u64 = CilPrimitive::u8(u64::MAX);
        let i64_result: Result<i64> = large_u64.try_into();
        assert!(i64_result.is_err());
    }

    #[test]
    fn test_display() {
        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.to_string(), "true");

        let int_prim = CilPrimitive::i4(42);
        assert_eq!(int_prim.to_string(), "42");

        let string_prim = CilPrimitive::string("Hello");
        assert_eq!(string_prim.to_string(), "\"Hello\"");

        let bytes_prim = CilPrimitive {
            kind: CilPrimitiveKind::I4,
            data: CilPrimitiveData::Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        };
        assert_eq!(bytes_prim.to_string(), "Bytes[01 02 03 04 05 06 07 08...]");

        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_prim.to_string(), "System.Void");

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.to_string(), "'A'");

        let i1_prim = CilPrimitive::i1(-42);
        assert_eq!(i1_prim.to_string(), "-42");

        let u1_prim = CilPrimitive::u1(255);
        assert_eq!(u1_prim.to_string(), "255");

        let i2_prim = CilPrimitive::i2(-1000);
        assert_eq!(i2_prim.to_string(), "-1000");

        let u2_prim = CilPrimitive::u2(65535);
        assert_eq!(u2_prim.to_string(), "65535");

        let u4_prim = CilPrimitive::u4(4294967295);
        assert_eq!(u4_prim.to_string(), "4294967295");

        let i8_prim = CilPrimitive::i8(-1000000000000);
        assert_eq!(i8_prim.to_string(), "-1000000000000");

        let u8_prim = CilPrimitive::u8(18446744073709551615);
        assert_eq!(u8_prim.to_string(), "18446744073709551615");

        let r4_prim = CilPrimitive::r4(3.01);
        assert!(r4_prim.to_string().starts_with("3.0"));

        let r8_prim = CilPrimitive::r8(3.01);
        assert!(r8_prim.to_string().starts_with("3.0"));

        let i_prim = CilPrimitive::i(42);
        assert_eq!(i_prim.to_string(), "42");

        let u_prim = CilPrimitive::u(42);
        assert_eq!(u_prim.to_string(), "42");

        let small_bytes_prim = CilPrimitive {
            kind: CilPrimitiveKind::I4,
            data: CilPrimitiveData::Bytes(vec![1, 2, 3]),
        };
        assert_eq!(small_bytes_prim.to_string(), "Bytes[01 02 03]");
    }

    #[test]
    fn test_serialization() {
        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.to_bytes(), vec![1]);

        let int_prim = CilPrimitive::i4(42);
        assert_eq!(int_prim.to_bytes(), vec![42, 0, 0, 0]);

        let string_prim = CilPrimitive::string("Hello");
        assert_eq!(string_prim.to_bytes(), "Hello".as_bytes());

        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert!(void_prim.to_bytes().is_empty());

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.to_bytes(), vec![65, 0]);

        let i1_prim = CilPrimitive::i1(-1);
        assert_eq!(i1_prim.to_bytes(), vec![255]);

        let u1_prim = CilPrimitive::u1(255);
        assert_eq!(u1_prim.to_bytes(), vec![255]);

        let i2_prim = CilPrimitive::i2(-1);
        assert_eq!(i2_prim.to_bytes(), vec![255, 255]);

        let u2_prim = CilPrimitive::u2(65535);
        assert_eq!(u2_prim.to_bytes(), vec![255, 255]);

        let i8_prim = CilPrimitive::i8(-1);
        assert_eq!(
            i8_prim.to_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );

        let u8_prim = CilPrimitive::u8(0xFFFFFFFFFFFFFFFF);
        assert_eq!(
            u8_prim.to_bytes(),
            vec![255, 255, 255, 255, 255, 255, 255, 255]
        );

        let bytes_prim = CilPrimitive {
            kind: CilPrimitiveKind::U1,
            data: CilPrimitiveData::Bytes(vec![1, 2, 3, 4]),
        };
        assert_eq!(bytes_prim.to_bytes(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_primitive_token() {
        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_prim.token().value(), 0xF0000001);

        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.token().value(), 0xF0000002);

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.token().value(), 0xF0000003);

        let i1_prim = CilPrimitive::i1(0);
        assert_eq!(i1_prim.token().value(), 0xF0000004);

        let u1_prim = CilPrimitive::u1(0);
        assert_eq!(u1_prim.token().value(), 0xF0000005);

        let i2_prim = CilPrimitive::i2(0);
        assert_eq!(i2_prim.token().value(), 0xF0000006);

        let u2_prim = CilPrimitive::u2(0);
        assert_eq!(u2_prim.token().value(), 0xF0000007);

        let i4_prim = CilPrimitive::i4(0);
        assert_eq!(i4_prim.token().value(), 0xF0000008);

        let u4_prim = CilPrimitive::u4(0);
        assert_eq!(u4_prim.token().value(), 0xF0000009);

        let i8_prim = CilPrimitive::i8(0);
        assert_eq!(i8_prim.token().value(), 0xF000000A);

        let u8_prim = CilPrimitive::u8(0);
        assert_eq!(u8_prim.token().value(), 0xF000000B);

        let r4_prim = CilPrimitive::r4(0.0);
        assert_eq!(r4_prim.token().value(), 0xF000000C);

        let r8_prim = CilPrimitive::r8(0.0);
        assert_eq!(r8_prim.token().value(), 0xF000000D);

        let i_prim = CilPrimitive::i(0);
        assert_eq!(i_prim.token().value(), 0xF000000E);

        let u_prim = CilPrimitive::u(0);
        assert_eq!(u_prim.token().value(), 0xF000000F);

        let obj_prim = CilPrimitive::new(CilPrimitiveKind::Object);
        assert_eq!(obj_prim.token().value(), 0xF0000010);

        let str_prim = CilPrimitive::string("");
        assert_eq!(str_prim.token().value(), 0xF0000011);

        let typed_ref_prim = CilPrimitive::new(CilPrimitiveKind::TypedReference);
        assert_eq!(typed_ref_prim.token().value(), 0xF0000012);

        let value_type_prim = CilPrimitive::new(CilPrimitiveKind::ValueType);
        assert_eq!(value_type_prim.token().value(), 0xF0000013);

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        assert_eq!(var_prim.token().value(), 0xF0000014);

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        assert_eq!(mvar_prim.token().value(), 0xF0000015);

        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.token().value(), 0xF0000016);

        let class_prim = CilPrimitive::new(CilPrimitiveKind::Class);
        assert_eq!(class_prim.token().value(), 0xF0000017);
    }

    #[test]
    fn test_as_byte() {
        let void_prim = CilPrimitive::new(CilPrimitiveKind::Void);
        assert_eq!(void_prim.as_byte(), ELEMENT_TYPE::VOID);

        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.as_byte(), ELEMENT_TYPE::BOOLEAN);

        let char_prim = CilPrimitive::char('A');
        assert_eq!(char_prim.as_byte(), ELEMENT_TYPE::CHAR);

        let i1_prim = CilPrimitive::i1(0);
        assert_eq!(i1_prim.as_byte(), ELEMENT_TYPE::I1);

        let u1_prim = CilPrimitive::u1(0);
        assert_eq!(u1_prim.as_byte(), ELEMENT_TYPE::U1);

        let i2_prim = CilPrimitive::i2(0);
        assert_eq!(i2_prim.as_byte(), ELEMENT_TYPE::I2);

        let u2_prim = CilPrimitive::u2(0);
        assert_eq!(u2_prim.as_byte(), ELEMENT_TYPE::U2);

        let i4_prim = CilPrimitive::i4(0);
        assert_eq!(i4_prim.as_byte(), ELEMENT_TYPE::I4);

        let u4_prim = CilPrimitive::u4(0);
        assert_eq!(u4_prim.as_byte(), ELEMENT_TYPE::U4);

        let i8_prim = CilPrimitive::i8(0);
        assert_eq!(i8_prim.as_byte(), ELEMENT_TYPE::I8);

        let u8_prim = CilPrimitive::u8(0);
        assert_eq!(u8_prim.as_byte(), ELEMENT_TYPE::U8);

        let r4_prim = CilPrimitive::r4(0.0);
        assert_eq!(r4_prim.as_byte(), ELEMENT_TYPE::R4);

        let r8_prim = CilPrimitive::r8(0.0);
        assert_eq!(r8_prim.as_byte(), ELEMENT_TYPE::R8);

        let i_prim = CilPrimitive::i(0);
        assert_eq!(i_prim.as_byte(), ELEMENT_TYPE::I);

        let u_prim = CilPrimitive::u(0);
        assert_eq!(u_prim.as_byte(), ELEMENT_TYPE::U);

        let obj_prim = CilPrimitive::new(CilPrimitiveKind::Object);
        assert_eq!(obj_prim.as_byte(), ELEMENT_TYPE::OBJECT);

        let str_prim = CilPrimitive::string("");
        assert_eq!(str_prim.as_byte(), ELEMENT_TYPE::STRING);

        let typed_ref_prim = CilPrimitive::new(CilPrimitiveKind::TypedReference);
        assert_eq!(typed_ref_prim.as_byte(), ELEMENT_TYPE::TYPEDBYREF);

        let value_type_prim = CilPrimitive::new(CilPrimitiveKind::ValueType);
        assert_eq!(value_type_prim.as_byte(), ELEMENT_TYPE::VALUETYPE);

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        assert_eq!(var_prim.as_byte(), ELEMENT_TYPE::VAR);

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        assert_eq!(mvar_prim.as_byte(), ELEMENT_TYPE::MVAR);

        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.as_byte(), 0xFF); // Not used in signatures

        let class_prim = CilPrimitive::new(CilPrimitiveKind::Class);
        assert_eq!(class_prim.as_byte(), ELEMENT_TYPE::CLASS);
    }

    #[test]
    fn test_from_byte() {
        let void_prim = CilPrimitive::from_byte(ELEMENT_TYPE::VOID).unwrap();
        assert_eq!(void_prim.kind, CilPrimitiveKind::Void);

        let bool_prim = CilPrimitive::from_byte(ELEMENT_TYPE::BOOLEAN).unwrap();
        assert_eq!(bool_prim.kind, CilPrimitiveKind::Boolean);

        let char_prim = CilPrimitive::from_byte(ELEMENT_TYPE::CHAR).unwrap();
        assert_eq!(char_prim.kind, CilPrimitiveKind::Char);

        let i1_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I1).unwrap();
        assert_eq!(i1_prim.kind, CilPrimitiveKind::I1);

        let u1_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U1).unwrap();
        assert_eq!(u1_prim.kind, CilPrimitiveKind::U1);

        let i2_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I2).unwrap();
        assert_eq!(i2_prim.kind, CilPrimitiveKind::I2);

        let u2_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U2).unwrap();
        assert_eq!(u2_prim.kind, CilPrimitiveKind::U2);

        let i4_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I4).unwrap();
        assert_eq!(i4_prim.kind, CilPrimitiveKind::I4);

        let u4_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U4).unwrap();
        assert_eq!(u4_prim.kind, CilPrimitiveKind::U4);

        let i8_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I8).unwrap();
        assert_eq!(i8_prim.kind, CilPrimitiveKind::I8);

        let u8_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U8).unwrap();
        assert_eq!(u8_prim.kind, CilPrimitiveKind::U8);

        let r4_prim = CilPrimitive::from_byte(ELEMENT_TYPE::R4).unwrap();
        assert_eq!(r4_prim.kind, CilPrimitiveKind::R4);

        let r8_prim = CilPrimitive::from_byte(ELEMENT_TYPE::R8).unwrap();
        assert_eq!(r8_prim.kind, CilPrimitiveKind::R8);

        let i_prim = CilPrimitive::from_byte(ELEMENT_TYPE::I).unwrap();
        assert_eq!(i_prim.kind, CilPrimitiveKind::I);

        let u_prim = CilPrimitive::from_byte(ELEMENT_TYPE::U).unwrap();
        assert_eq!(u_prim.kind, CilPrimitiveKind::U);

        let obj_prim = CilPrimitive::from_byte(ELEMENT_TYPE::OBJECT).unwrap();
        assert_eq!(obj_prim.kind, CilPrimitiveKind::Object);

        let str_prim = CilPrimitive::from_byte(ELEMENT_TYPE::STRING).unwrap();
        assert_eq!(str_prim.kind, CilPrimitiveKind::String);

        let typed_ref_prim = CilPrimitive::from_byte(ELEMENT_TYPE::TYPEDBYREF).unwrap();
        assert_eq!(typed_ref_prim.kind, CilPrimitiveKind::TypedReference);

        let result = CilPrimitive::from_byte(0xFF);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let result = CilPrimitive::from_byte(ELEMENT_TYPE::VALUETYPE);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let result = CilPrimitive::from_byte(ELEMENT_TYPE::VAR);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let result = CilPrimitive::from_byte(ELEMENT_TYPE::MVAR);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));
    }

    #[test]
    fn test_type_info() {
        let bool_prim = CilPrimitive::boolean(true);
        assert_eq!(bool_prim.namespace(), "System");
        assert_eq!(bool_prim.name(), "Boolean");
        assert_eq!(bool_prim.clr_full_name(), "System.Boolean");

        let int_prim = CilPrimitive::i4(42);
        assert_eq!(int_prim.namespace(), "System");
        assert_eq!(int_prim.name(), "Int32");
        assert_eq!(int_prim.clr_full_name(), "System.Int32");

        let var_prim = CilPrimitive::new(CilPrimitiveKind::Var);
        assert_eq!(var_prim.namespace(), "");
        assert_eq!(var_prim.name(), "<Generic Parameter>");
        assert_eq!(var_prim.clr_full_name(), "<Generic Parameter>");

        let mvar_prim = CilPrimitive::new(CilPrimitiveKind::MVar);
        assert_eq!(mvar_prim.namespace(), "");
        assert_eq!(mvar_prim.name(), "<Generic Method Parameter>");
        assert_eq!(mvar_prim.clr_full_name(), "<Generic Method Parameter>");

        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.namespace(), "");
        assert_eq!(null_prim.name(), "<null>");
        assert_eq!(null_prim.clr_full_name(), "<null>");
    }

    #[test]
    fn test_is_value_type_and_reference_type() {
        assert!(CilPrimitive::boolean(true).is_value_type());
        assert!(CilPrimitive::char('A').is_value_type());
        assert!(CilPrimitive::i1(0).is_value_type());
        assert!(CilPrimitive::u1(0).is_value_type());
        assert!(CilPrimitive::i2(0).is_value_type());
        assert!(CilPrimitive::u2(0).is_value_type());
        assert!(CilPrimitive::i4(0).is_value_type());
        assert!(CilPrimitive::u4(0).is_value_type());
        assert!(CilPrimitive::i8(0).is_value_type());
        assert!(CilPrimitive::u8(0).is_value_type());
        assert!(CilPrimitive::r4(0.0).is_value_type());
        assert!(CilPrimitive::r8(0.0).is_value_type());
        assert!(CilPrimitive::i(0).is_value_type());
        assert!(CilPrimitive::u(0).is_value_type());
        assert!(CilPrimitive::new(CilPrimitiveKind::ValueType).is_value_type());

        assert!(!CilPrimitive::new(CilPrimitiveKind::Void).is_value_type());
        assert!(!CilPrimitive::new(CilPrimitiveKind::Object).is_value_type());
        assert!(!CilPrimitive::string("").is_value_type());

        assert!(CilPrimitive::new(CilPrimitiveKind::Object).is_reference_type());
        assert!(CilPrimitive::string("").is_reference_type());

        assert!(!CilPrimitive::boolean(true).is_reference_type());
        assert!(!CilPrimitive::i4(0).is_reference_type());
        assert!(!CilPrimitive::new(CilPrimitiveKind::Void).is_reference_type());
    }

    #[test]
    fn test_cil_primitive_kind_from_byte() {
        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::BOOLEAN).unwrap(),
            CilPrimitiveKind::Boolean
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::CHAR).unwrap(),
            CilPrimitiveKind::Char
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I1).unwrap(),
            CilPrimitiveKind::I1
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U1).unwrap(),
            CilPrimitiveKind::U1
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I2).unwrap(),
            CilPrimitiveKind::I2
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U2).unwrap(),
            CilPrimitiveKind::U2
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I4).unwrap(),
            CilPrimitiveKind::I4
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U4).unwrap(),
            CilPrimitiveKind::U4
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I8).unwrap(),
            CilPrimitiveKind::I8
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U8).unwrap(),
            CilPrimitiveKind::U8
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::R4).unwrap(),
            CilPrimitiveKind::R4
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::R8).unwrap(),
            CilPrimitiveKind::R8
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::I).unwrap(),
            CilPrimitiveKind::I
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::U).unwrap(),
            CilPrimitiveKind::U
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::STRING).unwrap(),
            CilPrimitiveKind::String
        );

        assert_eq!(
            CilPrimitiveKind::from_byte(ELEMENT_TYPE::CLASS).unwrap(),
            CilPrimitiveKind::Class
        );

        let result = CilPrimitiveKind::from_byte(0xFF);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));
    }

    #[test]
    fn test_primitive_data_conversions() {
        let default_data = CilPrimitiveData::default();
        assert!(matches!(default_data, CilPrimitiveData::None));

        let bool_data = CilPrimitiveData::Boolean(true);
        assert_eq!(bool_data.as_boolean(), Some(true));
        assert_eq!(bool_data.as_i32(), Some(1));
        assert_eq!(bool_data.as_i64(), Some(1));
        assert_eq!(bool_data.as_f64(), Some(1.0));
        assert_eq!(bool_data.as_string(), Some("true".to_string()));

        let i4_data = CilPrimitiveData::I4(42);
        assert!((i4_data.as_f64().unwrap() - 42.0).abs() < 0.00001);

        let r4_data = CilPrimitiveData::R4(42.0);
        assert_eq!(r4_data.as_i32(), Some(42));
        assert_eq!(r4_data.as_i64(), Some(42));

        let max_i32_as_i64 = CilPrimitiveData::I8(i32::MAX as i64);
        assert_eq!(max_i32_as_i64.as_i32(), Some(i32::MAX));

        let over_i32_as_i64 = CilPrimitiveData::I8((i32::MAX as i64) + 1);
        assert_eq!(over_i32_as_i64.as_i32(), None);

        let min_i32_as_i64 = CilPrimitiveData::I8(i32::MIN as i64);
        assert_eq!(min_i32_as_i64.as_i32(), Some(i32::MIN));

        let under_i32_as_i64 = CilPrimitiveData::I8(i64::from(i32::MIN) - 1);
        assert_eq!(under_i32_as_i64.as_i32(), None);

        let max_i32_as_u32 = CilPrimitiveData::U4(u32::try_from(i32::MAX).unwrap());
        assert_eq!(max_i32_as_u32.as_i32(), Some(i32::MAX));

        let over_i32_as_u32 = CilPrimitiveData::U4(u32::try_from(i32::MAX).unwrap() + 1);
        assert_eq!(over_i32_as_u32.as_i32(), None);

        let max_i64_as_u64 = CilPrimitiveData::U8(u64::try_from(i64::MAX).unwrap());
        assert_eq!(max_i64_as_u64.as_i64(), Some(i64::MAX));

        let over_i64_as_u64 = CilPrimitiveData::U8(u64::try_from(i64::MAX).unwrap() + 1);
        assert_eq!(over_i64_as_u64.as_i64(), None);

        let max_i32_as_f32 = CilPrimitiveData::R4(i32::MAX as f32);
        assert_eq!(max_i32_as_f32.as_i32(), Some(i32::MAX));

        let over_i32_as_f32 = CilPrimitiveData::R4((i32::MAX as f32) * 2.0);
        assert_eq!(over_i32_as_f32.as_i32(), None);

        let max_i64_as_f64 = CilPrimitiveData::R8(i64::MAX as f64);
        assert_eq!(max_i64_as_f64.as_i64(), Some(i64::MAX));

        let over_i64_as_f64 = CilPrimitiveData::R8((i64::MAX as f64) * 2.0);
        assert_eq!(over_i64_as_f64.as_i64(), None);
    }

    #[test]
    fn test_from_blob_error_cases() {
        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::BOOLEAN, &[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::OutOfBounds)));

        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::CHAR, &[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::OutOfBounds)));

        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::I4, &[1, 2]);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::OutOfBounds)));

        let result = CilPrimitiveData::from_bytes(ELEMENT_TYPE::STRING, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CilPrimitiveData::String("".to_string()));
    }

    #[test]
    fn test_try_from_cil_flavor() {
        let flavor = CilFlavor::I4;
        let prim = CilPrimitive::try_from(flavor).unwrap();
        assert_eq!(prim.kind, CilPrimitiveKind::I4);

        let flavor = CilFlavor::Boolean;
        let prim = CilPrimitive::try_from(flavor).unwrap();
        assert_eq!(prim.kind, CilPrimitiveKind::Boolean);

        let flavor = CilFlavor::Pointer;
        let result = CilPrimitive::try_from(flavor);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));

        let flavor = CilFlavor::Array {
            rank: 1,
            dimensions: vec![],
        };
        let result = CilPrimitive::try_from(flavor);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotPrimitive)));
    }

    #[test]
    fn test_null_primitive() {
        let null_prim = CilPrimitive::null();
        assert_eq!(null_prim.kind, CilPrimitiveKind::Null);
        assert_eq!(null_prim.data, CilPrimitiveData::None);

        assert_eq!(null_prim.as_boolean(), None);
        assert_eq!(null_prim.as_i32(), None);
        assert_eq!(null_prim.as_i64(), None);
        assert_eq!(null_prim.as_f64(), None);
        assert_eq!(null_prim.as_string(), None);

        assert_eq!(null_prim.token().value(), 0xF0000016);

        assert!(!null_prim.is_value_type());
        assert!(!null_prim.is_reference_type());
    }
}
