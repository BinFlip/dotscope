//! Low-level byte stream parser for CIL and metadata decoding.
//!
//! The [`Parser`] type provides methods for reading primitive values, seeking, and slicing
//! byte streams. It is used internally by the disassembler and metadata loader, but is also
//! available for advanced users who need to decode custom data.
//!
//! # Example
//!
//! ```rust,no_run
//! use dotscope::Parser;
//! let data = [0x01, 0x02, 0x03, 0x04];
//! let mut parser = Parser::new(&data);
//! let value = parser.read_le::<u16>()?;
//! assert_eq!(value, 0x0201);
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    file::io::{read_be_at, read_le_at, CilIO},
    metadata::token::Token,
    Error::OutOfBounds,
    Result,
};

/// A generic binary data parser for reading .NET metadata structures.
///
/// `Parser` provides a cursor-based interface for reading binary data in both
/// little-endian and big-endian formats. It's designed specifically for parsing
/// .NET metadata structures that follow ECMA-335 specifications, including
/// method signatures, type signatures, custom attributes, and marshalling data.
///
/// The parser maintains an internal position cursor and provides bounds checking
/// to prevent buffer overruns when reading malformed or truncated data.
///
/// # Features
///
/// - **Bounds checking**: All read operations validate data availability
/// - **Endianness support**: Both little-endian and big-endian reading
/// - **Position tracking**: Maintains current offset for sequential parsing
/// - **Flexible seeking**: Random access to any position within the data
/// - **Type safety**: Strongly typed reading methods for common data types
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::Parser;
///
/// let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// let mut parser = Parser::new(&data);
///
/// // Read little-endian values
/// let first = parser.read_le::<u32>()?;
/// assert_eq!(first, 0x04030201);
///
/// // Seek to a specific position
/// parser.seek(6)?;
/// let last_bytes = parser.read_le::<u16>()?;
/// assert_eq!(last_bytes, 0x0807);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Metadata Parsing Usage
///
/// The Parser handles compressed integers, variable-length encodings, and complex metadata
/// structures found in .NET assemblies. It supports reading calling conventions, parameter
/// counts, type signatures, and other binary metadata formats efficiently.
pub struct Parser<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    /// Create a new `Parser` from a byte slice
    ///
    /// ## Arguments
    /// * 'data' - The byte slice to read from
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Parser { data, position: 0 }
    }

    /// Returns the length of the data
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the parser has no data
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns true if there is more data to parse
    #[must_use]
    pub fn has_more_data(&self) -> bool {
        self.position < self.data.len()
    }

    /// Move current position to N
    ///
    /// ## Arguments
    /// * 'pos' - The position to move the cursor to
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if position is beyond the data length
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos >= self.data.len() {
            return Err(OutOfBounds);
        }

        self.position = pos;
        Ok(())
    }

    /// Move the position forward by one
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if advancing would exceed the data length
    pub fn advance(&mut self) -> Result<()> {
        self.advance_by(1)
    }

    /// Mode the position forward by N
    ///
    /// ## Arguments
    /// * 'step' - Amount of steps to take
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if advancing by step would exceed the data length
    pub fn advance_by(&mut self, step: usize) -> Result<()> {
        if self.position + step >= self.data.len() {
            return Err(OutOfBounds);
        }

        self.position += step;
        Ok(())
    }

    /// Get the current position of the parser
    #[must_use]
    pub fn pos(&self) -> usize {
        self.position
    }

    /// Peak a single byte without moving
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if position is at or beyond the data length
    pub fn peek_byte(&self) -> Result<u8> {
        if self.position >= self.data.len() {
            return Err(OutOfBounds);
        }
        Ok(self.data[self.position])
    }

    /// Align the position to a specific boundary
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if aligning would exceed the data length
    pub fn align(&mut self, alignment: usize) -> Result<()> {
        let padding = (alignment - (self.position % alignment)) % alignment;
        if self.position + padding > self.data.len() {
            return Err(OutOfBounds);
        }
        self.position += padding;
        Ok(())
    }

    /// Read a type T from the current position in little-endian, and advance accordingly
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length
    pub fn read_le<T: CilIO>(&mut self) -> Result<T> {
        read_le_at::<T>(self.data, &mut self.position)
    }

    /// Read a type T from the current position in big-endian, and advance accordingly
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length
    pub fn read_be<T: CilIO>(&mut self) -> Result<T> {
        read_be_at::<T>(self.data, &mut self.position)
    }

    /// Read a compressed unsigned integer as defined in II.23.2
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Malformed`] for invalid compressed uint format
    pub fn read_compressed_uint(&mut self) -> Result<u32> {
        let first_byte = self.read_le::<u8>()?;

        // 1-byte encoding: 0xxxxxxx
        if (first_byte & 0x80) == 0 {
            return Ok(u32::from(first_byte));
        }

        // 2-byte encoding: 10xxxxxx xxxxxxxx
        if (first_byte & 0xC0) == 0x80 {
            let second_byte = self.read_le::<u8>()?;
            let value = ((u32::from(first_byte) & 0x3F) << 8) | u32::from(second_byte);
            return Ok(value);
        }

        // 4-byte encoding: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if (first_byte & 0xE0) == 0xC0 {
            let b1 = u32::from(self.read_le::<u8>()?);
            let b2 = u32::from(self.read_le::<u8>()?);
            let b3 = u32::from(self.read_le::<u8>()?);
            let value = ((u32::from(first_byte) & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3;
            return Ok(value);
        }

        Err(malformed_error!("Invalid compressed uint - {}", first_byte))
    }

    /// Read a compressed signed integer
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Error::Malformed`] for invalid encoding
    pub fn read_compressed_int(&mut self) -> Result<i32> {
        let unsigned = self.read_compressed_uint()?;

        // Convert to signed based on ECMA-335 II.23.2 encoding rules
        let signed = if (unsigned & 1) == 0 {
            #[allow(clippy::cast_possible_wrap)]
            let result = (unsigned >> 1) as i32;
            result
        } else {
            #[allow(clippy::cast_possible_wrap)]
            let result = -((unsigned >> 1) as i32 + 1);
            result
        };

        Ok(signed)
    }

    /// Read a compressed token
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Error::Malformed`] for invalid token encoding
    pub fn read_compressed_token(&mut self) -> Result<Token> {
        let compressed_token = self.read_compressed_uint()?;

        let table: u32 = match compressed_token & 0x3 {
            0x0 => 0x0200_0000, // TypeDef
            0x1 => 0x0100_0000, // TypeRef
            0x2 => 0x1B00_0000, // TypeSpec
            _ => {
                return Err(malformed_error!(
                    "Invalid compressed token - {}",
                    compressed_token
                ))
            }
        };

        let table_index = compressed_token >> 2;

        Ok(Token::new(table + table_index))
    }

    /// Read a 7-bit encoded integer (used in .NET for variable-length encoding)
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Error::Malformed`] for invalid encoding
    pub fn read_7bit_encoded_int(&mut self) -> Result<u32> {
        let mut value = 0u32;
        let mut shift = 0;

        loop {
            if self.position >= self.data.len() {
                return Err(OutOfBounds);
            }

            let byte = self.data[self.position];
            self.position += 1;

            value |= u32::from(byte & 0x7F) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                break;
            }

            if shift >= 32 {
                return Err(malformed_error!("Invalid 7-bit encoded integer"));
            }
        }

        Ok(value)
    }

    /// Reads a UTF-8 encoded null-terminated string
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Error::Malformed`] for invalid UTF-8
    pub fn read_string_utf8(&mut self) -> Result<String> {
        let start = self.position;
        let mut end = start;

        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }

        if end >= self.data.len() {
            return Err(OutOfBounds);
        }

        let string_data = &self.data[start..end];
        self.position = end + 1; // Skip null terminator

        String::from_utf8(string_data.to_vec()).map_err(|_| {
            malformed_error!("Invalid string - {} - {} - {:?}", start, end, string_data)
        })
    }

    /// Read a length-prefixed string (encoded as a 7-bit encoded length followed by UTF-8 bytes)
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Error::Malformed`] for invalid UTF-8
    pub fn read_prefixed_string_utf8(&mut self) -> Result<String> {
        let length = self.read_7bit_encoded_int()? as usize;

        if self.position + length > self.data.len() {
            return Err(OutOfBounds);
        }

        let string_data = &self.data[self.position..self.position + length];
        self.position += length;

        String::from_utf8(string_data.to_vec()).map_err(|_| {
            malformed_error!(
                "Invalid string - {} - {} - {:?}",
                self.position,
                self.position + length,
                string_data
            )
        })
    }

    /// Read a length-prefixed string (encoded as a 7-bit encoded length followed by UTF-16 bytes)
    ///
    /// # Errors
    /// Returns [`OutOfBounds`] if reading would exceed the data length or [`Error::Malformed`] for invalid UTF-16
    pub fn read_prefixed_string_utf16(&mut self) -> Result<String> {
        let length = self.read_7bit_encoded_int()? as usize;
        if self.position + length > self.data.len() {
            return Err(OutOfBounds);
        }

        if length % 2 != 0 || length < 2 {
            return Err(malformed_error!("Invalid UTF-16 length - {}", length));
        }

        let mut utf16_chars: Vec<u16> = Vec::with_capacity(length / 2);
        for _ in 0..length / 2 {
            let char = self.read_le::<u16>()?;
            utf16_chars.push(char);
        }

        match String::from_utf16(&utf16_chars) {
            Ok(s) => Ok(s),
            Err(_) => Err(malformed_error!(
                "Invalid UTF-16 str - {} - {} - {:?}",
                self.position,
                length,
                utf16_chars
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_compressed_uint() {
        let test_cases = vec![
            (vec![0x03], 3),                            // 1-byte format
            (vec![0x7F], 0x7F),                         // 1-byte format, max value
            (vec![0x80, 0x80], 0x80),                   // 2-byte format, min value
            (vec![0xBF, 0xFF], 0x3FFF),                 // 2-byte format, max value
            (vec![0xC0, 0x00, 0x00, 0x00], 0x00),       // 4-byte format, min value
            (vec![0xDF, 0xFF, 0xFF, 0xFF], 0x1FFFFFFF), // 4-byte format, max value
        ];

        for (input, expected) in test_cases {
            let mut parser = Parser::new(&input);
            let result = parser.read_compressed_uint().unwrap();
            assert_eq!(result, expected);
        }

        // Error on empty data
        let mut parser = Parser::new(&[]);
        assert!(matches!(parser.read_compressed_uint(), Err(OutOfBounds)));
    }

    #[test]
    fn test_read_compressed_int() {
        // Positive small integer: 10 (encoded as 20)
        let mut parser = Parser::new(&[20]);
        assert_eq!(parser.read_compressed_int().unwrap(), 10);

        // Negative small integer: -5 (encoded as 9)
        let mut parser = Parser::new(&[9]);
        assert_eq!(parser.read_compressed_int().unwrap(), -5);

        // Zero (encoded as 0)
        let mut parser = Parser::new(&[0]);
        assert_eq!(parser.read_compressed_int().unwrap(), 0);
    }

    #[test]
    fn test_parse_string() {
        let test_cases = vec![
            (vec![0x61, 0x62, 0x63, 0x00], "abc"), // Simple string
            (vec![0x00], ""),                      // Empty string
            (vec![0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87, 0x00], "中文"), // UTF-8 string
        ];

        for (input, expected) in test_cases {
            let mut parser = Parser::new(&input);
            let result = parser.read_string_utf8().unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_error_handling() {
        // Test unexpected end of data
        let mut parser = Parser::new(&[0x08]); // Just one byte
        assert!(matches!(parser.read_compressed_uint(), Ok(8)));
        assert!(matches!(parser.read_compressed_uint(), Err(OutOfBounds)));
    }

    #[test]
    fn test_read_7bit_encoded_int_single_byte() {
        {
            let input = &[0x00]; // Represents 0
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 0);
            assert_eq!(parser.pos(), 1);
        }

        {
            let input = &[0x7F]; // Represents 127 (max for single byte)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 127);
            assert_eq!(parser.pos(), 1);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_two_bytes() {
        {
            let input = &[0x80, 0x01]; // Represents 128
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 128);
            assert_eq!(parser.pos(), 2);
        }

        {
            let input = &[0xFF, 0x7F]; // Represents 16383 (max for two bytes)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 16383);
            assert_eq!(parser.pos(), 2);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_three_bytes() {
        {
            let input = &[0x80, 0x80, 0x01]; // Represents 16384
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 16384);
            assert_eq!(parser.pos(), 3);
        }

        {
            let input = &[0xFF, 0xFF, 0x7F]; // Represents 2097151 (max for three bytes)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 2097151);
            assert_eq!(parser.pos(), 3);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_four_bytes() {
        {
            let input = &[0x80, 0x80, 0x80, 0x01]; // Represents 2097152
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 2097152);
            assert_eq!(parser.pos(), 4);
        }

        {
            let input = &[0xFF, 0xFF, 0xFF, 0x7F]; // Represents 268435455 (max for four bytes)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 268435455);
            assert_eq!(parser.pos(), 4);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_five_bytes() {
        {
            let input = &[0x80, 0x80, 0x80, 0x80, 0x01]; // Represents 268435456
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 268435456);
            assert_eq!(parser.pos(), 5);
        }

        {
            let input = &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]; // Represents max u32 (4294967295)
            let mut parser = Parser::new(input);
            assert_eq!(parser.read_7bit_encoded_int().unwrap(), 4294967295);
            assert_eq!(parser.pos(), 5);
        }
    }

    #[test]
    fn test_read_7bit_encoded_int_truncated() {
        // Truncated data (should fail)
        let input = &[0x80];
        let mut parser = Parser::new(input);
        assert!(parser.read_7bit_encoded_int().is_err());
    }

    #[test]
    fn test_read_7bit_encoded_int_overflow() {
        // Too many continuation bits (would overflow u32)
        let input = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut parser = Parser::new(input);
        assert!(parser.read_7bit_encoded_int().is_err());
    }
}
