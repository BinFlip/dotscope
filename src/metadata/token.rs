use std::fmt;
use std::hash::{Hash, Hasher};

/// A metadata token representing a reference to a metadata table entry.
///
/// Tokens in .NET metadata consist of a 32-bit value where:
/// - The high byte (bits 24-31) indicates the table type
/// - The low 24 bits (bits 0-23) indicate the row index within that table
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Token(pub u32);

impl Token {
    /// Creates a new token from a raw 32-bit value
    #[must_use]
    pub fn new(value: u32) -> Self {
        Token(value)
    }

    /// Returns the raw token value
    #[must_use]
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Extracts the table type from the token (high byte)
    #[must_use]
    pub fn table(&self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Extracts the row index from the token (low 24 bits)
    #[must_use]
    pub fn row(&self) -> u32 {
        self.0 & 0x00FF_FFFF
    }

    /// Returns true if this is a null token (value 0)
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for Token {
    fn from(value: u32) -> Self {
        Token(value)
    }
}

impl From<Token> for u32 {
    fn from(token: Token) -> Self {
        token.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Token(0x{:08x}, table: 0x{:02x}, row: {})",
            self.0,
            self.table(),
            self.row()
        )
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl Hash for Token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_token_new() {
        let token = Token::new(0x06000001);
        assert_eq!(token.value(), 0x06000001);
    }

    #[test]
    fn test_token_value() {
        let token = Token(0x02000005);
        assert_eq!(token.value(), 0x02000005);
    }

    #[test]
    fn test_token_table() {
        let token = Token(0x06000001);
        assert_eq!(token.table(), 0x06);

        let token2 = Token(0x02000005);
        assert_eq!(token2.table(), 0x02);

        let token3 = Token(0x00000000);
        assert_eq!(token3.table(), 0x00);
    }

    #[test]
    fn test_token_row() {
        let token = Token(0x06000001);
        assert_eq!(token.row(), 1);

        let token2 = Token(0x02000005);
        assert_eq!(token2.row(), 5);

        let token3 = Token(0x06FFFFFF);
        assert_eq!(token3.row(), 0x00FFFFFF);
    }

    #[test]
    fn test_token_is_null() {
        let null_token = Token(0x00000000);
        assert!(null_token.is_null());

        let non_null_token = Token(0x06000001);
        assert!(!non_null_token.is_null());
    }

    #[test]
    fn test_token_from_conversion() {
        let value = 0x06000001u32;
        let token: Token = value.into();
        assert_eq!(token.value(), value);

        let back_to_u32: u32 = token.into();
        assert_eq!(back_to_u32, value);
    }

    #[test]
    fn test_token_display() {
        let token = Token(0x06000001);
        assert_eq!(format!("{}", token), "0x06000001");

        let token2 = Token(0x00000000);
        assert_eq!(format!("{}", token2), "0x00000000");
    }

    #[test]
    fn test_token_debug() {
        let token = Token(0x06000001);
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("Token(0x06000001"));
        assert!(debug_str.contains("table: 0x06"));
        assert!(debug_str.contains("row: 1"));
    }

    #[test]
    fn test_token_equality() {
        let token1 = Token(0x06000001);
        let token2 = Token(0x06000001);
        let token3 = Token(0x06000002);

        assert_eq!(token1, token2);
        assert_ne!(token1, token3);
    }

    #[test]
    fn test_token_ordering() {
        let token1 = Token(0x06000001);
        let token2 = Token(0x06000002);
        let token3 = Token(0x07000001);

        assert!(token1 < token2);
        assert!(token2 < token3);
        assert!(token1 < token3);
    }

    #[test]
    fn test_token_clone() {
        let token1 = Token(0x06000001);
        let token2 = token1;
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_token_copy() {
        let token1 = Token(0x06000001);
        let token2 = token1; // Copy semantics
        assert_eq!(token1, token2);
        // Both should still be usable
        assert_eq!(token1.value(), 0x06000001);
        assert_eq!(token2.value(), 0x06000001);
    }

    #[test]
    fn test_token_hash() {
        let mut map = HashMap::new();
        let token1 = Token(0x06000001);
        let token2 = Token(0x06000002);

        map.insert(token1, "Method1");
        map.insert(token2, "Method2");

        assert_eq!(map.get(&token1), Some(&"Method1"));
        assert_eq!(map.get(&token2), Some(&"Method2"));
    }

    #[test]
    fn test_token_boundary_values() {
        // Test maximum values
        let max_token = Token(0xFFFFFFFF);
        assert_eq!(max_token.table(), 0xFF);
        assert_eq!(max_token.row(), 0x00FFFFFF);

        // Test minimum values
        let min_token = Token(0x00000000);
        assert_eq!(min_token.table(), 0x00);
        assert_eq!(min_token.row(), 0x00000000);

        // Test table boundary
        let table_boundary = Token(0x01000000);
        assert_eq!(table_boundary.table(), 0x01);
        assert_eq!(table_boundary.row(), 0x00000000);
    }

    #[test]
    fn test_common_token_types() {
        // Test common .NET metadata table tokens

        // TypeDef (0x02)
        let typedef_token = Token(0x02000001);
        assert_eq!(typedef_token.table(), 0x02);
        assert_eq!(typedef_token.row(), 1);

        // MethodDef (0x06)
        let methoddef_token = Token(0x06000001);
        assert_eq!(methoddef_token.table(), 0x06);
        assert_eq!(methoddef_token.row(), 1);

        // TypeRef (0x01)
        let typeref_token = Token(0x01000001);
        assert_eq!(typeref_token.table(), 0x01);
        assert_eq!(typeref_token.row(), 1);

        // MemberRef (0x0A)
        let memberref_token = Token(0x0A000001);
        assert_eq!(memberref_token.table(), 0x0A);
        assert_eq!(memberref_token.row(), 1);
    }
}
