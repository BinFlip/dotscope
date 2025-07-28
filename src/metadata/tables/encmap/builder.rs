//! Builder for constructing `EncMap` table entries
//!
//! This module provides the [`crate::metadata::tables::encmap::EncMapBuilder`] which enables fluent construction
//! of `EncMap` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let encmap_token = EncMapBuilder::new()
//!     .original_token(0x06000001)    // MethodDef token before editing
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{EncMapRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `EncMap` table entries
///
/// Provides a fluent interface for building `EncMap` metadata table entries.
/// These entries provide token mapping during Edit-and-Continue operations,
/// correlating original tokens with their updated counterparts.
///
/// # Required Fields
/// - `original_token`: Original metadata token before editing
///
/// # Edit-and-Continue Mapping
///
/// The EncMap table is used by .NET's Edit-and-Continue debugging feature to
/// track token mappings. When developers modify code during debugging, new
/// metadata is generated with updated token values. The EncMap table preserves
/// the original tokens, using table position for implicit mapping correlation.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Map original method token
/// let method_map = EncMapBuilder::new()
///     .original_token(0x06000042)  // Original MethodDef token
///     .build(&mut context)?;
///
/// // Map original type token
/// let type_map = EncMapBuilder::new()
///     .original_token(0x02000010)  // Original TypeDef token
///     .build(&mut context)?;
///
/// // Map original field token
/// let field_map = EncMapBuilder::new()
///     .original_token(0x04000025)  // Original Field token
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct EncMapBuilder {
    /// Original metadata token before editing
    original_token: Option<Token>,
}

impl EncMapBuilder {
    /// Creates a new `EncMapBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required original token before calling build().
    ///
    /// # Returns
    /// A new `EncMapBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = EncMapBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            original_token: None,
        }
    }

    /// Sets the original metadata token
    ///
    /// Specifies the metadata token that existed before the Edit-and-Continue
    /// operation occurred. This token is preserved in the EncMap table to
    /// enable correlation with updated tokens.
    ///
    /// # Parameters
    /// - `original_token`: The original metadata token value
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Using raw token value
    /// let builder = EncMapBuilder::new()
    ///     .original_token(0x06000001);  // MethodDef RID 1
    ///
    /// // Using Token object
    /// let token = Token::new(0x02000005);
    /// let builder = EncMapBuilder::new()
    ///     .original_token_obj(token);
    /// ```
    #[must_use]
    pub fn original_token(mut self, original_token: u32) -> Self {
        self.original_token = Some(Token::new(original_token));
        self
    }

    /// Sets the original metadata token using a Token object
    ///
    /// Alternative method for setting the original token using a Token object
    /// instead of a raw u32 value.
    ///
    /// # Parameters
    /// - `original_token`: The original Token object
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let token = Token::new(0x04000010);
    /// let builder = EncMapBuilder::new()
    ///     .original_token_obj(token);
    /// ```
    #[must_use]
    pub fn original_token_obj(mut self, original_token: Token) -> Self {
        self.original_token = Some(original_token);
        self
    }

    /// Builds and adds the `EncMap` entry to the metadata
    ///
    /// Validates all required fields, creates the `EncMap` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this token mapping entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created token mapping entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (original_token)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = EncMapBuilder::new()
    ///     .original_token(0x06000001)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let original_token =
            self.original_token
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Original token is required for EncMap".to_string(),
                })?;

        let next_rid = context.next_rid(TableId::EncMap);
        let token = Token::new(((TableId::EncMap as u32) << 24) | next_rid);

        let enc_map = EncMapRaw {
            rid: next_rid,
            token,
            offset: 0,
            original_token,
        };

        context.table_row_add(TableId::EncMap, TableDataOwned::EncMap(enc_map))?;
        Ok(token)
    }
}

impl Default for EncMapBuilder {
    /// Creates a default `EncMapBuilder`
    ///
    /// Equivalent to calling [`EncMapBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::BuilderContext, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_encmap_builder_new() {
        let builder = EncMapBuilder::new();

        assert!(builder.original_token.is_none());
    }

    #[test]
    fn test_encmap_builder_default() {
        let builder = EncMapBuilder::default();

        assert!(builder.original_token.is_none());
    }

    #[test]
    fn test_encmap_builder_method_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = EncMapBuilder::new()
            .original_token(0x06000001) // MethodDef token
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EncMap as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_encmap_builder_type_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = EncMapBuilder::new()
            .original_token(0x02000010) // TypeDef token
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EncMap as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_encmap_builder_field_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = EncMapBuilder::new()
            .original_token(0x04000025) // Field token
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EncMap as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_encmap_builder_token_object() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let original = Token::new(0x08000005);
        let token = EncMapBuilder::new()
            .original_token_obj(original)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EncMap as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_encmap_builder_missing_original_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = EncMapBuilder::new().build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Original token is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_encmap_builder_clone() {
        let original = Token::new(0x06000001);
        let builder = EncMapBuilder::new().original_token_obj(original);

        let cloned = builder.clone();
        assert_eq!(builder.original_token, cloned.original_token);
    }

    #[test]
    fn test_encmap_builder_debug() {
        let builder = EncMapBuilder::new().original_token(0x02000005);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("EncMapBuilder"));
        assert!(debug_str.contains("original_token"));
    }

    #[test]
    fn test_encmap_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = EncMapBuilder::new()
            .original_token(0x17000001) // Property token
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::EncMap as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_encmap_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first mapping entry
        let token1 = EncMapBuilder::new()
            .original_token(0x06000001) // Method
            .build(&mut context)
            .expect("Should build first mapping entry");

        // Build second mapping entry
        let token2 = EncMapBuilder::new()
            .original_token(0x02000001) // Type
            .build(&mut context)
            .expect("Should build second mapping entry");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }

    #[test]
    fn test_encmap_builder_various_tokens() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with different token types
        let tokens = [
            0x02000001, // TypeDef
            0x06000001, // MethodDef
            0x04000001, // Field
            0x08000001, // Param
            0x14000001, // Event
            0x17000001, // Property
        ];

        for (i, &token_val) in tokens.iter().enumerate() {
            let token = EncMapBuilder::new()
                .original_token(token_val)
                .build(&mut context)
                .expect("Should build successfully");

            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_encmap_builder_large_token_values() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with large token values
        let large_tokens = [
            0x06FFFFFF, // Large MethodDef
            0x02FFFFFF, // Large TypeDef
            0x04FFFFFF, // Large Field
        ];

        for (i, &token_val) in large_tokens.iter().enumerate() {
            let token = EncMapBuilder::new()
                .original_token(token_val)
                .build(&mut context)
                .expect("Should handle large token values");

            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }
}
