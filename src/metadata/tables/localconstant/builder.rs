//! Builder for constructing `LocalConstant` table entries
//!
//! This module provides the [`crate::metadata::tables::localconstant::LocalConstantBuilder`] which enables fluent construction
//! of `LocalConstant` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4 signature
//!
//! let constant_token = LocalConstantBuilder::new()
//!     .name("PI")                    // Constant name  
//!     .signature(&signature_bytes)   // Raw signature bytes
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{LocalConstantRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `LocalConstant` table entries
///
/// Provides a fluent interface for building `LocalConstant` metadata table entries.
/// The builder validates all required fields are provided and handles proper
/// integration with the metadata system.
///
/// # Required Fields
/// - `name`: Constant name (can be empty for anonymous constants, but must be explicitly set)
/// - `signature`: Raw signature bytes (must be provided)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Named local constant with I4 signature
/// let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
/// let constant_token = LocalConstantBuilder::new()
///     .name("MAX_VALUE")
///     .signature(&signature_bytes)
///     .build(&mut context)?;
///
/// // Anonymous constant (compiler-generated)
/// let anon_token = LocalConstantBuilder::new()
///     .name("")  // Empty name for anonymous constant
///     .signature(&signature_bytes)
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct LocalConstantBuilder {
    /// Constant name (empty string for anonymous constants)
    name: Option<String>,
    /// Raw signature bytes for the constant type
    signature: Option<Vec<u8>>,
}

impl LocalConstantBuilder {
    /// Creates a new `LocalConstantBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required fields (name and signature) before calling build().
    ///
    /// # Returns
    /// A new `LocalConstantBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalConstantBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            signature: None,
        }
    }

    /// Sets the constant name
    ///
    /// Specifies the name for this local constant. The name can be empty
    /// for anonymous or compiler-generated constants.
    ///
    /// # Parameters
    /// - `name`: The constant name (can be empty string)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Named constant
    /// let builder = LocalConstantBuilder::new()
    ///     .name("PI");
    ///
    /// // Anonymous constant
    /// let anon_builder = LocalConstantBuilder::new()
    ///     .name("");
    /// ```
    #[must_use]
    pub fn name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the constant signature bytes
    ///
    /// Specifies the raw signature bytes for this local constant. These bytes
    /// represent the field signature format as defined in ECMA-335.
    ///
    /// # Parameters
    /// - `signature`: The raw signature bytes
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // I4 (int32) constant signature
    /// let i4_signature = vec![0x08]; // ELEMENT_TYPE_I4
    /// let builder = LocalConstantBuilder::new()
    ///     .signature(&i4_signature);
    ///
    /// // String constant signature  
    /// let string_signature = vec![0x0E]; // ELEMENT_TYPE_STRING
    /// let builder = LocalConstantBuilder::new()
    ///     .signature(&string_signature);
    /// ```
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self
    }

    /// Builds and adds the `LocalConstant` entry to the metadata
    ///
    /// Validates all required fields, creates the `LocalConstant` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this local constant.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created local constant
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (name or signature)
    /// - Table operations fail due to metadata constraints
    /// - Local constant validation failed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    /// let token = LocalConstantBuilder::new()
    ///     .name("myConstant")
    ///     .signature(&signature_bytes)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details:
                    "Constant name is required for LocalConstant (use empty string for anonymous)"
                        .to_string(),
            })?;

        let signature = self
            .signature
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Constant signature is required for LocalConstant".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::LocalConstant);
        let token_value = ((TableId::LocalConstant as u32) << 24) | next_rid;
        let token = Token::new(token_value);

        let name_index = if name.is_empty() {
            0
        } else {
            context.string_add(&name)?
        };

        let signature_index = if signature.is_empty() {
            0
        } else {
            context.blob_add(&signature)?
        };

        let local_constant = LocalConstantRaw {
            rid: next_rid,
            token,
            offset: 0,
            name: name_index,
            signature: signature_index,
        };

        context.table_row_add(
            TableId::LocalConstant,
            TableDataOwned::LocalConstant(local_constant),
        )?;
        Ok(token)
    }
}

impl Default for LocalConstantBuilder {
    /// Creates a default `LocalConstantBuilder`
    ///
    /// Equivalent to calling [`LocalConstantBuilder::new()`].
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
    fn test_localconstant_builder_new() {
        let builder = LocalConstantBuilder::new();

        assert!(builder.name.is_none());
        assert!(builder.signature.is_none());
    }

    #[test]
    fn test_localconstant_builder_default() {
        let builder = LocalConstantBuilder::default();

        assert!(builder.name.is_none());
        assert!(builder.signature.is_none());
    }

    #[test]
    fn test_localconstant_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let token = LocalConstantBuilder::new()
            .name("testConstant")
            .signature(&signature_bytes)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalConstant as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_anonymous_constant() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let signature_bytes = vec![0x0E]; // ELEMENT_TYPE_STRING
        let token = LocalConstantBuilder::new()
            .name("") // Empty name for anonymous constant
            .signature(&signature_bytes)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalConstant as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let result = LocalConstantBuilder::new()
            .signature(&signature_bytes)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Constant name is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_missing_signature() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = LocalConstantBuilder::new()
            .name("testConstant")
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Constant signature is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_clone() {
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let builder = LocalConstantBuilder::new()
            .name("testConstant")
            .signature(&signature_bytes);

        let cloned = builder.clone();
        assert_eq!(builder.name, cloned.name);
        assert_eq!(builder.signature, cloned.signature);
    }

    #[test]
    fn test_localconstant_builder_debug() {
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let builder = LocalConstantBuilder::new()
            .name("testConstant")
            .signature(&signature_bytes);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("LocalConstantBuilder"));
        assert!(debug_str.contains("name"));
        assert!(debug_str.contains("signature"));
    }

    #[test]
    fn test_localconstant_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let signature_bytes = vec![0x02]; // ELEMENT_TYPE_BOOLEAN

        // Test method chaining
        let token = LocalConstantBuilder::new()
            .name("chainedConstant")
            .signature(&signature_bytes)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalConstant as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let signature1 = vec![0x08]; // ELEMENT_TYPE_I4
        let signature2 = vec![0x0E]; // ELEMENT_TYPE_STRING

        // Build first constant
        let token1 = LocalConstantBuilder::new()
            .name("constant1")
            .signature(&signature1)
            .build(&mut context)
            .expect("Should build first constant");

        // Build second constant
        let token2 = LocalConstantBuilder::new()
            .name("constant2")
            .signature(&signature2)
            .build(&mut context)
            .expect("Should build second constant");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }
}
