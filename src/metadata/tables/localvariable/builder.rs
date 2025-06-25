//! Builder for constructing `LocalVariable` table entries
//!
//! This module provides the [`crate::metadata::tables::localvariable::LocalVariableBuilder`] which enables fluent construction
//! of `LocalVariable` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let local_var_token = LocalVariableBuilder::new()
//!     .attributes(0x01)       // Set variable attributes
//!     .index(0)               // First local variable
//!     .name("counter")        // Variable name
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{LocalVariableRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `LocalVariable` table entries
///
/// Provides a fluent interface for building `LocalVariable` metadata table entries.
/// The builder validates all required fields are provided and handles proper
/// integration with the metadata system.
///
/// # Required Fields
/// - `index`: Variable index within the method (must be provided)
/// - `name`: Variable name (can be empty for anonymous variables, but must be explicitly set)
///
/// # Optional Fields  
/// - `attributes`: Variable attribute flags (defaults to 0)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Named local variable
/// let var_token = LocalVariableBuilder::new()
///     .attributes(0x01)
///     .index(0)
///     .name("myVariable")
///     .build(&mut context)?;
///
/// // Anonymous variable (compiler-generated)
/// let anon_token = LocalVariableBuilder::new()
///     .index(1)
///     .name("")  // Empty name for anonymous variable
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct LocalVariableBuilder {
    /// Variable attribute flags
    attributes: Option<u16>,
    /// Variable index within the method
    index: Option<u16>,
    /// Variable name (empty string for anonymous variables)
    name: Option<String>,
}

impl LocalVariableBuilder {
    /// Creates a new `LocalVariableBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required fields (index and name) before calling build().
    ///
    /// # Returns
    /// A new `LocalVariableBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalVariableBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            attributes: None,
            index: None,
            name: None,
        }
    }

    /// Sets the variable attribute flags
    ///
    /// Configures the attribute flags for this local variable. These flags
    /// describe characteristics of the variable such as whether it's compiler-generated,
    /// pinned, or has other special properties.
    ///
    /// # Parameters
    /// - `attributes`: The attribute flags to set (bitfield)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalVariableBuilder::new()
    ///     .attributes(0x01);  // Set specific attribute flag
    /// ```
    pub fn attributes(mut self, attributes: u16) -> Self {
        self.attributes = Some(attributes);
        self
    }

    /// Sets the variable index within the method
    ///
    /// Specifies the zero-based index that identifies this variable within
    /// the containing method. This index corresponds to the variable's position
    /// in the method's local variable signature and IL instructions.
    ///
    /// # Parameters
    /// - `index`: The variable index (0-based)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalVariableBuilder::new()
    ///     .index(0);  // First local variable
    /// ```
    pub fn index(mut self, index: u16) -> Self {
        self.index = Some(index);
        self
    }

    /// Sets the variable name
    ///
    /// Specifies the name for this local variable. The name can be empty
    /// for anonymous or compiler-generated variables.
    ///
    /// # Parameters
    /// - `name`: The variable name (can be empty string)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Named variable
    /// let builder = LocalVariableBuilder::new()
    ///     .name("counter");
    ///
    /// // Anonymous variable
    /// let anon_builder = LocalVariableBuilder::new()
    ///     .name("");
    /// ```
    pub fn name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Builds and adds the `LocalVariable` entry to the metadata
    ///
    /// Validates all required fields, creates the `LocalVariable` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this local variable.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created local variable
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (index or name)
    /// - Table operations fail due to metadata constraints
    /// - Local variable validation failed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = LocalVariableBuilder::new()
    ///     .index(0)
    ///     .name("myVar")
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let index = self
            .index
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Variable index is required for LocalVariable".to_string(),
            })?;

        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details:
                    "Variable name is required for LocalVariable (use empty string for anonymous)"
                        .to_string(),
            })?;

        let next_rid = context.next_rid(TableId::LocalVariable);
        let token = Token::new(0x3300_0000 + next_rid);
        let name_index = if name.is_empty() {
            0
        } else {
            context.add_string(&name)?
        };

        let local_variable = LocalVariableRaw {
            rid: next_rid,
            token,
            offset: 0,
            attributes: self.attributes.unwrap_or(0),
            index,
            name: name_index,
        };

        context.add_table_row(
            TableId::LocalVariable,
            TableDataOwned::LocalVariable(local_variable),
        )?;
        Ok(token)
    }
}

impl Default for LocalVariableBuilder {
    /// Creates a default `LocalVariableBuilder`
    ///
    /// Equivalent to calling [`LocalVariableBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
    };
    use std::path::PathBuf;

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        Ok(CilAssembly::new(view))
    }

    #[test]
    fn test_localvariable_builder_new() {
        let builder = LocalVariableBuilder::new();

        assert!(builder.attributes.is_none());
        assert!(builder.index.is_none());
        assert!(builder.name.is_none());
    }

    #[test]
    fn test_localvariable_builder_default() {
        let builder = LocalVariableBuilder::default();

        assert!(builder.attributes.is_none());
        assert!(builder.index.is_none());
        assert!(builder.name.is_none());
    }

    #[test]
    fn test_localvariable_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = LocalVariableBuilder::new()
            .index(0)
            .name("testVar")
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalVariable as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_with_all_fields() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = LocalVariableBuilder::new()
            .attributes(0x0001)
            .index(2)
            .name("myVariable")
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalVariable as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_anonymous_variable() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = LocalVariableBuilder::new()
            .index(1)
            .name("") // Empty name for anonymous variable
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalVariable as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_missing_index() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = LocalVariableBuilder::new()
            .name("testVar")
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Variable index is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = LocalVariableBuilder::new().index(0).build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Variable name is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_clone() {
        let builder = LocalVariableBuilder::new()
            .attributes(0x01)
            .index(0)
            .name("testVar");

        let cloned = builder.clone();
        assert_eq!(builder.attributes, cloned.attributes);
        assert_eq!(builder.index, cloned.index);
        assert_eq!(builder.name, cloned.name);
    }

    #[test]
    fn test_localvariable_builder_debug() {
        let builder = LocalVariableBuilder::new()
            .attributes(0x01)
            .index(0)
            .name("testVar");

        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("LocalVariableBuilder"));
        assert!(debug_str.contains("attributes"));
        assert!(debug_str.contains("index"));
        assert!(debug_str.contains("name"));
    }

    #[test]
    fn test_localvariable_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = LocalVariableBuilder::new()
            .attributes(0x0002)
            .index(3)
            .name("chainedVar")
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::LocalVariable as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_localvariable_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first variable
        let token1 = LocalVariableBuilder::new()
            .index(0)
            .name("var1")
            .build(&mut context)
            .expect("Should build first variable");

        // Build second variable
        let token2 = LocalVariableBuilder::new()
            .index(1)
            .name("var2")
            .build(&mut context)
            .expect("Should build second variable");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }
}
