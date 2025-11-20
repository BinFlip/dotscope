//! # NestedClass Builder
//!
//! Provides a fluent API for building NestedClass table entries that define hierarchical relationships
//! between nested types and their enclosing types. The NestedClass table establishes type containment
//! structure essential for proper type visibility and scoping in .NET assemblies.
//!
//! ## Overview
//!
//! The `NestedClassBuilder` enables creation of nested class relationships with:
//! - Nested type specification (required)
//! - Enclosing type specification (required)  
//! - Validation of type relationships
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # fn main() -> dotscope::Result<()> {
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create an enclosing type first
//! let outer_class_token = TypeDefBuilder::new()
//!     .name("OuterClass")
//!     .namespace("MyApp.Models")
//!     .public_class()
//!     .build(&mut context)?;
//!
//! // Create a nested type
//! let inner_class_token = TypeDefBuilder::new()
//!     .name("InnerClass")
//!     .namespace("MyApp.Models")
//!     .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
//!     .build(&mut context)?;
//!
//! // Establish the nesting relationship
//! let nesting_token = NestedClassBuilder::new()
//!     .nested_class(inner_class_token)
//!     .enclosing_class(outer_class_token)
//!     .build(&mut context)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Both nested and enclosing types are required
//! - **Relationship Validation**: Prevents invalid nesting scenarios
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Type Safety**: Ensures proper TypeDef token validation

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{NestedClassRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating NestedClass table entries.
///
/// `NestedClassBuilder` provides a fluent API for creating entries in the NestedClass
/// metadata table, which defines hierarchical relationships between nested types and
/// their enclosing types.
///
/// # Purpose
///
/// The NestedClass table serves several key functions:
/// - **Type Hierarchy**: Defines which types are nested within other types
/// - **Visibility Scoping**: Establishes access rules for nested types
/// - **Enclosing Context**: Links nested types to their containing types
/// - **Namespace Resolution**: Enables proper type resolution within nested contexts
/// - **Compilation Support**: Provides context for type compilation and loading
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing NestedClass entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// # let outer_token = Token::new(0x02000001);
/// # let inner_token = Token::new(0x02000002);
///
/// let nesting_token = NestedClassBuilder::new()
///     .nested_class(inner_token)
///     .enclosing_class(outer_token)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Nested Class Required**: A nested class token must be provided
/// - **Enclosing Class Required**: An enclosing class token must be provided
/// - **Token Validation**: Both tokens must be valid TypeDef tokens
/// - **Relationship Validation**: Prevents invalid nesting scenarios (self-nesting, etc.)
///
/// # Integration
///
/// NestedClass entries integrate with other metadata structures:
/// - **TypeDef**: Both nested and enclosing types must be TypeDef entries
/// - **Type Registry**: Establishes relationships in the type system
/// - **Visibility Rules**: Nested types inherit accessibility from their context
#[derive(Debug, Clone)]
pub struct NestedClassBuilder {
    /// The token of the nested type
    nested_class: Option<Token>,
    /// The token of the enclosing type
    enclosing_class: Option<Token>,
}

impl Default for NestedClassBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NestedClassBuilder {
    /// Creates a new `NestedClassBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = NestedClassBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            nested_class: None,
            enclosing_class: None,
        }
    }

    /// Sets the token of the nested type.
    ///
    /// The nested type must be a valid TypeDef token that represents
    /// the type being nested within the enclosing type.
    ///
    /// # Arguments
    ///
    /// * `nested_class_token` - Token of the TypeDef for the nested type
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # fn main() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let inner_token = TypeDefBuilder::new()
    ///     .name("InnerClass")
    ///     .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
    ///     .build(&mut context)?;
    ///
    /// let builder = NestedClassBuilder::new()
    ///     .nested_class(inner_token);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn nested_class(mut self, nested_class_token: Token) -> Self {
        self.nested_class = Some(nested_class_token);
        self
    }

    /// Sets the token of the enclosing type.
    ///
    /// The enclosing type must be a valid TypeDef token that represents
    /// the type containing the nested type.
    ///
    /// # Arguments
    ///
    /// * `enclosing_class_token` - Token of the TypeDef for the enclosing type
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # fn main() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let outer_token = TypeDefBuilder::new()
    ///     .name("OuterClass")
    ///     .public_class()
    ///     .build(&mut context)?;
    ///
    /// let builder = NestedClassBuilder::new()
    ///     .enclosing_class(outer_token);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn enclosing_class(mut self, enclosing_class_token: Token) -> Self {
        self.enclosing_class = Some(enclosing_class_token);
        self
    }

    /// Builds the NestedClass entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the type tokens are valid TypeDef
    /// tokens, validates the nesting relationship, creates the NestedClass table entry,
    /// and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created NestedClass entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The nested class token is not set
    /// - The enclosing class token is not set
    /// - Either token is not a valid TypeDef token
    /// - The tokens refer to the same type (self-nesting)
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// # let outer_token = Token::new(0x02000001);
    /// # let inner_token = Token::new(0x02000002);
    ///
    /// let nesting_token = NestedClassBuilder::new()
    ///     .nested_class(inner_token)
    ///     .enclosing_class(outer_token)
    ///     .build(&mut context)?;
    ///
    /// println!("Created NestedClass with token: {}", nesting_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let nested_class_token =
            self.nested_class
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Nested class token is required for NestedClass".to_string(),
                })?;

        let enclosing_class_token =
            self.enclosing_class
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Enclosing class token is required for NestedClass".to_string(),
                })?;

        if nested_class_token.table() != TableId::TypeDef as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Nested class token must be a TypeDef token, got table ID: {}",
                    nested_class_token.table()
                ),
            });
        }

        if enclosing_class_token.table() != TableId::TypeDef as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Enclosing class token must be a TypeDef token, got table ID: {}",
                    enclosing_class_token.table()
                ),
            });
        }

        if nested_class_token.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Nested class token row cannot be 0".to_string(),
            });
        }

        if enclosing_class_token.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Enclosing class token row cannot be 0".to_string(),
            });
        }

        // Prevent self-nesting
        if nested_class_token == enclosing_class_token {
            return Err(Error::ModificationInvalidOperation {
                details: "A type cannot be nested within itself".to_string(),
            });
        }

        let rid = context.next_rid(TableId::NestedClass);
        let token = Token::new(((TableId::NestedClass as u32) << 24) | rid);

        let nested_class = NestedClassRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            nested_class: nested_class_token.row(),
            enclosing_class: enclosing_class_token.row(),
        };

        let table_data = TableDataOwned::NestedClass(nested_class);
        context.table_row_add(TableId::NestedClass, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::{TableId, TypeAttributes},
        test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_nested_class_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create TypeDefs for testing
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut context)?;

        let inner_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        let token = NestedClassBuilder::new()
            .nested_class(inner_token)
            .enclosing_class(outer_token)
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::NestedClass as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_default() -> Result<()> {
        let builder = NestedClassBuilder::default();
        assert!(builder.nested_class.is_none());
        assert!(builder.enclosing_class.is_none());
        Ok(())
    }

    #[test]
    fn test_nested_class_builder_missing_nested_class() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create an enclosing type
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut context)?;

        let result = NestedClassBuilder::new()
            .enclosing_class(outer_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Nested class token is required"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_missing_enclosing_class() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a nested type
        let inner_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        let result = NestedClassBuilder::new()
            .nested_class(inner_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Enclosing class token is required"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_invalid_nested_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create valid enclosing type
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut context)?;

        // Use an invalid token (not TypeDef)
        let invalid_token = Token::new(0x01000001); // Module token instead of TypeDef

        let result = NestedClassBuilder::new()
            .nested_class(invalid_token)
            .enclosing_class(outer_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Nested class token must be a TypeDef token"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_invalid_enclosing_token() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create valid nested type
        let inner_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        // Use an invalid token (not TypeDef)
        let invalid_token = Token::new(0x01000001); // Module token instead of TypeDef

        let result = NestedClassBuilder::new()
            .nested_class(inner_token)
            .enclosing_class(invalid_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Enclosing class token must be a TypeDef token"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_self_nesting() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a type
        let type_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("SelfNestingClass")
            .public_class()
            .build(&mut context)?;

        // Try to nest it within itself
        let result = NestedClassBuilder::new()
            .nested_class(type_token)
            .enclosing_class(type_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("A type cannot be nested within itself"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_zero_row_nested() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create valid enclosing type
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut context)?;

        // Use a zero row token
        let zero_token = Token::new(0x02000000);

        let result = NestedClassBuilder::new()
            .nested_class(zero_token)
            .enclosing_class(outer_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Nested class token row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_zero_row_enclosing() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create valid nested type
        let inner_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        // Use a zero row token
        let zero_token = Token::new(0x02000000);

        let result = NestedClassBuilder::new()
            .nested_class(inner_token)
            .enclosing_class(zero_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Enclosing class token row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_multiple_relationships() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create an outer class
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut context)?;

        // Create two inner classes
        let inner1_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass1")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        let inner2_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass2")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        // Create nesting relationships
        let nesting1_token = NestedClassBuilder::new()
            .nested_class(inner1_token)
            .enclosing_class(outer_token)
            .build(&mut context)?;

        let nesting2_token = NestedClassBuilder::new()
            .nested_class(inner2_token)
            .enclosing_class(outer_token)
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(nesting1_token, nesting2_token);
        assert_eq!(nesting1_token.table(), TableId::NestedClass as u8);
        assert_eq!(nesting2_token.table(), TableId::NestedClass as u8);
        assert_eq!(nesting2_token.row(), nesting1_token.row() + 1);

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_deep_nesting() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a hierarchy: Outer -> Middle -> Inner
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("OuterClass")
            .public_class()
            .build(&mut context)?;

        let middle_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("MiddleClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        let inner_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("InnerClass")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        // Create the nesting relationships
        let nesting1_token = NestedClassBuilder::new()
            .nested_class(middle_token)
            .enclosing_class(outer_token)
            .build(&mut context)?;

        let nesting2_token = NestedClassBuilder::new()
            .nested_class(inner_token)
            .enclosing_class(middle_token)
            .build(&mut context)?;

        assert_eq!(nesting1_token.table(), TableId::NestedClass as u8);
        assert_eq!(nesting2_token.table(), TableId::NestedClass as u8);
        assert!(nesting1_token.row() > 0);
        assert!(nesting2_token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create types for testing
        let outer_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentOuter")
            .public_class()
            .build(&mut context)?;

        let inner_token = crate::metadata::tables::TypeDefBuilder::new()
            .name("FluentInner")
            .flags(TypeAttributes::NESTED_PUBLIC | TypeAttributes::CLASS)
            .build(&mut context)?;

        // Test fluent API chaining
        let token = NestedClassBuilder::new()
            .nested_class(inner_token)
            .enclosing_class(outer_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::NestedClass as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_nested_class_builder_clone() {
        let nested_token = Token::new(0x02000001);
        let enclosing_token = Token::new(0x02000002);

        let builder1 = NestedClassBuilder::new()
            .nested_class(nested_token)
            .enclosing_class(enclosing_token);
        let builder2 = builder1.clone();

        assert_eq!(builder1.nested_class, builder2.nested_class);
        assert_eq!(builder1.enclosing_class, builder2.enclosing_class);
    }

    #[test]
    fn test_nested_class_builder_debug() {
        let nested_token = Token::new(0x02000001);
        let enclosing_token = Token::new(0x02000002);

        let builder = NestedClassBuilder::new()
            .nested_class(nested_token)
            .enclosing_class(enclosing_token);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("NestedClassBuilder"));
    }
}
