//! Builder for constructing `FieldPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::fieldptr::FieldPtrBuilder`] which enables fluent construction
//! of `FieldPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let fieldptr_token = FieldPtrBuilder::new()
//!     .field(5)                      // Points to Field table RID 5
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{FieldPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `FieldPtr` table entries
///
/// Provides a fluent interface for building `FieldPtr` metadata table entries.
/// These entries provide indirection for field access when logical and physical
/// field ordering differs, enabling metadata optimizations and edit-and-continue.
///
/// # Required Fields
/// - `field`: Field table RID that this pointer references
///
/// # Indirection Context
///
/// The FieldPtr table provides a mapping layer between logical field references
/// and physical field table entries. This enables:
/// - Field reordering for metadata optimization
/// - Edit-and-continue field additions without breaking references
/// - Platform-specific field layout optimizations
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Create field pointer for field reordering
/// let ptr1 = FieldPtrBuilder::new()
///     .field(10)  // Points to Field table entry 10
///     .build(&mut context)?;
///
/// // Create pointer for optimized field layout
/// let ptr2 = FieldPtrBuilder::new()
///     .field(25)  // Points to Field table entry 25
///     .build(&mut context)?;
///
/// // Multiple pointers for complex reordering
/// let ptr3 = FieldPtrBuilder::new()
///     .field(3)   // Points to Field table entry 3
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct FieldPtrBuilder {
    /// Field table RID that this pointer references
    field: Option<u32>,
}

impl FieldPtrBuilder {
    /// Creates a new `FieldPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required field RID before calling build().
    ///
    /// # Returns
    /// A new `FieldPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = FieldPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { field: None }
    }

    /// Sets the Field table RID
    ///
    /// Specifies which Field table entry this pointer references. This creates
    /// the indirection mapping from the FieldPtr RID (logical index) to the
    /// actual Field table entry (physical index).
    ///
    /// # Parameters
    /// - `field`: The Field table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Point to first field
    /// let builder = FieldPtrBuilder::new()
    ///     .field(1);
    ///
    /// // Point to a later field for reordering
    /// let builder = FieldPtrBuilder::new()
    ///     .field(15);
    /// ```
    #[must_use]
    pub fn field(mut self, field: u32) -> Self {
        self.field = Some(field);
        self
    }

    /// Builds and adds the `FieldPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `FieldPtr` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this field pointer entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created field pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (field RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = FieldPtrBuilder::new()
    ///     .field(5)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let field = self
            .field
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Field RID is required for FieldPtr".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::FieldPtr);
        let token = Token::new(((TableId::FieldPtr as u32) << 24) | next_rid);

        let field_ptr = FieldPtrRaw {
            rid: next_rid,
            token,
            offset: 0,
            field,
        };

        context.table_row_add(TableId::FieldPtr, TableDataOwned::FieldPtr(field_ptr))?;
        Ok(token)
    }
}

impl Default for FieldPtrBuilder {
    /// Creates a default `FieldPtrBuilder`
    ///
    /// Equivalent to calling [`FieldPtrBuilder::new()`].
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
    fn test_fieldptr_builder_new() {
        let builder = FieldPtrBuilder::new();

        assert!(builder.field.is_none());
    }

    #[test]
    fn test_fieldptr_builder_default() {
        let builder = FieldPtrBuilder::default();

        assert!(builder.field.is_none());
    }

    #[test]
    fn test_fieldptr_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = FieldPtrBuilder::new()
            .field(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::FieldPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_reordering() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = FieldPtrBuilder::new()
            .field(10) // Point to later field for reordering
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::FieldPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_missing_field() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = FieldPtrBuilder::new().build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Field RID is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_clone() {
        let builder = FieldPtrBuilder::new().field(5);

        let cloned = builder.clone();
        assert_eq!(builder.field, cloned.field);
    }

    #[test]
    fn test_fieldptr_builder_debug() {
        let builder = FieldPtrBuilder::new().field(8);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("FieldPtrBuilder"));
        assert!(debug_str.contains("field"));
    }

    #[test]
    fn test_fieldptr_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = FieldPtrBuilder::new()
            .field(25)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::FieldPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first pointer
        let token1 = FieldPtrBuilder::new()
            .field(10)
            .build(&mut context)
            .expect("Should build first pointer");

        // Build second pointer
        let token2 = FieldPtrBuilder::new()
            .field(5)
            .build(&mut context)
            .expect("Should build second pointer");

        // Build third pointer
        let token3 = FieldPtrBuilder::new()
            .field(15)
            .build(&mut context)
            .expect("Should build third pointer");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_eq!(token3.row(), 3);
        assert_ne!(token1, token2);
        assert_ne!(token2, token3);
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_large_field_rid() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = FieldPtrBuilder::new()
            .field(0xFFFF) // Large Field RID
            .build(&mut context)
            .expect("Should handle large field RID");

        assert_eq!(token.table(), TableId::FieldPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_field_ordering_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate field reordering: logical order 1,2,3 -> physical order 3,1,2
        let logical_to_physical = [(1, 3), (2, 1), (3, 2)];

        let mut tokens = Vec::new();
        for (logical_idx, physical_field) in logical_to_physical {
            let token = FieldPtrBuilder::new()
                .field(physical_field)
                .build(&mut context)
                .expect("Should build field pointer");
            tokens.push((logical_idx, token));
        }

        // Verify logical ordering is preserved in tokens
        for (i, (logical_idx, token)) in tokens.iter().enumerate() {
            assert_eq!(*logical_idx, i + 1);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_fieldptr_builder_zero_field() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with field 0 (typically invalid but should not cause builder to fail)
        let result = FieldPtrBuilder::new().field(0).build(&mut context);

        // Should build successfully even with field 0
        assert!(result.is_ok());
        Ok(())
    }
}
