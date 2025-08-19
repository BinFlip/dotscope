//! Builder for constructing `MethodPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::methodptr::MethodPtrBuilder`] which enables fluent construction
//! of `MethodPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let methodptr_token = MethodPtrBuilder::new()
//!     .method(8)                     // Points to MethodDef table RID 8
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{MethodPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `MethodPtr` table entries
///
/// Provides a fluent interface for building `MethodPtr` metadata table entries.
/// These entries provide indirection for method access when logical and physical
/// method ordering differs, enabling method table optimizations and edit-and-continue.
///
/// # Required Fields
/// - `method`: MethodDef table RID that this pointer references
///
/// # Indirection Context
///
/// The MethodPtr table provides a mapping layer between logical method references
/// and physical MethodDef table entries. This enables:
/// - Method reordering for metadata optimization
/// - Edit-and-continue method additions without breaking references
/// - Runtime method hot-reload and debugging interception
/// - Incremental compilation with stable method references
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Create method pointer for method reordering
/// let ptr1 = MethodPtrBuilder::new()
///     .method(15)  // Points to MethodDef table entry 15
///     .build(&mut context)?;
///
/// // Create pointer for hot-reload scenario
/// let ptr2 = MethodPtrBuilder::new()
///     .method(42)  // Points to MethodDef table entry 42
///     .build(&mut context)?;
///
/// // Multiple pointers for complex reordering
/// let ptr3 = MethodPtrBuilder::new()
///     .method(7)   // Points to MethodDef table entry 7
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct MethodPtrBuilder {
    /// MethodDef table RID that this pointer references
    method: Option<u32>,
}

impl MethodPtrBuilder {
    /// Creates a new `MethodPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required method RID before calling build().
    ///
    /// # Returns
    /// A new `MethodPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = MethodPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { method: None }
    }

    /// Sets the MethodDef table RID
    ///
    /// Specifies which MethodDef table entry this pointer references. This creates
    /// the indirection mapping from the MethodPtr RID (logical index) to the
    /// actual MethodDef table entry (physical index).
    ///
    /// # Parameters
    /// - `method`: The MethodDef table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Point to first method
    /// let builder = MethodPtrBuilder::new()
    ///     .method(1);
    ///
    /// // Point to a later method for reordering
    /// let builder = MethodPtrBuilder::new()
    ///     .method(25);
    /// ```
    #[must_use]
    pub fn method(mut self, method: u32) -> Self {
        self.method = Some(method);
        self
    }

    /// Builds and adds the `MethodPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `MethodPtr` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this method pointer entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created method pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (method RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = MethodPtrBuilder::new()
    ///     .method(8)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let method = self
            .method
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Method RID is required for MethodPtr".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::MethodPtr);
        let token = Token::new(((TableId::MethodPtr as u32) << 24) | next_rid);

        let method_ptr = MethodPtrRaw {
            rid: next_rid,
            token,
            offset: 0,
            method,
        };

        context.table_row_add(TableId::MethodPtr, TableDataOwned::MethodPtr(method_ptr))?;
        Ok(token)
    }
}

impl Default for MethodPtrBuilder {
    /// Creates a default `MethodPtrBuilder`
    ///
    /// Equivalent to calling [`MethodPtrBuilder::new()`].
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
    fn test_methodptr_builder_new() {
        let builder = MethodPtrBuilder::new();

        assert!(builder.method.is_none());
    }

    #[test]
    fn test_methodptr_builder_default() {
        let builder = MethodPtrBuilder::default();

        assert!(builder.method.is_none());
    }

    #[test]
    fn test_methodptr_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = MethodPtrBuilder::new()
            .method(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::MethodPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_reordering() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = MethodPtrBuilder::new()
            .method(25) // Point to later method for reordering
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::MethodPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_missing_method() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = MethodPtrBuilder::new().build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Method RID is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_clone() {
        let builder = MethodPtrBuilder::new().method(8);

        let cloned = builder.clone();
        assert_eq!(builder.method, cloned.method);
    }

    #[test]
    fn test_methodptr_builder_debug() {
        let builder = MethodPtrBuilder::new().method(12);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("MethodPtrBuilder"));
        assert!(debug_str.contains("method"));
    }

    #[test]
    fn test_methodptr_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = MethodPtrBuilder::new()
            .method(42)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::MethodPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first pointer
        let token1 = MethodPtrBuilder::new()
            .method(20)
            .build(&mut context)
            .expect("Should build first pointer");

        // Build second pointer
        let token2 = MethodPtrBuilder::new()
            .method(10)
            .build(&mut context)
            .expect("Should build second pointer");

        // Build third pointer
        let token3 = MethodPtrBuilder::new()
            .method(30)
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
    fn test_methodptr_builder_large_method_rid() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = MethodPtrBuilder::new()
            .method(0xFFFF) // Large MethodDef RID
            .build(&mut context)
            .expect("Should handle large method RID");

        assert_eq!(token.table(), TableId::MethodPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_method_ordering_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate method reordering: logical order 1,2,3 -> physical order 3,1,2
        let logical_to_physical = [(1, 30), (2, 10), (3, 20)];

        let mut tokens = Vec::new();
        for (logical_idx, physical_method) in logical_to_physical {
            let token = MethodPtrBuilder::new()
                .method(physical_method)
                .build(&mut context)
                .expect("Should build method pointer");
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
    fn test_methodptr_builder_zero_method() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with method 0 (typically invalid but should not cause builder to fail)
        let result = MethodPtrBuilder::new().method(0).build(&mut context);

        // Should build successfully even with method 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_methodptr_builder_edit_continue_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate edit-and-continue scenario where methods are added/reordered
        let original_methods = [5, 10, 15];
        let mut tokens = Vec::new();

        for &method_rid in &original_methods {
            let token = MethodPtrBuilder::new()
                .method(method_rid)
                .build(&mut context)
                .expect("Should build method pointer for edit-continue");
            tokens.push(token);
        }

        // Verify stable logical tokens despite physical reordering
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(token.table(), TableId::MethodPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_methodptr_builder_hot_reload_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate hot-reload where new methods replace existing ones
        let new_method_implementations = [100, 200, 300];
        let mut pointer_tokens = Vec::new();

        for &new_method in &new_method_implementations {
            let pointer_token = MethodPtrBuilder::new()
                .method(new_method)
                .build(&mut context)
                .expect("Should build pointer for hot-reload");
            pointer_tokens.push(pointer_token);
        }

        // Verify pointer tokens maintain stable references for hot-reload
        assert_eq!(pointer_tokens.len(), 3);
        for (i, token) in pointer_tokens.iter().enumerate() {
            assert_eq!(token.table(), TableId::MethodPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }
}
