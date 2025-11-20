//! Builder for constructing `ParamPtr` table entries
//!
//! This module provides the [`crate::metadata::tables::paramptr::ParamPtrBuilder`] which enables fluent construction
//! of `ParamPtr` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let paramptr_token = ParamPtrBuilder::new()
//!     .param(3)                      // Points to Param table RID 3
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{ParamPtrRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `ParamPtr` table entries
///
/// Provides a fluent interface for building `ParamPtr` metadata table entries.
/// These entries provide indirection for parameter access when logical and physical
/// parameter ordering differs, enabling metadata optimizations and edit-and-continue.
///
/// # Required Fields
/// - `param`: Param table RID that this pointer references
///
/// # Indirection Context
///
/// The ParamPtr table provides a mapping layer between logical parameter references
/// and physical Param table entries. This enables:
/// - Parameter reordering for metadata optimization
/// - Edit-and-continue parameter additions without breaking references
/// - Compressed metadata streams with flexible parameter organization
/// - Runtime parameter hot-reload and debugging interception
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Create parameter pointer for parameter reordering
/// let ptr1 = ParamPtrBuilder::new()
///     .param(5)   // Points to Param table entry 5
///     .build(&mut context)?;
///
/// // Create pointer for optimized parameter layout
/// let ptr2 = ParamPtrBuilder::new()
///     .param(12)  // Points to Param table entry 12
///     .build(&mut context)?;
///
/// // Multiple pointers for complex reordering
/// let ptr3 = ParamPtrBuilder::new()
///     .param(2)   // Points to Param table entry 2
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct ParamPtrBuilder {
    /// Param table RID that this pointer references
    param: Option<u32>,
}

impl ParamPtrBuilder {
    /// Creates a new `ParamPtrBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required param RID before calling build().
    ///
    /// # Returns
    /// A new `ParamPtrBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = ParamPtrBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { param: None }
    }

    /// Sets the Param table RID
    ///
    /// Specifies which Param table entry this pointer references. This creates
    /// the indirection mapping from the ParamPtr RID (logical index) to the
    /// actual Param table entry (physical index).
    ///
    /// # Parameters
    /// - `param`: The Param table RID to reference
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Point to first parameter
    /// let builder = ParamPtrBuilder::new()
    ///     .param(1);
    ///
    /// // Point to a later parameter for reordering
    /// let builder = ParamPtrBuilder::new()
    ///     .param(10);
    /// ```
    #[must_use]
    pub fn param(mut self, param: u32) -> Self {
        self.param = Some(param);
        self
    }

    /// Builds and adds the `ParamPtr` entry to the metadata
    ///
    /// Validates all required fields, creates the `ParamPtr` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this parameter pointer entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created parameter pointer entry
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (param RID)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = ParamPtrBuilder::new()
    ///     .param(3)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let param = self
            .param
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Param RID is required for ParamPtr".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::ParamPtr);
        let token = Token::new(((TableId::ParamPtr as u32) << 24) | next_rid);

        let param_ptr = ParamPtrRaw {
            rid: next_rid,
            token,
            offset: 0,
            param,
        };

        context.table_row_add(TableId::ParamPtr, TableDataOwned::ParamPtr(param_ptr))?;
        Ok(token)
    }
}

impl Default for ParamPtrBuilder {
    /// Creates a default `ParamPtrBuilder`
    ///
    /// Equivalent to calling [`ParamPtrBuilder::new()`].
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
    fn test_paramptr_builder_new() {
        let builder = ParamPtrBuilder::new();

        assert!(builder.param.is_none());
    }

    #[test]
    fn test_paramptr_builder_default() {
        let builder = ParamPtrBuilder::default();

        assert!(builder.param.is_none());
    }

    #[test]
    fn test_paramptr_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = ParamPtrBuilder::new()
            .param(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ParamPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_reordering() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = ParamPtrBuilder::new()
            .param(10) // Point to later parameter for reordering
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ParamPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_missing_param() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = ParamPtrBuilder::new().build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Param RID is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_clone() {
        let builder = ParamPtrBuilder::new().param(3);

        let cloned = builder.clone();
        assert_eq!(builder.param, cloned.param);
    }

    #[test]
    fn test_paramptr_builder_debug() {
        let builder = ParamPtrBuilder::new().param(7);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ParamPtrBuilder"));
        assert!(debug_str.contains("param"));
    }

    #[test]
    fn test_paramptr_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = ParamPtrBuilder::new()
            .param(15)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ParamPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first pointer
        let token1 = ParamPtrBuilder::new()
            .param(5)
            .build(&mut context)
            .expect("Should build first pointer");

        // Build second pointer
        let token2 = ParamPtrBuilder::new()
            .param(2)
            .build(&mut context)
            .expect("Should build second pointer");

        // Build third pointer
        let token3 = ParamPtrBuilder::new()
            .param(8)
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
    fn test_paramptr_builder_large_param_rid() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = ParamPtrBuilder::new()
            .param(0xFFFF) // Large Param RID
            .build(&mut context)
            .expect("Should handle large param RID");

        assert_eq!(token.table(), TableId::ParamPtr as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_param_ordering_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate parameter reordering: logical order 1,2,3 -> physical order 3,1,2
        let logical_to_physical = [(1, 8), (2, 3), (3, 6)];

        let mut tokens = Vec::new();
        for (logical_idx, physical_param) in logical_to_physical {
            let token = ParamPtrBuilder::new()
                .param(physical_param)
                .build(&mut context)
                .expect("Should build parameter pointer");
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
    fn test_paramptr_builder_zero_param() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test with param 0 (typically invalid but should not cause builder to fail)
        let result = ParamPtrBuilder::new().param(0).build(&mut context);

        // Should build successfully even with param 0
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_paramptr_builder_method_parameter_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate method parameters with custom ordering
        let method_params = [4, 1, 7, 2]; // Parameters in custom order

        let mut param_pointers = Vec::new();
        for &param_rid in &method_params {
            let pointer_token = ParamPtrBuilder::new()
                .param(param_rid)
                .build(&mut context)
                .expect("Should build parameter pointer");
            param_pointers.push(pointer_token);
        }

        // Verify parameter pointers maintain logical sequence
        for (i, token) in param_pointers.iter().enumerate() {
            assert_eq!(token.table(), TableId::ParamPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_compressed_metadata_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate compressed metadata scenario with parameter indirection
        let compressed_order = [10, 5, 15, 1, 20];

        let mut pointer_tokens = Vec::new();
        for &param_order in &compressed_order {
            let token = ParamPtrBuilder::new()
                .param(param_order)
                .build(&mut context)
                .expect("Should build pointer for compressed metadata");
            pointer_tokens.push(token);
        }

        // Verify consistent indirection mapping
        assert_eq!(pointer_tokens.len(), 5);
        for (i, token) in pointer_tokens.iter().enumerate() {
            assert_eq!(token.table(), TableId::ParamPtr as u8);
            assert_eq!(token.row(), (i + 1) as u32);
        }

        Ok(())
    }

    #[test]
    fn test_paramptr_builder_edit_continue_parameter_scenario() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Simulate edit-and-continue where parameters are added/modified
        let original_params = [1, 2, 3];
        let mut pointers = Vec::new();

        for &param_rid in &original_params {
            let pointer = ParamPtrBuilder::new()
                .param(param_rid)
                .build(&mut context)
                .expect("Should build parameter pointer for edit-continue");
            pointers.push(pointer);
        }

        // Add new parameter during edit session
        let new_param_pointer = ParamPtrBuilder::new()
            .param(100) // New parameter added during edit
            .build(&mut context)
            .expect("Should build new parameter pointer");

        // Verify stable parameter pointer tokens
        for (i, token) in pointers.iter().enumerate() {
            assert_eq!(token.row(), (i + 1) as u32);
        }
        assert_eq!(new_param_pointer.row(), 4);

        Ok(())
    }
}
