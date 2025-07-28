//! Builder for constructing `ImportScope` table entries
//!
//! This module provides the [`crate::metadata::tables::importscope::ImportScopeBuilder`] which enables fluent construction
//! of `ImportScope` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let imports_bytes = vec![0x01, 0x02]; // Raw import data
//!
//! let scope_token = ImportScopeBuilder::new()
//!     .parent(0)                     // Root scope (no parent)
//!     .imports(&imports_bytes)       // Raw import blob data
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{ImportScopeRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `ImportScope` table entries
///
/// Provides a fluent interface for building `ImportScope` metadata table entries.
/// The builder validates all required fields are provided and handles proper
/// integration with the metadata system.
///
/// # Required Fields
/// - `parent`: Parent scope index (0 for root scope, must be explicitly set)
/// - `imports`: Raw import blob data (must be provided)
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // Root import scope
/// let imports_data = vec![0x01, 0x02, 0x03]; // Raw import blob
/// let root_scope = ImportScopeBuilder::new()
///     .parent(0)  // Root scope
///     .imports(&imports_data)
///     .build(&mut context)?;
///
/// // Child import scope
/// let child_scope = ImportScopeBuilder::new()
///     .parent(1)  // References first scope
///     .imports(&imports_data)
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct ImportScopeBuilder {
    /// Parent scope index (0 for root scope)
    parent: Option<u32>,
    /// Raw import blob data
    imports: Option<Vec<u8>>,
}

impl ImportScopeBuilder {
    /// Creates a new `ImportScopeBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required fields (parent and imports) before calling build().
    ///
    /// # Returns
    /// A new `ImportScopeBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = ImportScopeBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            imports: None,
        }
    }

    /// Sets the parent scope index
    ///
    /// Specifies the parent import scope that encloses this scope. Use 0 for
    /// root-level import scopes that have no parent.
    ///
    /// # Parameters
    /// - `parent`: The parent scope index (0 for root scope)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Root scope
    /// let builder = ImportScopeBuilder::new()
    ///     .parent(0);
    ///
    /// // Child scope referencing parent
    /// let child_builder = ImportScopeBuilder::new()
    ///     .parent(1);  // References scope with RID 1
    /// ```
    #[must_use]
    pub fn parent(mut self, parent: u32) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the import blob data
    ///
    /// Specifies the raw import blob data for this scope. These bytes
    /// represent the import information as defined in the Portable PDB format.
    ///
    /// # Parameters
    /// - `imports`: The raw import blob data
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // Import scope with namespace imports
    /// let import_data = vec![0x01, 0x10, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D]; // System namespace
    /// let builder = ImportScopeBuilder::new()
    ///     .imports(&import_data);
    ///
    /// // Empty import scope
    /// let empty_builder = ImportScopeBuilder::new()
    ///     .imports(&[]);
    /// ```
    #[must_use]
    pub fn imports(mut self, imports: &[u8]) -> Self {
        self.imports = Some(imports.to_vec());
        self
    }

    /// Builds and adds the `ImportScope` entry to the metadata
    ///
    /// Validates all required fields, creates the `ImportScope` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this import scope.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created import scope
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (parent or imports)
    /// - Table operations fail due to metadata constraints
    /// - Import scope validation failed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let imports_data = vec![0x01, 0x02, 0x03];
    /// let token = ImportScopeBuilder::new()
    ///     .parent(0)
    ///     .imports(&imports_data)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Parent scope index is required for ImportScope (use 0 for root scope)"
                    .to_string(),
            })?;

        let imports = self
            .imports
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Import blob data is required for ImportScope".to_string(),
            })?;

        let next_rid = context.next_rid(TableId::ImportScope);
        let token_value = ((TableId::ImportScope as u32) << 24) | next_rid;
        let token = Token::new(token_value);

        let imports_index = if imports.is_empty() {
            0
        } else {
            context.blob_add(&imports)?
        };

        let import_scope = ImportScopeRaw {
            rid: next_rid,
            token,
            offset: 0,
            parent,
            imports: imports_index,
        };

        context.table_row_add(
            TableId::ImportScope,
            TableDataOwned::ImportScope(import_scope),
        )?;
        Ok(token)
    }
}

impl Default for ImportScopeBuilder {
    /// Creates a default `ImportScopeBuilder`
    ///
    /// Equivalent to calling [`ImportScopeBuilder::new()`].
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
    fn test_importscope_builder_new() {
        let builder = ImportScopeBuilder::new();

        assert!(builder.parent.is_none());
        assert!(builder.imports.is_none());
    }

    #[test]
    fn test_importscope_builder_default() {
        let builder = ImportScopeBuilder::default();

        assert!(builder.parent.is_none());
        assert!(builder.imports.is_none());
    }

    #[test]
    fn test_importscope_builder_root_scope() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let imports_data = vec![0x01, 0x10, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D]; // System namespace
        let token = ImportScopeBuilder::new()
            .parent(0) // Root scope
            .imports(&imports_data)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ImportScope as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_importscope_builder_child_scope() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let imports_data = vec![0x01, 0x02, 0x03];
        let token = ImportScopeBuilder::new()
            .parent(1) // Child scope referencing parent
            .imports(&imports_data)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ImportScope as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_importscope_builder_empty_imports() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = ImportScopeBuilder::new()
            .parent(0)
            .imports(&[]) // Empty imports
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ImportScope as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_importscope_builder_missing_parent() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let imports_data = vec![0x01, 0x02];
        let result = ImportScopeBuilder::new()
            .imports(&imports_data)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Parent scope index is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_importscope_builder_missing_imports() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = ImportScopeBuilder::new().parent(0).build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Import blob data is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_importscope_builder_clone() {
        let imports_data = vec![0x01, 0x02, 0x03];
        let builder = ImportScopeBuilder::new().parent(0).imports(&imports_data);

        let cloned = builder.clone();
        assert_eq!(builder.parent, cloned.parent);
        assert_eq!(builder.imports, cloned.imports);
    }

    #[test]
    fn test_importscope_builder_debug() {
        let imports_data = vec![0x01, 0x02, 0x03];
        let builder = ImportScopeBuilder::new().parent(1).imports(&imports_data);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ImportScopeBuilder"));
        assert!(debug_str.contains("parent"));
        assert!(debug_str.contains("imports"));
    }

    #[test]
    fn test_importscope_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let imports_data = vec![0x01, 0x05, 0x54, 0x65, 0x73, 0x74, 0x73]; // Tests namespace

        // Test method chaining
        let token = ImportScopeBuilder::new()
            .parent(0)
            .imports(&imports_data)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::ImportScope as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_importscope_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let imports1 = vec![0x01, 0x02];
        let imports2 = vec![0x03, 0x04];

        // Build first scope
        let token1 = ImportScopeBuilder::new()
            .parent(0)
            .imports(&imports1)
            .build(&mut context)
            .expect("Should build first scope");

        // Build second scope
        let token2 = ImportScopeBuilder::new()
            .parent(1) // Child of first scope
            .imports(&imports2)
            .build(&mut context)
            .expect("Should build second scope");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }
}
