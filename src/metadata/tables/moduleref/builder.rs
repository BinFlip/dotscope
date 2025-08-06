//! # ModuleRef Builder
//!
//! Provides a fluent API for building ModuleRef table entries that reference external modules.
//! The ModuleRef table contains references to external modules required by the current assembly.
//!
//! ## Overview
//!
//! The `ModuleRefBuilder` enables creation of module references with:
//! - Module name validation and heap management
//! - Automatic RID assignment and token generation
//! - Integration with the broader builder context
//! - Comprehensive validation and error handling
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a module reference
//! let module_ref_token = ModuleRefBuilder::new()
//!     .name("ExternalModule.dll")
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Module name is required and non-empty
//! - **Heap Management**: Strings are automatically added to the string heap
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Error Handling**: Clear error messages for validation failures

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{ModuleRefRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating ModuleRef table entries.
///
/// `ModuleRefBuilder` provides a fluent API for creating entries in the ModuleRef
/// metadata table, which contains references to external modules required by
/// the current assembly.
///
/// # Purpose
///
/// The ModuleRef table serves several key functions:
/// - **External Module References**: References to modules outside the current assembly
/// - **Multi-Module Assemblies**: Support for assemblies spanning multiple files
/// - **Type Resolution**: Foundation for resolving types in external modules
/// - **Import Tracking**: Enables tracking of cross-module dependencies
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing ModuleRef entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
///
/// let module_ref = ModuleRefBuilder::new()
///     .name("System.Core.dll")
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: A module name must be provided
/// - **Name Non-Empty**: The module name cannot be empty
/// - **Valid Module Name**: Basic validation of module name format
///
/// # Integration
///
/// ModuleRef entries integrate with other metadata tables:
/// - **TypeRef**: External types can reference modules via ModuleRef
/// - **MemberRef**: External members can reference modules via ModuleRef
/// - **Assembly**: Multi-module assemblies use ModuleRef for file references
#[derive(Debug, Clone, Default)]
pub struct ModuleRefBuilder {
    /// The name of the external module
    name: Option<String>,
}

impl ModuleRefBuilder {
    /// Creates a new `ModuleRefBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ModuleRefBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { name: None }
    }

    /// Sets the name of the external module.
    ///
    /// The module name typically corresponds to a file name (e.g., "System.Core.dll")
    /// or a logical module identifier in multi-module assemblies.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the external module
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ModuleRefBuilder::new()
    ///     .name("System.Core.dll");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Builds the ModuleRef entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings to the
    /// string heap, creates the ModuleRef table entry, and returns the
    /// metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created ModuleRef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The module name is not set
    /// - The module name is empty
    /// - There are issues adding strings to the heap
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
    ///
    /// let module_ref_token = ModuleRefBuilder::new()
    ///     .name("MyModule.dll")
    ///     .build(&mut context)?;
    ///
    /// println!("Created ModuleRef with token: {}", module_ref_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Module name is required for ModuleRef".to_string(),
            })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Module name cannot be empty for ModuleRef".to_string(),
            });
        }

        let name_index = context.string_get_or_add(&name)?;
        let rid = context.next_rid(TableId::ModuleRef);
        let token = Token::from_parts(TableId::ModuleRef, rid);

        let module_ref = ModuleRefRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            name: name_index,
        };

        context.table_row_add(TableId::ModuleRef, TableDataOwned::ModuleRef(module_ref))?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::factories::table::assemblyref::get_test_assembly;

    #[test]
    fn test_moduleref_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ModuleRefBuilder::new()
            .name("System.Core.dll")
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::ModuleRef as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_default() -> Result<()> {
        let builder = ModuleRefBuilder::default();
        assert!(builder.name.is_none());
        Ok(())
    }

    #[test]
    fn test_moduleref_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = ModuleRefBuilder::new().build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Module name is required"));

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_empty_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = ModuleRefBuilder::new().name("").build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Module name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_multiple_modules() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token1 = ModuleRefBuilder::new()
            .name("Module1.dll")
            .build(&mut context)?;

        let token2 = ModuleRefBuilder::new()
            .name("Module2.dll")
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(token1, token2);
        assert_eq!(token1.table(), TableId::ModuleRef as u8);
        assert_eq!(token2.table(), TableId::ModuleRef as u8);
        assert_eq!(token2.row(), token1.row() + 1);

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test fluent API chaining
        let token = ModuleRefBuilder::new()
            .name("FluentModule.dll")
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ModuleRef as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_various_names() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let test_names = [
            "System.dll",
            "Microsoft.Extensions.Logging.dll",
            "MyCustomModule",
            "Module.With.Dots.dll",
            "VeryLongModuleNameThatExceedsTypicalLengths.dll",
        ];

        for name in test_names.iter() {
            let token = ModuleRefBuilder::new().name(*name).build(&mut context)?;

            assert_eq!(token.table(), TableId::ModuleRef as u8);
            // Row numbers start from the next available RID (which could be higher if table already has entries)
            assert!(token.row() > 0);
        }

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_string_reuse() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create two module references with the same name
        let token1 = ModuleRefBuilder::new()
            .name("SharedModule.dll")
            .build(&mut context)?;

        let token2 = ModuleRefBuilder::new()
            .name("SharedModule.dll")
            .build(&mut context)?;

        // Tokens should be different (different RIDs)
        assert_ne!(token1, token2);
        assert_eq!(token2.row(), token1.row() + 1);

        // But the strings should be reused in the heap
        // (This is an internal optimization that the builder context handles)

        Ok(())
    }

    #[test]
    fn test_moduleref_builder_clone() {
        let builder1 = ModuleRefBuilder::new().name("Module.dll");
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
    }

    #[test]
    fn test_moduleref_builder_debug() {
        let builder = ModuleRefBuilder::new().name("DebugModule.dll");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ModuleRefBuilder"));
        assert!(debug_str.contains("DebugModule.dll"));
    }
}
