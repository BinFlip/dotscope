//! Builder for constructing `AssemblyRefProcessor` table entries
//!
//! This module provides the [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorBuilder`] which enables fluent construction
//! of `AssemblyRefProcessor` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let processor_token = AssemblyRefProcessorBuilder::new()
//!     .processor(0x8664)             // x64 processor architecture
//!     .assembly_ref(1)               // AssemblyRef RID
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{AssemblyRefProcessorRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `AssemblyRefProcessor` table entries
///
/// Provides a fluent interface for building `AssemblyRefProcessor` metadata table entries.
/// These entries specify processor architecture requirements for external assembly references,
/// though they are rarely used in modern .NET applications.
///
/// # Required Fields
/// - `processor`: Processor architecture identifier
/// - `assembly_ref`: AssemblyRef table RID
///
/// # Historical Context
///
/// The AssemblyRefProcessor table was designed for early .NET Framework scenarios where
/// assemblies might need to declare explicit processor compatibility dependencies for
/// external references. Modern applications typically rely on runtime platform detection.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // x64 processor requirement for external assembly
/// let x64_ref = AssemblyRefProcessorBuilder::new()
///     .processor(0x8664)  // x64 architecture
///     .assembly_ref(1)    // References first AssemblyRef
///     .build(&mut context)?;
///
/// // x86 processor requirement
/// let x86_ref = AssemblyRefProcessorBuilder::new()
///     .processor(0x014C)  // x86 architecture
///     .assembly_ref(2)    // References second AssemblyRef
///     .build(&mut context)?;
///
/// // ARM64 processor requirement
/// let arm64_ref = AssemblyRefProcessorBuilder::new()
///     .processor(0xAA64)  // ARM64 architecture
///     .assembly_ref(3)    // References third AssemblyRef
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct AssemblyRefProcessorBuilder {
    /// Processor architecture identifier
    processor: Option<u32>,
    /// AssemblyRef table RID
    assembly_ref: Option<u32>,
}

impl AssemblyRefProcessorBuilder {
    /// Creates a new `AssemblyRefProcessorBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide both required fields before calling build().
    ///
    /// # Returns
    /// A new `AssemblyRefProcessorBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyRefProcessorBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            processor: None,
            assembly_ref: None,
        }
    }

    /// Sets the processor architecture identifier
    ///
    /// Specifies the target processor architecture required for the referenced
    /// external assembly. Common values include x86, x64, ARM, and ARM64.
    ///
    /// # Parameters
    /// - `processor`: The processor architecture identifier
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Common Values
    /// - `0x0000`: No specific processor requirement
    /// - `0x014C`: Intel 386 (x86)
    /// - `0x8664`: AMD64 (x64)
    /// - `0x01C0`: ARM (32-bit)
    /// - `0xAA64`: ARM64
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // x64 requirement
    /// let builder = AssemblyRefProcessorBuilder::new()
    ///     .processor(0x8664);
    ///
    /// // ARM64 requirement
    /// let builder = AssemblyRefProcessorBuilder::new()
    ///     .processor(0xAA64);
    /// ```
    pub fn processor(mut self, processor: u32) -> Self {
        self.processor = Some(processor);
        self
    }

    /// Sets the AssemblyRef table RID
    ///
    /// Specifies the AssemblyRef table row ID that this processor requirement
    /// applies to. This must reference a valid AssemblyRef entry.
    ///
    /// # Parameters
    /// - `assembly_ref`: The AssemblyRef table RID
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyRefProcessorBuilder::new()
    ///     .assembly_ref(1);  // References first AssemblyRef
    /// ```
    pub fn assembly_ref(mut self, assembly_ref: u32) -> Self {
        self.assembly_ref = Some(assembly_ref);
        self
    }

    /// Builds and adds the `AssemblyRefProcessor` entry to the metadata
    ///
    /// Validates all required fields, creates the `AssemblyRefProcessor` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this assembly ref processor entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created assembly ref processor
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (processor or assembly_ref)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = AssemblyRefProcessorBuilder::new()
    ///     .processor(0x8664)
    ///     .assembly_ref(1)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let processor = self
            .processor
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Processor architecture identifier is required for AssemblyRefProcessor"
                    .to_string(),
            })?;

        let assembly_ref =
            self.assembly_ref
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "AssemblyRef RID is required for AssemblyRefProcessor".to_string(),
                })?;

        let next_rid = context.next_rid(TableId::AssemblyRefProcessor);
        let token_value = ((TableId::AssemblyRefProcessor as u32) << 24) | next_rid;
        let token = Token::new(token_value);

        let assembly_ref_processor = AssemblyRefProcessorRaw {
            rid: next_rid,
            token,
            offset: 0,
            processor,
            assembly_ref,
        };

        context.add_table_row(
            TableId::AssemblyRefProcessor,
            TableDataOwned::AssemblyRefProcessor(assembly_ref_processor),
        )?;
        Ok(token)
    }
}

impl Default for AssemblyRefProcessorBuilder {
    /// Creates a default `AssemblyRefProcessorBuilder`
    ///
    /// Equivalent to calling [`AssemblyRefProcessorBuilder::new()`].
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
    fn test_assemblyrefprocessor_builder_new() {
        let builder = AssemblyRefProcessorBuilder::new();

        assert!(builder.processor.is_none());
        assert!(builder.assembly_ref.is_none());
    }

    #[test]
    fn test_assemblyrefprocessor_builder_default() {
        let builder = AssemblyRefProcessorBuilder::default();

        assert!(builder.processor.is_none());
        assert!(builder.assembly_ref.is_none());
    }

    #[test]
    fn test_assemblyrefprocessor_builder_x64() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0x8664) // x64
            .assembly_ref(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_x86() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0x014C) // x86
            .assembly_ref(2)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_arm64() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0xAA64) // ARM64
            .assembly_ref(3)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_no_requirement() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0x0000) // No specific requirement
            .assembly_ref(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_missing_processor() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = AssemblyRefProcessorBuilder::new()
            .assembly_ref(1)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("Processor architecture identifier is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_missing_assembly_ref() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = AssemblyRefProcessorBuilder::new()
            .processor(0x8664)
            .build(&mut context);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalidOperation { details } => {
                assert!(details.contains("AssemblyRef RID is required"));
            }
            _ => panic!("Expected ModificationInvalidOperation error"),
        }
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_clone() {
        let builder = AssemblyRefProcessorBuilder::new()
            .processor(0x8664)
            .assembly_ref(1);

        let cloned = builder.clone();
        assert_eq!(builder.processor, cloned.processor);
        assert_eq!(builder.assembly_ref, cloned.assembly_ref);
    }

    #[test]
    fn test_assemblyrefprocessor_builder_debug() {
        let builder = AssemblyRefProcessorBuilder::new()
            .processor(0x014C)
            .assembly_ref(2);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyRefProcessorBuilder"));
        assert!(debug_str.contains("processor"));
        assert!(debug_str.contains("assembly_ref"));
    }

    #[test]
    fn test_assemblyrefprocessor_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0x01C0) // ARM
            .assembly_ref(5)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first processor entry
        let token1 = AssemblyRefProcessorBuilder::new()
            .processor(0x8664) // x64
            .assembly_ref(1)
            .build(&mut context)
            .expect("Should build first processor entry");

        // Build second processor entry
        let token2 = AssemblyRefProcessorBuilder::new()
            .processor(0x014C) // x86
            .assembly_ref(2)
            .build(&mut context)
            .expect("Should build second processor entry");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_large_assembly_ref() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0x8664)
            .assembly_ref(0xFFFF) // Large AssemblyRef RID
            .build(&mut context)
            .expect("Should handle large assembly ref RID");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyrefprocessor_builder_custom_processor() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyRefProcessorBuilder::new()
            .processor(0x1234) // Custom processor identifier
            .assembly_ref(1)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyRefProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }
}
