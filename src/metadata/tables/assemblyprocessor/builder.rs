//! Builder for constructing `AssemblyProcessor` table entries
//!
//! This module provides the [`crate::metadata::tables::assemblyprocessor::builder::AssemblyProcessorBuilder`] which enables fluent construction
//! of `AssemblyProcessor` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use dotscope::prelude::*;
//!
//! let builder_context = BuilderContext::new();
//!
//! let processor_token = AssemblyProcessorBuilder::new()
//!     .processor(0x014C)             // x86 processor architecture
//!     .build(&mut builder_context)?;
//! ```

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{AssemblyProcessorRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `AssemblyProcessor` table entries
///
/// Provides a fluent interface for building `AssemblyProcessor` metadata table entries.
/// These entries specify processor architecture targeting information for assemblies,
/// though they are rarely used in modern .NET applications which typically use AnyCPU.
///
/// # Required Fields
/// - `processor`: Processor architecture identifier (must be provided)
///
/// # Historical Context
///
/// The AssemblyProcessor table was designed for early .NET Framework scenarios where
/// assemblies might need explicit CPU architecture declarations. Modern applications
/// typically use AnyCPU compilation and rely on runtime JIT optimization.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
///
/// // x86 processor targeting
/// let x86_proc = AssemblyProcessorBuilder::new()
///     .processor(0x014C)  // x86 architecture
///     .build(&mut context)?;
///
/// // x64 processor targeting
/// let x64_proc = AssemblyProcessorBuilder::new()
///     .processor(0x8664)  // x64 architecture
///     .build(&mut context)?;
///
/// // Custom processor identifier
/// let custom_proc = AssemblyProcessorBuilder::new()
///     .processor(0x1234)  // Custom architecture identifier
///     .build(&mut context)?;
/// ```
#[derive(Debug, Clone)]
pub struct AssemblyProcessorBuilder {
    /// Processor architecture identifier
    processor: Option<u32>,
}

impl AssemblyProcessorBuilder {
    /// Creates a new `AssemblyProcessorBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the processor field before calling build().
    ///
    /// # Returns
    /// A new `AssemblyProcessorBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let builder = AssemblyProcessorBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { processor: None }
    }

    /// Sets the processor architecture identifier
    ///
    /// Specifies the target CPU architecture for this assembly. While ECMA-335
    /// doesn't standardize exact values, common historical identifiers include
    /// x86, x64, and IA64 architectures.
    ///
    /// # Parameters
    /// - `processor`: The processor architecture identifier
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Common Values
    /// - `0x014C`: x86 (32-bit Intel)
    /// - `0x8664`: x64 (64-bit AMD/Intel)
    /// - `0x0200`: IA64 (Intel Itanium, deprecated)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// // x86 targeting
    /// let builder = AssemblyProcessorBuilder::new()
    ///     .processor(0x014C);
    ///
    /// // x64 targeting
    /// let builder = AssemblyProcessorBuilder::new()
    ///     .processor(0x8664);
    /// ```
    #[must_use]
    pub fn processor(mut self, processor: u32) -> Self {
        self.processor = Some(processor);
        self
    }

    /// Builds and adds the `AssemblyProcessor` entry to the metadata
    ///
    /// Validates all required fields, creates the `AssemblyProcessor` table entry,
    /// and adds it to the builder context. Returns a token that can be used
    /// to reference this assembly processor entry.
    ///
    /// # Parameters
    /// - `context`: Mutable reference to the builder context
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created assembly processor
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (processor)
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    ///
    /// let mut context = BuilderContext::new();
    /// let token = AssemblyProcessorBuilder::new()
    ///     .processor(0x014C)
    ///     .build(&mut context)?;
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let processor = self
            .processor
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Processor architecture identifier is required for AssemblyProcessor"
                    .to_string(),
            })?;

        let next_rid = context.next_rid(TableId::AssemblyProcessor);
        let token_value = ((TableId::AssemblyProcessor as u32) << 24) | next_rid;
        let token = Token::new(token_value);

        let assembly_processor = AssemblyProcessorRaw {
            rid: next_rid,
            token,
            offset: 0,
            processor,
        };

        context.table_row_add(
            TableId::AssemblyProcessor,
            TableDataOwned::AssemblyProcessor(assembly_processor),
        )?;
        Ok(token)
    }
}

impl Default for AssemblyProcessorBuilder {
    /// Creates a default `AssemblyProcessorBuilder`
    ///
    /// Equivalent to calling [`AssemblyProcessorBuilder::new()`].
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
    fn test_assemblyprocessor_builder_new() {
        let builder = AssemblyProcessorBuilder::new();

        assert!(builder.processor.is_none());
    }

    #[test]
    fn test_assemblyprocessor_builder_default() {
        let builder = AssemblyProcessorBuilder::default();

        assert!(builder.processor.is_none());
    }

    #[test]
    fn test_assemblyprocessor_builder_x86() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyProcessorBuilder::new()
            .processor(0x014C) // x86
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_x64() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyProcessorBuilder::new()
            .processor(0x8664) // x64
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_ia64() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyProcessorBuilder::new()
            .processor(0x0200) // IA64
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_custom() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyProcessorBuilder::new()
            .processor(0x1234) // Custom processor ID
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_missing_processor() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let result = AssemblyProcessorBuilder::new().build(&mut context);

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
    fn test_assemblyprocessor_builder_clone() {
        let builder = AssemblyProcessorBuilder::new().processor(0x014C);

        let cloned = builder.clone();
        assert_eq!(builder.processor, cloned.processor);
    }

    #[test]
    fn test_assemblyprocessor_builder_debug() {
        let builder = AssemblyProcessorBuilder::new().processor(0x8664);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AssemblyProcessorBuilder"));
        assert!(debug_str.contains("processor"));
    }

    #[test]
    fn test_assemblyprocessor_builder_fluent_interface() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test method chaining
        let token = AssemblyProcessorBuilder::new()
            .processor(0x9999)
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_multiple_builds() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Build first processor
        let token1 = AssemblyProcessorBuilder::new()
            .processor(0x014C) // x86
            .build(&mut context)
            .expect("Should build first processor");

        // Build second processor
        let token2 = AssemblyProcessorBuilder::new()
            .processor(0x8664) // x64
            .build(&mut context)
            .expect("Should build second processor");

        assert_eq!(token1.row(), 1);
        assert_eq!(token2.row(), 2);
        assert_ne!(token1, token2);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_zero_processor() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyProcessorBuilder::new()
            .processor(0) // Zero processor ID
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }

    #[test]
    fn test_assemblyprocessor_builder_max_processor() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);
        let token = AssemblyProcessorBuilder::new()
            .processor(u32::MAX) // Maximum processor ID
            .build(&mut context)
            .expect("Should build successfully");

        assert_eq!(token.table(), TableId::AssemblyProcessor as u8);
        assert_eq!(token.row(), 1);
        Ok(())
    }
}
