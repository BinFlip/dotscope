//! ParamBuilder for creating parameter definitions.
//!
//! This module provides [`crate::metadata::tables::param::ParamBuilder`] for creating Param table entries
//! with a fluent API. Parameters define method parameter information including
//! names, attributes, sequence numbers, and characteristics for proper method
//! signature construction and parameter binding.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{ParamRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Param metadata entries.
///
/// `ParamBuilder` provides a fluent API for creating Param table entries
/// with validation and automatic heap management. Param entries define
/// method parameter information including names, attributes, sequence numbers,
/// and marshalling information for proper method invocation.
///
/// # Parameter Sequencing
///
/// The sequence field determines parameter ordering:
/// - **0**: Reserved for return type information
/// - **1+**: Method parameters in declaration order
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::ParamBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create a method parameter
/// let param = ParamBuilder::new()
///     .name("value")
///     .flags(0x0001) // IN parameter
///     .sequence(1)   // First parameter
///     .build(&mut context)?;
///
/// // Create a return type parameter (no name, sequence 0)
/// let return_param = ParamBuilder::new()
///     .flags(0x0000) // No special flags
///     .sequence(0)   // Return type
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ParamBuilder {
    name: Option<String>,
    flags: Option<u32>,
    sequence: Option<u32>,
}

impl Default for ParamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ParamBuilder {
    /// Creates a new ParamBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::param::ParamBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            sequence: None,
        }
    }

    /// Sets the parameter name.
    ///
    /// Parameter names are used for debugging, reflection, and IDE support.
    /// Return type parameters (sequence 0) typically don't have names.
    ///
    /// # Arguments
    ///
    /// * `name` - The parameter name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the parameter flags (attributes).
    ///
    /// Parameter flags control direction, optional status, and special behaviors.
    /// Common flag values from [`crate::metadata::tables::ParamAttributes`]:
    /// - `0x0001`: IN - Parameter is input (default for most parameters)
    /// - `0x0002`: OUT - Parameter is output (for ref/out parameters)
    /// - `0x0010`: OPTIONAL - Parameter is optional (COM interop)
    /// - `0x1000`: HAS_DEFAULT - Parameter has default value in Constant table
    /// - `0x2000`: HAS_FIELD_MARSHAL - Parameter has marshalling information
    ///
    /// # Arguments
    ///
    /// * `flags` - The parameter attribute flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the parameter sequence number.
    ///
    /// The sequence number determines parameter ordering in method signatures:
    /// - **0**: Return type parameter (usually unnamed)
    /// - **1**: First method parameter
    /// - **2**: Second method parameter
    /// - **N**: Nth method parameter
    ///
    /// # Arguments
    ///
    /// * `sequence` - The parameter sequence number (0 for return type, 1+ for parameters)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Builds the parameter and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name to
    /// the string heap (if provided), creates the raw parameter structure,
    /// and adds it to the Param table.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created parameter, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if flags are not set
    /// - Returns error if sequence is not set
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let flags = self
            .flags
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Parameter flags are required".to_string(),
            })?;

        let sequence = self
            .sequence
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Parameter sequence is required".to_string(),
            })?;

        let name_index = if let Some(name) = self.name {
            context.string_get_or_add(&name)?
        } else {
            0 // No name (common for return type parameters)
        };

        let rid = context.next_rid(TableId::Param);

        let token = Token::from_parts(TableId::Param, rid);

        let param_raw = ParamRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags,
            sequence,
            name: name_index,
        };

        context.table_row_add(TableId::Param, TableDataOwned::Param(param_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, tables::ParamAttributes},
    };
    use std::path::PathBuf;

    #[test]
    fn test_param_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);

            // Check existing Param table count
            let existing_param_count = assembly.original_table_row_count(TableId::Param);
            let expected_rid = existing_param_count + 1;

            let mut context = BuilderContext::new(assembly);

            let token = ParamBuilder::new()
                .name("testParam")
                .flags(ParamAttributes::IN)
                .sequence(1)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x08000000); // Param table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_param_builder_return_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create a return type parameter (no name, sequence 0)
            let token = ParamBuilder::new()
                .flags(0) // No special flags for return type
                .sequence(0) // Return type
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x08000000);
        }
    }

    #[test]
    fn test_param_builder_with_attributes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create an OUT parameter with optional flag
            let token = ParamBuilder::new()
                .name("outParam")
                .flags(ParamAttributes::OUT | ParamAttributes::OPTIONAL)
                .sequence(2)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x08000000);
        }
    }

    #[test]
    fn test_param_builder_default_value() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create a parameter with default value
            let token = ParamBuilder::new()
                .name("defaultParam")
                .flags(ParamAttributes::IN | ParamAttributes::HAS_DEFAULT)
                .sequence(3)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x08000000);
        }
    }

    #[test]
    fn test_param_builder_missing_flags() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = ParamBuilder::new()
                .name("testParam")
                .sequence(1)
                .build(&mut context);

            // Should fail because flags are required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_param_builder_missing_sequence() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = ParamBuilder::new()
                .name("testParam")
                .flags(ParamAttributes::IN)
                .build(&mut context);

            // Should fail because sequence is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_param_builder_multiple_params() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create multiple parameters with different sequences
            let param1 = ParamBuilder::new()
                .name("param1")
                .flags(ParamAttributes::IN)
                .sequence(1)
                .build(&mut context)
                .unwrap();

            let param2 = ParamBuilder::new()
                .name("param2")
                .flags(ParamAttributes::OUT)
                .sequence(2)
                .build(&mut context)
                .unwrap();

            let return_param = ParamBuilder::new()
                .flags(0)
                .sequence(0) // Return type
                .build(&mut context)
                .unwrap();

            // All should succeed and have different RIDs
            assert_ne!(param1.value() & 0x00FFFFFF, param2.value() & 0x00FFFFFF);
            assert_ne!(
                param1.value() & 0x00FFFFFF,
                return_param.value() & 0x00FFFFFF
            );
            assert_ne!(
                param2.value() & 0x00FFFFFF,
                return_param.value() & 0x00FFFFFF
            );

            // All should have Param table prefix
            assert_eq!(param1.value() & 0xFF000000, 0x08000000);
            assert_eq!(param2.value() & 0xFF000000, 0x08000000);
            assert_eq!(return_param.value() & 0xFF000000, 0x08000000);
        }
    }
}
