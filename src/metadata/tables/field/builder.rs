//! FieldBuilder for creating field definitions.
//!
//! This module provides [`crate::metadata::tables::field::FieldBuilder`] for creating Field table entries
//! with a fluent API. Fields define data members for types including instance
//! fields, static fields, constants, and literals with their associated types
//! and characteristics.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{FieldRaw, TableDataOwned, TableId},
        token::Token,
    },
    Result,
};

/// Builder for creating Field metadata entries.
///
/// `FieldBuilder` provides a fluent API for creating Field table entries
/// with validation and automatic heap management. Field entries define
/// data members of types including instance fields, static fields, and
/// compile-time constants.
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::FieldBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create a field signature for System.String
/// let string_signature = &[0x12]; // ELEMENT_TYPE_STRING
///
/// // Create a private instance field
/// let my_field = FieldBuilder::new()
///     .name("myField")
///     .flags(0x0001) // Private
///     .signature(string_signature)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct FieldBuilder {
    name: Option<String>,
    flags: Option<u32>,
    signature: Option<Vec<u8>>,
}

impl Default for FieldBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldBuilder {
    /// Creates a new FieldBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::field::FieldBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            signature: None,
        }
    }

    /// Sets the field name.
    ///
    /// # Arguments
    ///
    /// * `name` - The field name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the field flags (attributes).
    ///
    /// Field flags control accessibility, storage type, and special behaviors.
    /// Common flag values:
    /// - `0x0001`: CompilerControlled
    /// - `0x0002`: Private
    /// - `0x0003`: FamANDAssem (Family AND Assembly)
    /// - `0x0004`: Assembly
    /// - `0x0005`: Family (Protected)
    /// - `0x0006`: FamORAssem (Family OR Assembly)
    /// - `0x0007`: Public
    /// - `0x0010`: Static
    /// - `0x0020`: InitOnly (Readonly)
    /// - `0x0040`: Literal (Const)
    /// - `0x0080`: NotSerialized
    /// - `0x0100`: SpecialName
    /// - `0x0200`: PinvokeImpl
    /// - `0x0400`: RTSpecialName
    /// - `0x0800`: HasFieldMarshal
    /// - `0x1000`: HasDefault
    /// - `0x2000`: HasFieldRVA
    ///
    /// # Arguments
    ///
    /// * `flags` - The field attribute flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the field type signature.
    ///
    /// The signature defines the field's type using ECMA-335 signature encoding.
    /// Common signatures:
    /// - `[0x08]`: ELEMENT_TYPE_I4 (int32)
    /// - `[0x0C]`: ELEMENT_TYPE_U4 (uint32)
    /// - `[0x0E]`: ELEMENT_TYPE_STRING (System.String)
    /// - `[0x1C]`: ELEMENT_TYPE_OBJECT (System.Object)
    ///
    /// # Arguments
    ///
    /// * `signature` - The field type signature bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self
    }

    /// Builds the field and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name and
    /// signature to the appropriate heaps, creates the raw field structure,
    /// and adds it to the Field table.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created field, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if name is not set
    /// - Returns error if flags are not set
    /// - Returns error if signature is not set
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| crate::Error::ModificationInvalidOperation {
                details: "Field name is required".to_string(),
            })?;

        let flags = self
            .flags
            .ok_or_else(|| crate::Error::ModificationInvalidOperation {
                details: "Field flags are required".to_string(),
            })?;

        let signature =
            self.signature
                .ok_or_else(|| crate::Error::ModificationInvalidOperation {
                    details: "Field signature is required".to_string(),
                })?;

        // Add name to string heap
        let name_index = context.string_get_or_add(&name)?;

        // Add signature to blob heap
        let signature_index = context.blob_add(&signature)?;

        // Get the next RID for the Field table
        let rid = context.next_rid(TableId::Field);

        // Create the token for this field
        let token = Token::from_parts(TableId::Field, rid);

        // Create the raw field structure
        let field_raw = FieldRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags,
            name: name_index,
            signature: signature_index,
        };

        // Add the field to the table
        context.table_row_add(TableId::Field, TableDataOwned::Field(field_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        prelude::FieldAttributes,
    };
    use std::path::PathBuf;

    #[test]
    fn test_field_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);

            // Check existing Field table count
            let existing_field_count = assembly.original_table_row_count(TableId::Field);
            let expected_rid = existing_field_count + 1;

            let mut context = BuilderContext::new(assembly);

            // Create a field signature for System.String (ELEMENT_TYPE_STRING = 0x0E)
            let string_signature = &[0x0E];

            let token = FieldBuilder::new()
                .name("testField")
                .flags(FieldAttributes::PRIVATE)
                .signature(string_signature)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert!(token.is_table(TableId::Field)); // Field table prefix
            assert_eq!(token.row(), expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_field_builder_with_attributes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create an int32 signature (ELEMENT_TYPE_I4 = 0x08)
            let int32_signature = &[0x08];

            // Create a public static readonly field
            let token = FieldBuilder::new()
                .name("PublicStaticField")
                .flags(
                    FieldAttributes::PUBLIC | FieldAttributes::STATIC | FieldAttributes::INIT_ONLY,
                )
                .signature(int32_signature)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert!(token.is_table(TableId::Field));
        }
    }

    #[test]
    fn test_field_builder_literal_field() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create a boolean signature (ELEMENT_TYPE_BOOLEAN = 0x02)
            let bool_signature = &[0x02];

            // Create a private const field
            let token = FieldBuilder::new()
                .name("ConstField")
                .flags(
                    FieldAttributes::PRIVATE | FieldAttributes::LITERAL | FieldAttributes::STATIC,
                )
                .signature(bool_signature)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert!(token.is_table(TableId::Field));
        }
    }

    #[test]
    fn test_field_builder_missing_name() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = FieldBuilder::new()
                .flags(FieldAttributes::PRIVATE)
                .signature(&[0x08])
                .build(&mut context);

            // Should fail because name is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_builder_missing_flags() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = FieldBuilder::new()
                .name("testField")
                .signature(&[0x08])
                .build(&mut context);

            // Should fail because flags are required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_builder_missing_signature() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = FieldBuilder::new()
                .name("testField")
                .flags(FieldAttributes::PRIVATE)
                .build(&mut context);

            // Should fail because signature is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_builder_multiple_fields() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let signature = &[0x08]; // int32

            // Create multiple fields - now this will work!
            let field1 = FieldBuilder::new()
                .name("Field1")
                .flags(FieldAttributes::PRIVATE)
                .signature(signature)
                .build(&mut context)
                .unwrap();

            let field2 = FieldBuilder::new()
                .name("Field2")
                .flags(FieldAttributes::PUBLIC)
                .signature(signature)
                .build(&mut context)
                .unwrap();

            // Both should succeed and have different RIDs
            assert_ne!(field1.row(), field2.row());
            assert!(field1.is_table(TableId::Field));
            assert!(field2.is_table(TableId::Field));
        }
    }
}
