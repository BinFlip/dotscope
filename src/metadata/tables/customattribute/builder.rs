//! CustomAttributeBuilder for creating custom attribute definitions.
//!
//! This module provides [`crate::metadata::tables::customattribute::CustomAttributeBuilder`] for creating CustomAttribute table entries
//! with a fluent API. Custom attributes allow adding declarative metadata to any element
//! in the .NET metadata system, providing extensible annotation mechanisms for types,
//! methods, fields, assemblies, and other metadata entities.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{CodedIndex, CodedIndexType, CustomAttributeRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating CustomAttribute metadata entries.
///
/// `CustomAttributeBuilder` provides a fluent API for creating CustomAttribute table entries
/// with validation and automatic heap management. Custom attributes associate declarative
/// metadata with elements throughout the assembly, enabling extensible annotation of types,
/// methods, fields, parameters, assemblies, and other metadata entities.
///
/// # Custom Attribute Model
///
/// .NET custom attributes follow a standard pattern:
/// - **Target Element**: The metadata entity being annotated (parent)
/// - **Attribute Type**: The constructor method that defines the attribute type
/// - **Attribute Values**: Serialized constructor arguments and named property/field values
/// - **Metadata Integration**: Full reflection and runtime discovery support
///
/// # Coded Index Types
///
/// Custom attributes use two important coded index types:
/// - **HasCustomAttribute**: Identifies the target element (parent) being annotated
/// - **CustomAttributeType**: References the constructor method (MethodDef or MemberRef)
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{CustomAttributeBuilder, CodedIndex, TableId};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create coded indices for the custom attribute
/// let target_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute); // Target class
/// let constructor = CodedIndex::new(TableId::MethodDef, 5, CodedIndexType::CustomAttributeType); // Attribute constructor
///
/// // Create an empty custom attribute blob (no arguments)
/// let empty_blob = &[];
///
/// // Create a custom attribute
/// let attribute = CustomAttributeBuilder::new()
///     .parent(target_type)
///     .constructor(constructor.clone())
///     .value(empty_blob)
///     .build(&mut context)?;
///
/// // Create a custom attribute with values  
/// let attribute_blob = &[0x01, 0x00, 0x00, 0x00]; // Prolog + no arguments
/// let target_method = CodedIndex::new(TableId::MethodDef, 3, CodedIndexType::HasCustomAttribute); // Another target
/// let complex_attribute = CustomAttributeBuilder::new()
///     .parent(target_method)
///     .constructor(constructor)
///     .value(attribute_blob)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct CustomAttributeBuilder {
    parent: Option<CodedIndex>,
    constructor: Option<CodedIndex>,
    value: Option<Vec<u8>>,
}

impl Default for CustomAttributeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CustomAttributeBuilder {
    /// Creates a new CustomAttributeBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::customattribute::CustomAttributeBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            constructor: None,
            value: None,
        }
    }

    /// Sets the parent element that this custom attribute is applied to.
    ///
    /// The parent must be a valid `HasCustomAttribute` coded index that references
    /// a metadata element that can have custom attributes applied to it. This includes
    /// types, methods, fields, parameters, assemblies, modules, and many other entities.
    ///
    /// Valid parent types include:
    /// - `TypeDef` - Type definitions
    /// - `MethodDef` - Method definitions  
    /// - `Field` - Field definitions
    /// - `Param` - Parameter definitions
    /// - `Assembly` - Assembly metadata
    /// - `Module` - Module metadata
    /// - `Property` - Property definitions
    /// - `Event` - Event definitions
    /// - And many others supported by HasCustomAttribute
    ///
    /// # Arguments
    ///
    /// * `parent` - A `HasCustomAttribute` coded index pointing to the target element
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn parent(mut self, parent: CodedIndex) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the constructor method for the custom attribute type.
    ///
    /// The constructor must be a valid `CustomAttributeType` coded index that references
    /// a constructor method (`.ctor`) for the attribute type. This can be either a
    /// `MethodDef` for types defined in this assembly or a `MemberRef` for external types.
    ///
    /// Valid constructor types:
    /// - `MethodDef` - Constructor method defined in this assembly
    /// - `MemberRef` - Constructor method from external assembly
    ///
    /// The referenced method must be a constructor (name = ".ctor") and must have
    /// a signature compatible with the attribute value blob.
    ///
    /// # Arguments
    ///
    /// * `constructor` - A `CustomAttributeType` coded index pointing to the constructor
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn constructor(mut self, constructor: CodedIndex) -> Self {
        self.constructor = Some(constructor);
        self
    }

    /// Sets the serialized attribute value blob.
    ///
    /// The value blob contains the serialized constructor arguments and named field/property
    /// values according to the ECMA-335 custom attribute binary format. The blob structure
    /// depends on the constructor signature and any named arguments provided.
    ///
    /// Blob format:
    /// - **Prolog**: 2-byte signature (0x0001 for valid attributes)
    /// - **Fixed Args**: Constructor arguments in declaration order
    /// - **Named Args Count**: 2-byte count of named arguments
    /// - **Named Args**: Property/field assignments with names and values
    ///
    /// Common patterns:
    /// - `[]` - Empty blob (no value)
    /// - `[0x01, 0x00]` - Empty attribute with prolog only
    /// - `[0x01, 0x00, 0x00, 0x00]` - Empty attribute with prolog and no named args
    ///
    /// # Arguments
    ///
    /// * `value` - The serialized attribute value bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn value(mut self, value: &[u8]) -> Self {
        self.value = Some(value.to_vec());
        self
    }

    /// Builds the custom attribute and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the value blob to
    /// the blob heap (if provided), creates the raw custom attribute structure,
    /// and adds it to the CustomAttribute table.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created custom attribute, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if parent is not set
    /// - Returns error if constructor is not set
    /// - Returns error if parent is not a valid HasCustomAttribute coded index
    /// - Returns error if constructor is not a valid CustomAttributeType coded index
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "CustomAttribute parent is required".to_string(),
            })?;

        let constructor = self
            .constructor
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "CustomAttribute constructor is required".to_string(),
            })?;

        let valid_parent_tables = CodedIndexType::HasCustomAttribute.tables();
        if !valid_parent_tables.contains(&parent.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Parent must be a HasCustomAttribute coded index, got {:?}",
                    parent.tag
                ),
            });
        }

        let valid_constructor_tables = CodedIndexType::CustomAttributeType.tables();
        if !valid_constructor_tables.contains(&constructor.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Constructor must be a CustomAttributeType coded index (MethodDef/MemberRef), got {:?}",
                    constructor.tag
                ),
            });
        }

        let value_index = if let Some(value) = self.value {
            if value.is_empty() {
                0 // Empty blob
            } else {
                context.blob_add(&value)?
            }
        } else {
            0 // No value provided
        };

        let rid = context.next_rid(TableId::CustomAttribute);

        let token = Token::from_parts(TableId::CustomAttribute, rid);

        let custom_attribute_raw = CustomAttributeRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            parent,
            constructor,
            value: value_index,
        };

        context.table_row_add(
            TableId::CustomAttribute,
            TableDataOwned::CustomAttribute(custom_attribute_raw),
        )
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

    #[test]
    fn test_custom_attribute_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);

            // Check existing CustomAttribute table count
            let existing_count = assembly.original_table_row_count(TableId::CustomAttribute);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(assembly);

            // Create coded indices for HasCustomAttribute and CustomAttributeType
            let target_type =
                CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute); // HasCustomAttribute
            let constructor =
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType); // CustomAttributeType

            let token = CustomAttributeBuilder::new()
                .parent(target_type)
                .constructor(constructor)
                .value(&[]) // Empty value
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x0C000000); // CustomAttribute table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_custom_attribute_builder_with_value() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let target_field =
                CodedIndex::new(TableId::Field, 1, CodedIndexType::HasCustomAttribute); // HasCustomAttribute
            let constructor =
                CodedIndex::new(TableId::MemberRef, 1, CodedIndexType::CustomAttributeType); // CustomAttributeType

            // Create a custom attribute with a simple value blob
            let attribute_blob = &[0x01, 0x00, 0x00, 0x00]; // Prolog + no named args

            let token = CustomAttributeBuilder::new()
                .parent(target_field)
                .constructor(constructor)
                .value(attribute_blob)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x0C000000);
        }
    }

    #[test]
    fn test_custom_attribute_builder_no_value() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let target_method =
                CodedIndex::new(TableId::MethodDef, 2, CodedIndexType::HasCustomAttribute); // HasCustomAttribute
            let constructor =
                CodedIndex::new(TableId::MethodDef, 3, CodedIndexType::CustomAttributeType); // CustomAttributeType

            // Create a custom attribute with no value (will use 0 blob index)
            let token = CustomAttributeBuilder::new()
                .parent(target_method)
                .constructor(constructor)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x0C000000);
        }
    }

    #[test]
    fn test_custom_attribute_builder_missing_parent() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let constructor =
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType);

            let result = CustomAttributeBuilder::new()
                .constructor(constructor)
                .build(&mut context);

            // Should fail because parent is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_custom_attribute_builder_missing_constructor() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let target_type =
                CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute);

            let result = CustomAttributeBuilder::new()
                .parent(target_type)
                .build(&mut context);

            // Should fail because constructor is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_custom_attribute_builder_invalid_parent_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Use a table type that's not valid for HasCustomAttribute
            let invalid_parent =
                CodedIndex::new(TableId::Constant, 1, CodedIndexType::HasCustomAttribute); // Constant not in HasCustomAttribute
            let constructor =
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType);

            let result = CustomAttributeBuilder::new()
                .parent(invalid_parent)
                .constructor(constructor)
                .build(&mut context);

            // Should fail because parent type is not valid for HasCustomAttribute
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_custom_attribute_builder_invalid_constructor_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let target_type =
                CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute);
            // Use a table type that's not valid for CustomAttributeType
            let invalid_constructor =
                CodedIndex::new(TableId::Field, 1, CodedIndexType::CustomAttributeType); // Field not in CustomAttributeType

            let result = CustomAttributeBuilder::new()
                .parent(target_type)
                .constructor(invalid_constructor)
                .build(&mut context);

            // Should fail because constructor type is not valid for CustomAttributeType
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_custom_attribute_builder_multiple_attributes() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let target1 = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasCustomAttribute);
            let target2 =
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::HasCustomAttribute);
            let target3 = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasCustomAttribute);

            let constructor1 =
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::CustomAttributeType);
            let constructor2 =
                CodedIndex::new(TableId::MemberRef, 1, CodedIndexType::CustomAttributeType);

            // Create multiple custom attributes
            let attr1 = CustomAttributeBuilder::new()
                .parent(target1)
                .constructor(constructor1.clone())
                .value(&[0x01, 0x00])
                .build(&mut context)
                .unwrap();

            let attr2 = CustomAttributeBuilder::new()
                .parent(target2)
                .constructor(constructor2.clone())
                .build(&mut context)
                .unwrap();

            let attr3 = CustomAttributeBuilder::new()
                .parent(target3)
                .constructor(constructor1)
                .value(&[0x01, 0x00, 0x00, 0x00])
                .build(&mut context)
                .unwrap();

            // All should succeed and have different RIDs
            assert_ne!(attr1.value() & 0x00FFFFFF, attr2.value() & 0x00FFFFFF);
            assert_ne!(attr1.value() & 0x00FFFFFF, attr3.value() & 0x00FFFFFF);
            assert_ne!(attr2.value() & 0x00FFFFFF, attr3.value() & 0x00FFFFFF);

            // All should have CustomAttribute table prefix
            assert_eq!(attr1.value() & 0xFF000000, 0x0C000000);
            assert_eq!(attr2.value() & 0xFF000000, 0x0C000000);
            assert_eq!(attr3.value() & 0xFF000000, 0x0C000000);
        }
    }
}
