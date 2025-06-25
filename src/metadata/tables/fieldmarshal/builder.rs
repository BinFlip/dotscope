//! FieldMarshalBuilder for creating P/Invoke marshaling specifications.
//!
//! This module provides [`crate::metadata::tables::fieldmarshal::FieldMarshalBuilder`] for creating FieldMarshal table entries
//! with a fluent API. Field marshaling defines how managed types are converted to and
//! from native types during P/Invoke calls, COM interop, and platform invoke scenarios,
//! enabling seamless interoperability between managed and unmanaged code.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        marshalling::NATIVE_TYPE,
        tables::{CodedIndex, CodedIndexType, FieldMarshalRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating FieldMarshal metadata entries.
///
/// `FieldMarshalBuilder` provides a fluent API for creating FieldMarshal table entries
/// with validation and automatic blob management. Field marshaling defines the conversion
/// rules between managed and native types for fields and parameters during interop
/// scenarios including P/Invoke calls, COM interop, and platform invoke operations.
///
/// # Marshaling Model
///
/// .NET marshaling follows a structured pattern:
/// - **Parent Entity**: The field or parameter that requires marshaling
/// - **Native Type**: How the managed type appears in native code
/// - **Conversion Rules**: Automatic conversion behavior during calls
/// - **Memory Management**: Responsibility for allocation and cleanup
///
/// # Coded Index Types
///
/// Field marshaling uses the `HasFieldMarshal` coded index to specify targets:
/// - **Field**: Marshaling for struct fields and class fields
/// - **Param**: Marshaling for method parameters and return values
///
/// # Marshaling Scenarios and Types
///
/// Different native types serve various interop scenarios:
/// - **Primitive Types**: Direct mapping for integers, floats, and booleans
/// - **String Types**: Character encoding and memory management (ANSI, Unicode)
/// - **Array Types**: Element type specification and size management
/// - **Pointer Types**: Memory layout and dereferencing behavior
/// - **Interface Types**: COM interface marshaling and reference counting
/// - **Custom Types**: User-defined marshaling with custom marshalers
///
/// # Marshaling Descriptors
///
/// Marshaling information is stored as binary descriptors in the blob heap:
/// - **Simple Types**: Single byte indicating native type (e.g., NATIVE_TYPE_I4)
/// - **Complex Types**: Multi-byte descriptors with parameters (arrays, strings)
/// - **Custom Marshalers**: Full type name and initialization parameters
/// - **Array Descriptors**: Element type, dimensions, and size specifications
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Marshal a parameter as a null-terminated Unicode string
/// let param_ref = CodedIndex::new(TableId::Param, 1); // String parameter
/// let unicode_string_descriptor = vec![NATIVE_TYPE::LPWSTR]; // Simple descriptor
///
/// let string_marshal = FieldMarshalBuilder::new()
///     .parent(param_ref)
///     .native_type(&unicode_string_descriptor)
///     .build(&mut context)?;
///
/// // Marshal a field as a fixed-size ANSI character array
/// let field_ref = CodedIndex::new(TableId::Field, 1); // Character array field
/// let fixed_array_descriptor = vec![
///     NATIVE_TYPE::ARRAY,
///     0x04, // Array element type (I1 - signed byte)
///     0x20, 0x00, 0x00, 0x00, // Array size (32 elements, little-endian)
/// ];
///
/// let array_marshal = FieldMarshalBuilder::new()
///     .parent(field_ref)
///     .native_type(&fixed_array_descriptor)
///     .build(&mut context)?;
///
/// // Marshal a parameter as a COM interface pointer
/// let interface_param = CodedIndex::new(TableId::Param, 2); // Interface parameter
/// let interface_descriptor = vec![NATIVE_TYPE::INTERFACE]; // COM interface
///
/// let interface_marshal = FieldMarshalBuilder::new()
///     .parent(interface_param)
///     .native_type(&interface_descriptor)
///     .build(&mut context)?;
///
/// // Marshal a return value as a platform-dependent integer
/// let return_param = CodedIndex::new(TableId::Param, 0); // Return value (sequence 0)
/// let platform_int_descriptor = vec![NATIVE_TYPE::INT]; // Platform IntPtr
///
/// let return_marshal = FieldMarshalBuilder::new()
///     .parent(return_param)
///     .native_type(&platform_int_descriptor)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct FieldMarshalBuilder {
    parent: Option<CodedIndex>,
    native_type: Option<Vec<u8>>,
}

impl Default for FieldMarshalBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldMarshalBuilder {
    /// Creates a new FieldMarshalBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::fieldmarshal::FieldMarshalBuilder`] instance ready for configuration.
    pub fn new() -> Self {
        Self {
            parent: None,
            native_type: None,
        }
    }

    /// Sets the parent field or parameter that requires marshaling.
    ///
    /// The parent must be a valid `HasFieldMarshal` coded index that references
    /// either a field definition or parameter definition. This establishes which
    /// entity will have marshaling behavior applied during interop operations.
    ///
    /// Valid parent types include:
    /// - `Field` - Marshaling for struct fields in P/Invoke scenarios
    /// - `Param` - Marshaling for method parameters and return values
    ///
    /// Marshaling scope considerations:
    /// - **Field marshaling**: Applied when the containing struct crosses managed/native boundary
    /// - **Parameter marshaling**: Applied during each method call that crosses boundaries
    /// - **Return marshaling**: Applied to return values from native methods
    /// - **Array marshaling**: Applied to array elements and overall array structure
    ///
    /// # Arguments
    ///
    /// * `parent` - A `HasFieldMarshal` coded index pointing to the target field or parameter
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn parent(mut self, parent: CodedIndex) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the native type marshaling descriptor.
    ///
    /// The native type descriptor defines how the managed type should be represented
    /// and converted in native code. This binary descriptor is stored in the blob heap
    /// and follows .NET's marshaling specification format.
    ///
    /// Descriptor format varies by complexity:
    /// - **Simple types**: Single byte (e.g., `[NATIVE_TYPE::I4]` for 32-bit integer)
    /// - **String types**: May include encoding and length parameters
    /// - **Array types**: Include element type, dimensions, and size information
    /// - **Custom types**: Include full type names and initialization parameters
    ///
    /// Common descriptor patterns:
    /// - **Primitive**: `[NATIVE_TYPE::I4]` - 32-bit signed integer
    /// - **Unicode String**: `[NATIVE_TYPE_LPWSTR]` - Null-terminated wide string
    /// - **ANSI String**: `[NATIVE_TYPE_LPSTR]` - Null-terminated ANSI string
    /// - **Fixed Array**: `[NATIVE_TYPE_BYVALARRAY, element_type, size...]` - In-place array
    /// - **Interface**: `[NATIVE_TYPE_INTERFACE]` - COM interface pointer
    ///
    /// # Arguments
    ///
    /// * `native_type` - The binary marshaling descriptor specifying conversion behavior
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn native_type(mut self, native_type: &[u8]) -> Self {
        self.native_type = Some(native_type.to_vec());
        self
    }

    /// Sets a simple native type marshaling descriptor.
    ///
    /// This is a convenience method for common marshaling scenarios that require
    /// only a single native type identifier without additional parameters.
    ///
    /// # Arguments
    ///
    /// * `type_id` - The native type identifier from the NativeType constants
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn simple_native_type(mut self, type_id: u8) -> Self {
        self.native_type = Some(vec![type_id]);
        self
    }

    /// Sets Unicode string marshaling (LPWSTR).
    ///
    /// This convenience method configures marshaling for Unicode string parameters
    /// and fields, using null-terminated wide character representation.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn unicode_string(self) -> Self {
        self.simple_native_type(NATIVE_TYPE::LPWSTR)
    }

    /// Sets ANSI string marshaling (LPSTR).
    ///
    /// This convenience method configures marshaling for ANSI string parameters
    /// and fields, using null-terminated single-byte character representation.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn ansi_string(self) -> Self {
        self.simple_native_type(NATIVE_TYPE::LPSTR)
    }

    /// Sets fixed-size array marshaling.
    ///
    /// This convenience method configures marshaling for fixed-size arrays with
    /// specified element type and count. The array is marshaled in-place within
    /// the containing structure.
    ///
    /// # Arguments
    ///
    /// * `element_type` - The native type of array elements
    /// * `size` - The number of elements in the array
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn fixed_array(mut self, element_type: u8, size: u32) -> Self {
        let mut descriptor = vec![NATIVE_TYPE::ARRAY, element_type];
        descriptor.extend_from_slice(&size.to_le_bytes());
        self.native_type = Some(descriptor);
        self
    }

    /// Sets COM interface marshaling.
    ///
    /// This convenience method configures marshaling for COM interface pointers,
    /// enabling proper reference counting and interface negotiation.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn com_interface(self) -> Self {
        self.simple_native_type(NATIVE_TYPE::INTERFACE)
    }

    /// Builds the field marshal entry and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the marshaling
    /// descriptor to the blob heap, creates the raw field marshal structure,
    /// and adds it to the FieldMarshal table with proper token generation.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created field marshal entry, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if parent is not set
    /// - Returns error if native_type is not set or empty
    /// - Returns error if parent is not a valid HasFieldMarshal coded index
    /// - Returns error if blob operations fail
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Marshal parent is required".to_string(),
            })?;

        let native_type = self
            .native_type
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Native type descriptor is required".to_string(),
            })?;

        if native_type.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Native type descriptor cannot be empty".to_string(),
            });
        }

        let valid_parent_tables = CodedIndexType::HasFieldMarshal.tables();
        if !valid_parent_tables.contains(&parent.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Parent must be a HasFieldMarshal coded index (Field/Param), got {:?}",
                    parent.tag
                ),
            });
        }

        // Add native type descriptor to blob heap
        let native_type_index = context.add_blob(&native_type)?;

        let rid = context.next_rid(TableId::FieldMarshal);

        let token_value = ((TableId::FieldMarshal as u32) << 24) | rid;
        let token = Token::new(token_value);

        let field_marshal_raw = FieldMarshalRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            parent,
            native_type: native_type_index,
        };

        context.add_table_row(
            TableId::FieldMarshal,
            TableDataOwned::FieldMarshal(field_marshal_raw),
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
    fn test_field_marshal_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);

            // Check existing FieldMarshal table count
            let existing_count = assembly.original_table_row_count(TableId::FieldMarshal);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(assembly);

            // Create a basic field marshal entry
            let param_ref = CodedIndex::new(TableId::Param, 1); // Parameter target
            let marshal_descriptor = vec![NATIVE_TYPE::I4]; // Simple integer marshaling

            let token = FieldMarshalBuilder::new()
                .parent(param_ref)
                .native_type(&marshal_descriptor)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x0D000000); // FieldMarshal table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_field_marshal_builder_different_parents() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let marshal_descriptor = vec![NATIVE_TYPE::I4];

            // Test Field parent
            let field_parent = CodedIndex::new(TableId::Field, 1);
            let field_marshal = FieldMarshalBuilder::new()
                .parent(field_parent)
                .native_type(&marshal_descriptor)
                .build(&mut context)
                .unwrap();

            // Test Param parent
            let param_parent = CodedIndex::new(TableId::Param, 1);
            let param_marshal = FieldMarshalBuilder::new()
                .parent(param_parent)
                .native_type(&marshal_descriptor)
                .build(&mut context)
                .unwrap();

            // Both should succeed with different tokens
            assert_eq!(field_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(param_marshal.value() & 0xFF000000, 0x0D000000);
            assert_ne!(field_marshal.value(), param_marshal.value());
        }
    }

    #[test]
    fn test_field_marshal_builder_different_native_types() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Test various native types
            let param_refs: Vec<_> = (1..=8)
                .map(|i| CodedIndex::new(TableId::Param, i))
                .collect();

            // Simple integer types
            let int_marshal = FieldMarshalBuilder::new()
                .parent(param_refs[0].clone())
                .simple_native_type(NATIVE_TYPE::I4)
                .build(&mut context)
                .unwrap();

            // Unicode string
            let unicode_marshal = FieldMarshalBuilder::new()
                .parent(param_refs[1].clone())
                .unicode_string()
                .build(&mut context)
                .unwrap();

            // ANSI string
            let ansi_marshal = FieldMarshalBuilder::new()
                .parent(param_refs[2].clone())
                .ansi_string()
                .build(&mut context)
                .unwrap();

            // Fixed array
            let array_marshal = FieldMarshalBuilder::new()
                .parent(param_refs[3].clone())
                .fixed_array(NATIVE_TYPE::I1, 32) // 32-byte array
                .build(&mut context)
                .unwrap();

            // COM interface
            let interface_marshal = FieldMarshalBuilder::new()
                .parent(param_refs[4].clone())
                .com_interface()
                .build(&mut context)
                .unwrap();

            // All should succeed with FieldMarshal table prefix
            assert_eq!(int_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(unicode_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(ansi_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(array_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(interface_marshal.value() & 0xFF000000, 0x0D000000);

            // All should have different RIDs
            let tokens = [
                int_marshal,
                unicode_marshal,
                ansi_marshal,
                array_marshal,
                interface_marshal,
            ];
            for i in 0..tokens.len() {
                for j in i + 1..tokens.len() {
                    assert_ne!(
                        tokens[i].value() & 0x00FFFFFF,
                        tokens[j].value() & 0x00FFFFFF
                    );
                }
            }
        }
    }

    #[test]
    fn test_field_marshal_builder_complex_descriptors() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let field_ref = CodedIndex::new(TableId::Field, 1);

            // Complex array descriptor with multiple parameters
            let complex_array_descriptor = vec![
                NATIVE_TYPE::ARRAY,
                NATIVE_TYPE::I4, // Element type
                0x02,            // Array rank
                0x10,
                0x00,
                0x00,
                0x00, // Size parameter (16 elements)
                0x00,
                0x00,
                0x00,
                0x00, // Lower bound
            ];

            let token = FieldMarshalBuilder::new()
                .parent(field_ref)
                .native_type(&complex_array_descriptor)
                .build(&mut context)
                .unwrap();

            // Should succeed
            assert_eq!(token.value() & 0xFF000000, 0x0D000000);
        }
    }

    #[test]
    fn test_field_marshal_builder_missing_parent() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let marshal_descriptor = vec![NATIVE_TYPE::I4];

            let result = FieldMarshalBuilder::new()
                .native_type(&marshal_descriptor)
                // Missing parent
                .build(&mut context);

            // Should fail because parent is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_marshal_builder_missing_native_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let param_ref = CodedIndex::new(TableId::Param, 1);

            let result = FieldMarshalBuilder::new()
                .parent(param_ref)
                // Missing native_type
                .build(&mut context);

            // Should fail because native type is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_marshal_builder_empty_native_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let param_ref = CodedIndex::new(TableId::Param, 1);
            let empty_descriptor = vec![]; // Empty descriptor

            let result = FieldMarshalBuilder::new()
                .parent(param_ref)
                .native_type(&empty_descriptor)
                .build(&mut context);

            // Should fail because native type cannot be empty
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_marshal_builder_invalid_parent_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Use a table type that's not valid for HasFieldMarshal
            let invalid_parent = CodedIndex::new(TableId::TypeDef, 1); // TypeDef not in HasFieldMarshal
            let marshal_descriptor = vec![NATIVE_TYPE::I4];

            let result = FieldMarshalBuilder::new()
                .parent(invalid_parent)
                .native_type(&marshal_descriptor)
                .build(&mut context);

            // Should fail because parent type is not valid for HasFieldMarshal
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_field_marshal_builder_all_primitive_types() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Test all primitive native types
            let primitive_types = [
                NATIVE_TYPE::BOOLEAN,
                NATIVE_TYPE::I1,
                NATIVE_TYPE::U1,
                NATIVE_TYPE::I2,
                NATIVE_TYPE::U2,
                NATIVE_TYPE::I4,
                NATIVE_TYPE::U4,
                NATIVE_TYPE::I8,
                NATIVE_TYPE::U8,
                NATIVE_TYPE::R4,
                NATIVE_TYPE::R8,
                NATIVE_TYPE::INT,
                NATIVE_TYPE::UINT,
            ];

            for (i, &native_type) in primitive_types.iter().enumerate() {
                let param_ref = CodedIndex::new(TableId::Param, (i + 1) as u32);

                let token = FieldMarshalBuilder::new()
                    .parent(param_ref)
                    .simple_native_type(native_type)
                    .build(&mut context)
                    .unwrap();

                // All should succeed
                assert_eq!(token.value() & 0xFF000000, 0x0D000000);
            }
        }
    }

    #[test]
    fn test_field_marshal_builder_string_types() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Test string marshaling types
            let param1 = CodedIndex::new(TableId::Param, 1);
            let param2 = CodedIndex::new(TableId::Param, 2);
            let param3 = CodedIndex::new(TableId::Param, 3);
            let param4 = CodedIndex::new(TableId::Param, 4);

            // LPSTR (ANSI string)
            let ansi_marshal = FieldMarshalBuilder::new()
                .parent(param1)
                .simple_native_type(NATIVE_TYPE::LPSTR)
                .build(&mut context)
                .unwrap();

            // LPWSTR (Unicode string)
            let unicode_marshal = FieldMarshalBuilder::new()
                .parent(param2)
                .simple_native_type(NATIVE_TYPE::LPWSTR)
                .build(&mut context)
                .unwrap();

            // BSTR (COM string)
            let bstr_marshal = FieldMarshalBuilder::new()
                .parent(param3)
                .simple_native_type(NATIVE_TYPE::BSTR)
                .build(&mut context)
                .unwrap();

            // BYVALSTR (fixed-length string)
            let byval_marshal = FieldMarshalBuilder::new()
                .parent(param4)
                .simple_native_type(NATIVE_TYPE::BYVALSTR)
                .build(&mut context)
                .unwrap();

            // All should succeed
            assert_eq!(ansi_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(unicode_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(bstr_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(byval_marshal.value() & 0xFF000000, 0x0D000000);
        }
    }

    #[test]
    fn test_field_marshal_builder_realistic_pinvoke() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Realistic P/Invoke scenario: Win32 API function
            // BOOL CreateDirectory(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

            // Parameter 1: LPCWSTR (Unicode string path)
            let path_param = CodedIndex::new(TableId::Param, 1);
            let path_marshal = FieldMarshalBuilder::new()
                .parent(path_param)
                .unicode_string() // LPCWSTR
                .build(&mut context)
                .unwrap();

            // Parameter 2: LPSECURITY_ATTRIBUTES (structure pointer)
            let security_param = CodedIndex::new(TableId::Param, 2);
            let security_marshal = FieldMarshalBuilder::new()
                .parent(security_param)
                .simple_native_type(NATIVE_TYPE::PTR) // Pointer to struct
                .build(&mut context)
                .unwrap();

            // Return value: BOOL (32-bit integer)
            let return_param = CodedIndex::new(TableId::Param, 0); // Return value
            let return_marshal = FieldMarshalBuilder::new()
                .parent(return_param)
                .simple_native_type(NATIVE_TYPE::I4) // 32-bit bool
                .build(&mut context)
                .unwrap();

            // All should succeed
            assert_eq!(path_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(security_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(return_marshal.value() & 0xFF000000, 0x0D000000);

            // All should have different RIDs
            assert_ne!(
                path_marshal.value() & 0x00FFFFFF,
                security_marshal.value() & 0x00FFFFFF
            );
            assert_ne!(
                path_marshal.value() & 0x00FFFFFF,
                return_marshal.value() & 0x00FFFFFF
            );
            assert_ne!(
                security_marshal.value() & 0x00FFFFFF,
                return_marshal.value() & 0x00FFFFFF
            );
        }
    }

    #[test]
    fn test_field_marshal_builder_struct_fields() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Realistic struct marshaling: POINT structure
            // struct POINT { LONG x; LONG y; };

            let x_field = CodedIndex::new(TableId::Field, 1);
            let y_field = CodedIndex::new(TableId::Field, 2);

            // X coordinate as 32-bit signed integer
            let x_marshal = FieldMarshalBuilder::new()
                .parent(x_field)
                .simple_native_type(NATIVE_TYPE::I4)
                .build(&mut context)
                .unwrap();

            // Y coordinate as 32-bit signed integer
            let y_marshal = FieldMarshalBuilder::new()
                .parent(y_field)
                .simple_native_type(NATIVE_TYPE::I4)
                .build(&mut context)
                .unwrap();

            // Both should succeed
            assert_eq!(x_marshal.value() & 0xFF000000, 0x0D000000);
            assert_eq!(y_marshal.value() & 0xFF000000, 0x0D000000);
            assert_ne!(x_marshal.value(), y_marshal.value());
        }
    }
}
