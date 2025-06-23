//! MethodSpecBuilder for creating generic method instantiation specifications.
//!
//! This module provides [`MethodSpecBuilder`] for creating MethodSpec table entries
//! with a fluent API. Method specifications define instantiations of generic methods
//! with concrete type arguments, enabling type-safe generic method dispatch and
//! supporting both compile-time and runtime generic method resolution.

use crate::{
    metadata::{
        cilassembly::BuilderContext,
        tables::{CodedIndex, CodedIndexType, MethodSpecRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating MethodSpec metadata entries.
///
/// `MethodSpecBuilder` provides a fluent API for creating MethodSpec table entries
/// with validation and automatic blob management. Method specifications define
/// instantiations of generic methods with concrete type arguments, enabling
/// type-safe generic method dispatch and runtime generic method resolution.
///
/// # Generic Method Instantiation Model
///
/// .NET generic method instantiation follows a structured pattern:
/// - **Generic Method**: The parameterized method definition or reference
/// - **Type Arguments**: Concrete types that replace generic parameters
/// - **Instantiation Signature**: Binary encoding of the type arguments
/// - **Runtime Resolution**: Type-safe method dispatch with concrete types
///
/// # Coded Index Types
///
/// Method specifications use the `MethodDefOrRef` coded index to specify targets:
/// - **MethodDef**: Generic methods defined within the current assembly
/// - **MemberRef**: Generic methods from external assemblies or references
///
/// # Generic Method Scenarios and Patterns
///
/// Different instantiation patterns serve various generic programming scenarios:
/// - **Simple Instantiation**: `List<T>.Add(T)` → `List<int>.Add(int)`
/// - **Multiple Parameters**: `Dictionary<TKey, TValue>.TryGetValue` → `Dictionary<string, int>.TryGetValue`
/// - **Nested Generics**: `Task<List<T>>` → `Task<List<string>>`
/// - **Constraint Satisfaction**: Generic methods with type constraints
/// - **Variance Support**: Covariant and contravariant generic parameters
///
/// # Method Specification Signatures
///
/// Instantiation signatures are stored as binary blobs containing:
/// - **Generic Argument Count**: Number of type arguments provided
/// - **Type Signatures**: Encoded signatures for each concrete type argument
/// - **Constraint Validation**: Ensuring type arguments satisfy constraints
/// - **Variance Information**: Covariance and contravariance specifications
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(&mut assembly);
///
/// // Instantiate a generic method with a single type argument
/// let generic_method = CodedIndex::new(TableId::MethodDef, 1); // Generic Add<T> method
/// let int_instantiation = vec![
///     0x01, // Generic argument count (1)
///     0x08, // ELEMENT_TYPE_I4 (int32)
/// ];
///
/// let add_int = MethodSpecBuilder::new()
///     .method(generic_method)
///     .instantiation(&int_instantiation)
///     .build(&mut context)?;
///
/// // Instantiate a generic method with multiple type arguments
/// let dictionary_method = CodedIndex::new(TableId::MemberRef, 1); // Dictionary<TKey, TValue>.TryGetValue
/// let string_int_instantiation = vec![
///     0x02, // Generic argument count (2)
///     0x0E, // ELEMENT_TYPE_STRING
///     0x08, // ELEMENT_TYPE_I4 (int32)
/// ];
///
/// let trygetvalue_string_int = MethodSpecBuilder::new()
///     .method(dictionary_method)
///     .instantiation(&string_int_instantiation)
///     .build(&mut context)?;
///
/// // Instantiate a generic method with complex type arguments
/// let complex_method = CodedIndex::new(TableId::MethodDef, 2); // Complex generic method
/// let complex_instantiation = vec![
///     0x01, // Generic argument count (1)
///     0x1D, // ELEMENT_TYPE_SZARRAY (single-dimensional array)
///     0x0E, // Array element type: ELEMENT_TYPE_STRING
/// ];
///
/// let complex_string_array = MethodSpecBuilder::new()
///     .method(complex_method)
///     .instantiation(&complex_instantiation)
///     .build(&mut context)?;
///
/// // Instantiate with a reference to another type
/// let reference_method = CodedIndex::new(TableId::MemberRef, 2); // Generic method reference
/// let typeref_instantiation = vec![
///     0x01, // Generic argument count (1)
///     0x12, // ELEMENT_TYPE_CLASS
///     0x02, // TypeDefOrRef coded index (simplified)
/// ];
///
/// let typeref_instantiation_spec = MethodSpecBuilder::new()
///     .method(reference_method)
///     .instantiation(&typeref_instantiation)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct MethodSpecBuilder {
    method: Option<CodedIndex>,
    instantiation: Option<Vec<u8>>,
}

impl Default for MethodSpecBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodSpecBuilder {
    /// Creates a new MethodSpecBuilder.
    ///
    /// # Returns
    ///
    /// A new [`MethodSpecBuilder`] instance ready for configuration.
    pub fn new() -> Self {
        Self {
            method: None,
            instantiation: None,
        }
    }

    /// Sets the generic method that will be instantiated.
    ///
    /// The method must be a valid `MethodDefOrRef` coded index that references
    /// either a generic method definition or a generic method reference. This
    /// establishes which generic method template will be instantiated with
    /// concrete type arguments.
    ///
    /// Valid method types include:
    /// - `MethodDef` - Generic methods defined within the current assembly
    /// - `MemberRef` - Generic methods from external assemblies or references
    ///
    /// Generic method considerations:
    /// - **Method Definition**: Must be a generic method with type parameters
    /// - **Type Constraints**: Type arguments must satisfy method constraints
    /// - **Accessibility**: Instantiation must respect method visibility
    /// - **Assembly Boundaries**: External methods require proper assembly references
    ///
    /// # Arguments
    ///
    /// * `method` - A `MethodDefOrRef` coded index pointing to the generic method
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn method(mut self, method: CodedIndex) -> Self {
        self.method = Some(method);
        self
    }

    /// Sets the instantiation signature specifying concrete type arguments.
    ///
    /// The instantiation signature defines the concrete types that will replace
    /// the generic parameters in the method definition. This binary signature
    /// is stored in the blob heap and follows .NET's method specification format.
    ///
    /// Signature structure:
    /// - **Generic Argument Count**: Number of type arguments (compressed integer)
    /// - **Type Arguments**: Type signatures for each concrete type argument
    /// - **Type Encoding**: Following ELEMENT_TYPE constants and encoding rules
    /// - **Reference Resolution**: TypeDefOrRef coded indexes for complex types
    ///
    /// Common signature patterns:
    /// - **Primitive Types**: Single byte ELEMENT_TYPE values (I4, STRING, etc.)
    /// - **Reference Types**: ELEMENT_TYPE_CLASS followed by TypeDefOrRef coded index
    /// - **Value Types**: ELEMENT_TYPE_VALUETYPE followed by TypeDefOrRef coded index
    /// - **Arrays**: ELEMENT_TYPE_SZARRAY followed by element type signature
    /// - **Generic Types**: ELEMENT_TYPE_GENERICINST with type definition and arguments
    ///
    /// # Arguments
    ///
    /// * `instantiation` - The binary signature containing concrete type arguments
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn instantiation(mut self, instantiation: &[u8]) -> Self {
        self.instantiation = Some(instantiation.to_vec());
        self
    }

    /// Sets a simple single-type instantiation for common scenarios.
    ///
    /// This convenience method creates an instantiation signature for generic
    /// methods with a single type parameter, using a primitive type specified
    /// by its ELEMENT_TYPE constant.
    ///
    /// # Arguments
    ///
    /// * `element_type` - The ELEMENT_TYPE constant for the concrete type argument
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn simple_instantiation(mut self, element_type: u8) -> Self {
        let signature = vec![
            0x01,         // Generic argument count (1)
            element_type, // The concrete type
        ];
        self.instantiation = Some(signature);
        self
    }

    /// Sets an instantiation with multiple primitive type arguments.
    ///
    /// This convenience method creates an instantiation signature for generic
    /// methods with multiple type parameters, all using primitive types.
    ///
    /// # Arguments
    ///
    /// * `element_types` - Array of ELEMENT_TYPE constants for each type argument
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn multiple_primitives(mut self, element_types: &[u8]) -> Self {
        let mut signature = vec![element_types.len() as u8]; // Generic argument count
        signature.extend_from_slice(element_types);
        self.instantiation = Some(signature);
        self
    }

    /// Sets an instantiation with a single array type argument.
    ///
    /// This convenience method creates an instantiation signature for generic
    /// methods instantiated with a single-dimensional array type.
    ///
    /// # Arguments
    ///
    /// * `element_type` - The ELEMENT_TYPE constant for the array element type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn array_instantiation(mut self, element_type: u8) -> Self {
        let signature = vec![
            0x01,         // Generic argument count (1)
            0x1D,         // ELEMENT_TYPE_SZARRAY
            element_type, // Array element type
        ];
        self.instantiation = Some(signature);
        self
    }

    /// Builds the method specification entry and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the instantiation
    /// signature to the blob heap, creates the raw method specification structure,
    /// and adds it to the MethodSpec table with proper token generation.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`Token`] representing the newly created method specification, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if method is not set
    /// - Returns error if instantiation is not set or empty
    /// - Returns error if method is not a valid MethodDefOrRef coded index
    /// - Returns error if blob operations fail
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let method = self
            .method
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Generic method is required".to_string(),
            })?;

        let instantiation =
            self.instantiation
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Instantiation signature is required".to_string(),
                })?;

        if instantiation.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Instantiation signature cannot be empty".to_string(),
            });
        }

        let valid_method_tables = CodedIndexType::MethodDefOrRef.tables();
        if !valid_method_tables.contains(&method.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Method must be a MethodDefOrRef coded index (MethodDef/MemberRef), got {:?}",
                    method.tag
                ),
            });
        }

        if instantiation.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Instantiation signature must contain at least the generic argument count"
                    .to_string(),
            });
        }

        let arg_count = instantiation[0];
        if arg_count == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Generic argument count cannot be zero".to_string(),
            });
        }

        let instantiation_index = context.add_blob(&instantiation)?;

        let rid = context.next_rid(TableId::MethodSpec);

        let token_value = ((TableId::MethodSpec as u32) << 24) | rid;
        let token = Token::new(token_value);

        let method_spec_raw = MethodSpecRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            method,
            instantiation: instantiation_index,
        };

        context.add_table_row(
            TableId::MethodSpec,
            TableDataOwned::MethodSpec(method_spec_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        cilassembly::{BuilderContext, CilAssembly},
        cilassemblyview::CilAssemblyView,
    };
    use std::path::PathBuf;

    #[test]
    fn test_method_spec_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            // Check existing MethodSpec table count
            let existing_count = assembly.original_table_row_count(TableId::MethodSpec);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(&mut assembly);

            // Create a basic method specification
            let method_ref = CodedIndex::new(TableId::MethodDef, 1); // Generic method
            let instantiation_blob = vec![0x01, 0x08]; // Single int32 argument

            let token = MethodSpecBuilder::new()
                .method(method_ref)
                .instantiation(&instantiation_blob)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x2B000000); // MethodSpec table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_method_spec_builder_different_methods() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let instantiation_blob = vec![0x01, 0x08]; // Single int32 argument

            // Test MethodDef
            let methoddef = CodedIndex::new(TableId::MethodDef, 1);
            let methoddef_spec = MethodSpecBuilder::new()
                .method(methoddef)
                .instantiation(&instantiation_blob)
                .build(&mut context)
                .unwrap();

            // Test MemberRef
            let memberref = CodedIndex::new(TableId::MemberRef, 1);
            let memberref_spec = MethodSpecBuilder::new()
                .method(memberref)
                .instantiation(&instantiation_blob)
                .build(&mut context)
                .unwrap();

            // Both should succeed with MethodSpec table prefix
            assert_eq!(methoddef_spec.value() & 0xFF000000, 0x2B000000);
            assert_eq!(memberref_spec.value() & 0xFF000000, 0x2B000000);
            assert_ne!(methoddef_spec.value(), memberref_spec.value());
        }
    }

    #[test]
    fn test_method_spec_builder_convenience_methods() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let method_ref = CodedIndex::new(TableId::MethodDef, 1);

            // Test simple instantiation
            let simple_spec = MethodSpecBuilder::new()
                .method(method_ref.clone())
                .simple_instantiation(0x08) // int32
                .build(&mut context)
                .unwrap();

            // Test multiple primitives
            let multiple_spec = MethodSpecBuilder::new()
                .method(method_ref.clone())
                .multiple_primitives(&[0x08, 0x0E]) // int32, string
                .build(&mut context)
                .unwrap();

            // Test array instantiation
            let array_spec = MethodSpecBuilder::new()
                .method(method_ref)
                .array_instantiation(0x08) // int32[]
                .build(&mut context)
                .unwrap();

            // All should succeed
            assert_eq!(simple_spec.value() & 0xFF000000, 0x2B000000);
            assert_eq!(multiple_spec.value() & 0xFF000000, 0x2B000000);
            assert_eq!(array_spec.value() & 0xFF000000, 0x2B000000);
        }
    }

    #[test]
    fn test_method_spec_builder_complex_instantiations() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let method_ref = CodedIndex::new(TableId::MemberRef, 1);

            // Complex instantiation with multiple type arguments
            let complex_instantiation = vec![
                0x03, // 3 generic arguments
                0x08, // ELEMENT_TYPE_I4 (int32)
                0x0E, // ELEMENT_TYPE_STRING
                0x1D, // ELEMENT_TYPE_SZARRAY
                0x08, // Array element type: int32
            ];

            let complex_spec = MethodSpecBuilder::new()
                .method(method_ref)
                .instantiation(&complex_instantiation)
                .build(&mut context)
                .unwrap();

            assert_eq!(complex_spec.value() & 0xFF000000, 0x2B000000);
        }
    }

    #[test]
    fn test_method_spec_builder_missing_method() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let instantiation_blob = vec![0x01, 0x08];

            let result = MethodSpecBuilder::new()
                .instantiation(&instantiation_blob)
                // Missing method
                .build(&mut context);

            // Should fail because method is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_method_spec_builder_missing_instantiation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let method_ref = CodedIndex::new(TableId::MethodDef, 1);

            let result = MethodSpecBuilder::new()
                .method(method_ref)
                // Missing instantiation
                .build(&mut context);

            // Should fail because instantiation is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_method_spec_builder_empty_instantiation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let method_ref = CodedIndex::new(TableId::MethodDef, 1);
            let empty_blob = vec![]; // Empty instantiation

            let result = MethodSpecBuilder::new()
                .method(method_ref)
                .instantiation(&empty_blob)
                .build(&mut context);

            // Should fail because instantiation cannot be empty
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_method_spec_builder_invalid_method_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Use a table type that's not valid for MethodDefOrRef
            let invalid_method = CodedIndex::new(TableId::Field, 1); // Field not in MethodDefOrRef
            let instantiation_blob = vec![0x01, 0x08];

            let result = MethodSpecBuilder::new()
                .method(invalid_method)
                .instantiation(&instantiation_blob)
                .build(&mut context);

            // Should fail because method type is not valid for MethodDefOrRef
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_method_spec_builder_zero_generic_args() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let method_ref = CodedIndex::new(TableId::MethodDef, 1);
            let zero_args_blob = vec![0x00]; // Zero generic arguments

            let result = MethodSpecBuilder::new()
                .method(method_ref)
                .instantiation(&zero_args_blob)
                .build(&mut context);

            // Should fail because generic argument count cannot be zero
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_method_spec_builder_realistic_scenarios() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Scenario 1: List<T>.Add(T) instantiated with int
            let list_add = CodedIndex::new(TableId::MethodDef, 1);
            let list_int_spec = MethodSpecBuilder::new()
                .method(list_add)
                .simple_instantiation(0x08) // int32
                .build(&mut context)
                .unwrap();

            // Scenario 2: Dictionary<TKey, TValue>.TryGetValue instantiated with string, int
            let dict_tryget = CodedIndex::new(TableId::MemberRef, 1);
            let dict_string_int_spec = MethodSpecBuilder::new()
                .method(dict_tryget)
                .multiple_primitives(&[0x0E, 0x08]) // string, int32
                .build(&mut context)
                .unwrap();

            // Scenario 3: Generic method with array type
            let array_method = CodedIndex::new(TableId::MethodDef, 2);
            let array_string_spec = MethodSpecBuilder::new()
                .method(array_method)
                .array_instantiation(0x0E) // string[]
                .build(&mut context)
                .unwrap();

            // All should succeed with proper tokens
            assert_eq!(list_int_spec.value() & 0xFF000000, 0x2B000000);
            assert_eq!(dict_string_int_spec.value() & 0xFF000000, 0x2B000000);
            assert_eq!(array_string_spec.value() & 0xFF000000, 0x2B000000);

            // All should have different RIDs
            assert_ne!(
                list_int_spec.value() & 0x00FFFFFF,
                dict_string_int_spec.value() & 0x00FFFFFF
            );
            assert_ne!(
                list_int_spec.value() & 0x00FFFFFF,
                array_string_spec.value() & 0x00FFFFFF
            );
            assert_ne!(
                dict_string_int_spec.value() & 0x00FFFFFF,
                array_string_spec.value() & 0x00FFFFFF
            );
        }
    }
}
