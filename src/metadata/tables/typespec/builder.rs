//! TypeSpecBuilder for creating type specification metadata entries.
//!
//! This module provides [`crate::metadata::tables::typespec::TypeSpecBuilder`] for creating TypeSpec table entries
//! with a fluent API. Type specifications define complex types such as generic
//! instantiations, arrays, pointers, and function types that cannot be represented
//! by simple TypeDef or TypeRef entries.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        signatures::{SignatureMethod, SignatureTypeSpec, TypeSignature},
        tables::{TableDataOwned, TableId, TypeSpecRaw},
        token::Token,
        typesystem::TypeSignatureEncoder,
    },
    Error, Result,
};

/// Builder for creating TypeSpec metadata entries.
///
/// `TypeSpecBuilder` provides a fluent API for creating TypeSpec table entries
/// with validation and automatic blob management. Type specifications define
/// complex types that require full signature representation, including generic
/// instantiations, arrays, pointers, and function types.
///
/// # Type Specification Model
///
/// .NET type specifications represent complex types through signatures:
/// - **Generic Instantiations**: Concrete types from generic templates
/// - **Array Types**: Single and multi-dimensional arrays with bounds
/// - **Pointer Types**: Managed references and unmanaged pointers
/// - **Function Types**: Delegates and function pointer signatures
/// - **Modified Types**: Types with custom modifiers (const, volatile)
///
/// # Type Specification Categories
///
/// Different categories of type specifications serve various purposes:
/// - **Constructed Types**: Generic instantiations like `List<int>`
/// - **Array Types**: Array definitions like `int[]` or `string[,]`
/// - **Pointer Types**: Pointer definitions like `int*` or `ref string`
/// - **Function Types**: Function pointer signatures for delegates
/// - **Modified Types**: Types with additional semantic information
///
/// # Signature Management
///
/// Type specifications are stored as binary signatures in the blob heap:
/// - **Signature Encoding**: Binary format following ECMA-335 standards
/// - **Blob Storage**: Automatic blob heap management and deduplication
/// - **Type References**: Embedded references to other metadata types
/// - **Validation**: Signature format validation and consistency checking
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # fn main() -> Result<()> {
/// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create a generic instantiation: List<int>
/// let list_type = Token::new(0x02000001); // List<T> type definition
/// let list_int = TypeSpecBuilder::new()
///     .generic_instantiation(list_type, vec![TypeSignature::I4])
///     .build(&mut context)?;
///
/// // Create a single-dimensional array: string[]
/// let string_array = TypeSpecBuilder::new()
///     .single_dimensional_array(TypeSignature::String)
///     .build(&mut context)?;
///
/// // Create a multi-dimensional array: int[,]
/// let int_2d_array = TypeSpecBuilder::new()
///     .multi_dimensional_array(TypeSignature::I4, 2)
///     .build(&mut context)?;
///
/// // Create a pointer type: int*
/// let int_pointer = TypeSpecBuilder::new()
///     .pointer(TypeSignature::I4)
///     .build(&mut context)?;
///
/// // Create a reference type: ref string
/// let string_ref = TypeSpecBuilder::new()
///     .managed_reference(TypeSignature::String)
///     .build(&mut context)?;
///
/// // Create a complex nested generic: Dictionary<string, List<int>>
/// let dict_type = Token::new(0x02000002); // Dictionary<K,V> type definition
/// let nested_generic = TypeSpecBuilder::new()
///     .generic_instantiation(dict_type, vec![
///         TypeSignature::String,
///         TypeSignature::GenericInst(
///             Box::new(TypeSignature::Class(list_type)),
///             vec![TypeSignature::I4]
///         )
///     ])
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct TypeSpecBuilder {
    signature: Option<TypeSignature>,
}

impl Default for TypeSpecBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeSpecBuilder {
    /// Creates a new TypeSpecBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::typespec::TypeSpecBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { signature: None }
    }

    /// Sets the type signature directly.
    ///
    /// Allows setting any [`crate::metadata::signatures::TypeSignature`] directly for maximum flexibility.
    /// This method provides complete control over the type specification
    /// and can be used to create any valid type signature.
    ///
    /// # Type Signature Categories
    ///
    /// The signature can represent any valid .NET type:
    /// - **Primitive Types**: `I4`, `String`, `Boolean`, etc.
    /// - **Reference Types**: `Class(token)`, `ValueType(token)`
    /// - **Generic Types**: `GenericInst(base, args)`
    /// - **Array Types**: `Array(array_sig)`, `SzArray(sz_array_sig)`
    /// - **Pointer Types**: `Ptr(pointer_sig)`, `ByRef(boxed_sig)`
    /// - **Function Types**: `FnPtr(method_sig)`
    /// - **Generic Parameters**: `GenericParamType(index)`, `GenericParamMethod(index)`
    ///
    /// # Arguments
    ///
    /// * `signature` - The complete type signature for this type specification
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn signature(mut self, signature: TypeSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Creates a generic type instantiation.
    ///
    /// Creates a type specification for a generic type with concrete type arguments.
    /// This is used for types like `List<int>`, `Dictionary<string, object>`, or
    /// any other generic type with specific type arguments provided.
    ///
    /// # Generic Type Instantiation Model
    ///
    /// Generic instantiation follows this pattern:
    /// - **Generic Definition**: The generic type template (e.g., `List<>`)
    /// - **Type Arguments**: Concrete types for each generic parameter
    /// - **Validation**: Argument count must match parameter count
    /// - **Constraints**: Type arguments must satisfy generic constraints
    ///
    /// # Arguments
    ///
    /// * `generic_type` - Token referencing the generic type definition
    /// * `type_arguments` - Vector of concrete type arguments
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    /// let list_type = Token::new(0x02000001); // List<T>
    ///
    /// // Create List<int>
    /// let list_int = TypeSpecBuilder::new()
    ///     .generic_instantiation(list_type, vec![TypeSignature::I4])
    ///     .build(&mut context)?;
    ///
    /// // Create Dictionary<string, int>
    /// let dict_type = Token::new(0x02000002); // Dictionary<K,V>
    /// let dict_string_int = TypeSpecBuilder::new()
    ///     .generic_instantiation(dict_type, vec![
    ///         TypeSignature::String,
    ///         TypeSignature::I4
    ///     ])
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn generic_instantiation(
        mut self,
        generic_type: Token,
        type_arguments: Vec<TypeSignature>,
    ) -> Self {
        self.signature = Some(TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(generic_type)),
            type_arguments,
        ));
        self
    }

    /// Creates a single-dimensional array type.
    ///
    /// Creates a type specification for a single-dimensional, zero-indexed array.
    /// This is the most common array type in .NET, represented as `T[]` in C#.
    /// Single-dimensional arrays have optimized runtime support and are the
    /// preferred array type for most scenarios.
    ///
    /// # Array Characteristics
    ///
    /// Single-dimensional arrays have these properties:
    /// - **Zero-indexed**: Always start at index 0
    /// - **Single dimension**: Only one dimension allowed
    /// - **Optimized**: Faster than multi-dimensional arrays
    /// - **Covariant**: Reference type arrays support covariance
    ///
    /// # Arguments
    ///
    /// * `element_type` - The type of elements stored in the array
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    /// // Create int[]
    /// let int_array = TypeSpecBuilder::new()
    ///     .single_dimensional_array(TypeSignature::I4)
    ///     .build(&mut context)?;
    ///
    /// // Create string[]
    /// let string_array = TypeSpecBuilder::new()
    ///     .single_dimensional_array(TypeSignature::String)
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn single_dimensional_array(mut self, element_type: TypeSignature) -> Self {
        use crate::metadata::signatures::SignatureSzArray;

        self.signature = Some(TypeSignature::SzArray(SignatureSzArray {
            base: Box::new(element_type),
            modifiers: Vec::new(),
        }));
        self
    }

    /// Creates a multi-dimensional array type.
    ///
    /// Creates a type specification for a multi-dimensional array with the specified
    /// number of dimensions. These arrays can have custom bounds and sizes for each
    /// dimension, though this builder creates arrays with default bounds.
    ///
    /// # Multi-Dimensional Array Model
    ///
    /// Multi-dimensional arrays support:
    /// - **Multiple Dimensions**: 2D, 3D, or higher dimensional arrays
    /// - **Custom Bounds**: Non-zero lower bounds for each dimension
    /// - **Size Specifications**: Fixed sizes for each dimension
    /// - **Rectangular Layout**: All dimensions have the same bounds
    ///
    /// # Arguments
    ///
    /// * `element_type` - The type of elements stored in the array
    /// * `rank` - The number of dimensions (must be > 1)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    /// // Create int[,] (2D array)
    /// let int_2d = TypeSpecBuilder::new()
    ///     .multi_dimensional_array(TypeSignature::I4, 2)
    ///     .build(&mut context)?;
    ///
    /// // Create string[,,] (3D array)
    /// let string_3d = TypeSpecBuilder::new()
    ///     .multi_dimensional_array(TypeSignature::String, 3)
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn multi_dimensional_array(mut self, element_type: TypeSignature, rank: u32) -> Self {
        use crate::metadata::{signatures::SignatureArray, typesystem::ArrayDimensions};

        // Create default dimensions (no size or bound specifications)
        let dimensions = (0..rank)
            .map(|_| ArrayDimensions {
                size: None,
                lower_bound: None,
            })
            .collect();

        self.signature = Some(TypeSignature::Array(SignatureArray {
            base: Box::new(element_type),
            rank,
            dimensions,
        }));
        self
    }

    /// Creates an unmanaged pointer type.
    ///
    /// Creates a type specification for an unmanaged pointer to the specified type.
    /// Unmanaged pointers are used in unsafe code and interop scenarios where
    /// direct memory access is required without garbage collection overhead.
    ///
    /// # Pointer Characteristics
    ///
    /// Unmanaged pointers have these properties:
    /// - **No GC Tracking**: Not tracked by garbage collector
    /// - **Unsafe Access**: Requires unsafe code context
    /// - **Manual Management**: Lifetime management is manual
    /// - **Interop Friendly**: Compatible with native code
    ///
    /// # Arguments
    ///
    /// * `pointed_type` - The type that the pointer points to
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    /// // Create int*
    /// let int_pointer = TypeSpecBuilder::new()
    ///     .pointer(TypeSignature::I4)
    ///     .build(&mut context)?;
    ///
    /// // Create void*
    /// let void_pointer = TypeSpecBuilder::new()
    ///     .pointer(TypeSignature::Void)
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn pointer(mut self, pointed_type: TypeSignature) -> Self {
        use crate::metadata::signatures::SignaturePointer;

        self.signature = Some(TypeSignature::Ptr(SignaturePointer {
            base: Box::new(pointed_type),
            modifiers: Vec::new(),
        }));
        self
    }

    /// Creates a managed reference type.
    ///
    /// Creates a type specification for a managed reference to the specified type.
    /// Managed references are used for `ref`, `out`, and `in` parameters and return
    /// values, providing safe access to value types without copying.
    ///
    /// # Reference Characteristics
    ///
    /// Managed references have these properties:
    /// - **GC Tracked**: Tracked by garbage collector
    /// - **Safe Access**: No unsafe code required
    /// - **Automatic Lifetime**: Lifetime managed automatically
    /// - **Cannot be null**: Always points to valid memory
    ///
    /// # Arguments
    ///
    /// * `referenced_type` - The type that is being referenced
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    /// // Create ref int
    /// let int_ref = TypeSpecBuilder::new()
    ///     .managed_reference(TypeSignature::I4)
    ///     .build(&mut context)?;
    ///
    /// // Create ref string
    /// let string_ref = TypeSpecBuilder::new()
    ///     .managed_reference(TypeSignature::String)
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn managed_reference(mut self, referenced_type: TypeSignature) -> Self {
        self.signature = Some(TypeSignature::ByRef(Box::new(referenced_type)));
        self
    }

    /// Creates a function pointer type.
    ///
    /// Creates a type specification for a function pointer with the specified
    /// method signature. Function pointers are used for delegates and callback
    /// scenarios where method references need to be stored and invoked.
    ///
    /// # Function Pointer Types
    ///
    /// Function pointers support:
    /// - **Managed Delegates**: Standard .NET delegate types
    /// - **Unmanaged Pointers**: Direct function pointers for interop
    /// - **Custom Calling Conventions**: Platform-specific calling conventions
    /// - **Type Safety**: Compile-time signature verification
    ///
    /// # Arguments
    ///
    /// * `method_signature` - The signature of the function being pointed to
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// // Create a function pointer for: int Function(string, bool)
    /// let method_sig = SignatureMethod {
    ///     has_this: false,
    ///     explicit_this: false,
    ///     default: true,
    ///     vararg: false,
    ///     cdecl: false,
    ///     stdcall: false,
    ///     thiscall: false,
    ///     fastcall: false,
    ///     param_count_generic: 0,
    ///     param_count: 2,
    ///     return_type: SignatureParameter {
    ///         modifiers: vec![],
    ///         by_ref: false,
    ///         base: TypeSignature::I4,
    ///     },
    ///     params: vec![
    ///         SignatureParameter {
    ///             modifiers: vec![],
    ///             by_ref: false,
    ///             base: TypeSignature::String,
    ///         },
    ///         SignatureParameter {
    ///             modifiers: vec![],
    ///             by_ref: false,
    ///             base: TypeSignature::Boolean,
    ///         },
    ///     ],
    ///     varargs: vec![],
    /// };
    ///
    /// let func_ptr = TypeSpecBuilder::new()
    ///     .function_pointer(method_sig)
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn function_pointer(mut self, method_signature: SignatureMethod) -> Self {
        self.signature = Some(TypeSignature::FnPtr(Box::new(method_signature)));
        self
    }

    /// Builds the TypeSpec metadata entry.
    ///
    /// Creates a new TypeSpec entry in the metadata with the configured signature.
    /// The signature is encoded using the [`crate::metadata::typesystem::TypeSignatureEncoder`] and stored in
    /// the blob heap, with the TypeSpec entry containing a reference to the blob heap index.
    ///
    /// # Validation
    ///
    /// The build process performs several validation checks:
    /// - **Signature Required**: A type signature must be specified
    /// - **Signature Validity**: The signature must be well-formed
    /// - **Token References**: Referenced tokens must be valid
    /// - **Blob Encoding**: Signature must encode successfully
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for metadata operations
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] referencing the created TypeSpec entry.
    ///
    /// # Errors
    ///
    /// - No type signature was specified
    /// - Invalid token references in the signature
    /// - Blob heap encoding failed
    /// - Signature validation failed
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let signature = self
            .signature
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "TypeSpecBuilder requires a type signature".to_string(),
            })?;

        let typespec_signature = SignatureTypeSpec { base: signature };

        let signature_blob = TypeSignatureEncoder::encode(&typespec_signature.base)?;
        let signature_index = context.blob_add(&signature_blob)?;

        let next_rid = context.next_rid(TableId::TypeSpec);
        let token = Token::new(((TableId::TypeSpec as u32) << 24) | next_rid);

        let typespec_raw = TypeSpecRaw {
            rid: next_rid,
            token,
            offset: 0, // Will be set during binary generation
            signature: signature_index,
        };

        context.table_row_add(TableId::TypeSpec, TableDataOwned::TypeSpec(typespec_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{
            cilassemblyview::CilAssemblyView,
            signatures::{SignatureMethod, SignatureParameter},
        },
    };
    use std::path::PathBuf;

    #[test]
    fn test_typespec_builder_creation() {
        let builder = TypeSpecBuilder::new();
        assert!(builder.signature.is_none());
    }

    #[test]
    fn test_typespec_builder_default() {
        let builder = TypeSpecBuilder::default();
        assert!(builder.signature.is_none());
    }

    #[test]
    fn test_direct_signature() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let token = TypeSpecBuilder::new()
                .signature(TypeSignature::I4)
                .build(&mut context)
                .expect("Should build TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_single_dimensional_array() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let token = TypeSpecBuilder::new()
                .single_dimensional_array(TypeSignature::String)
                .build(&mut context)
                .expect("Should build string array TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_multi_dimensional_array() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let token = TypeSpecBuilder::new()
                .multi_dimensional_array(TypeSignature::I4, 2)
                .build(&mut context)
                .expect("Should build 2D int array TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_generic_instantiation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let list_type = Token::new(0x02000001);
            let token = TypeSpecBuilder::new()
                .generic_instantiation(list_type, vec![TypeSignature::I4])
                .build(&mut context)
                .expect("Should build generic instantiation TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_pointer_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let token = TypeSpecBuilder::new()
                .pointer(TypeSignature::I4)
                .build(&mut context)
                .expect("Should build pointer TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_managed_reference() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let token = TypeSpecBuilder::new()
                .managed_reference(TypeSignature::String)
                .build(&mut context)
                .expect("Should build managed reference TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_function_pointer() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let method_sig = SignatureMethod {
                has_this: false,
                explicit_this: false,
                default: true,
                vararg: false,
                cdecl: false,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                param_count: 1,
                param_count_generic: 0,
                varargs: vec![],
                return_type: SignatureParameter {
                    modifiers: vec![],
                    by_ref: false,
                    base: TypeSignature::I4,
                },
                params: vec![SignatureParameter {
                    modifiers: vec![],
                    by_ref: false,
                    base: TypeSignature::String,
                }],
            };

            let token = TypeSpecBuilder::new()
                .function_pointer(method_sig)
                .build(&mut context)
                .expect("Should build function pointer TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_complex_nested_generic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for TypeSpec
            let expected_rid = context.next_rid(TableId::TypeSpec);

            let dict_type = Token::new(0x02000002);
            let list_type = Token::new(0x02000001);

            // Create Dictionary<string, List<int>>
            let nested_list = TypeSignature::GenericInst(
                Box::new(TypeSignature::Class(list_type)),
                vec![TypeSignature::I4],
            );

            let token = TypeSpecBuilder::new()
                .generic_instantiation(dict_type, vec![TypeSignature::String, nested_list])
                .build(&mut context)
                .expect("Should build complex nested generic TypeSpec");

            assert_eq!(token.value() & 0xFF000000, 0x1B000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_build_without_signature_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = TypeSpecBuilder::new().build(&mut context);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("requires a type signature"));
        }
    }

    #[test]
    fn test_multiple_typespecs() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected first RID for TypeSpec
            let expected_rid1 = context.next_rid(TableId::TypeSpec);

            let token1 = TypeSpecBuilder::new()
                .signature(TypeSignature::I4)
                .build(&mut context)
                .expect("Should build first TypeSpec");

            let token2 = TypeSpecBuilder::new()
                .single_dimensional_array(TypeSignature::String)
                .build(&mut context)
                .expect("Should build second TypeSpec");

            assert_eq!(token1.value() & 0x00FFFFFF, expected_rid1);
            assert_eq!(token2.value() & 0x00FFFFFF, expected_rid1 + 1);
        }
    }
}
