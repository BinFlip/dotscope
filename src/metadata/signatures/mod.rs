//! Method and type signature parsing for .NET metadata according to ECMA-335.
//!
//! This module provides comprehensive parsing of .NET metadata signatures, which encode
//! type information, method parameters, generic constraints, and calling conventions in a
//! compact binary format. Signatures are fundamental to the .NET type system and are used
//! throughout assembly metadata to describe types, methods, and their relationships.
//!
//! # .NET Signature System Overview
//!
//! The .NET metadata format defines signatures as binary-encoded type descriptions that
//! provide complete type information for methods, fields, properties, and local variables.
//! These signatures enable the CLR to understand type relationships, perform type checking,
//! and support generic type instantiation.
//!
//! ## Signature Categories
//!
//! The .NET metadata format defines several signature types, each serving specific purposes:
//!
//! ### Method Signatures
//! - **Purpose**: Describe method parameter types, return types, and calling conventions
//! - **Usage**: Method definitions, method references, and method specifications
//! - **Features**: Support for instance methods, static methods, generic methods, and varargs
//! - **Calling Conventions**: Default, varargs, C calling convention, stdcall, fastcall
//!
//! ### Field Signatures  
//! - **Purpose**: Describe field type information and custom modifiers
//! - **Usage**: Field definitions and field references
//! - **Features**: Support for custom modifiers (modreq/modopt), array types, and generic types
//! - **Modifiers**: Required and optional custom modifiers for advanced type scenarios
//!
//! ### Property Signatures
//! - **Purpose**: Describe property type and indexer parameter information
//! - **Usage**: Property definitions with getter/setter methods
//! - **Features**: Support for indexed properties, instance properties, and generic property types
//! - **Indexers**: Multi-dimensional indexers with complex parameter types
//!
//! ### Local Variable Signatures
//! - **Purpose**: Describe local variable types within method bodies
//! - **Usage**: Method body metadata for JIT compilation and debugging
//! - **Features**: Support for pinned variables, byref variables, and complex local types
//! - **Memory Management**: Pinned locals for interop scenarios and unsafe code
//!
//! ### Type Specification Signatures
//! - **Purpose**: Define generic type instantiations and complex type references
//! - **Usage**: Generic type instantiations like `List<int>` or `Dictionary<string, object>`
//! - **Features**: Nested generic types, generic method instantiations, and type constraints
//! - **Instantiation**: Runtime type creation from generic type definitions
//!
//! ### Method Specification Signatures
//! - **Purpose**: Provide type arguments for generic method instantiations
//! - **Usage**: Generic method calls with specific type arguments
//! - **Features**: Multiple type arguments, nested generic types, and method constraints
//! - **Resolution**: Runtime method resolution for generic method calls
//!
//! # Binary Encoding Format
//!
//! Signatures use a compressed binary encoding optimized for space efficiency while
//! maintaining complete type information. The encoding follows ECMA-335 specifications
//! and includes several key characteristics:
//!
//! ## Encoding Characteristics
//! - **Calling Conventions**: Encoded as single-byte prefixes (0x00-0x0F range)
//! - **Parameter Counts**: Use compressed integer encoding for space efficiency
//! - **Type References**: Element type tokens and metadata table references
//! - **Generic Parameters**: Positional indices into generic parameter lists
//! - **Custom Modifiers**: Inline encoding with type information for advanced scenarios
//!
//! ## Compression Techniques
//! - **Compressed Integers**: Variable-length encoding for counts and indices
//! - **Element Types**: Single-byte encoding for primitive types (int32, string, etc.)
//! - **Token Compression**: Compressed encoding for metadata table references
//! - **Recursive Encoding**: Nested type information for complex generic types
//!
//! # Common Usage Patterns
//!
//! ## Basic Method Signature Analysis
//!
//! ```rust
//! use dotscope::metadata::signatures::parse_method_signature;
//!
//! # fn analyze_method_signature() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse a simple method signature: void Method()
//! let signature_data = &[0x00, 0x00, 0x01]; // DEFAULT, 0 params, VOID return
//! let method_sig = parse_method_signature(signature_data)?;
//!
//! println!("Method has {} parameters", method_sig.params.len());
//! println!("Return type: {:?}", method_sig.return_type.base);
//! println!("Has 'this' parameter: {}", method_sig.has_this);
//! println!("Generic parameter count: {}", method_sig.param_count_generic);
//! # Ok(())
//! # }
//! ```
//!
//! ## Generic Method Signature Analysis
//!
//! ```rust
//! use dotscope::metadata::signatures::{parse_method_signature, TypeSignature};
//!
//! # fn analyze_generic_method() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse generic method: T Method<T>(T item)
//! let signature_data = &[
//!     0x30, // HASTHIS | GENERIC
//!     0x01, // 1 generic parameter
//!     0x01, // 1 method parameter  
//!     0x13, 0x00, // GenericParam(0) - return type
//!     0x13, 0x00, // GenericParam(0) - parameter type
//! ];
//! let method_sig = parse_method_signature(signature_data)?;
//!
//! if method_sig.param_count_generic > 0 {
//!     println!("Generic method with {} type parameters", method_sig.param_count_generic);
//! }
//!
//! // Check if return type is a generic parameter
//! if let TypeSignature::GenericParamType(index) = method_sig.return_type.base {
//!     println!("Return type is generic parameter {}", index);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Field Type Analysis
//!
//! ```rust
//! use dotscope::metadata::signatures::{parse_field_signature, TypeSignature};
//!
//! # fn analyze_field_type() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse array field signature: string[] field
//! let signature_data = &[0x06, 0x1D, 0x0E]; // FIELD, SZARRAY, String
//! let field_sig = parse_field_signature(signature_data)?;
//!
//! match &field_sig.base {
//!     TypeSignature::SzArray(element_type) => {
//!         println!("Array field with element type: {:?}", element_type.base);
//!     },
//!     TypeSignature::String => {
//!         println!("String field");
//!     },
//!     TypeSignature::I4 => {
//!         println!("Integer field");
//!     },
//!     _ => {
//!         println!("Other field type: {:?}", field_sig.base);
//!     }
//! }
//!
//! if !field_sig.modifiers.is_empty() {
//!     println!("Field has {} custom modifiers", field_sig.modifiers.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Local Variable Analysis
//!
//! ```rust
//! use dotscope::metadata::signatures::parse_local_var_signature;
//!
//! # fn analyze_local_variables() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse locals: int a; ref string b; pinned byte* c;
//! let signature_data = &[
//!     0x07, // LOCAL_SIG
//!     0x03, // 3 variables
//!     0x08, // I4 (int)
//!     0x10, 0x0E, // BYREF String (ref string)
//!     0x45, 0x0F, // PINNED PTR (pinned byte*)
//! ];
//! let locals_sig = parse_local_var_signature(signature_data)?;
//!
//! for (i, local) in locals_sig.locals.iter().enumerate() {
//!     println!("Local {}: {:?}", i, local.base);
//!     
//!     if local.is_byref {
//!         println!("  -> Passed by reference");
//!     }
//!     if local.is_pinned {
//!         println!("  -> Pinned in memory (for interop)");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Generic Type Instantiation Analysis
//!
//! ```rust
//! use dotscope::metadata::signatures::{parse_type_spec_signature, TypeSignature};
//!
//! # fn analyze_generic_instantiation() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse List<int> type specification
//! let signature_data = &[
//!     0x15, // GENERICINST
//!     0x12, 0x49, // Class token reference
//!     0x01, // 1 type argument
//!     0x08, // I4 (int)
//! ];
//! let type_spec = parse_type_spec_signature(signature_data)?;
//!
//! if let TypeSignature::GenericInst(class_type, args) = &type_spec.base {
//!     println!("Generic type instantiation:");
//!     println!("  Base type: {:?}", class_type);
//!     println!("  Type arguments: {} types", args.len());
//!     
//!     for (i, arg) in args.iter().enumerate() {
//!         println!("    [{}]: {:?}", i, arg);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Advanced Features
//!
//! ## Custom Modifiers (modreq/modopt)
//!
//! Custom modifiers provide additional type information for advanced scenarios:
//! - **modreq**: Required modifiers that affect type identity and compatibility
//! - **modopt**: Optional modifiers that provide hints but don't affect compatibility
//! - **Usage**: C++/CLI interop, volatile fields, const fields, and custom type constraints
//!
//! ## Calling Conventions
//!
//! Different calling conventions are supported for platform interop:
//! - **DEFAULT**: Standard managed calling convention
//! - **VARARG**: Variable argument lists (params arrays)
//! - **C**: C-style calling convention for P/Invoke
//! - **STDCALL**: Windows standard calling convention
//! - **FASTCALL**: Fast calling convention for performance-critical code
//!
//! ## Memory Layout Specifications
//!
//! Signatures include information for memory management:
//! - **Pinned Variables**: Fixed memory location for interop scenarios
//! - **ByRef Parameters**: Reference semantics for value types
//! - **Pointer Types**: Unsafe pointer types for low-level operations
//! - **Array Bounds**: Multi-dimensional array layout information
//!
//! # Thread Safety
//!
//! All parsing functions in this module are thread-safe:
//! - Stateless parsing functions can be called concurrently
//! - Parsed signature structures are immutable and shareable
//! - No global state or shared mutable data
//!
//! # Error Handling
//!
//! Parsing can fail for several reasons:
//! - **Malformed Data**: Invalid signature encoding or truncated data
//! - **Unsupported Features**: Unknown element types or calling conventions
//! - **Version Incompatibility**: Signatures from newer .NET versions
//! - **Corrupted Metadata**: Damaged assembly files or invalid token references
//!
//! # ECMA-335 Compliance
//!
//! This implementation follows ECMA-335 6th Edition specifications:
//! - **Partition II, Section 23.2**: Blobs and signature encoding formats
//! - **Partition II, Section 23.1**: Metadata validation and well-formedness rules
//! - **Partition I, Section 8**: Type system fundamentals and signature semantics
//! - **Partition III, Section 1.6**: Calling conventions and method signatures
//!
//! The implementation handles all standard signature types and element types
//! defined in the specification, including legacy formats for backward compatibility.

mod builders;
mod encoders;
mod parser;
mod types;

pub use builders::*;
pub use encoders::*;
pub use parser::*;
pub use types::*;

use crate::Result;

/// Parse a method signature from binary signature data.
///
/// Parses .NET method signatures that define method parameter types, return types,
/// and calling conventions. Method signatures are used in method definitions,
/// method references, and generic method instantiations throughout .NET metadata.
///
/// # Method Signature Format
///
/// Method signatures begin with a calling convention byte followed by parameter
/// count and type information:
/// ```text
/// [CallingConvention] [GenericParamCount?] [ParamCount] [ReturnType] [Param1] [Param2] ...
/// ```
///
/// ## Calling Conventions
/// - `0x00`: DEFAULT - Standard managed method
/// - `0x05`: VARARG - Variable argument method  
/// - `0x20`: HASTHIS - Instance method (has implicit 'this' parameter)
/// - `0x30`: HASTHIS | GENERIC - Generic instance method
/// - `0x10`: GENERIC - Static generic method
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::signatures::{parse_method_signature, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse "void Method()" - static method with no parameters
/// let signature = parse_method_signature(&[
///     0x00, // DEFAULT calling convention
///     0x00, // 0 parameters
///     0x01, // VOID return type
/// ])?;
///
/// assert_eq!(signature.params.len(), 0);
/// assert_eq!(signature.return_type.base, TypeSignature::Void);
/// assert!(!signature.has_this);
///
/// // Parse "int Method(string s)" - instance method with parameters
/// let signature = parse_method_signature(&[
///     0x20, // HASTHIS calling convention
///     0x01, // 1 parameter
///     0x08, // I4 (int) return type
///     0x0E, // String parameter type
/// ])?;
///
/// assert!(signature.has_this);
/// assert_eq!(signature.params.len(), 1);
/// assert_eq!(signature.return_type.base, TypeSignature::I4);
/// assert_eq!(signature.params[0].base, TypeSignature::String);
/// # Ok(())
/// # }
/// ```
///
/// # Parameters
/// - `data`: Binary signature data from a .NET assembly's blob heap
///
/// # Returns
/// A [`crate::metadata::signatures::SignatureMethod`] containing:
/// - Parameter types and modifiers
/// - Return type information
/// - Calling convention details
/// - Generic parameter count (for generic methods)
///
/// # Errors
/// Returns [`crate::Error`] if:
/// - Signature data is malformed or truncated
/// - Unknown calling convention or element types
/// - Invalid compressed integer encoding
/// - Recursive type references exceed depth limits
pub fn parse_method_signature(data: &[u8]) -> Result<SignatureMethod> {
    let mut parser = SignatureParser::new(data);
    parser.parse_method_signature()
}

/// Parse a field signature from binary signature data.
///
/// Parses .NET field signatures that define field types and custom modifiers.
/// Field signatures are used in field definitions and field references to
/// specify the exact type and any custom modifiers applied to the field.
///
/// # Field Signature Format
///
/// Field signatures begin with a field signature marker followed by optional
/// custom modifiers and the field type:
/// ```text
/// [FIELD_SIG] [CustomModifier*] [FieldType]
/// ```
///
/// ## Custom Modifiers
/// - `modreq`: Required modifiers that affect type identity
/// - `modopt`: Optional modifiers that provide additional type information
/// - Common uses: `volatile`, `const`, interop type constraints
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::signatures::{parse_field_signature, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse "int field" - simple integer field
/// let signature = parse_field_signature(&[
///     0x06, // FIELD signature marker
///     0x08, // I4 (int) field type
/// ])?;
///
/// assert_eq!(signature.base, TypeSignature::I4);
/// assert!(signature.modifiers.is_empty());
///
/// // Parse "string[] array" - array field
/// let signature = parse_field_signature(&[
///     0x06, // FIELD signature marker
///     0x1D, // SZARRAY (single-dimensional array)
///     0x0E, // String element type
/// ])?;
///
/// # if let TypeSignature::SzArray(element_type) = &signature.base {
///     assert_eq!(*element_type.base, TypeSignature::String);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Parameters
/// - `data`: Binary signature data from a .NET assembly's blob heap
///
/// # Returns
/// A [`crate::metadata::signatures::SignatureField`] containing:
/// - Field type information
/// - Custom modifiers (modreq/modopt)
/// - Type constraints and annotations
///
/// # Errors
/// Returns [`crate::Error`] if:
/// - Signature data is malformed or doesn't start with field marker
/// - Unknown element types or custom modifier tokens
/// - Invalid type encoding or recursive type depth exceeded
/// - Corrupted metadata references
///
/// # Custom Modifier Usage
/// Custom modifiers are commonly used for:
/// - **volatile**: Memory barrier semantics for multithreading
/// - **const**: Compile-time constant fields
/// - **Interop**: C++/CLI and native interop type constraints
/// - **Security**: Type-based security annotations
pub fn parse_field_signature(data: &[u8]) -> Result<SignatureField> {
    let mut parser = SignatureParser::new(data);
    parser.parse_field_signature()
}

/// Parse a property signature from binary signature data.
///
/// Parses .NET property signatures that define property types and indexer parameters.
/// Property signatures are used in property definitions to specify the property type
/// and any parameters for indexed properties (indexers).
///
/// # Property Signature Format
///
/// Property signatures specify whether the property is an instance property and
/// include parameter information for indexed properties:
/// ```text
/// [PROPERTY] [HASTHIS?] [ParamCount] [PropertyType] [Param1] [Param2] ...
/// ```
///
/// ## Property Types
/// - **Simple Properties**: `int Property { get; set; }`
/// - **Indexed Properties**: `string this[int index] { get; set; }`
/// - **Multi-dimensional Indexers**: `T this[int x, int y] { get; set; }`
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::signatures::{parse_property_signature, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse "int Property { get; set; }" - simple instance property
/// let signature = parse_property_signature(&[
///     0x28, // PROPERTY | HASTHIS
///     0x00, // 0 parameters (not indexed)
///     0x08, // I4 (int) property type
/// ])?;
///
/// assert!(signature.has_this);
/// assert_eq!(signature.base, TypeSignature::I4);
/// assert!(signature.params.is_empty());
///
/// // Parse "string this[int index] { get; set; }" - indexed property
/// let signature = parse_property_signature(&[
///     0x28, // PROPERTY | HASTHIS  
///     0x01, // 1 parameter (index)
///     0x0E, // String property type
///     0x08, // I4 (int) index parameter type
/// ])?;
///
/// assert!(signature.has_this);
/// assert_eq!(signature.base, TypeSignature::String);
/// assert_eq!(signature.params.len(), 1);
/// assert_eq!(signature.params[0].base, TypeSignature::I4);
/// # Ok(())
/// # }
/// ```
///
/// # Parameters
/// - `data`: Binary signature data from a .NET assembly's blob heap
///
/// # Returns
/// A [`crate::metadata::signatures::SignatureProperty`] containing:
/// - Property type information
/// - Indexer parameter types (if applicable)
/// - Instance vs. static property indication
///
/// # Errors
/// Returns [`crate::Error`] if:
/// - Signature data is malformed or doesn't start with property marker
/// - Invalid parameter count or type encoding
/// - Unknown element types in property or parameter types
/// - Corrupted signature data or invalid metadata references
///
/// # Indexer Support
/// Multi-dimensional indexers are fully supported:
/// - Parameter types can be any valid .NET type
/// - Custom modifiers are supported on parameters
/// - Generic type parameters are resolved in context
pub fn parse_property_signature(data: &[u8]) -> Result<SignatureProperty> {
    let mut parser = SignatureParser::new(data);
    parser.parse_property_signature()
}

/// Parse a local variable signature from binary signature data.
///
/// Parses .NET local variable signatures that define the types of local variables
/// within method bodies. These signatures are used by the JIT compiler for type
/// checking and memory management, and by debuggers for variable inspection.
///
/// # Local Variable Signature Format
///
/// Local variable signatures specify the count and types of all local variables:
/// ```text
/// [LOCAL_SIG] [LocalCount] [Local1Type] [Local2Type] ...
/// ```
///
/// ## Local Variable Modifiers
/// - **BYREF**: Reference to another variable (`ref` in C#)
/// - **PINNED**: Fixed memory location for interop scenarios
/// - **TYPEDBYREF**: Special runtime type for reflection scenarios
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::signatures::{parse_local_var_signature, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse "int a; string b;" - simple local variables
/// let signature = parse_local_var_signature(&[
///     0x07, // LOCAL_SIG marker
///     0x02, // 2 local variables
///     0x08, // I4 (int) - first local
///     0x0E, // String - second local
/// ])?;
///
/// assert_eq!(signature.locals.len(), 2);
/// assert_eq!(signature.locals[0].base, TypeSignature::I4);
/// assert_eq!(signature.locals[1].base, TypeSignature::String);
///
/// // Parse "ref int a; pinned byte* b;" - advanced local types
/// let signature = parse_local_var_signature(&[
///     0x07, // LOCAL_SIG marker
///     0x02, // 2 local variables
///     0x10, 0x08, // BYREF I4 (ref int)
///     0x45, 0x0F, // PINNED PTR (pinned byte*)
/// ])?;
///
/// assert!(signature.locals[0].is_byref);
/// assert!(!signature.locals[0].is_pinned);
/// assert_eq!(signature.locals[0].base, TypeSignature::I4);
///
/// assert!(!signature.locals[1].is_byref);
/// assert!(signature.locals[1].is_pinned);
/// # Ok(())
/// # }
/// ```
///
/// # Parameters
/// - `data`: Binary signature data from a .NET assembly's blob heap
///
/// # Returns
/// A [`crate::metadata::signatures::SignatureLocalVariables`] containing:
/// - Array of local variable type information
/// - Byref and pinned modifiers for each local
/// - Type information for debugging and JIT compilation
///
/// # Errors
/// Returns [`crate::Error`] if:
/// - Signature data is malformed or doesn't start with local variable marker
/// - Invalid local count or type encoding
/// - Unknown element types or modifiers
/// - Inconsistent signature length vs. declared local count
///
/// # Memory Management
/// Local variable signatures include critical information for memory management:
/// - **Pinned locals**: Fixed memory addresses for P/Invoke and unsafe code
/// - **`ByRef` locals**: Reference semantics that affect garbage collection
/// - **Type layout**: Information needed for stack frame construction
/// - **Lifetime tracking**: GC root analysis for reference types
pub fn parse_local_var_signature(data: &[u8]) -> Result<SignatureLocalVariables> {
    let mut parser = SignatureParser::new(data);
    parser.parse_local_var_signature()
}

/// Parse a type specification signature from binary signature data.
///
/// Parses .NET type specification signatures that define generic type instantiations
/// and complex type references. Type specifications are used to represent constructed
/// generic types like `List<int>`, `Dictionary<string, object>`, and nested generic types.
///
/// # Type Specification Format
///
/// Type specifications encode complete type information including generic arguments:
/// ```text
/// [TypeSpec] [GenericArgCount?] [TypeArg1] [TypeArg2] ...
/// ```
///
/// ## Common Type Specifications
/// - **Generic Instantiations**: `List<T>`, `Dictionary<K,V>`
/// - **Array Types**: `T[]`, `T[,]`, `T[,,]`
/// - **Pointer Types**: `T*`, `void*`
/// - **`ByRef` Types**: `ref T`, `out T`
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::signatures::{parse_type_spec_signature, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse "List<int>" - generic type instantiation
/// let signature = parse_type_spec_signature(&[
///     0x15, // GENERICINST marker
///     0x12, 0x49, // CLASS token reference to List<T>
///     0x01, // 1 type argument
///     0x08, // I4 (int) type argument
/// ])?;
///
/// if let TypeSignature::GenericInst(class_type, args) = &signature.base {
///     assert_eq!(args.len(), 1);
///     assert_eq!(args[0], TypeSignature::I4);
/// }
///
/// // Parse "int[]" - single-dimensional array
/// let signature = parse_type_spec_signature(&[
///     0x1D, // SZARRAY marker
///     0x08, // I4 (int) element type
/// ])?;
///
/// # if let TypeSignature::SzArray(element_type) = &signature.base {
///     assert_eq!(*element_type.base, TypeSignature::I4);
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Parameters
/// - `data`: Binary signature data from a .NET assembly's blob heap
///
/// # Returns
/// A [`crate::metadata::signatures::SignatureTypeSpec`] containing:
/// - Complete type specification information
/// - Generic type arguments (if applicable)
/// - Array dimension information (if applicable)
/// - Custom modifiers and type constraints
///
/// # Errors
/// Returns [`crate::Error`] if:
/// - Signature data is malformed or has invalid type encoding
/// - Unknown element types or generic instantiation format
/// - Invalid generic argument count or recursive type depth exceeded
/// - Corrupted metadata token references
///
/// # Generic Type Support
/// Full support for complex generic scenarios:
/// - **Nested Generics**: `List<Dictionary<string, int>>`
/// - **Generic Constraints**: Type parameter constraints and variance
/// - **Open Generic Types**: Uninstantiated generic type definitions
/// - **Recursive Generics**: Self-referential generic types
pub fn parse_type_spec_signature(data: &[u8]) -> Result<SignatureTypeSpec> {
    let mut parser = SignatureParser::new(data);
    parser.parse_type_spec_signature()
}

/// Parse a method specification signature from binary signature data.
///
/// Parses .NET method specification signatures that provide type arguments for
/// generic method instantiations. Method specifications are used when calling
/// generic methods with specific type arguments, enabling the runtime to create
/// specialized method implementations.
///
/// # Method Specification Format
///
/// Method specifications provide type arguments for generic method calls:
/// ```text
/// [METHODSPEC] [GenericArgCount] [TypeArg1] [TypeArg2] ...
/// ```
///
/// ## Generic Method Instantiation
/// - **Generic Methods**: `Method<T>(T item)` becomes `Method<int>(int item)`
/// - **Multiple Type Args**: `Method<T,U>(T first, U second)`
/// - **Nested Generics**: `Method<List<T>>(List<T> items)`
/// - **Constrained Types**: Type arguments satisfying method constraints
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::signatures::{parse_method_spec_signature, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse "Method<int>" - single type argument
/// let signature = parse_method_spec_signature(&[
///     0x0A, // METHODSPEC marker
///     0x01, // 1 type argument
///     0x08, // I4 (int) type argument
/// ])?;
///
/// assert_eq!(signature.generic_args.len(), 1);
/// assert_eq!(signature.generic_args[0], TypeSignature::I4);
///
/// // Parse "Method<int, string>" - multiple type arguments
/// let signature = parse_method_spec_signature(&[
///     0x0A, // METHODSPEC marker
///     0x02, // 2 type arguments
///     0x08, // I4 (int) first type argument
///     0x0E, // String second type argument
/// ])?;
///
/// assert_eq!(signature.generic_args.len(), 2);
/// assert_eq!(signature.generic_args[0], TypeSignature::I4);
/// assert_eq!(signature.generic_args[1], TypeSignature::String);
/// # Ok(())
/// # }
/// ```
///
/// # Parameters
/// - `data`: Binary signature data from a .NET assembly's blob heap
///
/// # Returns
/// A [`crate::metadata::signatures::SignatureMethodSpec`] containing:
/// - Array of type arguments for generic method instantiation
/// - Type information for runtime method specialization
/// - Generic constraint validation data
///
/// # Errors
/// Returns [`crate::Error`] if:
/// - Signature data is malformed or doesn't start with method spec marker
/// - Invalid type argument count or type encoding
/// - Unknown element types in type arguments
/// - Recursive type references exceed maximum depth
///
/// # Runtime Behavior
/// Method specifications enable the runtime to:
/// - **Create Specialized Methods**: Generate type-specific IL code
/// - **Validate Constraints**: Ensure type arguments satisfy generic constraints  
/// - **Optimize Performance**: Enable type-specific optimizations
/// - **Support Reflection**: Provide complete type information for introspection
pub fn parse_method_spec_signature(data: &[u8]) -> Result<SignatureMethodSpec> {
    let mut parser = SignatureParser::new(data);
    parser.parse_method_spec_signature()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::token::Token;

    #[test]
    fn test_parse_method_signature() {
        // Simple method: void Method()
        let result = parse_method_signature(&[
            0x00, // DEFAULT
            0x00, // 0 parameters
            0x01, // VOID return
        ])
        .unwrap();
        assert_eq!(result.params.len(), 0);
        assert_eq!(result.return_type.base, TypeSignature::Void);
        assert!(!result.has_this);

        // Instance method with parameters: int Method(string s, ref int[] numbers)
        let result = parse_method_signature(&[
            0x20, // HASTHIS
            0x02, // 2 parameters
            0x08, // I4 return
            0x0E, // String (first param)
            0x10, 0x1D, 0x08, // BYREF SZARRAY I4 (second param: ref int[])
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.params.len(), 2);
        // Check return type
        assert_eq!(result.return_type.base, TypeSignature::I4);
        // Check first parameter (string)
        assert_eq!(result.params[0].base, TypeSignature::String);
        assert!(!result.params[0].by_ref);
        // Check second parameter (ref int[])
        assert!(result.params[1].by_ref);
        assert!(matches!(result.params[1].base, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = &result.params[1].base {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // Generic method: T Method<T>(T item)
        let result = parse_method_signature(&[
            0x30, // HASTHIS | GENERIC
            0x01, // 1 generic parameter
            0x01, // 1 method parameter
            0x13, 0x00, // GenericParam(0) - return type is T
            0x13, 0x00, // GenericParam(0) - parameter type is T
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.param_count_generic, 1);
        assert_eq!(result.params.len(), 1);
        // Check return type is T (generic param 0)
        assert_eq!(result.return_type.base, TypeSignature::GenericParamType(0));
        // Check parameter type is also T
        assert_eq!(result.params[0].base, TypeSignature::GenericParamType(0));
    }

    #[test]
    fn test_parse_field_signature() {
        // Simple field: int field
        let result = parse_field_signature(&[
            0x06, // FIELD
            0x08, // I4
        ])
        .unwrap();
        assert_eq!(result.base, TypeSignature::I4);
        assert!(result.modifiers.is_empty());

        // Field with custom modifier: modreq(IsConst) int field
        let result = parse_field_signature(&[
            0x06, // FIELD
            0x1F, 0x42, // CMOD_REQD, token 0x1B000010 (IsConst)
            0x08, // I4
        ])
        .unwrap();
        assert_eq!(result.base, TypeSignature::I4);
        assert_eq!(
            result.modifiers,
            vec![crate::metadata::signatures::CustomModifier {
                is_required: true,
                modifier_type: Token::new(0x1B000010)
            }]
        );

        // Array field: string[] field
        let result = parse_field_signature(&[
            0x06, // FIELD
            0x1D, 0x0E, // SZARRAY, String
        ])
        .unwrap();
        assert!(matches!(result.base, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = result.base {
            assert_eq!(*inner.base, TypeSignature::String);
        }
    }

    #[test]
    fn test_parse_property_signature() {
        // Simple property: int Property { get; set; }
        let result = parse_property_signature(&[
            0x28, // PROPERTY | HASTHIS
            0x00, // 0 parameters
            0x08, // I4
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.base, TypeSignature::I4);
        assert!(result.params.is_empty());

        // Indexed property: string this[int index] { get; set; }
        let result = parse_property_signature(&[
            0x28, // PROPERTY | HASTHIS
            0x01, // 1 parameter
            0x0E, // String return type
            0x08, // I4 parameter type
        ])
        .unwrap();
        assert!(result.has_this);
        assert_eq!(result.base, TypeSignature::String);
        assert_eq!(result.params.len(), 1);
        assert_eq!(result.params[0].base, TypeSignature::I4);
    }

    #[test]
    fn test_parse_local_var_signature() {
        // Local variables: int a; string b;
        let result = parse_local_var_signature(&[
            0x07, // LOCAL_SIG
            0x02, // 2 variables
            0x08, // I4
            0x0E, // String
        ])
        .unwrap();
        assert_eq!(result.locals.len(), 2);
        assert_eq!(result.locals[0].base, TypeSignature::I4);
        assert_eq!(result.locals[1].base, TypeSignature::String);

        // Local variables with byref and pinned: ref int a; pinned string b;
        let result = parse_local_var_signature(&[
            0x07, // LOCAL_SIG
            0x02, // 2 variables
            0x10, 0x08, // BYREF I4
            0x45, 0x0E, // PINNED String
        ])
        .unwrap();
        assert_eq!(result.locals.len(), 2);
        // Check first local is ref int
        assert!(result.locals[0].is_byref);
        assert!(!result.locals[0].is_pinned);
        assert_eq!(result.locals[0].base, TypeSignature::I4);
        // Check second local is pinned string
        assert!(!result.locals[1].is_byref);
        assert!(result.locals[1].is_pinned);
        assert_eq!(result.locals[1].base, TypeSignature::String);
    }

    #[test]
    fn test_parse_type_spec_signature() {
        // TypeSpec: List<int>
        let result = parse_type_spec_signature(&[
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // 1 arg count
            0x08, // I4 type arg
        ])
        .unwrap();
        assert!(matches!(result.base, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = result.base {
            assert!(matches!(*class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_method_spec_signature() {
        // MethodSpec: Method<int, string>
        let result = parse_method_spec_signature(&[
            0x0A, // METHOD_SPEC
            0x02, // 2 type args
            0x08, // I4
            0x0E, // String
        ])
        .unwrap();
        assert_eq!(result.generic_args.len(), 2);
        assert_eq!(result.generic_args[0], TypeSignature::I4);
        assert_eq!(result.generic_args[1], TypeSignature::String);
    }

    #[test]
    fn test_method_signature_roundtrip() {
        // Test simple void method
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .returns(TypeSignature::Void)
            .build()
            .unwrap();

        let encoded = encode_method_signature(&signature).unwrap();
        let reparsed = parse_method_signature(&encoded).unwrap();

        assert_eq!(signature.has_this, reparsed.has_this);
        assert_eq!(signature.explicit_this, reparsed.explicit_this);
        assert_eq!(signature.default, reparsed.default);
        assert_eq!(signature.vararg, reparsed.vararg);
        assert_eq!(signature.return_type, reparsed.return_type);
        assert_eq!(signature.params, reparsed.params);

        // Test method with parameters
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .has_this(true)
            .returns(TypeSignature::I4)
            .param(TypeSignature::String)
            .param(TypeSignature::I4)
            .build()
            .unwrap();

        let encoded = encode_method_signature(&signature).unwrap();
        let reparsed = parse_method_signature(&encoded).unwrap();

        assert_eq!(signature.has_this, reparsed.has_this);
        assert_eq!(signature.return_type, reparsed.return_type);
        assert_eq!(signature.params.len(), reparsed.params.len());
        assert_eq!(signature.params, reparsed.params);
    }

    #[test]
    fn test_field_signature_roundtrip() {
        // Test simple field
        let signature = FieldSignatureBuilder::new()
            .field_type(TypeSignature::I4)
            .build()
            .unwrap();

        let encoded = encode_field_signature(&signature).unwrap();
        let reparsed = parse_field_signature(&encoded).unwrap();

        assert_eq!(signature.base, reparsed.base);
        assert_eq!(signature.modifiers, reparsed.modifiers);

        // Test field with array type
        let signature = FieldSignatureBuilder::new()
            .field_type(TypeSignature::SzArray(
                crate::metadata::signatures::SignatureSzArray {
                    modifiers: vec![],
                    base: Box::new(TypeSignature::String),
                },
            ))
            .build()
            .unwrap();

        let encoded = encode_field_signature(&signature).unwrap();
        let reparsed = parse_field_signature(&encoded).unwrap();

        assert_eq!(signature.base, reparsed.base);
        assert_eq!(signature.modifiers, reparsed.modifiers);
    }

    #[test]
    fn test_property_signature_roundtrip() {
        // Test simple property
        let signature = PropertySignatureBuilder::new()
            .property_type(TypeSignature::String)
            .build()
            .unwrap();

        let encoded = encode_property_signature(&signature).unwrap();
        let reparsed = parse_property_signature(&encoded).unwrap();

        assert_eq!(signature.has_this, reparsed.has_this);
        assert_eq!(signature.base, reparsed.base);
        assert_eq!(signature.params, reparsed.params);

        // Test indexed property
        let signature = PropertySignatureBuilder::new()
            .has_this(true)
            .property_type(TypeSignature::I4)
            .param(TypeSignature::String)
            .param(TypeSignature::I4)
            .build()
            .unwrap();

        let encoded = encode_property_signature(&signature).unwrap();
        let reparsed = parse_property_signature(&encoded).unwrap();

        assert_eq!(signature.has_this, reparsed.has_this);
        assert_eq!(signature.base, reparsed.base);
        assert_eq!(signature.params.len(), reparsed.params.len());
        assert_eq!(signature.params, reparsed.params);
    }

    #[test]
    fn test_local_var_signature_roundtrip() {
        // Test simple locals
        let signature = LocalVariableSignatureBuilder::new()
            .add_local(TypeSignature::I4)
            .add_local(TypeSignature::String)
            .build()
            .unwrap();

        let encoded = encode_local_var_signature(&signature).unwrap();
        let reparsed = parse_local_var_signature(&encoded).unwrap();

        assert_eq!(signature.locals.len(), reparsed.locals.len());
        assert_eq!(signature.locals, reparsed.locals);

        // Test locals with modifiers
        let signature = LocalVariableSignatureBuilder::new()
            .add_local(TypeSignature::I4)
            .add_byref_local(TypeSignature::String)
            .add_pinned_local(TypeSignature::Object)
            .build()
            .unwrap();

        let encoded = encode_local_var_signature(&signature).unwrap();
        let reparsed = parse_local_var_signature(&encoded).unwrap();

        assert_eq!(signature.locals.len(), reparsed.locals.len());
        assert_eq!(signature.locals, reparsed.locals);
    }

    #[test]
    fn test_typespec_signature_roundtrip() {
        // Test simple type specification
        let signature = TypeSpecSignatureBuilder::new()
            .type_signature(TypeSignature::String)
            .build()
            .unwrap();

        let encoded = encode_typespec_signature(&signature).unwrap();
        let reparsed = parse_type_spec_signature(&encoded).unwrap();

        assert_eq!(signature.base, reparsed.base);

        // Test byref type specification
        let signature = TypeSpecSignatureBuilder::new()
            .type_signature(TypeSignature::ByRef(Box::new(TypeSignature::I4)))
            .build()
            .unwrap();

        let encoded = encode_typespec_signature(&signature).unwrap();
        let reparsed = parse_type_spec_signature(&encoded).unwrap();

        assert_eq!(signature.base, reparsed.base);
    }

    #[test]
    fn test_complex_signature_roundtrips() {
        // Test method with complex return type and parameters
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .has_this(true)
            .returns(TypeSignature::SzArray(
                crate::metadata::signatures::SignatureSzArray {
                    modifiers: vec![],
                    base: Box::new(TypeSignature::String),
                },
            ))
            .param(TypeSignature::I4)
            .param_by_ref(TypeSignature::Object)
            .build()
            .unwrap();

        let encoded = encode_method_signature(&signature).unwrap();
        let reparsed = parse_method_signature(&encoded).unwrap();

        assert_eq!(signature.has_this, reparsed.has_this);
        assert_eq!(signature.return_type, reparsed.return_type);
        assert_eq!(signature.params.len(), reparsed.params.len());
        assert_eq!(signature.params, reparsed.params);

        // Test generic instantiation type specification
        let list_token = Token::new(0x02000001);
        let signature = TypeSpecSignatureBuilder::new()
            .type_signature(TypeSignature::GenericInst(
                Box::new(TypeSignature::Class(list_token)),
                vec![TypeSignature::I4],
            ))
            .build()
            .unwrap();

        let encoded = encode_typespec_signature(&signature).unwrap();
        let reparsed = parse_type_spec_signature(&encoded).unwrap();

        assert_eq!(signature.base, reparsed.base);
    }

    #[test]
    fn test_roundtrip_with_all_primitive_types() {
        // Test all primitive types in method signatures
        let primitives = vec![
            TypeSignature::Void,
            TypeSignature::Boolean,
            TypeSignature::Char,
            TypeSignature::I1,
            TypeSignature::U1,
            TypeSignature::I2,
            TypeSignature::U2,
            TypeSignature::I4,
            TypeSignature::U4,
            TypeSignature::I8,
            TypeSignature::U8,
            TypeSignature::R4,
            TypeSignature::R8,
            TypeSignature::String,
            TypeSignature::Object,
            TypeSignature::I,
            TypeSignature::U,
        ];

        for primitive in primitives {
            // Test as method return type (except void gets no parameters)
            let mut builder = MethodSignatureBuilder::new()
                .calling_convention_default()
                .returns(primitive.clone());

            // Add a parameter for non-void methods
            if !matches!(primitive, TypeSignature::Void) {
                builder = builder.param(TypeSignature::I4);
            }

            let signature = builder.build().unwrap();
            let encoded = encode_method_signature(&signature).unwrap();
            let reparsed = parse_method_signature(&encoded).unwrap();

            assert_eq!(
                signature.return_type, reparsed.return_type,
                "Failed roundtrip for primitive return type: {primitive:?}"
            );

            // Test as field type (skip void)
            if !matches!(primitive, TypeSignature::Void) {
                let field_sig = FieldSignatureBuilder::new()
                    .field_type(primitive.clone())
                    .build()
                    .unwrap();

                let encoded = encode_field_signature(&field_sig).unwrap();
                let reparsed = parse_field_signature(&encoded).unwrap();

                assert_eq!(
                    field_sig.base, reparsed.base,
                    "Failed roundtrip for primitive field type: {primitive:?}"
                );
            }
        }
    }

    #[test]
    fn test_byref_parameters_comprehensive() {
        // Test byref parameters across all signature types that support them

        // Method signature with byref parameter
        let method_sig = MethodSignatureBuilder::new()
            .calling_convention_default()
            .returns(TypeSignature::Void)
            .param_by_ref(TypeSignature::I4)
            .build()
            .unwrap();

        let encoded = encode_method_signature(&method_sig).unwrap();
        let reparsed = parse_method_signature(&encoded).unwrap();

        assert_eq!(method_sig.params[0].by_ref, reparsed.params[0].by_ref);
        assert_eq!(method_sig.params[0].base, reparsed.params[0].base);

        // Property signature with byref indexer parameter
        let property_sig = PropertySignatureBuilder::new()
            .has_this(true)
            .property_type(TypeSignature::String)
            .param_by_ref(TypeSignature::I4)
            .build()
            .unwrap();

        let encoded = encode_property_signature(&property_sig).unwrap();
        let reparsed = parse_property_signature(&encoded).unwrap();

        assert_eq!(property_sig.params[0].by_ref, reparsed.params[0].by_ref);
        assert_eq!(property_sig.params[0].base, reparsed.params[0].base);
    }

    #[test]
    fn test_roundtrip_edge_cases() {
        // Test empty local variable signature
        let signature = LocalVariableSignatureBuilder::new().build().unwrap();
        let encoded = encode_local_var_signature(&signature).unwrap();
        let reparsed = parse_local_var_signature(&encoded).unwrap();
        assert_eq!(signature.locals.len(), 0);
        assert_eq!(reparsed.locals.len(), 0);

        // Test method with many parameters
        let mut builder = MethodSignatureBuilder::new()
            .calling_convention_default()
            .returns(TypeSignature::Void);

        for i in 0..10 {
            builder = builder.param(if i % 2 == 0 {
                TypeSignature::I4
            } else {
                TypeSignature::String
            });
        }

        let signature = builder.build().unwrap();
        let encoded = encode_method_signature(&signature).unwrap();
        let reparsed = parse_method_signature(&encoded).unwrap();

        assert_eq!(signature.params.len(), 10);
        assert_eq!(reparsed.params.len(), 10);
        assert_eq!(signature.params, reparsed.params);

        // Test property with no parameters (simple property)
        let signature = PropertySignatureBuilder::new()
            .has_this(true)
            .property_type(TypeSignature::Object)
            .build()
            .unwrap();

        let encoded = encode_property_signature(&signature).unwrap();
        let reparsed = parse_property_signature(&encoded).unwrap();

        assert_eq!(signature.has_this, reparsed.has_this);
        assert_eq!(signature.base, reparsed.base);
        assert_eq!(signature.params.len(), 0);
        assert_eq!(reparsed.params.len(), 0);
    }
}
