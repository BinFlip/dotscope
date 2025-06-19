//! .NET signature type definitions and data structures according to ECMA-335.
//!
//! This module provides the complete type system for representing parsed .NET metadata signatures
//! as defined in ECMA-335. It includes all signature types used throughout the .NET metadata
//! system, from simple primitive types to complex generic instantiations and method signatures.
//!
//! # Signature Type System Overview
//!
//! The .NET signature system encodes type information in binary form within assembly metadata.
//! This module provides Rust representations of these types that maintain full fidelity to
//! the original specification while offering a convenient programming interface.
//!
//! ## Core Type Categories
//!
//! ### Primitive Types
//! Basic value types and system types that form the foundation of the .NET type system:
//! - **Integral Types**: `I1`, `U1`, `I2`, `U2`, `I4`, `U4`, `I8`, `U8`, `I`, `U`
//! - **Floating Point**: `R4` (float), `R8` (double)  
//! - **Character Types**: `Char`, `Boolean`
//! - **Special Types**: `Void`, `String`, `Object`, `TypedByRef`
//!
//! ### Reference and Pointer Types
//! Types that provide indirection and memory management semantics:
//! - **Managed References**: [`TypeSignature::ByRef`] for `ref` and `out` parameters
//! - **Unmanaged Pointers**: [`SignaturePointer`] for unsafe pointer operations
//! - **Arrays**: [`SignatureArray`] (multi-dimensional) and [`SignatureSzArray`] (single-dimensional)
//!
//! ### Object-Oriented Types
//! Types supporting .NET's object-oriented programming model:
//! - **Classes**: [`TypeSignature::Class`] for reference types
//! - **Value Types**: [`TypeSignature::ValueType`] for structures and enums
//! - **Interfaces**: Represented through class tokens with interface semantics
//!
//! ### Generic Types
//! Support for .NET's generic programming model:
//! - **Generic Instantiations**: [`TypeSignature::GenericInst`] for `List<T>`, `Dictionary<K,V>`
//! - **Type Parameters**: [`TypeSignature::GenericParamType`] for class generic parameters
//! - **Method Parameters**: [`TypeSignature::GenericParamMethod`] for method generic parameters
//!
//! ### Method and Property Signatures
//! Specialized signature types for callable members:
//! - **Method Signatures**: [`SignatureMethod`] with calling conventions and parameters
//! - **Property Signatures**: [`SignatureProperty`] for property accessors
//! - **Function Pointers**: [`TypeSignature::FnPtr`] for delegate and function pointer types
//!
//! ### Custom Modifications
//! Advanced type annotation system for interop and optimization:
//! - **Required Modifiers**: [`TypeSignature::ModifiedRequired`] affecting type identity
//! - **Optional Modifiers**: [`TypeSignature::ModifiedOptional`] providing hints
//! - **Common Uses**: `volatile`, `const`, platform-specific annotations
//!
//! # Type Compatibility and Conversions
//!
//! The type system includes comprehensive compatibility checking for constant assignment,
//! supporting .NET's type conversion rules including safe widening conversions and
//! reference type compatibility.
//!
//! ## Safe Conversions Supported
//! - **Integer Widening**: `sbyte` → `short` → `int` → `long`
//! - **Unsigned Widening**: `byte` → `ushort` → `uint` → `ulong`  
//! - **Float Widening**: `float` → `double`
//! - **Integer to Float**: All integer types to appropriate floating point types
//! - **Reference Assignments**: `string` → `object`, `null` → any reference type
//!
//! # ECMA-335 Compliance
//!
//! All types in this module correspond directly to ECMA-335 specification sections:
//! - **Partition II, Section 23.2**: Binary signature encoding formats
//! - **Partition I, Section 8**: Common Type System (CTS) definitions
//! - **Partition II, Section 7**: Type system fundamentals and metadata representation
//! - **Partition II, Section 22**: Metadata table schemas and relationships
//!
//! # Usage Examples
//!
//! ## Working with Primitive Types
//! ```rust
//! use dotscope::metadata::signatures::TypeSignature;
//! use dotscope::metadata::typesystem::{CilPrimitive, CilPrimitiveKind};
//!
//! # fn example() {
//! // Check type compatibility for constants
//! let int_type = TypeSignature::I4;
//! let int_constant = CilPrimitive::i4(42);
//!
//! assert!(int_type.accepts_constant(&int_constant));
//!
//! // Safe widening conversion
//! let long_type = TypeSignature::I8;
//! assert!(long_type.accepts_constant(&int_constant)); // int32 → int64 is safe
//! # }
//! ```
//!
//! ## Working with Generic Types
//! ```rust
//! use dotscope::metadata::signatures::{TypeSignature, SignatureArray};
//! use dotscope::metadata::typesystem::ArrayDimensions;
//!
//! # fn example() {
//! // Representing List<int>
//! let list_of_int = TypeSignature::GenericInst(
//!     Box::new(TypeSignature::Class(dotscope::metadata::token::Token::new(0x02000001))), // List<T> class token
//!     vec![TypeSignature::I4] // Type argument: int
//! );
//!
//! // Representing int[,] (2D array)
//! let int_2d_array = TypeSignature::Array(SignatureArray {
//!     base: Box::new(TypeSignature::I4),
//!     rank: 2,
//!     dimensions: vec![
//!         ArrayDimensions { size: None, lower_bound: None },
//!         ArrayDimensions { size: None, lower_bound: None },
//!     ],
//! });
//! # }
//! ```
//!
//! ## Method Signature Construction
//! ```rust
//! use dotscope::metadata::signatures::{SignatureMethod, SignatureParameter, TypeSignature};
//!
//! # fn example() {
//! // Representing: public int Method(string arg)
//! let method_signature = SignatureMethod {
//!     has_this: true,        // Instance method
//!     default: true,         // Default calling convention
//!     param_count: 1,        // One parameter
//!     return_type: SignatureParameter {
//!         by_ref: false,
//!         base: TypeSignature::I4,  // int return type
//!         modifiers: vec![],
//!     },
//!     params: vec![
//!         SignatureParameter {
//!             by_ref: false,
//!             base: TypeSignature::String,  // string parameter
//!             modifiers: vec![],
//!         }
//!     ],
//!     ..Default::default()
//! };
//! # }
//! ```
//!
//! # References
//!
//! - **ECMA-335 Standard**: [6th Edition Specification](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - **.NET Runtime Source**: [CoreCLR metadata implementation](https://github.com/dotnet/runtime/tree/main/src/coreclr/md)
//! - **CLI Specification**: Partition I (Architecture), Partition II (Metadata)

use crate::metadata::{token::Token, typesystem::ArrayDimensions};

/// Complete .NET type signature representation supporting all ECMA-335 type encodings.
///
/// `TypeSignature` represents any type that can appear in .NET metadata signatures,
/// from simple primitive types to complex generic instantiations. This enum provides
/// a complete mapping of ECMA-335's type encoding system to Rust types.
///
/// # Type Categories
///
/// ## Primitive Types (`ELEMENT_TYPE_*`)
/// Direct mappings from ECMA-335 element type constants:
/// - [`Void`](TypeSignature::Void): `void` type (`ELEMENT_TYPE_VOID` = 0x01)
/// - [`Boolean`](TypeSignature::Boolean): `bool` type (`ELEMENT_TYPE_BOOLEAN` = 0x02)
/// - [`Char`](TypeSignature::Char): `char` type (`ELEMENT_TYPE_CHAR` = 0x03)
/// - [`I1`](TypeSignature::I1): `sbyte` type (`ELEMENT_TYPE_I1` = 0x04)
/// - [`U1`](TypeSignature::U1): `byte` type (`ELEMENT_TYPE_U1` = 0x05)
/// - [`I2`](TypeSignature::I2): `short` type (`ELEMENT_TYPE_I2` = 0x06)
/// - [`U2`](TypeSignature::U2): `ushort` type (`ELEMENT_TYPE_U2` = 0x07)
/// - [`I4`](TypeSignature::I4): `int` type (`ELEMENT_TYPE_I4` = 0x08)
/// - [`U4`](TypeSignature::U4): `uint` type (`ELEMENT_TYPE_U4` = 0x09)
/// - [`I8`](TypeSignature::I8): `long` type (`ELEMENT_TYPE_I8` = 0x0A)
/// - [`U8`](TypeSignature::U8): `ulong` type (`ELEMENT_TYPE_U8` = 0x0B)
/// - [`R4`](TypeSignature::R4): `float` type (`ELEMENT_TYPE_R4` = 0x0C)
/// - [`R8`](TypeSignature::R8): `double` type (`ELEMENT_TYPE_R8` = 0x0D)
/// - [`String`](TypeSignature::String): `string` type (`ELEMENT_TYPE_STRING` = 0x0E)
/// - [`Object`](TypeSignature::Object): `object` type (`ELEMENT_TYPE_OBJECT` = 0x1C)
/// - [`I`](TypeSignature::I): `IntPtr` type (`ELEMENT_TYPE_I` = 0x18)
/// - [`U`](TypeSignature::U): `UIntPtr` type (`ELEMENT_TYPE_U` = 0x19)
///
/// ## Reference and Pointer Types
/// Types providing memory indirection:
/// - [`Ptr`](TypeSignature::Ptr): Unmanaged pointer (T*) (`ELEMENT_TYPE_PTR` = 0x0F)
/// - [`ByRef`](TypeSignature::ByRef): Managed reference (ref T) (`ELEMENT_TYPE_BYREF` = 0x10)
/// - [`Pinned`](TypeSignature::Pinned): Pinned reference for interop (`ELEMENT_TYPE_PINNED` = 0x45)
///
/// ## Object-Oriented Types
/// Class and value type representations:
/// - [`Class`](TypeSignature::Class): Reference types (`ELEMENT_TYPE_CLASS` = 0x12)
/// - [`ValueType`](TypeSignature::ValueType): Value types (`ELEMENT_TYPE_VALUETYPE` = 0x11)
///
/// ## Array Types
/// Single and multi-dimensional array support:
/// - [`Array`](TypeSignature::Array): Multi-dimensional arrays (`ELEMENT_TYPE_ARRAY` = 0x14)
/// - [`SzArray`](TypeSignature::SzArray): Single-dimensional arrays (`ELEMENT_TYPE_SZARRAY` = 0x1D)
///
/// ## Generic Types
/// Support for .NET generics:
/// - [`GenericInst`](TypeSignature::GenericInst): Generic instantiation (`List<T>`) (`ELEMENT_TYPE_GENERICINST` = 0x15)
/// - [`GenericParamType`](TypeSignature::GenericParamType): Type parameter (T) (`ELEMENT_TYPE_VAR` = 0x13)
/// - [`GenericParamMethod`](TypeSignature::GenericParamMethod): Method parameter (M) (`ELEMENT_TYPE_MVAR` = 0x1E)
///
/// ## Function Types
/// Callable type representations:
/// - [`FnPtr`](TypeSignature::FnPtr): Function pointer (`ELEMENT_TYPE_FNPTR` = 0x1B)
///
/// ## Custom Modifiers
/// Type annotation system:
/// - [`ModifiedRequired`](TypeSignature::ModifiedRequired): Required modifiers (`ELEMENT_TYPE_CMOD_REQD` = 0x1F)
/// - [`ModifiedOptional`](TypeSignature::ModifiedOptional): Optional modifiers (`ELEMENT_TYPE_CMOD_OPT` = 0x20)
///
/// ## Special Types
/// Runtime and metadata-specific types:
/// - [`TypedByRef`](TypeSignature::TypedByRef): Typed references (`ELEMENT_TYPE_TYPEDBYREF` = 0x16)
/// - [`Internal`](TypeSignature::Internal): CLI-internal type (`ELEMENT_TYPE_INTERNAL` = 0x21)
/// - [`Sentinel`](TypeSignature::Sentinel): Vararg separator (`ELEMENT_TYPE_SENTINEL` = 0x41)
/// - [`Unknown`](TypeSignature::Unknown): Unresolved or invalid type
///
/// ## Custom Attribute Types
/// Types used in custom attribute encoding:
/// - [`Type`](TypeSignature::Type): System.Type reference in attributes
/// - [`Boxed`](TypeSignature::Boxed): Boxed value type in attributes
/// - [`Field`](TypeSignature::Field): Field reference in attributes
///
/// # Usage Examples
///
/// ## Primitive Type Matching
/// ```rust
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn check_primitive_type(sig: &TypeSignature) {
/// match sig {
///     TypeSignature::I4 => println!("32-bit signed integer"),
///     TypeSignature::String => println!("System.String"),
///     TypeSignature::Object => println!("System.Object"),
///     _ => println!("Other type"),
/// }
/// # }
/// ```
///
/// ## Generic Type Inspection
/// ```rust
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn inspect_generic(sig: &TypeSignature) {
/// if let TypeSignature::GenericInst(base_type, type_args) = sig {
///     println!("Generic type with {} type arguments", type_args.len());
///     for (i, arg) in type_args.iter().enumerate() {
///         println!("  Type argument {}: {:?}", i, arg);
///     }
/// }
/// # }
/// ```
///
/// ## Array Type Analysis
/// ```rust
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn analyze_array(sig: &TypeSignature) {
/// match sig {
///     TypeSignature::SzArray(array) => {
///         println!("Single-dimensional array of {:?}", array.base);
///     },
///     TypeSignature::Array(array) => {
///         println!("{}-dimensional array of {:?}", array.rank, array.base);
///     },
///     _ => println!("Not an array type"),
/// }
/// # }
/// ```
///
/// # Memory Layout
///
/// The enum uses Rust's discriminated union representation with boxed recursive references
/// to minimize memory usage. Complex nested types use `Box<TypeSignature>` to prevent
/// infinite-sized types and reduce stack usage during recursive operations.
///
/// # ECMA-335 Compliance
///
/// Each variant corresponds directly to an ECMA-335 element type constant or composite
/// type encoding. The representation maintains full fidelity to the specification while
/// providing a type-safe Rust interface.
///
/// # See Also
/// - [`crate::metadata::signatures::SignatureParser`]: For parsing binary signatures into these types
/// - [`crate::metadata::typesystem`]: For complete type system representation with resolution
/// - [`crate::metadata::token::Token`]: For metadata table references
#[derive(Debug, Clone, PartialEq, Default)]
pub enum TypeSignature {
    #[default]
    /// Represents an unresolved, invalid, or unknown type signature.
    ///
    /// This variant is used as a fallback when:
    /// - Type resolution fails due to missing metadata
    /// - Invalid or corrupted signature data is encountered
    /// - Forward references cannot be resolved during parsing
    /// - Placeholder during incremental signature construction
    ///
    /// # Usage Notes
    /// - Should not appear in fully resolved type signatures
    /// - May indicate parsing errors or incomplete metadata loading
    /// - Used as a safe default during signature construction
    Unknown,

    /// The `void` type (`ELEMENT_TYPE_VOID` = 0x01).
    ///
    /// Represents the absence of a value, typically used as:
    /// - Method return types for procedures that don't return values
    /// - Pointer base types in unsafe scenarios (`void*`)
    /// - Generic type constraints in advanced scenarios
    ///
    /// # Examples
    /// ```csharp
    /// public void Method() { }           // void return type
    /// public unsafe void* GetPointer();  // void* return type
    /// ```
    ///
    /// # ECMA-335 Reference
    /// Partition II, Section 23.1.16: `ELEMENT_TYPE_VOID`
    Void,

    /// The `bool` type (`ELEMENT_TYPE_BOOLEAN` = 0x02).
    ///
    /// Represents a boolean value that can be either `true` or `false`.
    /// Stored as a single byte in memory with 0 = false, non-zero = true.
    ///
    /// # Examples
    /// ```csharp
    /// public bool IsValid { get; set; }
    /// public bool CheckCondition() => true;
    /// ```
    ///
    /// # Storage
    /// - Size: 1 byte
    /// - Values: 0 (false), 1 (true), though any non-zero is treated as true
    /// - CLI verification ensures only 0 or 1 values in verifiable code
    Boolean,

    /// The `char` type (`ELEMENT_TYPE_CHAR` = 0x03).
    ///
    /// Represents a Unicode UTF-16 character value. Always unsigned 16-bit.
    /// Part of the .NET character and string system with full Unicode support.
    ///
    /// # Examples
    /// ```csharp
    /// public char FirstLetter = 'A';
    /// public char UnicodeChar = '\u03A9';  // Greek Omega
    /// ```
    ///
    /// # Storage
    /// - Size: 2 bytes
    /// - Range: U+0000 to U+FFFF (Basic Multilingual Plane)
    /// - Encoding: UTF-16 code units
    /// - Surrogate pairs handled at string level
    Char,

    /// Signed 8-bit integer type `sbyte` (`ELEMENT_TYPE_I1` = 0x04).
    ///
    /// Represents signed byte values from -128 to 127.
    /// Commonly used for small numeric values and interop scenarios.
    ///
    /// # Examples
    /// ```csharp
    /// public sbyte Temperature = -10;
    /// public sbyte GetOffset() => -1;
    /// ```
    ///
    /// # Storage
    /// - Size: 1 byte
    /// - Range: -128 to 127
    /// - Two's complement representation
    I1,

    /// Unsigned 8-bit integer type `byte` (`ELEMENT_TYPE_U1` = 0x05).
    ///
    /// Represents unsigned byte values from 0 to 255.
    /// Most commonly used numeric type for binary data and byte arrays.
    ///
    /// # Examples
    /// ```csharp
    /// public byte[] Data = new byte[1024];
    /// public byte Age = 25;
    /// ```
    ///
    /// # Storage
    /// - Size: 1 byte  
    /// - Range: 0 to 255
    /// - Common use: Binary data, small positive integers
    U1,

    /// Signed 16-bit integer type `short` (`ELEMENT_TYPE_I2` = 0x06).
    ///
    /// Represents signed 16-bit values from -32,768 to 32,767.
    /// Used for moderate-range integer values and interop scenarios.
    ///
    /// # Examples
    /// ```csharp
    /// public short Year = 2024;
    /// public short GetDelta() => -500;
    /// ```
    ///
    /// # Storage
    /// - Size: 2 bytes
    /// - Range: -32,768 to 32,767  
    /// - Two's complement representation
    /// - Little-endian byte order in memory
    I2,

    /// Unsigned 16-bit integer type `ushort` (`ELEMENT_TYPE_U2` = 0x07).
    ///
    /// Represents unsigned 16-bit values from 0 to 65,535.
    /// Commonly used for port numbers, small identifiers, and Unicode code points.
    ///
    /// # Examples
    /// ```csharp
    /// public ushort Port = 8080;
    /// public ushort CharCode = 0x03A9;  // Unicode code point
    /// ```
    ///
    /// # Storage
    /// - Size: 2 bytes
    /// - Range: 0 to 65,535
    /// - Little-endian byte order in memory
    U2,

    /// Signed 32-bit integer type `int` (`ELEMENT_TYPE_I4` = 0x08).
    ///
    /// The most commonly used integer type in .NET applications.
    /// Default integer type for literals and general-purpose numeric values.
    ///
    /// # Examples
    /// ```csharp
    /// public int Count = 42;
    /// public int Calculate() => 12345;
    /// ```
    ///
    /// # Storage
    /// - Size: 4 bytes
    /// - Range: -2,147,483,648 to 2,147,483,647
    /// - Two's complement representation
    /// - Most efficient integer type on 32-bit and 64-bit platforms
    I4,

    /// Unsigned 32-bit integer type `uint` (`ELEMENT_TYPE_U4` = 0x09).
    ///
    /// Represents unsigned 32-bit values from 0 to 4,294,967,295.
    /// Used for large positive values, bit manipulation, and interop.
    ///
    /// # Examples
    /// ```csharp
    /// public uint Flags = 0xDEADBEEF;
    /// public uint LargeCount = 3000000000;
    /// ```
    ///
    /// # Storage
    /// - Size: 4 bytes
    /// - Range: 0 to 4,294,967,295
    /// - Common use: Bit flags, large counts, memory addresses
    U4,

    /// Signed 64-bit integer type `long` (`ELEMENT_TYPE_I8` = 0x0A).
    ///
    /// Represents large signed integer values. Used for file sizes,
    /// timestamps, large counters, and high-precision calculations.
    ///
    /// # Examples
    /// ```csharp
    /// public long FileSize = 1024L * 1024 * 1024;  // 1 GB
    /// public long Timestamp = DateTimeOffset.Now.Ticks;
    /// ```
    ///
    /// # Storage
    /// - Size: 8 bytes
    /// - Range: -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807
    /// - Two's complement representation
    I8,

    /// Unsigned 64-bit integer type `ulong` (`ELEMENT_TYPE_U8` = 0x0B).
    ///
    /// Represents the largest standard unsigned integer type in .NET.
    /// Used for very large positive values, memory sizes, and bit manipulation.
    ///
    /// # Examples
    /// ```csharp
    /// public ulong MaxMemory = 16UL * 1024 * 1024 * 1024;  // 16 GB
    /// public ulong BitMask = 0xFFFFFFFFFFFFFFFF;
    /// ```
    ///
    /// # Storage
    /// - Size: 8 bytes
    /// - Range: 0 to 18,446,744,073,709,551,615
    /// - Common use: Large memory sizes, 64-bit bit manipulation
    U8,

    /// Single-precision 32-bit floating-point type `float` (`ELEMENT_TYPE_R4` = 0x0C).
    ///
    /// IEEE 754 single-precision floating-point number with ~7 decimal digits
    /// of precision. Used for graphics, scientific calculations, and scenarios
    /// where memory usage is more important than precision.
    ///
    /// # Examples
    /// ```csharp
    /// public float Temperature = 98.6f;
    /// public float Distance = 123.45f;
    /// ```
    ///
    /// # Storage
    /// - Size: 4 bytes
    /// - Precision: ~7 decimal digits
    /// - Range: ±1.5 × 10^-45 to ±3.4 × 10^38
    /// - IEEE 754 single-precision format
    R4,

    /// Double-precision 64-bit floating-point type `double` (`ELEMENT_TYPE_R8` = 0x0D).
    ///
    /// IEEE 754 double-precision floating-point number with ~15-17 decimal digits
    /// of precision. Default floating-point type for most calculations.
    ///
    /// # Examples
    /// ```csharp
    /// public double Pi = 3.14159265358979323846;
    /// public double Calculate() => Math.Sqrt(2.0);
    /// ```
    ///
    /// # Storage
    /// - Size: 8 bytes
    /// - Precision: ~15-17 decimal digits
    /// - Range: ±5.0 × 10^-324 to ±1.7 × 10^308
    /// - IEEE 754 double-precision format
    R8,

    /// The `string` type (`ELEMENT_TYPE_STRING` = 0x0E).
    ///
    /// Represents immutable Unicode text strings. Reference type with
    /// automatic memory management and comprehensive Unicode support.
    ///
    /// # Examples
    /// ```csharp
    /// public string Name = "Hello, World!";
    /// public string GetMessage() => "Success";
    /// ```
    ///
    /// # Characteristics
    /// - Reference type (can be null)
    /// - Immutable (modifications create new instances)
    /// - UTF-16 encoding internally
    /// - Interned string optimization available
    /// - Length-prefixed with automatic bounds checking
    String,

    /// Unmanaged pointer type `T*` (`ELEMENT_TYPE_PTR` = 0x0F).
    ///
    /// Represents a pointer to unmanaged memory containing the specified type.
    /// Used in unsafe code and interop scenarios. Requires unsafe context.
    ///
    /// # Safety
    /// - No automatic memory management
    /// - No bounds checking
    /// - Can point to invalid memory
    /// - Requires `unsafe` keyword in C#
    ///
    /// # Examples
    /// ```csharp
    /// public unsafe int* GetPointer();
    /// public unsafe void ProcessBuffer(byte* buffer, int length);
    /// ```
    ///
    /// # See Also
    /// - [`SignaturePointer`]: Contains the pointed-to type and custom modifiers
    /// - [`TypeSignature::ByRef`]: For managed references
    Ptr(SignaturePointer),

    /// Managed reference type `ref T` (`ELEMENT_TYPE_BYREF` = 0x10).
    ///
    /// Represents a managed reference to a value of the specified type.
    /// Used for `ref`, `out`, and `in` parameters and return values.
    /// Provides safe, garbage-collected reference semantics.
    ///
    /// # Examples
    /// ```csharp
    /// public void Method(ref int value);
    /// public ref int GetReference();
    /// public void OutMethod(out string result);
    /// ```
    ///
    /// # Characteristics
    /// - Always points to valid, managed memory
    /// - Cannot be null (unlike pointers)
    /// - Garbage collector aware
    /// - Automatic lifetime management
    /// - Cannot outlive the referenced object
    ///
    /// # See Also
    /// - [`TypeSignature::Ptr`]: For unmanaged pointers
    ByRef(Box<TypeSignature>),

    /// Value type reference (`ELEMENT_TYPE_VALUETYPE` = 0x11).
    ///
    /// Represents a value type (struct, enum, or primitive type) defined in metadata.
    /// Value types are stored by value rather than reference, with direct memory layout.
    ///
    /// # Examples
    /// ```csharp
    /// public struct Point { public int X, Y; }      // Custom value type
    /// public enum Status { Active, Inactive }       // Enum value type
    /// public DateTime Timestamp;                     // Built-in value type
    /// ```
    ///
    /// # Characteristics
    /// - Stored by value (copied on assignment)
    /// - Cannot be null (unless wrapped in `Nullable<T>`)
    /// - Stack allocated for locals, embedded in objects
    /// - Can implement interfaces
    /// - Supports custom constructors and methods
    ///
    /// # Token Reference
    /// The contained [`Token`] references the `TypeDef` or `TypeRef` metadata table
    /// entry that defines this value type.
    ///
    /// # See Also
    /// - [`TypeSignature::Class`]: For reference types
    ValueType(Token),

    /// Reference type (class) definition (`ELEMENT_TYPE_CLASS` = 0x12).
    ///
    /// Represents a reference type (class or interface) defined in metadata.
    /// Reference types are allocated on the managed heap with automatic garbage collection.
    ///
    /// # Examples
    /// ```csharp
    /// public class Customer { }           // Custom reference type
    /// public interface IDisposable { }    // Interface reference type  
    /// public List<int> Items;             // Generic reference type
    /// ```
    ///
    /// # Characteristics
    /// - Allocated on managed heap
    /// - Can be null
    /// - Reference semantics (shared on assignment)
    /// - Automatic garbage collection
    /// - Supports inheritance and polymorphism
    /// - Can contain virtual methods and properties
    ///
    /// # Token Reference
    /// The contained [`Token`] references the `TypeDef` or `TypeRef` metadata table
    /// entry that defines this class type.
    ///
    /// # See Also
    /// - [`TypeSignature::ValueType`]: For value types
    /// - [`TypeSignature::GenericInst`]: For generic instantiations
    Class(Token),

    /// Generic type parameter `T` (`ELEMENT_TYPE_VAR` = 0x13).
    ///
    /// Represents a generic type parameter defined on a type (class, struct, or interface).
    /// The parameter is identified by its zero-based index in the generic parameter list.
    ///
    /// # Examples
    /// ```csharp
    /// public class Container<T, U> {      // T is index 0, U is index 1
    ///     public T Value;                 // T referenced as index 0
    ///     public U Secondary;             // U referenced as index 1
    /// }
    /// ```
    ///
    /// # Parameter Index
    /// The `u32` value represents the zero-based index into the generic type's
    /// parameter list. Index 0 is the first parameter, index 1 is the second, etc.
    ///
    /// # Resolution
    /// During type instantiation, these parameters are replaced with concrete types:
    /// ```csharp
    /// Container<string, int> instance;   // T=string (index 0), U=int (index 1)
    /// ```
    ///
    /// # See Also
    /// - [`TypeSignature::GenericParamMethod`]: For method generic parameters
    /// - [`TypeSignature::GenericInst`]: For generic instantiations
    GenericParamType(u32),

    /// Multi-dimensional array type `T[,]` (`ELEMENT_TYPE_ARRAY` = 0x14).
    ///
    /// Represents arrays with one or more dimensions, including size and bound information.
    /// Supports jagged arrays, rectangular arrays, and arrays with non-zero lower bounds.
    ///
    /// # Examples
    /// ```csharp
    /// int[,] matrix = new int[3, 4];           // 2D rectangular array
    /// string[,,] cube = new string[2, 3, 4];   // 3D rectangular array
    /// int[,] bounded = new int[1..5, 2..8];    // Array with bounds [1-4, 2-7]
    /// ```
    ///
    /// # Array Characteristics
    /// - Multiple dimensions with rank information
    /// - Optional size specifications for each dimension
    /// - Optional lower bound specifications (default is 0)
    /// - Element type can be any valid .NET type
    /// - Bounds checking at runtime
    ///
    /// # See Also
    /// - [`SignatureArray`]: Contains element type, rank, and dimension information
    /// - [`TypeSignature::SzArray`]: For single-dimensional arrays
    Array(SignatureArray),

    /// Generic type instantiation `List<T>` (`ELEMENT_TYPE_GENERICINST` = 0x15).
    ///
    /// Represents a generic type with specific type arguments provided.
    /// The first element is the generic type definition, followed by type arguments.
    ///
    /// # Examples
    /// ```csharp
    /// List<int> numbers;                           // List<T> with int argument
    /// Dictionary<string, Person> people;           // Dictionary<K,V> with string, Person arguments
    /// Nullable<DateTime> timestamp;                // Nullable<T> with DateTime argument
    /// ```
    ///
    /// # Structure
    /// - **Base Type**: Generic type definition (e.g., `List<>`, `Dictionary<,>`)
    /// - **Type Arguments**: Concrete types for each generic parameter
    /// - **Argument Count**: Must match the generic type's parameter count
    ///
    /// # Nested Generics
    /// Supports arbitrarily nested generic instantiations:
    /// ```csharp
    /// List<Dictionary<string, List<int>>> complex;  // Deeply nested generics
    /// ```
    ///
    /// # Type Safety
    /// The runtime ensures type argument compatibility with generic constraints
    /// defined on the generic type definition.
    GenericInst(Box<TypeSignature>, Vec<TypeSignature>),

    /// Typed reference type (`ELEMENT_TYPE_TYPEDBYREF` = 0x16).
    ///
    /// Special type that combines a managed reference with its runtime type information.
    /// Primarily used for advanced reflection scenarios and variable argument lists.
    ///
    /// # Examples
    /// ```csharp
    /// __makeref(variable);        // Creates typed reference
    /// __reftype(typedRef);        // Gets type from typed reference
    /// __refvalue(typedRef, Type); // Gets value from typed reference
    /// ```
    ///
    /// # Characteristics
    /// - Contains both reference and type information
    /// - Used in reflection and metaprogramming
    /// - Supports variable argument processing
    /// - Runtime type safety verification
    /// - Cannot be stored in fields or arrays
    ///
    /// # Usage Notes
    /// - Rarely used in normal application code
    /// - Primarily for advanced runtime scenarios
    /// - Supported mainly for completeness and interop
    TypedByRef,

    /// Platform-sized signed integer `IntPtr` (`ELEMENT_TYPE_I` = 0x18).
    ///
    /// Represents a signed integer whose size matches the platform pointer size.
    /// 32-bit on 32-bit platforms, 64-bit on 64-bit platforms.
    ///
    /// # Examples
    /// ```csharp
    /// public IntPtr WindowHandle;
    /// public IntPtr GetNativePointer();
    /// ```
    ///
    /// # Characteristics
    /// - Size: 4 bytes on 32-bit, 8 bytes on 64-bit platforms
    /// - Used for interop and native resource handles
    /// - Can represent memory addresses
    /// - Automatic platform adaptation
    ///
    /// # Common Uses
    /// - Window handles (HWND)
    /// - Native library pointers
    /// - Memory addresses in interop scenarios
    /// - File handles and other OS resources
    I,

    /// Platform-sized unsigned integer `UIntPtr` (`ELEMENT_TYPE_U` = 0x19).
    ///
    /// Represents an unsigned integer whose size matches the platform pointer size.
    /// 32-bit on 32-bit platforms, 64-bit on 64-bit platforms.
    ///
    /// # Examples
    /// ```csharp
    /// public UIntPtr BufferSize;
    /// public UIntPtr GetMemorySize();
    /// ```
    ///
    /// # Characteristics
    /// - Size: 4 bytes on 32-bit, 8 bytes on 64-bit platforms
    /// - Used for memory sizes and unsigned addresses
    /// - Cannot be negative
    /// - Automatic platform adaptation
    ///
    /// # Common Uses
    /// - Memory buffer sizes
    /// - Unsigned memory addresses
    /// - Array sizes in interop scenarios
    /// - Bit manipulation with platform-sized values
    U,

    /// Function pointer type (`ELEMENT_TYPE_FNPTR` = 0x1B).
    ///
    /// Represents a pointer to a function with a specific signature.
    /// Used for delegates, callbacks, and function pointer interop.
    ///
    /// # Examples
    /// ```csharp
    /// delegate int Calculator(int a, int b);       // Managed delegate
    /// delegate* unmanaged<int, int, int> FuncPtr;  // Unmanaged function pointer
    /// ```
    ///
    /// # Function Pointer Types
    /// - **Managed**: Standard .NET delegates with GC support
    /// - **Unmanaged**: Direct function pointers for interop
    /// - **Custom Calling Conventions**: cdecl, stdcall, fastcall, etc.
    ///
    /// # Safety Considerations
    /// - Unmanaged function pointers require unsafe context
    /// - Calling convention must match exactly
    /// - Parameter and return types must be compatible
    /// - Lifetime management is manual for unmanaged pointers
    ///
    /// # See Also
    /// - [`SignatureMethod`]: Contains the function signature details
    FnPtr(Box<SignatureMethod>),

    /// The `object` type (`ELEMENT_TYPE_OBJECT` = 0x1C).
    ///
    /// Represents the root of the .NET type hierarchy. All reference and value types
    /// derive from `object` (System.Object). Can hold any .NET type.
    ///
    /// # Examples
    /// ```csharp
    /// public object Value = "Hello";      // String assigned to object
    /// public object Number = 42;          // Integer boxed to object
    /// public object GetAnyValue();        // Can return any type
    /// ```
    ///
    /// # Boxing and Unboxing
    /// - **Boxing**: Value types automatically converted to object references
    /// - **Unboxing**: Object references cast back to value types
    /// - **Performance**: Boxing creates heap allocations
    ///
    /// # Universal Container
    /// - Can store any .NET type
    /// - Enables polymorphic collections
    /// - Foundation for reflection operations
    /// - Base for all virtual method dispatch
    Object,

    /// Single-dimensional array type `T[]` (`ELEMENT_TYPE_SZARRAY` = 0x1D).
    ///
    /// Represents zero-indexed, single-dimensional arrays. The most common array type
    /// in .NET applications with optimized runtime support.
    ///
    /// # Examples
    /// ```csharp
    /// int[] numbers = new int[10];           // Integer array
    /// string[] names = {"Alice", "Bob"};     // String array  
    /// Person[] people = new Person[5];       // Reference type array
    /// ```
    ///
    /// # Characteristics
    /// - Always zero-indexed (starts at index 0)
    /// - Single dimension only
    /// - Optimized runtime implementation
    /// - Bounds checking at runtime
    /// - Covariance support for reference types
    ///
    /// # Performance
    /// - Faster than multi-dimensional arrays
    /// - Direct memory layout
    /// - CPU cache-friendly access patterns
    /// - Optimized runtime intrinsics
    ///
    /// # See Also
    /// - [`SignatureSzArray`]: Contains element type and custom modifiers
    /// - [`TypeSignature::Array`]: For multi-dimensional arrays
    SzArray(SignatureSzArray),

    /// Generic method parameter `M` (`ELEMENT_TYPE_MVAR` = 0x1E).
    ///
    /// Represents a generic type parameter defined on a method.
    /// The parameter is identified by its zero-based index in the method's generic parameter list.
    ///
    /// # Examples
    /// ```csharp
    /// public T Process<T, U>(T input, U context) {  // T is index 0, U is index 1
    ///     return input;                             // T referenced as index 0
    /// }
    /// ```
    ///
    /// # Method vs Type Parameters
    /// - **Method Parameters**: Defined on specific methods
    /// - **Type Parameters**: Defined on types (classes, structs, interfaces)
    /// - **Scope**: Method parameters only visible within the method
    /// - **Resolution**: Provided at method call site
    ///
    /// # Resolution Example
    /// ```csharp
    /// result = Process<string, int>("hello", 42);   // T=string, U=int
    /// ```
    ///
    /// # See Also
    /// - [`TypeSignature::GenericParamType`]: For type generic parameters
    GenericParamMethod(u32),

    /// Required custom modifier (`ELEMENT_TYPE_CMOD_REQD` = 0x1F).
    ///
    /// Represents required custom modifiers that are part of the type's identity.
    /// These modifiers affect type compatibility and must be understood by the runtime.
    ///
    /// # Examples
    /// ```csharp
    /// [MethodImpl(MethodImplOptions.Synchronized)]
    /// public void SynchronizedMethod();              // May use required modifiers
    ///
    /// const int ConstantValue = 42;                  // May use modreq(IsConst)
    /// ```
    ///
    /// # Common Required Modifiers
    /// - `IsConst`: For constant fields and values
    /// - `IsVolatile`: For volatile memory semantics
    /// - Platform-specific calling conventions
    /// - Interop type constraints
    /// - Security and verification annotations
    ///
    /// # Type Identity Impact
    /// Types with different required modifiers are considered different types
    /// for assignment compatibility and method resolution.
    ///
    /// # See Also
    /// - [`TypeSignature::ModifiedOptional`]: For optional modifiers
    ModifiedRequired(Vec<Token>),

    /// Optional custom modifier (`ELEMENT_TYPE_CMOD_OPT` = 0x20).
    ///
    /// Represents optional custom modifiers that provide additional information
    /// but don't affect type identity or compatibility. Safe to ignore if not understood.
    ///
    /// # Examples
    /// ```csharp
    /// // Compiler-generated modifiers for:
    /// public ref readonly int GetValue();            // May use modopt hints
    /// public async Task<int> CalculateAsync();       // May use modopt annotations
    /// ```
    ///
    /// # Common Optional Modifiers
    /// - Compiler-generated hints
    /// - Optimization annotations
    /// - Tool-specific metadata
    /// - Non-essential type information
    /// - Debugging and profiling hints
    ///
    /// # Compatibility
    /// Types with different optional modifiers are still considered compatible
    /// for assignment and method calls. Modifiers can be safely ignored.
    ///
    /// # See Also
    /// - [`TypeSignature::ModifiedRequired`]: For required modifiers
    ModifiedOptional(Vec<Token>),

    /// CLI-internal type (`ELEMENT_TYPE_INTERNAL` = 0x21).
    ///
    /// Represents types that are internal to the CLI implementation and not
    /// directly accessible to user code. Used for runtime implementation details.
    ///
    /// # Usage
    /// - Runtime internal data structures
    /// - JIT compiler temporary types
    /// - Garbage collector metadata
    /// - Implementation-specific optimizations
    ///
    /// # Characteristics
    /// - Not accessible from user code
    /// - Runtime and JIT implementation details
    /// - May vary between .NET implementations
    /// - Used for performance optimizations
    Internal,

    /// Modifier sentinel (`ELEMENT_TYPE_MODIFIER` = 0x22).
    ///
    /// Special marker used in signature encoding to indicate modified types.
    /// Part of the internal signature encoding mechanism.
    ///
    /// # Usage
    /// - Internal signature encoding
    /// - Modifier type resolution
    /// - Metadata parsing state machine
    /// - Binary signature format implementation
    ///
    /// # Implementation Detail
    /// This is primarily an implementation artifact of the signature encoding
    /// format and rarely appears in fully parsed signatures.
    Modifier,

    /// Variable argument sentinel (`ELEMENT_TYPE_SENTINEL` = 0x41).
    ///
    /// Special marker that separates fixed parameters from variable arguments
    /// in `vararg` method signatures. Indicates the start of optional parameters.
    ///
    /// # Examples
    /// ```csharp
    /// // P/Invoke method with varargs
    /// [DllImport("msvcrt")]
    /// public static extern int printf(string format, __arglist);
    /// ```
    ///
    /// # Vararg Processing
    /// - Marks transition from fixed to variable parameters
    /// - Used in P/Invoke and C-style vararg functions
    /// - Supports interop with C/C++ vararg functions
    /// - Runtime argument list processing
    ///
    /// # Usage Context
    /// Primarily used in:
    /// - Platform invoke (P/Invoke) signatures
    /// - C-style vararg function calls
    /// - Legacy COM interop scenarios
    Sentinel,

    /// Pinned reference type (`ELEMENT_TYPE_PINNED` = 0x45).
    ///
    /// Represents a reference that is pinned in memory, preventing the garbage
    /// collector from moving the referenced object. Used for unsafe code and interop.
    ///
    /// # Examples
    /// ```csharp
    /// fixed (byte* ptr = &array[0]) {    // Array pinned during fixed block
    ///     // ptr points to pinned memory
    ///     NativeMethod(ptr, array.Length);
    /// }
    /// ```
    ///
    /// # Pinning Characteristics
    /// - Prevents garbage collection of target object
    /// - Maintains stable memory addresses
    /// - Required for certain interop scenarios
    /// - Performance impact on GC
    /// - Limited scope and lifetime
    ///
    /// # Safety Considerations
    /// - Can cause memory fragmentation
    /// - Should be used minimally and briefly
    /// - Requires unsafe code context
    /// - Must ensure pinning scope doesn't exceed object lifetime
    ///
    /// # See Also
    /// - [`TypeSignature::Ptr`]: For unmanaged pointers
    /// - [`TypeSignature::ByRef`]: For managed references
    Pinned(Box<TypeSignature>),

    /// System.Type reference in custom attributes.
    ///
    /// Special encoding used within custom attribute value blobs to indicate
    /// that a parameter or field represents a `System.Type` value.
    ///
    /// # Usage Context
    /// - Custom attribute constructors with Type parameters
    /// - Attribute fields of Type type
    /// - Metadata encoding for reflection scenarios
    /// - Type references in attribute value serialization
    ///
    /// # Examples
    /// ```csharp
    /// [MyAttribute(typeof(string))]          // Type parameter in attribute
    /// public class Example {
    ///     [MyAttribute(TargetType = typeof(int))]  // Type property in attribute
    ///     public void Method() { }
    /// }
    /// ```
    Type,

    /// Boxed value type in custom attributes.
    ///
    /// Special encoding used within custom attribute value blobs to indicate
    /// that a value type has been boxed to an object reference.
    ///
    /// # Boxing in Attributes
    /// - Value types stored as object references
    /// - Enables polymorphic attribute parameters
    /// - Preserves type information at runtime
    /// - Used with object-typed attribute parameters
    ///
    /// # Examples
    /// ```csharp
    /// [MyAttribute(42)]              // int boxed to object parameter
    /// [MyAttribute(3.14)]            // double boxed to object parameter
    /// ```
    Boxed,

    /// Reserved type slot.
    ///
    /// Placeholder for future extension or internal use. Not currently
    /// used in standard .NET metadata but reserved for potential future features.
    ///
    /// # Usage
    /// - Future specification extensions
    /// - Vendor-specific type encodings
    /// - Experimental type system features
    /// - Implementation-specific markers
    Reserved,

    /// Field reference in custom attributes.
    ///
    /// Special encoding used within custom attribute value blobs to indicate
    /// that a parameter represents a field reference.
    ///
    /// # Usage Context
    /// - Custom attributes with field references
    /// - Reflection-based attribute processing
    /// - Metadata analysis tools
    /// - Field-based configuration attributes
    ///
    /// # Examples
    /// ```csharp
    /// [FieldAttribute("FieldName")]     // String identifying a field
    /// public class Example { }
    /// ```
    Field,
}

/// Multi-dimensional array signature with bounds and dimension information.
///
/// Represents arrays with one or more dimensions according to ECMA-335 Section II.23.2.13.
/// Supports rectangular arrays, jagged arrays, and arrays with custom lower bounds.
/// Unlike single-dimensional arrays ([`SignatureSzArray`]), these arrays can have
/// non-zero lower bounds and explicit size specifications.
///
/// # Array Types Supported
///
/// ## Rectangular Arrays
/// Arrays where all dimensions have the same bounds structure:
/// ```csharp
/// int[,] matrix = new int[3, 4];        // 2D: 3×4 matrix  
/// string[,,] cube = new string[2,3,4];  // 3D: 2×3×4 cube
/// ```
///
/// ## Arrays with Custom Bounds
/// Arrays that don't start at index 0:
/// ```csharp
/// int[,] bounded = new int[1..5, 2..8]; // Bounds: [1-4, 2-7]
/// ```
///
/// ## Variable-Sized Dimensions
/// Arrays where only some dimensions have size specifications:
/// ```csharp
/// // Implementation-specific: some dimensions sized, others not
/// ```
///
/// # Binary Format (ECMA-335)
///
/// Multi-dimensional arrays are encoded as:
/// ```text
/// ARRAY <type> <rank> <numSizes> <size>* <numLoBounds> <loBound>*
/// ```
///
/// Where:
/// - `<type>`: Element type signature
/// - `<rank>`: Number of dimensions
/// - `<numSizes>`: Number of size specifications provided
/// - `<size>*`: Size for each specified dimension
/// - `<numLoBounds>`: Number of lower bound specifications
/// - `<loBound>*`: Lower bound for each specified dimension
///
/// # Memory Layout
///
/// Multi-dimensional arrays use row-major order storage:
/// ```text
/// int[,] array = new int[2,3];
/// // Memory: [0,0] [0,1] [0,2] [1,0] [1,1] [1,2]
/// ```
///
/// # Examples
///
/// ## 2D Matrix Creation
/// ```rust
/// use dotscope::metadata::signatures::{SignatureArray, TypeSignature};
/// use dotscope::metadata::typesystem::ArrayDimensions;
///
/// # fn create_2d_matrix() {
/// let matrix_signature = SignatureArray {
///     base: Box::new(TypeSignature::I4),  // int elements
///     rank: 2,                            // 2 dimensions
///     dimensions: vec![
///         ArrayDimensions { size: Some(3), lower_bound: Some(0) }, // [0..2]
///         ArrayDimensions { size: Some(4), lower_bound: Some(0) }, // [0..3]
///     ],
/// };
/// # }
/// ```
///
/// ## Custom Bounds Array
/// ```rust
/// use dotscope::metadata::signatures::{SignatureArray, TypeSignature};
/// use dotscope::metadata::typesystem::ArrayDimensions;
///
/// # fn create_custom_bounds() {
/// let custom_array = SignatureArray {
///     base: Box::new(TypeSignature::String),
///     rank: 2,
///     dimensions: vec![
///         ArrayDimensions { size: Some(5), lower_bound: Some(1) }, // [1..5]
///         ArrayDimensions { size: Some(6), lower_bound: Some(2) }, // [2..7]
///     ],
/// };
/// # }
/// ```
///
/// # Dimension Information
///
/// The `dimensions` vector can contain fewer entries than `rank`:
/// - Missing dimensions are assumed to have default bounds (0-based, no size limit)
/// - Size specifications enable compile-time bounds checking
/// - Lower bound specifications support non-zero indexed arrays
///
/// # Runtime Behavior
///
/// - **Bounds Checking**: Runtime validates all array access operations
/// - **Exception Handling**: `IndexOutOfRangeException` for invalid indices  
/// - **Memory Management**: Garbage collected like all managed arrays
/// - **Type Safety**: Element type enforced at runtime
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.13 (Array signature)
/// and supports all standard multi-dimensional array scenarios defined in the specification.
///
/// # See Also
/// - [`SignatureSzArray`]: For single-dimensional arrays (more efficient)
/// - [`crate::metadata::typesystem::ArrayDimensions`]: For dimension specification details
/// - [`TypeSignature::Array`]: The type signature variant that contains this struct
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureArray {
    /// The type of elements stored in the array.
    ///
    /// Can be any valid .NET type including:
    /// - Primitive types (`int`, `string`, `bool`)
    /// - Reference types (classes, interfaces)
    /// - Value types (structs, enums)  
    /// - Other array types (creating jagged arrays)
    /// - Generic instantiations (`List<T>`)
    /// - Pointers and references
    pub base: Box<TypeSignature>,

    /// The number of dimensions in the array.
    ///
    /// - **1**: Single-dimensional (but prefer [`SignatureSzArray`] for efficiency)
    /// - **2**: Two-dimensional (matrices, tables)
    /// - **3+**: Multi-dimensional (cubes, hypercubes)
    ///
    /// # Practical Limits
    /// - .NET supports up to 32 dimensions theoretically
    /// - Performance degrades significantly beyond 3-4 dimensions
    /// - Most applications use 1-3 dimensions
    pub rank: u32,

    /// Dimension specifications for size and bounds information.
    ///
    /// This vector can be shorter than `rank`, in which case missing dimensions
    /// use default specifications (zero lower bound, no explicit size).
    ///
    /// # Dimension Specification Rules
    /// - **Size**: Upper bound for the dimension (0 means unlimited)
    /// - **Lower Bound**: Starting index for the dimension (default is 0)
    /// - **Order**: Dimensions are specified in declaration order
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::typesystem::ArrayDimensions;
    ///
    /// // Standard zero-based dimensions
    /// let standard = vec![
    ///     ArrayDimensions { size: Some(10), lower_bound: None },    // [0..9]
    ///     ArrayDimensions { size: Some(20), lower_bound: None },    // [0..19]
    /// ];
    ///
    /// // Custom bounds
    /// let custom = vec![
    ///     ArrayDimensions { size: Some(5), lower_bound: Some(1) },  // [1..5]
    ///     ArrayDimensions { size: None, lower_bound: Some(10) },   // [10..∞]
    /// ];
    /// ```
    pub dimensions: Vec<ArrayDimensions>,
}

/// Single-dimensional array signature with custom modifiers.
///
/// Represents the most common array type in .NET applications: zero-indexed,
/// single-dimensional arrays (e.g., `int[]`, `string[]`). These arrays are
/// optimized by the runtime for performance and are the preferred array type
/// for most scenarios.
///
/// # Array Characteristics
///
/// ## Zero-Indexed
/// Always starts at index 0, unlike multi-dimensional arrays which can have
/// custom lower bounds:
/// ```csharp
/// int[] numbers = new int[10];  // Indices: 0, 1, 2, ..., 9
/// ```
///
/// ## Single Dimension Only
/// Can only represent one-dimensional arrays. For multi-dimensional arrays,
/// use [`SignatureArray`] instead:
/// ```csharp
/// int[] valid;      // Single-dimensional ✓
/// int[,] invalid;   // Multi-dimensional ✗ (use SignatureArray)
/// ```
///
/// ## Runtime Optimization
/// Single-dimensional arrays receive special optimization treatment:
/// - Faster element access (no dimension calculations)
/// - Better CPU cache utilization
/// - Specialized runtime intrinsics
/// - More efficient memory layout
///
/// # Custom Modifiers
///
/// The `modifiers` field supports advanced scenarios requiring type annotations:
///
/// ## Common Modifier Uses
/// - **Interop Constraints**: Platform-specific array requirements
/// - **Memory Semantics**: Volatile or const array declarations
/// - **Security Annotations**: Type-based security attributes
/// - **Tool Metadata**: Compiler or analyzer hints
///
/// ## Modifier Examples
/// ```csharp
/// // These might generate custom modifiers:
/// public volatile int[] VolatileArray;        // modopt(IsVolatile)
/// public const string[] ConstantArray;        // modreq(IsConst)
/// ```
///
/// # Binary Format (ECMA-335)
///
/// Single-dimensional arrays are encoded as:
/// ```text
/// SZARRAY [CustomMod*] <type>
/// ```
///
/// Where:
/// - `SZARRAY`: Element type constant (0x1D)
/// - `[CustomMod*]`: Optional custom modifier sequence
/// - `<type>`: Element type signature
///
///
/// # Examples
///
/// ## Simple Array Type
/// ```rust
/// use dotscope::metadata::signatures::{SignatureSzArray, TypeSignature};
///
/// # fn create_int_array() {
/// let int_array = SignatureSzArray {
///     modifiers: vec![],                    // No custom modifiers
///     base: Box::new(TypeSignature::I4),   // int[] array
/// };
/// # }
/// ```
///
/// ## Array with Custom Modifiers
/// ```rust
/// use dotscope::metadata::signatures::{SignatureSzArray, TypeSignature};
/// use dotscope::metadata::token::Token;
///
/// # fn create_modified_array() {
/// let modified_array = SignatureSzArray {
///     modifiers: vec![
///         Token::new(0x02000001),  // Custom modifier token
///     ],
///     base: Box::new(TypeSignature::String),  // string[] with modifier
/// };
/// # }
/// ```
///
/// ## Generic Element Arrays
/// ```rust
/// use dotscope::metadata::signatures::{SignatureSzArray, TypeSignature};
///
/// # fn create_generic_array() {
/// // List<int>[] - array of generic lists
/// let generic_element_array = SignatureSzArray {
///     modifiers: vec![],
///     base: Box::new(TypeSignature::GenericInst(
///         Box::new(TypeSignature::Class(dotscope::metadata::token::Token::new(0x02000001))), // List<T>
///         vec![TypeSignature::I4],  // Type argument: int
///     )),
/// };
/// # }
/// ```
///
/// # Jagged vs Rectangular Arrays
///
/// Single-dimensional arrays enable jagged array creation:
/// ```csharp
/// // Jagged array: array of arrays (each sub-array can have different length)
/// int[][] jaggedArray = new int[3][];      // SignatureSzArray<SignatureSzArray<I4>>
/// jaggedArray[0] = new int[4];
/// jaggedArray[1] = new int[2];
/// jaggedArray[2] = new int[6];
///
/// // Rectangular array: fixed dimensions (all rows same length)
/// int[,] rectangularArray = new int[3,4];  // SignatureArray with rank=2
/// ```
///
/// # Runtime Behavior
///
/// - **Bounds Checking**: Automatic index validation
/// - **Exception Handling**: `IndexOutOfRangeException` for invalid indices
/// - **Memory Management**: Garbage collected automatically
/// - **Type Safety**: Element type enforced at runtime and compile time
/// - **Null Safety**: Arrays themselves can be null, elements follow type rules
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.12 (Single-dimensional
/// array signature) and provides full compatibility with .NET array semantics.
///
/// # See Also
/// - [`SignatureArray`]: For multi-dimensional arrays with custom bounds
/// - [`TypeSignature::SzArray`]: The type signature variant that contains this struct
/// - [`crate::metadata::token::Token`]: For custom modifier token references
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureSzArray {
    /// Custom modifiers that apply to the array type.
    ///
    /// A vector of metadata tokens referencing `TypeDef` or `TypeRef` entries
    /// that specify additional type constraints or annotations. Most arrays
    /// have no custom modifiers (empty vector).
    ///
    /// # Modifier Types
    /// - **Required Modifiers**: Must be understood for type compatibility
    /// - **Optional Modifiers**: Can be safely ignored if not recognized
    /// - **Platform Modifiers**: OS or architecture-specific constraints
    /// - **Tool Modifiers**: Compiler or analyzer metadata
    ///
    /// # Common Scenarios
    /// - Interop with native arrays requiring specific memory layout
    /// - Volatile arrays for multithreaded scenarios
    /// - Const arrays for immutable data
    /// - Security attributes for trusted/untrusted data
    pub modifiers: Vec<Token>,

    /// The type of elements stored in the array.
    ///
    /// Can be any valid .NET type, enabling arrays of:
    /// - **Primitives**: `int[]`, `double[]`, `bool[]`
    /// - **Strings**: `string[]` (very common)
    /// - **Objects**: `object[]` (can hold any type)
    /// - **Classes**: `Person[]`, `Customer[]`
    /// - **Structs**: `Point[]`, `DateTime[]`
    /// - **Generics**: `List<T>[]`, `Dictionary<K,V>[]`
    /// - **Arrays**: `int[][]` (jagged arrays)
    /// - **Pointers**: `int*[]` (arrays of pointers)
    ///
    /// # Type Safety
    /// The runtime enforces that all elements are assignment-compatible
    /// with the base type, including:
    /// - Exact type matches
    /// - Inheritance relationships (derived types to base arrays)
    /// - Interface implementations
    /// - Generic type parameter constraints
    pub base: Box<TypeSignature>,
}

/// Unmanaged pointer signature with custom modifiers.
///
/// Represents pointer types that directly reference unmanaged memory locations.
/// Used primarily in unsafe code scenarios, platform invoke (P/Invoke) operations,
/// and interoperability with native libraries.
///
/// # Pointer Characteristics
///
/// ## Unmanaged Memory
/// Pointers reference memory that is not managed by the .NET garbage collector:
/// - Manual memory management required
/// - No automatic bounds checking
/// - Direct memory address arithmetic
/// - Potential for memory corruption if misused
///
/// ## Type Safety
/// While pointers bypass many .NET safety features, they maintain type information:
/// ```csharp
/// int* intPtr;      // Points to int values
/// char* charPtr;    // Points to char values  
/// void* voidPtr;    // Points to untyped memory
/// ```
///
/// ## Unsafe Context Required
/// Pointer operations require unsafe code context:
/// ```csharp
/// unsafe {
///     int value = 42;
///     int* ptr = &value;          // Address-of operator
///     int result = *ptr;          // Dereference operator
/// }
/// ```
///
/// # Custom Modifiers for Pointers
///
/// Custom modifiers provide additional type information for advanced scenarios:
///
/// ## Common Pointer Modifiers
/// - **Calling Conventions**: Function pointer calling conventions
/// - **Memory Semantics**: Volatile, const, restrict annotations
/// - **Platform Constraints**: OS-specific pointer requirements
/// - **Interop Metadata**: Native library compatibility information
///
/// ## Example Modifier Uses
/// ```csharp
/// // These might generate custom modifiers:
/// const int* constPtr;               // modreq(IsConst)
/// volatile char* volatilePtr;        // modopt(IsVolatile)
/// ```
///
/// # Binary Format (ECMA-335)
///
/// Pointer signatures are encoded as:
/// ```text
/// PTR [CustomMod*] <type>
/// ```
///
/// Where:
/// - `PTR`: Element type constant (0x0F)
/// - `[CustomMod*]`: Optional custom modifier sequence
/// - `<type>`: Pointed-to type signature
///
/// # Pointer Arithmetic
///
/// Pointers support arithmetic operations for memory navigation:
/// ```csharp
/// unsafe {
///     int[] array = {1, 2, 3, 4, 5};
///     fixed (int* ptr = array) {
///         int* current = ptr;
///         int* next = current + 1;     // Points to next int
///         int* offset = ptr + 3;       // Points to array[3]
///     }
/// }
/// ```
///
/// # Safety Considerations
///
/// ## Memory Safety
/// - **Dangling Pointers**: Pointing to freed or invalid memory
/// - **Buffer Overflows**: Accessing memory beyond allocated bounds
/// - **Type Confusion**: Casting pointers to incompatible types
/// - **Memory Leaks**: Forgetting to free allocated memory
///
/// ## Best Practices
/// - Minimize pointer usage scope
/// - Use `fixed` statements for managed memory access
/// - Validate pointer arithmetic bounds
/// - Consider `Span<T>` and `Memory<T>` as safer alternatives
///
/// # Examples
///
/// ## Simple Pointer Type
/// ```rust
/// use dotscope::metadata::signatures::{SignaturePointer, TypeSignature};
///
/// # fn create_int_pointer() {
/// let int_pointer = SignaturePointer {
///     modifiers: vec![],                    // No custom modifiers
///     base: Box::new(TypeSignature::I4),   // int* pointer
/// };
/// # }
/// ```
///
/// ## Void Pointer
/// ```rust
/// use dotscope::metadata::signatures::{SignaturePointer, TypeSignature};
///
/// # fn create_void_pointer() {
/// let void_pointer = SignaturePointer {
///     modifiers: vec![],
///     base: Box::new(TypeSignature::Void),  // void* pointer
/// };
/// # }
/// ```
///
/// ## Pointer with Custom Modifiers
/// ```rust
/// use dotscope::metadata::signatures::{SignaturePointer, TypeSignature};
/// use dotscope::metadata::token::Token;
///
/// # fn create_modified_pointer() {
/// let const_pointer = SignaturePointer {
///     modifiers: vec![
///         Token::new(0x02000001),  // const modifier token
///     ],
///     base: Box::new(TypeSignature::Char),  // const char* pointer
/// };
/// # }
/// ```
///
/// ## Function Pointer
/// Function pointers are represented differently using [`TypeSignature::FnPtr`],
/// but they share similar safety and usage characteristics:
/// ```csharp
/// delegate* unmanaged<int, int, int> funcPtr;  // Function pointer type
/// ```
///
/// # Platform Invoke (P/Invoke)
///
/// Pointers are essential for P/Invoke operations:
/// ```csharp
/// [DllImport("kernel32.dll")]
/// public static extern IntPtr VirtualAlloc(
///     IntPtr lpAddress,        // Pointer parameter
///     UIntPtr dwSize,
///     uint flAllocationType,
///     uint flProtect);
/// ```
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.11 (Pointer signature)
/// and supports all standard pointer scenarios defined in the specification.
///
/// # See Also
/// - [`TypeSignature::Ptr`]: The type signature variant that contains this struct
/// - [`TypeSignature::ByRef`]: For managed references (safer alternative)
/// - [`TypeSignature::FnPtr`]: For function pointers
/// - [`crate::metadata::token::Token`]: For custom modifier token references
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignaturePointer {
    /// Custom modifiers that apply to the pointer type.
    ///
    /// A vector of metadata tokens referencing `TypeDef` or `TypeRef` entries
    /// that specify additional constraints or annotations for the pointer.
    /// Most pointers have no custom modifiers (empty vector).
    ///
    /// # Modifier Applications
    /// - **Memory Semantics**: `const`, `volatile`, `restrict` equivalents
    /// - **Platform Constraints**: OS-specific pointer requirements
    /// - **Calling Conventions**: Function pointer calling conventions
    /// - **Safety Annotations**: Tool-specific safety metadata
    ///
    /// # Interop Scenarios
    /// Custom modifiers are particularly important for P/Invoke and COM interop
    /// where native calling conventions and memory semantics must be preserved.
    pub modifiers: Vec<Token>,

    /// The type that this pointer references.
    ///
    /// Can be any valid .NET type, though some combinations are more common:
    /// - **Primitive Types**: `int*`, `char*`, `double*`
    /// - **Void Pointers**: `void*` for untyped memory
    /// - **Struct Pointers**: Pointers to value types
    /// - **Nested Pointers**: `int**` (pointer to pointer)
    /// - **Array Pointers**: Pointers to array elements
    ///
    /// # Special Cases
    /// - **Void Pointers**: Used for generic memory operations
    /// - **Function Pointers**: Use [`TypeSignature::FnPtr`] instead
    /// - **Managed References**: Use [`TypeSignature::ByRef`] for safety
    ///
    /// # Type Compatibility
    /// Pointer types are compatible based on their pointed-to types:
    /// - Exact type matches are always compatible
    /// - `void*` can convert to/from any pointer type
    /// - Related types may be compatible with explicit casting
    pub base: Box<TypeSignature>,
}

/// Method parameter signature with modifiers and reference semantics.
///
/// Represents a single parameter or return type in method signatures, property
/// signatures, and other callable member definitions. Includes support for
/// custom modifiers, by-reference semantics, and all .NET parameter types.
///
/// # Parameter Categories
///
/// ## Value Parameters
/// Standard pass-by-value semantics where the parameter receives a copy:
/// ```csharp
/// public void Method(int value)           // Value parameter
/// public void Method(string text)         // Reference type, but passed by value
/// ```
///
/// ## Reference Parameters  
/// Pass-by-reference semantics using `ref`, `out`, or `in` keywords:
/// ```csharp
/// public void Method(ref int value)       // Bidirectional reference
/// public void Method(out int result)      // Output-only reference  
/// public void Method(in DateTime time)    // Read-only reference
/// ```
///
/// ## Return Types
/// Method return types use the same parameter structure:
/// ```csharp
/// public int GetValue()                   // Value return
/// public ref int GetReference()           // Reference return
/// ```
///
/// # Custom Modifiers for Parameters
///
/// Parameters can have custom modifiers for advanced scenarios:
///
/// ## Common Parameter Modifiers
/// - **Calling Conventions**: Platform-specific parameter passing
/// - **Marshalling Hints**: Interop type conversion guidance
/// - **Optimization Annotations**: Compiler optimization hints
/// - **Security Metadata**: Parameter validation requirements
///
/// ## Example Modifier Uses
/// ```csharp
/// // These might generate custom modifiers:
/// [MarshalAs(UnmanagedType.LPStr)]
/// public void Method(string text);        // Marshalling modifier
///
/// [In, Out]
/// public void Method(ref byte[] buffer);  // Directional modifiers
/// ```
///
/// # Binary Format (ECMA-335)
///
/// Parameters are encoded as:
/// ```text
/// [CustomMod*] [BYREF] <type>
/// ```
///
/// Where:
/// - `[CustomMod*]`: Optional custom modifier sequence
/// - `[BYREF]`: Optional reference semantics marker (0x10)
/// - `<type>`: Parameter type signature
///
/// # Reference Semantics Details
///
/// ## `ref` Parameters (`by_ref = true`)
/// - **Initialization**: Must be initialized before passing
/// - **Direction**: Input and output
/// - **Null Safety**: Cannot pass null references
/// - **Lifetime**: Reference must not outlive the referenced object
///
/// ## `out` Parameters (`by_ref = true` with attribute)
/// - **Initialization**: Does not need to be initialized before passing
/// - **Direction**: Output only
/// - **Assignment**: Must be assigned before method returns
/// - **Compiler Checking**: Definite assignment analysis
///
/// ## `in` Parameters (`by_ref = true` with attribute)
/// - **Read-Only**: Cannot modify the referenced value
/// - **Performance**: Avoids copying large value types
/// - **Safety**: Compiler prevents modification
/// - **Implicit**: Can be called with value arguments
///
/// # Examples
///
/// ## Simple Value Parameter
/// ```rust
/// use dotscope::metadata::signatures::{SignatureParameter, TypeSignature};
///
/// # fn create_value_parameter() {
/// let int_param = SignatureParameter {
///     modifiers: vec![],                    // No custom modifiers
///     by_ref: false,                        // Pass by value
///     base: TypeSignature::I4,             // int parameter
/// };
/// # }
/// ```
///
/// ## Reference Parameter
/// ```rust
/// use dotscope::metadata::signatures::{SignatureParameter, TypeSignature};
///
/// # fn create_ref_parameter() {
/// let ref_param = SignatureParameter {
///     modifiers: vec![],
///     by_ref: true,                         // Pass by reference
///     base: TypeSignature::String,         // ref string parameter
/// };
/// # }
/// ```
///
/// ## Parameter with Custom Modifiers
/// ```rust
/// use dotscope::metadata::signatures::{SignatureParameter, TypeSignature};
/// use dotscope::metadata::token::Token;
///
/// # fn create_modified_parameter() {
/// let marshalled_param = SignatureParameter {
///     modifiers: vec![
///         Token::new(0x02000001),  // Marshalling modifier
///     ],
///     by_ref: false,
///     base: TypeSignature::String,         // String with marshalling info
/// };
/// # }
/// ```
///
/// ## Complex Return Type
/// ```rust
/// use dotscope::metadata::signatures::{SignatureParameter, TypeSignature};
///
/// # fn create_complex_return() {
/// // Return type: ref List<int>
/// let return_type = SignatureParameter {
///     modifiers: vec![],
///     by_ref: true,                         // Reference return
///     base: TypeSignature::GenericInst(
///         Box::new(TypeSignature::Class(dotscope::metadata::token::Token::new(0x02000001))), // List<T>
///         vec![TypeSignature::I4],          // Type argument: int
///     ),
/// };
/// # }
/// ```
///
/// # Compatibility Rules
///
/// Parameter compatibility follows .NET type system rules:
/// - **Exact Matches**: Always compatible
/// - **Inheritance**: Derived types compatible with base parameter types
/// - **Interfaces**: Implementing types compatible with interface parameters
/// - **Generics**: Type arguments must satisfy constraints
/// - **References**: Reference types must match exactly
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.10 (Parameter signature)
/// and supports all standard parameter scenarios defined in the specification.
///
/// # See Also
/// - [`SignatureMethod`]: Contains parameter lists for complete method signatures
/// - [`SignatureProperty`]: Uses parameters for indexed property signatures
/// - [`crate::metadata::token::Token`]: For custom modifier token references
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureParameter {
    /// Custom modifiers that apply to this parameter.
    ///
    /// A vector of metadata tokens referencing `TypeDef` or `TypeRef` entries
    /// that specify additional constraints or annotations. Most parameters
    /// have no custom modifiers (empty vector).
    ///
    /// # Modifier Types
    /// - **Marshalling**: How to convert between managed and native types
    /// - **Validation**: Parameter validation requirements
    /// - **Optimization**: Hints for compiler optimizations
    /// - **Platform**: OS or architecture-specific constraints
    ///
    /// # Common Scenarios
    /// - P/Invoke parameter marshalling specifications
    /// - COM interop calling convention requirements
    /// - Security annotations for parameter validation
    /// - Tool-specific metadata for static analysis
    pub modifiers: Vec<Token>,

    /// Whether this parameter uses reference semantics.
    ///
    /// When `true`, indicates that the parameter is passed by reference
    /// using `ref`, `out`, or `in` keywords in C#. The exact semantics
    /// are typically specified through attributes or calling context.
    ///
    /// # Reference Semantics
    /// - **Performance**: Avoids copying large value types
    /// - **Aliasing**: Parameter becomes an alias to the original variable
    /// - **Lifetime**: Reference must not outlive the referenced object
    /// - **Safety**: Managed references are GC-safe, unlike pointers
    ///
    /// # Usage Patterns
    /// - `ref`: Bidirectional parameter modification
    /// - `out`: Output parameter that must be assigned
    /// - `in`: Read-only reference for performance
    /// - Return values: Reference returns for efficient access
    pub by_ref: bool,

    /// The type of this parameter or return value.
    ///
    /// Can be any valid .NET type including:
    /// - **Primitives**: `int`, `double`, `bool`, `char`
    /// - **Objects**: `string`, `object`, custom classes
    /// - **Value Types**: `DateTime`, `Guid`, custom structs
    /// - **Generics**: `List<T>`, `Dictionary<K,V>`, type parameters
    /// - **Arrays**: `int[]`, `string[,]`, jagged arrays
    /// - **Special Types**: `void` (return only), `TypedByRef`
    ///
    /// # Type Constraints
    /// The type must be valid for the parameter context:
    /// - Return types can be `void`
    /// - Reference parameters have additional lifetime constraints
    /// - Generic parameters must satisfy type constraints
    /// - Pointer types require unsafe context
    pub base: TypeSignature,
}

/// Method signature with calling conventions, parameters, and return types.
///
/// Represents complete method signatures according to ECMA-335 Section II.23.2.1.
/// Encodes all aspects of method declarations including calling conventions,
/// parameter types, return types, generic parameters, and variable arguments.
///
/// # Method Signature Components
///
/// ## Calling Conventions
/// Different calling conventions determine how parameters are passed and
/// how the call stack is managed:
/// - **Instance Methods**: `has_this = true` for methods that receive an instance
/// - **Static Methods**: `has_this = false` for class-level methods
/// - **Explicit This**: `explicit_this = true` when `this` is explicitly declared
/// - **Variable Arguments**: `vararg = true` for methods with `params` arrays
///
/// ## Native Calling Conventions
/// Platform-specific conventions for interop scenarios:
/// - **C Declaration**: `cdecl = true` for C-style calls (caller cleans stack)
/// - **Standard Call**: `stdcall = true` for Win32 API calls (callee cleans stack)
/// - **This Call**: `thiscall = true` for C++ instance methods
/// - **Fast Call**: `fastcall = true` for optimized register-based calls
///
/// ## Generic Parameters
/// Support for generic method declarations:
/// - **Generic Count**: `param_count_generic` specifies number of type parameters
/// - **Type Constraints**: Specified in separate metadata tables
/// - **Instantiation**: Actual types provided at call sites
///
/// # Binary Format (ECMA-335)
///
/// Method signatures are encoded in compressed binary format:
/// ```text
/// MethodSig ::= [[HASTHIS] [EXPLICITTHIS]] [DEFAULT] [VARARG | GENERIC GenParamCount]
///               ParamCount RetType Param*
/// ```
///
/// # Examples
///
/// ## Instance Method
/// ```rust
/// use dotscope::metadata::signatures::{SignatureMethod, SignatureParameter, TypeSignature};
///
/// # fn create_instance_method() {
/// let instance_method = SignatureMethod {
///     has_this: true,              // Instance method
///     explicit_this: false,        // Implicit this parameter
///     default: true,               // Default calling convention
///     vararg: false,               // Fixed parameter count
///     param_count_generic: 0,      // No generic parameters
///     param_count: 2,              // Two parameters
///     return_type: SignatureParameter {
///         modifiers: vec![],
///         by_ref: false,
///         base: TypeSignature::Void,
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
///             base: TypeSignature::I4,
///         },
///     ],
///     varargs: vec![],
///     ..Default::default()
///     };
/// # }
/// ```
///
/// ## Generic Method
/// ```rust
/// use dotscope::metadata::signatures::{SignatureMethod, SignatureParameter, TypeSignature};
///
/// # fn create_generic_method() {
/// let generic_method = SignatureMethod {
///     has_this: false,             // Static method
///     param_count_generic: 1,      // One generic parameter <T>
///     param_count: 1,              // One regular parameter
///     return_type: SignatureParameter {
///         modifiers: vec![],
///         by_ref: false,
///         base: TypeSignature::GenericParamMethod(0), // Return T
///     },
///     params: vec![
///         SignatureParameter {
///             modifiers: vec![],
///             by_ref: false,
///             base: TypeSignature::GenericParamMethod(0), // Parameter T
///         },
///     ],
///     ..Default::default()
/// };
/// # }
/// ```
///
/// ## P/Invoke Method
/// ```rust
/// use dotscope::metadata::signatures::{SignatureMethod, SignatureParameter, TypeSignature};
///
/// # fn create_pinvoke_method() {
/// let pinvoke_method = SignatureMethod {
///     has_this: false,             // Static P/Invoke
///     stdcall: true,               // Win32 calling convention
///     param_count: 1,
///     return_type: SignatureParameter {
///         modifiers: vec![],
///         by_ref: false,
///         base: TypeSignature::I4,  // Win32 BOOL
///     },
///     params: vec![
///         SignatureParameter {
///             modifiers: vec![],      // May include marshalling modifiers
///             by_ref: false,
///             base: TypeSignature::String, // LPWSTR
///         },
///     ],
///     ..Default::default()
/// };
/// # }
/// ```
///
/// # Thread Safety
///
/// `SignatureMethod` is immutable after construction and safe to share between
/// threads. The contained type signatures and parameters follow the same safety model.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.1 (`MethodDefSig`)
/// and supports all standard method signature scenarios defined in the specification.
///
/// # See Also
/// - [`SignatureParameter`]: For individual parameter definitions
/// - [`TypeSignature`]: For supported type representations
/// - [`crate::metadata::method::Method`]: For complete method metadata
/// - [`crate::metadata::token::Token`]: For metadata token references
#[derive(Debug, Clone, PartialEq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SignatureMethod {
    /// Whether this method has an implicit `this` parameter.
    ///
    /// When `true`, indicates that this is an instance method that receives
    /// an implicit `this` parameter as its first argument. The `this` parameter
    /// is not included in the `param_count` or `params` vector.
    ///
    /// # Method Types
    /// - **Instance Methods**: `has_this = true` for virtual, non-virtual instance methods
    /// - **Static Methods**: `has_this = false` for class-level methods
    /// - **Constructors**: `has_this = true` (receive uninitialized `this`)
    /// - **Extension Methods**: `has_this = false` (static methods with special syntax)
    ///
    /// # Runtime Behavior
    /// When `has_this` is true, the runtime automatically:
    /// - Passes the instance as the first argument
    /// - Performs null checking (except for constructors)
    /// - Enables virtual method dispatch
    /// - Provides access to instance fields and methods
    pub has_this: bool,
    /// Whether the `this` parameter is explicitly declared in the signature.
    ///
    /// When `true`, indicates that the `this` parameter appears explicitly
    /// in the method signature rather than being implicit. This is used in
    /// advanced scenarios like function pointers to instance methods.
    ///
    /// # Usage Scenarios
    /// - **Function Pointers**: When creating delegates to instance methods
    /// - **Reflection**: For methods obtained through reflection APIs
    /// - **Advanced Interop**: When explicit control over `this` is needed
    /// - **Code Generation**: When emitting methods with explicit `this`
    ///
    /// # Relationship to `has_this`
    /// Both `has_this` and `explicit_this` can be true simultaneously:
    /// - `has_this = true, explicit_this = false`: Normal instance method
    /// - `has_this = true, explicit_this = true`: Explicit `this` instance method
    /// - `has_this = false`: Static method (`explicit_this` must be false)
    pub explicit_this: bool,
    /// Whether this method uses the default managed calling convention.
    ///
    /// When `true`, indicates that the method uses the standard .NET managed
    /// calling convention. This is the most common calling convention for
    /// regular managed methods.
    ///
    /// # Default Calling Convention
    /// The default convention includes:
    /// - **Stack Management**: Callee cleans the stack
    /// - **Parameter Order**: Left-to-right parameter passing
    /// - **Return Values**: Returned in standard locations (register/stack)
    /// - **Exception Handling**: Full structured exception handling support
    ///
    /// # Alternative Conventions
    /// When `default = false`, one of the native calling conventions
    /// (`cdecl`, `stdcall`, `thiscall`, `fastcall`) should be true.
    ///
    /// # Performance
    /// Default calling convention is optimized for managed code and provides
    /// the best performance for regular .NET method calls.
    pub default: bool,
    /// Whether this method accepts variable arguments (varargs).
    ///
    /// When `true`, indicates that the method can accept a variable number
    /// of arguments beyond the fixed parameters specified in `params`.
    /// The additional arguments are stored in the `varargs` vector.
    ///
    /// # Varargs Support
    /// Variable arguments enable methods like:
    /// - **Printf-style**: `Console.WriteLine(string format, params object[] args)`
    /// - **Flexible APIs**: Methods that accept varying parameter counts
    /// - **Legacy Interop**: Integration with C-style varargs functions
    ///
    /// # Parameter Structure
    /// When `vararg = true`:
    /// - `params`: Contains the fixed parameters
    /// - `varargs`: Contains the variable parameter types
    /// - Runtime: Additional arguments must match varargs types
    ///
    /// # Type Safety
    /// Unlike C-style varargs, .NET varargs maintain type safety:
    /// - Each vararg has a specific type
    /// - Runtime validates argument types
    /// - No silent type conversions
    pub vararg: bool,
    /// Whether this method uses the C declaration calling convention.
    ///
    /// When `true`, indicates that the method uses the C language calling
    /// convention where the caller is responsible for cleaning up the stack.
    /// Primarily used for P/Invoke scenarios with C libraries.
    ///
    /// # C Calling Convention Characteristics
    /// - **Stack Cleanup**: Caller removes parameters from stack
    /// - **Parameter Order**: Right-to-left parameter pushing
    /// - **Varargs Support**: Full support for variable arguments
    /// - **Compatibility**: Compatible with most C libraries
    ///
    /// # Performance Implications
    /// - Slightly higher overhead due to caller cleanup
    /// - Better support for variable argument functions
    /// - Required for some legacy C library interop
    pub cdecl: bool,
    /// Whether this method uses the standard call calling convention.
    ///
    /// When `true`, indicates that the method uses the Win32 standard calling
    /// convention where the callee is responsible for cleaning up the stack.
    /// This is the most common convention for Win32 API functions.
    ///
    /// # Standard Call Characteristics
    /// - **Stack Cleanup**: Callee removes parameters from stack
    /// - **Parameter Order**: Right-to-left parameter pushing
    /// - **Efficiency**: More efficient than cdecl for fixed parameters
    /// - **Win32 APIs**: Standard for most Windows API functions
    ///
    /// # Limitations
    /// - No support for variable arguments (incompatible with varargs)
    /// - Platform-specific (primarily Windows)
    /// - Fixed parameter count only
    pub stdcall: bool,
    /// Whether this method uses the `this` call calling convention.
    ///
    /// When `true`, indicates that the method uses the C++ instance method
    /// calling convention where the `this` pointer is passed in a register
    /// (typically ECX on x86). Used for C++ class method interop.
    ///
    /// # This Call Characteristics
    /// - **This Pointer**: Passed in register (ECX on x86, RCX on x64)
    /// - **Stack Cleanup**: Callee cleans the stack
    /// - **C++ Interop**: Standard for C++ instance methods
    /// - **Performance**: Optimized register passing for `this`
    ///
    /// # Usage Scenarios
    /// - Calling C++ class methods from .NET
    /// - COM object method invocation
    /// - Native C++ library integration
    /// - Optimized instance method calls
    pub thiscall: bool,
    /// Whether this method uses the fast call calling convention.
    ///
    /// When `true`, indicates that the method uses an optimized calling
    /// convention that passes the first few parameters in registers instead
    /// of on the stack, providing better performance for frequently called functions.
    ///
    /// # Fast Call Characteristics
    /// - **Register Parameters**: First 2 parameters in registers (ECX, EDX on x86)
    /// - **Stack Parameters**: Remaining parameters passed on stack
    /// - **Stack Cleanup**: Callee cleans the stack
    /// - **Performance**: Faster for small parameter counts
    ///
    /// # Platform Specifics
    /// - **x86**: First 2 parameters in ECX, EDX
    /// - **x64**: Different register allocation (RCX, RDX, R8, R9)
    /// - **ARM**: Platform-specific register usage
    ///
    /// # Usage Scenarios
    /// - High-performance native function calls
    /// - Optimized library interfaces
    /// - Performance-critical P/Invoke scenarios
    pub fastcall: bool,
    /// Number of generic type parameters this method declares.
    ///
    /// When non-zero, indicates that this is a generic method with the specified
    /// number of type parameters (e.g., `<T>`, `<T, U>`, `<T, U, V>`).
    /// Generic parameters are referenced in signatures using [`TypeSignature::GenericParamMethod`].
    ///
    /// # Generic Method Examples
    /// - **Single Parameter**: `public T Identity<T>(T value)` → `param_count_generic = 1`
    /// - **Multiple Parameters**: `public U Convert<T, U>(T input)` → `param_count_generic = 2`
    /// - **Non-Generic**: `public int Add(int a, int b)` → `param_count_generic = 0`
    ///
    /// # Type Parameter Numbering
    /// Generic parameters are referenced by zero-based index:
    /// - First parameter (`T`): [`TypeSignature::GenericParamMethod(0)`]
    /// - Second parameter (`U`): [`TypeSignature::GenericParamMethod(1)`]
    /// - Third parameter (`V`): [`TypeSignature::GenericParamMethod(2)`]
    ///
    /// # Constraints and Bounds
    /// Type parameter constraints are stored in separate metadata tables
    /// and not directly in the method signature.
    pub param_count_generic: u32,
    /// Number of fixed parameters this method accepts.
    ///
    /// Specifies the count of regular (non-varargs) parameters in the method signature.
    /// This count does not include the implicit `this` parameter for instance methods
    /// or any variable arguments specified in `varargs`.
    ///
    /// # Parameter Counting
    /// - **Instance Methods**: `param_count` excludes the implicit `this` parameter
    /// - **Static Methods**: `param_count` includes all parameters
    /// - **Varargs Methods**: `param_count` includes only fixed parameters
    /// - **Parameterless**: `param_count = 0` for methods with no parameters
    ///
    /// # Examples
    /// ```csharp
    /// public void Method1()                    // param_count = 0
    /// public int Method2(string s)             // param_count = 1  
    /// public void Method3(int a, bool b)       // param_count = 2
    /// public void Method4(params int[] args)   // param_count = 0 (varargs only)
    /// ```
    ///
    /// # Array Bounds
    /// The `params` vector must have exactly `param_count` elements,
    /// providing type information for each fixed parameter.
    pub param_count: u32,
    /// The return type of this method.
    ///
    /// Specifies what type of value the method returns to its caller.
    /// All methods must have a return type, even if it's `void` for
    /// methods that don't return a value.
    ///
    /// # Return Type Categories
    /// - **Void**: Methods that perform actions but return nothing
    /// - **Primitives**: `int`, `bool`, `double`, etc.
    /// - **Objects**: `string`, custom classes, interfaces
    /// - **Value Types**: `DateTime`, `Guid`, custom structs
    /// - **Generics**: Type parameters or generic instantiations
    /// - **Arrays**: Single or multi-dimensional arrays
    /// - **References**: `ref` returns for efficient access
    ///
    /// # Special Considerations
    /// - **Constructors**: Always return `void` (object initialization handled separately)
    /// - **Destructors**: Always return `void`
    /// - **Properties**: Return type matches the property type
    /// - **Async Methods**: May return `Task`, `Task<T>`, or `ValueTask<T>`
    pub return_type: SignatureParameter,
    /// The fixed parameters of this method.
    ///
    /// A vector containing type and modifier information for each regular
    /// parameter. The vector length must equal `param_count`. Parameters
    /// are ordered from left to right as they appear in the method signature.
    ///
    /// # Parameter Information
    /// Each [`SignatureParameter`] includes:
    /// - **Type**: The parameter's .NET type
    /// - **Modifiers**: Custom attributes and marshalling information  
    /// - **Reference Semantics**: Whether passed by reference (`ref`/`out`/`in`)
    ///
    /// # Parameter Categories
    /// - **Value Parameters**: Passed by value (copied)
    /// - **Reference Parameters**: Passed by reference (aliased)
    /// - **Output Parameters**: Must be assigned before method returns
    /// - **Input Parameters**: Read-only references for performance
    ///
    /// # Ordering
    /// Parameters appear in declaration order:
    /// ```csharp
    /// void Method(int first, string second, bool third)
    /// // params[0] = int, params[1] = string, params[2] = bool
    /// ```
    pub params: Vec<SignatureParameter>,
    /// Variable argument parameters for methods that accept varargs.
    ///
    /// When `vararg = true`, this vector contains type information for
    /// the variable arguments that can be passed to the method beyond
    /// the fixed parameters. Only used for methods with variable argument support.
    ///
    /// # Varargs vs Params Array
    /// - **Varargs**: True variable arguments (like C printf)
    /// - **Params Array**: C# `params` keyword (syntactic sugar for arrays)
    /// - **Type Safety**: Both maintain .NET type safety
    ///
    /// # Usage Patterns
    /// - **Legacy Interop**: Calling C functions with variable arguments
    /// - **Flexible APIs**: Methods that need true variable argument support
    /// - **Printf-style**: Formatted string methods with type-safe arguments
    ///
    /// # Empty for Most Methods
    /// Most .NET methods use fixed parameters or `params` arrays instead
    /// of true variable arguments, so this vector is typically empty.
    pub varargs: Vec<SignatureParameter>,
}

/// Field signature with type information and custom modifiers.
///
/// Represents field signatures according to ECMA-335 Section II.23.2.4.
/// Fields are the data members of classes and structures, storing the state
/// of objects and value types.
///
/// # Field Categories
///
/// ## Instance Fields
/// Fields that belong to specific instances of a type:
/// - Each object has its own copy of the field
/// - Accessed through object references
/// - Can have different values per instance
/// - Contribute to object size and layout
///
/// ## Static Fields
/// Fields that belong to the type itself rather than instances:
/// - Shared across all instances of the type
/// - Accessed through the type name
/// - Initialized once when the type is first used
/// - Stored in type metadata rather than object instances
///
/// ## Constants
/// Compile-time constant values that are embedded directly:
/// - Values known at compile time
/// - No runtime storage required
/// - Replaced with literal values during compilation
/// - Often used for configuration and magic numbers
///
/// # Field Types
///
/// Fields can store any valid .NET type:
/// - **Primitives**: `int`, `double`, `bool`, `char`
/// - **Objects**: `string`, custom classes, interfaces
/// - **Value Types**: `DateTime`, `Guid`, custom structs
/// - **Arrays**: Single or multi-dimensional arrays
/// - **Generics**: Generic type instantiations
/// - **Pointers**: For unsafe field scenarios
///
/// # Custom Modifiers
///
/// Fields can have custom modifiers that affect their behavior:
/// - **Memory Layout**: `StructLayout` attributes for precise control
/// - **Threading**: `volatile` for thread-safe access
/// - **Marshalling**: Interop-specific type conversions
/// - **Security**: Access control and validation attributes
///
/// # Binary Format (ECMA-335)
///
/// Field signatures are encoded as:
/// ```text
/// FieldSig ::= FIELD CustomMod* Type
/// ```
///
/// # Examples
///
/// ## Simple Field
/// ```rust
/// use dotscope::metadata::signatures::{SignatureField, TypeSignature};
///
/// # fn create_simple_field() {
/// let int_field = SignatureField {
///     modifiers: vec![],                    // No custom modifiers
///     base: TypeSignature::I4,              // int type
/// };
/// # }
/// ```
///
/// ## Field with Custom Modifiers
/// ```rust
/// use dotscope::metadata::signatures::{SignatureField, TypeSignature};
/// use dotscope::metadata::token::Token;
///
/// # fn create_modified_field() {
/// let volatile_field = SignatureField {
///     modifiers: vec![
///         Token::new(0x1B000001), // Hypothetical volatile modifier token
///     ],
///     base: TypeSignature::I4,
/// };
/// # }
/// ```
///
/// ## Generic Field
/// ```rust
/// use dotscope::metadata::signatures::{SignatureField, TypeSignature};
///
/// # fn create_generic_field() {
/// let generic_field = SignatureField {
///     modifiers: vec![],
///     base: TypeSignature::GenericParamType(0), // T parameter
/// };
/// # }
/// ```
///
/// # Thread Safety
///
/// `SignatureField` is immutable after construction and safe to share between
/// threads. The type signature and modifiers follow the same safety model.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.4 (`FieldSig`)
/// and supports all standard field signature scenarios.
///
/// # See Also
/// - [`TypeSignature`]: For supported field types
/// - [`crate::metadata::token::Token`]: For custom modifier references
/// - Field metadata types in [`crate::metadata::typesystem`] module
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureField {
    /// Custom modifiers that apply to this field.
    ///
    /// A vector of metadata tokens referencing `TypeDef` or `TypeRef` entries
    /// that specify additional constraints, attributes, or behaviors for
    /// the field. Most fields have no custom modifiers (empty vector).
    ///
    /// # Modifier Categories
    /// - **Layout Modifiers**: Control field alignment and packing
    /// - **Threading Modifiers**: `volatile` for thread-safe access patterns
    /// - **Marshalling Modifiers**: Control interop type conversions
    /// - **Security Modifiers**: Access control and validation requirements
    /// - **Tool Modifiers**: Compiler or analyzer-specific metadata
    ///
    /// # Common Scenarios
    /// - Fixed-size buffers in unsafe structs
    /// - Precise memory layout for interop structures
    /// - Thread-safe field access patterns
    /// - Platform-specific field requirements
    ///
    /// # Token References
    /// Each token typically references:
    /// - `TypeDef`: For custom modifier types defined in the same assembly
    /// - `TypeRef`: For external modifier types (from other assemblies)
    /// - `TypeSpec`: For complex generic modifier instantiations
    pub modifiers: Vec<Token>,
    /// The type of data stored in this field.
    ///
    /// Specifies the .NET type that this field can hold. The type determines:
    /// - Memory layout and size requirements
    /// - Value assignment compatibility
    /// - Garbage collection behavior (for reference types)
    /// - Default initialization values
    ///
    /// # Supported Types
    /// Fields can store any valid .NET type:
    /// - **Primitives**: `int`, `double`, `bool`, `char`
    /// - **Objects**: `string`, custom classes, interfaces
    /// - **Value Types**: `DateTime`, `Guid`, custom structs
    /// - **Arrays**: Single or multi-dimensional arrays
    /// - **Generics**: Generic type parameters or instantiations
    /// - **Pointers**: For unsafe field scenarios (requires unsafe context)
    ///
    /// # Type Safety
    /// The runtime enforces type safety for field access:
    /// - Values must be assignment-compatible with the field type
    /// - Null values only allowed for reference types and nullable value types
    /// - Generic type parameters must satisfy constraints
    /// - Pointer types require appropriate permissions
    pub base: TypeSignature,
}

/// Property signature with indexer support and custom modifiers.
///
/// Represents property signatures according to ECMA-335 Section II.23.2.5.
/// Properties provide controlled access to object state through getter and
/// setter methods, with optional support for indexed properties.
///
/// # Property Categories
///
/// ## Simple Properties
/// Properties that act like fields but use methods for access:
/// ```csharp
/// public string Name { get; set; }        // Auto-implemented property
/// public int Count { get; private set; }  // Read-only from outside
/// ```
///
/// ## Computed Properties
/// Properties that calculate values rather than storing them:
/// ```csharp
/// public string FullName => $"{FirstName} {LastName}";
/// public bool IsEmpty => Count == 0;
/// ```
///
/// ## Indexed Properties (Indexers)
/// Properties that accept parameters, acting like array access:
/// ```csharp
/// public string this[int index] { get; set; }           // Single index
/// public T this[string key, int version] { get; set; }  // Multiple indices
/// ```
///
/// # Property Characteristics
///
/// ## Instance vs Static
/// - **Instance Properties**: Accessed through object instances (`obj.Property`)
/// - **Static Properties**: Accessed through type names (`Type.Property`)
/// - **This Pointer**: Instance properties receive implicit `this` parameter
///
/// ## Access Control
/// Properties can have different access levels for getters and setters:
/// - Public getter, private setter (read-only from outside)
/// - Protected getter, public setter (unusual but possible)
/// - Different visibility for indexed property accessors
///
/// # Binary Format (ECMA-335)
///
/// Property signatures are encoded as:
/// ```text
/// PropertySig ::= PROPERTY [HASTHIS] CustomMod* Type Param*
/// ```
///
/// # Examples
///
/// ## Simple Property
/// ```rust
/// use dotscope::metadata::signatures::{SignatureProperty, TypeSignature};
///
/// # fn create_simple_property() {
/// let name_property = SignatureProperty {
///     has_this: true,                       // Instance property
///     modifiers: vec![],                    // No custom modifiers
///     base: TypeSignature::String,          // Returns string
///     params: vec![],                       // No parameters (not indexed)
/// };
/// # }
/// ```
///
/// ## Indexed Property
/// ```rust
/// use dotscope::metadata::signatures::{SignatureProperty, SignatureParameter, TypeSignature};
///
/// # fn create_indexed_property() {
/// let indexer_property = SignatureProperty {
///     has_this: true,                       // Instance indexer
///     modifiers: vec![],
///     base: TypeSignature::String,          // Returns string
///     params: vec![
///         SignatureParameter {
///             modifiers: vec![],
///             by_ref: false,
///             base: TypeSignature::I4,       // int index parameter
///         },
///     ],
/// };
/// # }
/// ```
///
/// ## Multi-Parameter Indexer
/// ```rust
/// use dotscope::metadata::signatures::{SignatureProperty, SignatureParameter, TypeSignature};
///
/// # fn create_multi_indexer() {
/// let multi_indexer = SignatureProperty {
///     has_this: true,
///     modifiers: vec![],
///     base: TypeSignature::Object,          // Returns object
///     params: vec![
///         SignatureParameter {
///             modifiers: vec![],
///             by_ref: false,
///             base: TypeSignature::String,   // string key
///         },
///         SignatureParameter {
///             modifiers: vec![],
///             by_ref: false,
///             base: TypeSignature::I4,       // int version
///         },
///     ],
/// };
/// # }
/// ```
///
/// # Thread Safety
///
/// `SignatureProperty` is immutable after construction and safe to share between
/// threads. Property access thread safety depends on the implementation.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.5 (`PropertySig`)
/// and supports all standard property signature scenarios.
///
/// # See Also
/// - [`SignatureParameter`]: For indexer parameter definitions
/// - [`TypeSignature`]: For supported property types
/// - [`crate::metadata::token::Token`]: For custom modifier references
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureProperty {
    /// Whether this property has an implicit `this` parameter.
    ///
    /// When `true`, indicates that this is an instance property that receives
    /// an implicit `this` parameter for accessing the object state. When `false`,
    /// indicates a static property that operates at the type level.
    ///
    /// # Instance Properties
    /// - Access object-specific state and behavior
    /// - Can have different values per object instance
    /// - Support polymorphic behavior through virtual accessors
    /// - Require object instance for access
    ///
    /// # Static Properties
    /// - Belong to the type rather than instances
    /// - Shared across all instances of the type
    /// - Accessed through type name rather than objects
    /// - Often used for configuration or global state
    pub has_this: bool,

    /// Custom modifiers that apply to this property.
    ///
    /// A vector of metadata tokens referencing `TypeDef` or `TypeRef` entries
    /// that specify additional constraints, attributes, or behaviors for
    /// the property. Most properties have no custom modifiers (empty vector).
    ///
    /// # Modifier Applications
    /// - **Threading**: Synchronization and thread-safety attributes
    /// - **Validation**: Property value validation requirements
    /// - **Serialization**: Custom serialization behavior
    /// - **Interop**: Platform-specific property requirements
    /// - **Security**: Access control and permission requirements
    ///
    /// # Common Scenarios
    /// - Properties with special marshalling requirements
    /// - Thread-safe property access patterns
    /// - Properties with custom validation logic
    /// - Tool-specific metadata for static analysis
    pub modifiers: Vec<Token>,

    /// The type of value this property represents.
    ///
    /// Specifies what type of data the property can get or set. This determines
    /// the return type of the getter method and the parameter type of the setter method.
    ///
    /// # Property Types
    /// Properties can represent any valid .NET type:
    /// - **Primitives**: `int`, `double`, `bool`, `string`
    /// - **Objects**: Custom classes, interfaces
    /// - **Value Types**: `DateTime`, `Guid`, custom structs
    /// - **Collections**: `List<T>`, `Dictionary<K,V>`, arrays
    /// - **Generics**: Generic type parameters or instantiations
    /// - **Special Types**: `object` for dynamic properties
    ///
    /// # Type Compatibility
    /// - Getter must return this exact type or compatible derived type
    /// - Setter must accept this exact type or compatible base type
    /// - Nullable reference types affect null handling semantics
    pub base: TypeSignature,

    /// Parameters for indexed properties (indexers).
    ///
    /// For simple properties, this vector is empty. For indexed properties
    /// (indexers), this contains the parameter types used to identify
    /// which element to get or set.
    ///
    /// # Indexer Parameters
    /// - **Single Index**: `this[int index]` → 1 parameter
    /// - **Multiple Indices**: `this[string key, int version]` → 2 parameters
    /// - **Complex Types**: Parameters can be any valid .NET type
    /// - **Reference Parameters**: Support `ref`, `out`, `in` semantics
    ///
    /// # Parameter Ordering
    /// Parameters appear in the same order as the indexer declaration:
    /// ```csharp
    /// public T this[string first, int second, bool third] { get; set; }
    /// // params[0] = string, params[1] = int, params[2] = bool
    /// ```
    ///
    /// # Overloading
    /// Multiple indexers can exist with different parameter signatures,
    /// enabling type-safe overloaded access patterns.
    pub params: Vec<SignatureParameter>,
}

/// Local variable signature collection for method bodies.
///
/// Represents the complete local variable signature according to ECMA-335 Section II.23.2.6.
/// This contains all local variables declared within a method body, including their types,
/// modifiers, and special attributes like pinning and reference semantics.
///
/// # Local Variable Characteristics
///
/// ## Scope and Lifetime
/// Local variables are scoped to the method in which they are declared:
/// - Created when the method is entered
/// - Destroyed when the method exits
/// - Accessible only within the declaring method
/// - Zero-initialized by default unless explicitly assigned
///
/// ## Memory Management
/// Local variables use stack-based allocation by default:
/// - Value types: Stored directly on the stack
/// - Reference types: References stored on stack, objects on heap
/// - Pinned variables: Prevent garbage collection movement
/// - Large objects: May be allocated on the large object heap
///
/// # Binary Format (ECMA-335)
///
/// Local variable signatures are encoded as:
/// ```text
/// LocalVarSig ::= LOCAL_SIG Count (TYPEDBYREF | ([CustomMod]* [Constraint])* [BYREF] Type)*
/// ```
///
/// # Examples
///
/// ## Simple Local Variables
/// ```rust
/// use dotscope::metadata::signatures::{SignatureLocalVariables, SignatureLocalVariable, TypeSignature};
///
/// # fn create_simple_locals() {
/// let locals = SignatureLocalVariables {
///     locals: vec![
///         SignatureLocalVariable {
///             modifiers: vec![],
///             is_byref: false,
///             is_pinned: false,
///             base: TypeSignature::I4,           // int local
///         },
///         SignatureLocalVariable {
///             modifiers: vec![],
///             is_byref: false,
///             is_pinned: false,
///             base: TypeSignature::String,       // string local
///         },
///     ],
/// };
/// # }
/// ```
///
/// ## Complex Local Variables
/// ```rust
/// use dotscope::metadata::signatures::{SignatureLocalVariables, SignatureLocalVariable, TypeSignature};
///
/// # fn create_complex_locals() {
/// let complex_locals = SignatureLocalVariables {
///     locals: vec![
///         SignatureLocalVariable {
///             modifiers: vec![],
///             is_byref: true,                    // ref variable
///             is_pinned: false,
///             base: TypeSignature::I4,
///         },
///         SignatureLocalVariable {
///             modifiers: vec![],
///             is_byref: false,
///             is_pinned: true,                   // pinned variable
///             base: TypeSignature::String,
///         },
///     ],
/// };
/// # }
/// ```
///
/// # Thread Safety
///
/// `SignatureLocalVariables` is immutable after construction and safe to share between
/// threads. The actual local variable storage is thread-local per method execution.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.6 (`LocalVarSig`)
/// and supports all standard local variable signature scenarios.
///
/// # See Also
/// - [`SignatureLocalVariable`]: For individual local variable definitions
/// - [`TypeSignature`]: For supported local variable types
/// - [`crate::metadata::method::MethodBody`]: For method body context
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureLocalVariables {
    /// The collection of local variables declared in this method.
    ///
    /// Each [`SignatureLocalVariable`] represents a single local variable
    /// with its type, modifiers, and special attributes. The order matches
    /// the declaration order in the method body.
    ///
    /// # Variable Access
    /// Local variables are accessed by index in IL instructions:
    /// - `ldloc.0`, `ldloc.1`, etc. for loading local variables
    /// - `stloc.0`, `stloc.1`, etc. for storing to local variables
    /// - Index corresponds to position in this vector
    ///
    /// # Empty Collections
    /// Methods without local variables have an empty vector.
    /// This is common for simple methods that only use parameters.
    pub locals: Vec<SignatureLocalVariable>,
}

/// Individual local variable declaration with type and attributes.
///
/// Represents a single local variable within a method body according to ECMA-335.
/// Local variables store temporary values during method execution and are
/// automatically managed by the runtime.
///
/// # Variable Categories
///
/// ## Value Variables
/// Variables that store values directly:
/// - Primitives: `int`, `double`, `bool`
/// - Structs: `DateTime`, `Point`, custom value types
/// - Enums: All enumeration types
/// - Storage: Values stored directly in the variable
///
/// ## Reference Variables
/// Variables that store references to objects:
/// - Classes: `string`, `object`, custom reference types
/// - Arrays: All array types (`int[]`, `string[,]`)
/// - Interfaces: All interface types
/// - Storage: References stored in variable, objects on heap
///
/// ## Special Variables
/// Variables with special runtime semantics:
/// - **By-Reference**: Variables that alias other memory locations
/// - **Pinned**: Variables that prevent garbage collection movement
/// - **Modified**: Variables with custom type constraints
///
/// # Memory Management
///
/// ## Stack Allocation
/// Most local variables use stack-based allocation:
/// - Fast allocation and deallocation
/// - Automatic cleanup when method exits
/// - Cache-friendly access patterns
/// - Limited to method scope
///
/// ## Pinning Semantics
/// Pinned variables have special memory behavior:
/// - Prevent garbage collector from moving referenced objects
/// - Enable safe interaction with native code
/// - Must be unpinned before method exit
/// - Used primarily for interop scenarios
///
/// # Examples
///
/// ## Simple Variable
/// ```rust
/// use dotscope::metadata::signatures::{SignatureLocalVariable, TypeSignature};
///
/// # fn create_simple_variable() {
/// let int_var = SignatureLocalVariable {
///     modifiers: vec![],
///     is_byref: false,
///     is_pinned: false,
///     base: TypeSignature::I4,              // int variable
/// };
/// # }
/// ```
///
/// ## Reference Variable
/// ```rust
/// use dotscope::metadata::signatures::{SignatureLocalVariable, TypeSignature};
///
/// # fn create_ref_variable() {
/// let ref_var = SignatureLocalVariable {
///     modifiers: vec![],
///     is_byref: true,                       // ref int variable
///     is_pinned: false,
///     base: TypeSignature::I4,
/// };
/// # }
/// ```
///
/// ## Pinned Variable
/// ```rust
/// use dotscope::metadata::signatures::{SignatureLocalVariable, TypeSignature};
///
/// # fn create_pinned_variable() {
/// let pinned_var = SignatureLocalVariable {
///     modifiers: vec![],
///     is_byref: false,
///     is_pinned: true,                      // pinned variable
///     base: TypeSignature::String,
/// };
/// # }
/// ```
///
/// # Thread Safety
///
/// `SignatureLocalVariable` is immutable after construction and safe to share between
/// threads. The actual local variable storage is thread-local per method execution.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 local variable semantics and supports
/// all standard local variable scenarios defined in the specification.
///
/// # See Also
/// - [`SignatureLocalVariables`]: For complete local variable collections
/// - [`TypeSignature`]: For supported variable types
/// - [`crate::metadata::token::Token`]: For custom modifier references
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureLocalVariable {
    /// Custom modifiers that apply to this local variable.
    ///
    /// A vector of metadata tokens referencing `TypeDef` or `TypeRef` entries
    /// that specify additional constraints, attributes, or behaviors for
    /// the local variable. Most variables have no custom modifiers (empty vector).
    ///
    /// # Modifier Applications
    /// - **Type Constraints**: Additional type safety requirements
    /// - **Memory Layout**: Specific alignment or packing requirements
    /// - **Tool Metadata**: Debugger or profiler annotations
    /// - **Security**: Access control or validation attributes
    ///
    /// # Common Scenarios
    /// - Variables with specific alignment requirements
    /// - Variables with debugging metadata
    /// - Variables with custom lifetime semantics
    /// - Tool-specific analysis annotations
    pub modifiers: Vec<Token>,

    /// Whether this variable uses reference semantics.
    ///
    /// When `true`, indicates that this local variable is a reference
    /// to another memory location rather than storing a value directly.
    /// This corresponds to `ref` local variables in C#.
    ///
    /// # Reference Semantics
    /// - **Aliasing**: Variable becomes an alias to another variable
    /// - **No Copy**: Assignment creates aliases, not copies
    /// - **Lifetime**: Reference must not outlive the referenced variable
    /// - **Safety**: Compiler ensures reference validity
    ///
    /// # Usage Patterns
    /// - Avoiding copies of large structs
    /// - Creating aliases for complex indexing operations
    /// - Efficient parameter passing patterns
    /// - Advanced memory optimization scenarios
    pub is_byref: bool,

    /// Whether this variable is pinned in memory.
    ///
    /// When `true`, indicates that this local variable prevents the
    /// garbage collector from moving the referenced object. This is
    /// critical for safe interop with native code.
    ///
    /// # Pinning Behavior
    /// - **Memory Stability**: Object address remains constant
    /// - **GC Interaction**: Prevents object movement during collection
    /// - **Performance Impact**: May reduce GC efficiency
    /// - **Safety**: Enables safe native code interaction
    ///
    /// # Usage Scenarios
    /// - P/Invoke operations requiring stable pointers
    /// - Unsafe code blocks with pointer arithmetic
    /// - High-performance interop scenarios
    /// - Fixed statement implementations
    ///
    /// # Automatic Unpinning
    /// Variables are automatically unpinned when:
    /// - Method execution completes
    /// - Variable goes out of scope
    /// - Exception occurs (finally blocks execute)
    pub is_pinned: bool,

    /// The type of data this local variable can store.
    ///
    /// Specifies the .NET type that this local variable can hold.
    /// The type determines storage requirements, assignment compatibility,
    /// and runtime behavior.
    ///
    /// # Supported Types
    /// Local variables can store any valid .NET type:
    /// - **Primitives**: `int`, `double`, `bool`, `char`
    /// - **Objects**: `string`, custom classes, interfaces
    /// - **Value Types**: `DateTime`, `Guid`, custom structs
    /// - **Arrays**: Single or multi-dimensional arrays
    /// - **Generics**: Generic type parameters or instantiations
    /// - **Pointers**: For unsafe local variables (requires unsafe context)
    ///
    /// # Type Safety
    /// The runtime enforces type safety for local variable access:
    /// - Values must be assignment-compatible with the variable type
    /// - Generic type parameters must satisfy constraints
    /// - Reference type assignments include null checking
    /// - Value type assignments include range validation
    ///
    /// # Initialization
    /// Local variables are zero-initialized by default:
    /// - Value types: Set to default value (0, false, etc.)
    /// - Reference types: Set to null
    /// - Custom initialization: Must be explicit in IL code
    pub base: TypeSignature,
}

/// Type specification signature for complex and generic types.
///
/// Represents type specification signatures according to ECMA-335 Section II.23.2.14.
/// Type specifications are used to represent complex types that cannot be expressed
/// through simple metadata tokens, particularly generic instantiations and complex
/// nested types.
///
/// # Type Specification Uses
///
/// ## Generic Instantiations
/// Complex generic types with specific type arguments:
/// - `List<int>` - Generic class with value type argument
/// - `Dictionary<string, object>` - Generic class with multiple arguments
/// - `Array<T>` - Generic array with type parameter
///
/// ## Nested Generic Types
/// Generic types nested within other generic types:
/// - `Outer<T>.Inner<U>` - Nested generic classes
/// - `Container<T>.Collection<U>.Item<V>` - Multiple nesting levels
///
/// ## Complex Array Types
/// Multi-dimensional and modified array types:
/// - `int[,]` - Multi-dimensional arrays
/// - `volatile int[]` - Arrays with custom modifiers
/// - `T[][]` - Jagged arrays with generic elements
///
/// ## Function Pointer Types
/// Complex function pointer signatures:
/// - `delegate*<int, string, bool>` - Function pointers with multiple parameters
/// - `delegate* managed<T, U>` - Generic function pointers
///
/// # Binary Format (ECMA-335)
///
/// Type specifications are encoded as complete type signatures:
/// ```text
/// TypeSpec ::= Type
/// ```
///
/// Where `Type` can be any valid type signature including complex generic instantiations.
///
/// # Examples
///
/// ## Generic Instantiation
/// ```rust
/// use dotscope::metadata::signatures::{SignatureTypeSpec, TypeSignature};
/// use dotscope::metadata::token::Token;
///
/// # fn create_generic_spec() {
/// let list_of_int = SignatureTypeSpec {
///     base: TypeSignature::GenericInst(
///         Box::new(TypeSignature::Class(Token::new(0x02000001))), // List<T> class
///         vec![TypeSignature::I4]                                 // int argument
///     ),
/// };
/// # }
/// ```
///
/// ## Complex Array Type
/// ```rust
/// use dotscope::metadata::signatures::{SignatureTypeSpec, TypeSignature, SignatureArray};
/// use dotscope::metadata::typesystem::ArrayDimensions;
///
/// # fn create_array_spec() {
/// let int_2d_array = SignatureTypeSpec {
///     base: TypeSignature::Array(SignatureArray {
///         base: Box::new(TypeSignature::I4),
///         rank: 2,
///         dimensions: vec![
///             ArrayDimensions { size: None, lower_bound: None },
///             ArrayDimensions { size: None, lower_bound: None },
///         ],
///     }),
/// };
/// # }
/// ```
///
/// # Performance Considerations
///
/// - Type specifications are resolved once and cached
/// - Complex generic instantiations may have resolution overhead
/// - Runtime type checking enforces specification constraints
///
/// # Thread Safety
///
/// `SignatureTypeSpec` is immutable after construction and safe to share between threads.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.14 (`TypeSpec`)
/// and supports all standard type specification scenarios.
///
/// # See Also
/// - [`TypeSignature`]: For the underlying type representation
/// - [`SignatureMethodSpec`]: For method specification signatures
/// - [`crate::metadata::token::Token`]: For metadata token references
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureTypeSpec {
    /// The complete type signature for this type specification.
    ///
    /// Contains the full type signature that defines this type specification.
    /// This can be any valid type signature, but is typically used for
    /// complex types that require full signature representation.
    ///
    /// # Type Categories
    /// - **Generic Instantiations**: `List<T>`, `Dictionary<K,V>`
    /// - **Complex Arrays**: Multi-dimensional or modified arrays
    /// - **Function Pointers**: Complex delegate types
    /// - **Nested Types**: Generic types within generic types
    ///
    /// # Resolution
    /// The type signature is resolved by the runtime to create
    /// the actual type representation used during execution.
    pub base: TypeSignature,
}

/// Method specification signature for generic method instantiations.
///
/// Represents method specification signatures according to ECMA-335 Section II.23.2.15.
/// Method specifications are used to represent instantiations of generic methods
/// with specific type arguments, enabling type-safe generic method calls.
///
/// # Method Specification Uses
///
/// ## Generic Method Instantiation
/// When calling generic methods with specific type arguments:
/// ```csharp
/// public static T Identity<T>(T value) { return value; }
///
/// // Calls require method specifications:
/// Identity<int>(42)        // MethodSpec with [int]
/// Identity<string>("hi")   // MethodSpec with [string]
/// ```
///
/// ## Complex Generic Arguments
/// Methods with multiple or complex generic arguments:
/// ```csharp
/// public static U Convert<T, U>(T input) { ... }
///
/// // Complex instantiations:
/// Convert<int, string>(42)              // MethodSpec with [int, string]
/// Convert<List<int>, Dictionary<K,V>>() // MethodSpec with complex types
/// ```
///
/// ## Generic Method References
/// Creating delegates to generic method instantiations:
/// ```csharp
/// Func<int, int> identity = Identity<int>;  // Requires MethodSpec
/// ```
///
/// # Binary Format (ECMA-335)
///
/// Method specifications are encoded as:
/// ```text
/// MethodSpec ::= GENRICINST GenArgCount Type*
/// ```
///
/// Where:
/// - `GENRICINST`: Indicates generic instantiation (0x0A)
/// - `GenArgCount`: Number of generic arguments
/// - `Type*`: Type signatures for each generic argument
///
/// # Examples
///
/// ## Simple Generic Method
/// ```rust
/// use dotscope::metadata::signatures::{SignatureMethodSpec, TypeSignature};
///
/// # fn create_simple_method_spec() {
/// let identity_int = SignatureMethodSpec {
///     generic_args: vec![TypeSignature::I4],  // Identity<int>
/// };
/// # }
/// ```
///
/// ## Multiple Generic Arguments
/// ```rust
/// use dotscope::metadata::signatures::{SignatureMethodSpec, TypeSignature};
///
/// # fn create_multi_arg_spec() {
/// let convert_spec = SignatureMethodSpec {
///     generic_args: vec![
///         TypeSignature::I4,       // T = int
///         TypeSignature::String,   // U = string
///     ],
/// };
/// # }
/// ```
///
/// ## Complex Generic Arguments
/// ```rust
/// use dotscope::metadata::signatures::{SignatureMethodSpec, TypeSignature, SignatureSzArray};
/// use dotscope::metadata::token::Token;
///
/// # fn create_complex_spec() {
/// let complex_spec = SignatureMethodSpec {
///     generic_args: vec![
///         TypeSignature::SzArray(SignatureSzArray {
///             modifiers: vec![],
///             base: Box::new(TypeSignature::I4),  // int[]
///         }),
///         TypeSignature::GenericInst(
///             Box::new(TypeSignature::Class(Token::new(0x02000001))), // List<T>
///             vec![TypeSignature::String]         // List<string>
///         ),
///     ],
/// };
/// # }
/// ```
///
/// # Runtime Behavior
///
/// - Method specifications enable JIT compilation of generic methods
/// - Type arguments are validated against method constraints
/// - Runtime creates specialized method implementations
/// - Generic sharing optimizes for compatible types
///
/// # Performance Characteristics
///
/// - **Compilation**: JIT compiles specialized versions
/// - **Type Checking**: Runtime validates generic constraints
/// - **Memory**: Shared implementations for reference types
/// - **Execution**: Native performance for specialized methods
///
/// # Thread Safety
///
/// `SignatureMethodSpec` is immutable after construction and safe to share between threads.
///
/// # ECMA-335 Compliance
///
/// This structure implements ECMA-335 Partition II, Section 23.2.15 (`MethodSpec`)
/// and supports all standard method specification scenarios.
///
/// # See Also
/// - [`TypeSignature`]: For generic argument type representations
/// - [`SignatureMethod`]: For the underlying generic method signatures
/// - [`crate::metadata::method::Method`]: For complete method metadata
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SignatureMethodSpec {
    /// The type arguments for this generic method instantiation.
    ///
    /// A vector containing the specific type signatures that replace
    /// the generic type parameters in the method signature. The order
    /// corresponds to the declaration order of generic parameters.
    ///
    /// # Type Argument Mapping
    /// Generic parameters are replaced by position:
    /// - First parameter (`!!0`): `generic_args[0]`
    /// - Second parameter (`!!1`): `generic_args[1]`
    /// - Third parameter (`!!2`): `generic_args[2]`
    ///
    /// # Constraint Validation
    /// Type arguments must satisfy the constraints of the generic method:
    /// - Type constraints: Must inherit from specified base types
    /// - Interface constraints: Must implement required interfaces
    /// - Constructor constraints: Must have parameterless constructors
    /// - Reference/value type constraints: Must match reference type requirements
    ///
    /// # Examples
    /// ```csharp
    /// public static T Max<T>(T a, T b) where T : IComparable<T>
    ///
    /// // For Max<int>(1, 2):
    /// // generic_args = [TypeSignature::I4]
    /// // Runtime validates that int implements IComparable<int>
    ///
    /// // For Max<string>("a", "b"):
    /// // generic_args = [TypeSignature::String]
    /// // Runtime validates that string implements IComparable<string>
    /// ```
    ///
    /// # Empty for Non-Generic Methods
    /// Non-generic methods have an empty vector since they don't
    /// require type argument instantiation.
    pub generic_args: Vec<TypeSignature>,
}

impl TypeSignature {
    /// Check if a constant primitive value is compatible with this type signature
    ///
    /// This implements .NET type compatibility rules for constants including:
    /// - Exact type matching for primitives
    /// - Safe widening conversions (e.g., int32 constant to int64 type)
    /// - String constants to Object types
    ///
    /// # Arguments
    /// * `constant` - The constant primitive value to check
    ///
    /// # Returns
    /// `true` if the constant can be assigned to this type signature
    #[must_use]
    #[allow(clippy::unnested_or_patterns)] // Keep patterns separate for readability
    pub fn accepts_constant(&self, constant: &crate::metadata::typesystem::CilPrimitive) -> bool {
        use crate::metadata::typesystem::CilPrimitiveKind;

        match (constant.kind, self) {
            // Exact primitive matches and type conversions - all return true
            // Exact type matches
            (CilPrimitiveKind::Void, TypeSignature::Void)
            | (CilPrimitiveKind::Boolean, TypeSignature::Boolean)
            | (CilPrimitiveKind::Char, TypeSignature::Char)
            | (CilPrimitiveKind::I1, TypeSignature::I1)
            | (CilPrimitiveKind::U1, TypeSignature::U1)
            | (CilPrimitiveKind::I2, TypeSignature::I2)
            | (CilPrimitiveKind::U2, TypeSignature::U2)
            | (CilPrimitiveKind::I4, TypeSignature::I4)
            | (CilPrimitiveKind::U4, TypeSignature::U4)
            | (CilPrimitiveKind::I8, TypeSignature::I8)
            | (CilPrimitiveKind::U8, TypeSignature::U8)
            | (CilPrimitiveKind::R4, TypeSignature::R4)
            | (CilPrimitiveKind::R8, TypeSignature::R8)
            | (CilPrimitiveKind::I, TypeSignature::I)
            | (CilPrimitiveKind::U, TypeSignature::U)
            | (CilPrimitiveKind::String, TypeSignature::String)
            | (CilPrimitiveKind::Object, TypeSignature::Object)
            // Safe widening conversions for signed integers
            | (CilPrimitiveKind::I1, TypeSignature::I2 | TypeSignature::I4 | TypeSignature::I8)
            | (CilPrimitiveKind::I2, TypeSignature::I4 | TypeSignature::I8)
            | (CilPrimitiveKind::I4, TypeSignature::I8)
            // Safe widening conversions for unsigned integers
            | (CilPrimitiveKind::U1, TypeSignature::U2 | TypeSignature::U4 | TypeSignature::U8)
            | (CilPrimitiveKind::U2, TypeSignature::U4 | TypeSignature::U8)
            | (CilPrimitiveKind::U4, TypeSignature::U8)
            // Float widening
            | (CilPrimitiveKind::R4, TypeSignature::R8)
            // Integer to float (with potential precision loss, but allowed for constants)
            | (
                CilPrimitiveKind::I1
                | CilPrimitiveKind::U1
                | CilPrimitiveKind::I2
                | CilPrimitiveKind::U2
                | CilPrimitiveKind::I4,
                TypeSignature::R4 | TypeSignature::R8,
            )
            | (
                CilPrimitiveKind::I8 | CilPrimitiveKind::U4 | CilPrimitiveKind::U8,
                TypeSignature::R8,
            )
            // String constants to Object
            | (CilPrimitiveKind::String, TypeSignature::Object)
            // Null and Class constants can be assigned to any reference type
            | (
                CilPrimitiveKind::Null | CilPrimitiveKind::Class,
                TypeSignature::String | TypeSignature::Object,
            )
            // For complex types (Class, ValueType, etc.), we can't easily validate without
            // full type resolution, so we allow them (conservative approach)
            // Note: This also covers Null and Class constants to complex types
            | (_, TypeSignature::Class(_) | TypeSignature::ValueType(_)) => true,

            // All other combinations are incompatible
            _ => false,
        }
    }
}
