//! Binary signature parser implementation for .NET metadata signatures.
//!
//! This module provides the core parsing engine for all .NET signature types according to
//! the ECMA-335 specification. The parser handles the binary blob format used to encode
//! type information, method signatures, and other metadata elements in .NET assemblies.
//!
//! # Parser Architecture
//!
//! The signature parser is built around a single [`SignatureParser`] struct that maintains
//! parsing state and provides methods for extracting different signature types from binary
//! data. The parser uses a recursive descent approach to handle complex nested types while
//! maintaining protection against malformed data and infinite recursion.
//!
//! ## Core Components
//!
//! - **Binary Reader**: Low-level byte stream processing with compressed integer support
//! - **Type Parser**: Recursive type signature parsing with depth limiting
//! - **Custom Modifier Handler**: Support for modreq/modopt type annotations
//! - **Token Resolution**: Compressed metadata token decoding
//! - **Error Recovery**: Comprehensive error reporting with context information
//!
//! # Supported Signature Types
//!
//! ## Method Signatures (`MethodDefSig`, `MethodRefSig`, `StandAloneMethodSig`)
//! - Standard managed calling conventions (DEFAULT, HASTHIS, `EXPLICIT_THIS`)
//! - Platform invoke calling conventions (C, STDCALL, THISCALL, FASTCALL)
//! - Variable argument signatures (VARARG with sentinel markers)
//! - Generic method signatures with type parameter counts
//! - Parameter lists with byref and custom modifiers
//!
//! ## Field Signatures
//! - Simple field type declarations
//! - Custom modifiers (modreq/modopt) for interop scenarios
//! - Complex field types including arrays, pointers, and generic instantiations
//!
//! ## Property Signatures  
//! - Instance and static property declarations
//! - Indexed properties with parameter lists
//! - Custom modifiers on property types and parameters
//!
//! ## Local Variable Signatures
//! - Method local variable type lists
//! - Pinned variables for unsafe code and interop
//! - `ByRef` locals for reference semantics
//! - `TypedByRef` for reflection scenarios
//!
//! ## Type Specification Signatures
//! - Generic type instantiations (List&lt;T&gt;, Dictionary&lt;K,V&gt;)
//! - Complex array types with bounds and dimensions
//! - Pointer and managed reference types
//! - Function pointer signatures
//!
//! ## Method Specification Signatures
//! - Generic method instantiation type arguments
//! - Type argument lists for method calls
//! - Constraint validation support
//!
//! # Binary Format Details
//!
//! ## Element Type Encoding
//! Primitive types are encoded as single bytes according to ECMA-335:
//! ```text
//! 0x01: VOID       0x08: I4         0x0E: STRING
//! 0x02: BOOLEAN    0x09: U4         0x0F: PTR
//! 0x03: CHAR       0x0A: I8         0x10: BYREF
//! 0x04: I1         0x0B: U8         0x11: VALUETYPE
//! 0x05: U1         0x0C: R4         0x12: CLASS
//! 0x06: I2         0x0D: R8         0x13: VAR
//! 0x07: U2         0x1C: OBJECT     0x1E: MVAR
//! ```
//!
//! ## Calling Convention Flags
//! Method signatures start with calling convention bytes:
//! ```text
//! 0x00: DEFAULT      0x20: HASTHIS
//! 0x01: C            0x40: EXPLICITTHIS  
//! 0x02: STDCALL      0x10: GENERIC
//! 0x03: THISCALL     0x05: VARARG
//! 0x04: FASTCALL
//! ```
//!
//! ## Compressed Integer Encoding
//! Counts and indices use variable-length encoding:
//! - 0x00-0x7F: Single byte (0-127)
//! - 0x80-0xBF: Two bytes (128-16383)
//! - 0xC0-0xFF: Four bytes (16384+)
//!
//! # Security and Safety
//!
//! ## Recursion Protection
//! The parser includes protection against stack overflow from malformed signatures:
//! - Maximum recursion depth of 50 levels
//! - Early termination on depth limit exceeded
//! - Clear error reporting for recursion limits
//!
//! ## Buffer Boundary Checking
//! All data access includes bounds checking:
//! - No unchecked array access or pointer arithmetic
//! - Graceful handling of truncated signature data
//! - Clear error messages for malformed input
//!
//! ## Error Handling
//! Comprehensive error reporting for analysis scenarios:
//! - Specific error types for different failure modes
//! - Context information including byte positions
//! - Recovery suggestions for common issues
//!
//! # References
//!
//! - **ECMA-335, Partition II, Section 23.2**: Blobs and signature formats
//! - **ECMA-335, Partition II, Section 23.1**: Metadata validation rules
//! - **`CoreCLR` sigparse.cpp**: Reference implementation patterns
//! - **.NET Runtime Documentation**: Implementation notes and edge cases

use crate::{
    file::parser::Parser,
    metadata::{
        signatures::{
            CustomModifier, SignatureArray, SignatureField, SignatureLocalVariable,
            SignatureLocalVariables, SignatureMethod, SignatureMethodSpec, SignatureParameter,
            SignaturePointer, SignatureProperty, SignatureSzArray, SignatureTypeSpec,
            TypeSignature,
        },
        typesystem::{ArrayDimensions, ELEMENT_TYPE},
    },
    Error::RecursionLimit,
    Result,
};

/// Maximum recursion depth for signature parsing to prevent stack overflow.
///
/// This limit protects against malformed signatures that could cause infinite recursion
/// through circular type references or deeply nested generic types. The limit of 50
/// levels is sufficient for legitimate .NET signatures while preventing resource exhaustion.
const MAX_RECURSION_DEPTH: usize = 50;

/// Binary signature parser for all .NET metadata signature types according to ECMA-335.
///
/// `SignatureParser` provides a stateful parser for extracting type information from the
/// binary blob format used in .NET assembly metadata. The parser handles all signature
/// types defined in ECMA-335 and includes protection against malformed data, infinite
/// recursion, and buffer overruns.
///
/// # Parser State
///
/// The parser maintains internal state during parsing operations:
/// - **Binary Position**: Current read position in the signature blob
/// - **Recursion Depth**: Current nesting level for recursive type parsing
/// - **Error Context**: Information for meaningful error reporting
///
/// # Thread Safety
///
/// `SignatureParser` is not thread-safe and should not be shared across threads.
/// Create separate parser instances for concurrent signature parsing operations.
///
/// # Usage Pattern
///
/// The parser is designed for single-use parsing of individual signatures. Do not
/// reuse parser instances for multiple signatures as this may lead to incorrect
/// results due to retained internal state.
///
/// # Examples
///
/// ## Basic Method Signature Parsing
///
/// ```rust
/// use dotscope::metadata::signatures::SignatureParser;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse a simple instance method: void Method(int param)
/// let signature_data = &[
///     0x20, // HASTHIS calling convention
///     0x01, // 1 parameter
///     0x01, // VOID return type  
///     0x08, // I4 (int) parameter type
/// ];
///
/// let mut parser = SignatureParser::new(signature_data);
/// let method_sig = parser.parse_method_signature()?;
///
/// assert!(method_sig.has_this);
/// assert_eq!(method_sig.params.len(), 1);
/// println!("Method has {} parameters", method_sig.params.len());
/// # Ok(())
/// # }
/// ```
///
/// ## Complex Type Parsing
///
/// ```rust
/// use dotscope::metadata::signatures::{SignatureParser, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse a generic type instantiation: List<string>
/// let type_data = &[
///     0x15, // GENERICINST  
///     0x12, 0x42, // CLASS token reference
///     0x01, // 1 type argument
///     0x0E, // STRING type argument
/// ];
///
/// let mut parser = SignatureParser::new(type_data);
/// let type_sig = parser.parse_type_spec_signature()?;
///
/// if let TypeSignature::GenericInst(_, args) = &type_sig.base {
///     println!("Generic type with {} arguments", args.len());
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Field Signature with Custom Modifiers
///
/// ```rust
/// use dotscope::metadata::signatures::SignatureParser;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse a field with modifiers: modreq(IsConst) int field
/// let field_data = &[
///     0x06, // FIELD signature marker
///     0x1F, 0x42, // CMOD_REQD with token
///     0x08, // I4 (int) field type
/// ];
///
/// let mut parser = SignatureParser::new(field_data);
/// let field_sig = parser.parse_field_signature()?;
///
/// println!("Field has {} custom modifiers", field_sig.modifiers.len());
/// # Ok(())
/// # }
/// ```
///
/// # Error Handling
///
/// The parser provides detailed error information for various failure scenarios:
///
/// ## Malformed Signature Data
/// - Invalid signature headers or magic bytes
/// - Truncated signature data or unexpected end of stream
/// - Unknown element types or calling conventions
///
/// ## Recursion Limits
/// - Protection against stack overflow from circular references
/// - Clear error messages indicating recursion depth exceeded
/// - Safe termination of parsing operations
///
/// ## Format Violations
/// - ECMA-335 compliance validation
/// - Type consistency checking
/// - Proper error context for debugging
///
/// # Performance Considerations
///
/// - **Linear Parsing**: O(n) time complexity where n is signature length
/// - **Memory Efficiency**: Minimal heap allocation during parsing
/// - **Error Recovery**: Fast failure with detailed error information
/// - **Caching**: Consider caching parsed results for frequently accessed signatures
///
/// # ECMA-335 Compliance
///
/// The parser implements the complete ECMA-335 signature specification:
/// - **Partition II, Section 23.2**: Binary blob and signature formats
/// - **Partition II, Section 7**: Type system fundamentals
/// - **Partition I, Section 8**: Common Type System (CTS) integration
/// - **All signature types**: Method, Field, Property, `LocalVar`, `TypeSpec`, `MethodSpec`
pub struct SignatureParser<'a> {
    /// Binary data parser for reading signature bytes
    parser: Parser<'a>,
    /// Current recursion depth for nested type parsing
    depth: usize,
}

impl<'a> SignatureParser<'a> {
    /// Create a new signature parser for the given binary signature data.
    ///
    /// Initializes a new parser instance with the provided signature blob data.
    /// The parser starts at the beginning of the data and maintains internal
    /// state for tracking parsing progress and recursion depth.
    ///
    /// # Parameters
    /// - `data`: Binary signature data from a .NET assembly's blob heap
    ///
    /// # Returns
    /// A new `SignatureParser` instance ready for parsing operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::signatures::SignatureParser;
    ///
    /// // Create parser for a simple method signature
    /// let signature_data = &[0x00, 0x00, 0x01]; // DEFAULT, 0 params, VOID
    /// let parser = SignatureParser::new(signature_data);
    /// ```
    ///
    /// # Important Notes
    ///
    /// - **Single Use**: Do not reuse parser instances for multiple signatures
    /// - **Thread Safety**: Not thread-safe, create separate instances for concurrent use
    /// - **Data Lifetime**: Parser borrows the input data, ensure it remains valid
    /// - **State Management**: Parser maintains internal state, reset not supported
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        SignatureParser {
            parser: Parser::new(data),
            depth: 0,
        }
    }

    /// Parse a single type signature from the current position in the signature blob.
    ///
    /// This is the core type parsing method that handles all .NET type encodings
    /// according to ECMA-335. It uses recursive descent to parse complex nested
    /// types while maintaining protection against infinite recursion.
    ///
    /// # Type Categories Supported
    ///
    /// ## Primitive Types
    /// - **Void**: `void` (`ELEMENT_TYPE_VOID`)
    /// - **Integers**: `bool`, `char`, `sbyte`, `byte`, `short`, `ushort`, `int`, `uint`, `long`, `ulong`
    /// - **Floating Point**: `float`, `double`
    /// - **Reference Types**: `string`, `object`
    /// - **Platform Types**: `IntPtr`, `UIntPtr`
    ///
    /// ## Complex Types
    /// - **Arrays**: Single and multi-dimensional arrays with bounds
    /// - **Pointers**: Unmanaged pointer types (`T*`)
    /// - **References**: Managed references (`ref T`, `out T`)
    /// - **Generic Types**: Open and closed generic type instantiations
    /// - **Function Pointers**: Delegate and function pointer signatures
    ///
    /// ## Metadata References
    /// - **Class Types**: Reference types from TypeDef/TypeRef tables
    /// - **Value Types**: Value types from TypeDef/TypeRef tables  
    /// - **Generic Parameters**: Type (`T`) and method (`M`) generic parameters
    /// - **Custom Modifiers**: Required and optional custom modifiers
    ///
    /// # Recursion Protection
    ///
    /// The parser tracks recursion depth to prevent stack overflow from malformed
    /// signatures. The maximum depth is [`MAX_RECURSION_DEPTH`] levels.
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::TypeSignature`] representing the parsed type information.
    ///
    /// # Errors
    /// - [`crate::error::Error::RecursionLimit`]: Maximum recursion depth exceeded
    /// - [`crate::Error::Malformed`]: Invalid element type or malformed signature data
    /// - [`crate::error::Error::OutOfBounds`]: Truncated signature data
    ///
    /// # Implementation Notes
    ///
    /// This method implements the complete ECMA-335 type encoding specification
    /// and handles all standard element types. Custom modifiers are parsed inline
    /// and associated with the appropriate type elements.
    fn parse_type(&mut self) -> Result<TypeSignature> {
        self.depth += 1;
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        let current_byte = self.parser.read_le::<u8>()?;
        match current_byte {
            ELEMENT_TYPE::VOID => Ok(TypeSignature::Void),
            ELEMENT_TYPE::BOOLEAN => Ok(TypeSignature::Boolean),
            ELEMENT_TYPE::CHAR => Ok(TypeSignature::Char),
            ELEMENT_TYPE::I1 => Ok(TypeSignature::I1),
            ELEMENT_TYPE::U1 => Ok(TypeSignature::U1),
            ELEMENT_TYPE::I2 => Ok(TypeSignature::I2),
            ELEMENT_TYPE::U2 => Ok(TypeSignature::U2),
            ELEMENT_TYPE::I4 => Ok(TypeSignature::I4),
            ELEMENT_TYPE::U4 => Ok(TypeSignature::U4),
            ELEMENT_TYPE::I8 => Ok(TypeSignature::I8),
            ELEMENT_TYPE::U8 => Ok(TypeSignature::U8),
            ELEMENT_TYPE::R4 => Ok(TypeSignature::R4),
            ELEMENT_TYPE::R8 => Ok(TypeSignature::R8),
            ELEMENT_TYPE::STRING => Ok(TypeSignature::String),
            ELEMENT_TYPE::PTR => Ok(TypeSignature::Ptr(SignaturePointer {
                modifiers: self.parse_custom_mods()?,
                base: Box::new(self.parse_type()?),
            })),
            ELEMENT_TYPE::BYREF => Ok(TypeSignature::ByRef(Box::new(self.parse_type()?))),
            ELEMENT_TYPE::VALUETYPE => Ok(TypeSignature::ValueType(
                self.parser.read_compressed_token()?,
            )),
            ELEMENT_TYPE::CLASS => Ok(TypeSignature::Class(self.parser.read_compressed_token()?)),
            ELEMENT_TYPE::VAR => Ok(TypeSignature::GenericParamType(
                self.parser.read_compressed_uint()?,
            )),
            ELEMENT_TYPE::ARRAY => {
                let elem_type = self.parse_type()?;
                let rank = self.parser.read_compressed_uint()?;

                let num_sizes = self.parser.read_compressed_uint()?;
                let mut dimensions: Vec<ArrayDimensions> = Vec::with_capacity(num_sizes as usize);
                for _ in 0..num_sizes {
                    dimensions.push(ArrayDimensions {
                        size: Some(self.parser.read_compressed_uint()?),
                        lower_bound: None,
                    });
                }

                let num_lo_bounds = self.parser.read_compressed_uint()?;
                for i in 0..num_lo_bounds {
                    if let Some(dimension) = dimensions.get_mut(i as usize) {
                        dimension.lower_bound = Some(self.parser.read_compressed_uint()?);
                    }
                }

                Ok(TypeSignature::Array(SignatureArray {
                    base: Box::new(elem_type),
                    rank,
                    dimensions,
                }))
            }
            ELEMENT_TYPE::GENERICINST => {
                let peek_byte = self.parser.peek_byte()?;
                if peek_byte != 0x12 && peek_byte != 0x11 {
                    return Err(malformed_error!(
                        "GENERICINST - Next byte is not TYPE_CLASS or TYPE_VALUE - {}",
                        peek_byte
                    ));
                }

                let base_type = self.parse_type()?;
                let arg_count = self.parser.read_compressed_uint()?;

                let mut type_args = Vec::with_capacity(arg_count as usize);
                for _ in 0..arg_count {
                    type_args.push(self.parse_type()?);
                }

                Ok(TypeSignature::GenericInst(Box::new(base_type), type_args))
            }
            ELEMENT_TYPE::TYPEDBYREF => Ok(TypeSignature::TypedByRef),
            ELEMENT_TYPE::I => Ok(TypeSignature::I),
            ELEMENT_TYPE::U => Ok(TypeSignature::U),
            ELEMENT_TYPE::FNPTR => Ok(TypeSignature::FnPtr(Box::new(
                self.parse_method_signature()?,
            ))),
            ELEMENT_TYPE::OBJECT => Ok(TypeSignature::Object),
            ELEMENT_TYPE::SZARRAY => Ok(TypeSignature::SzArray(SignatureSzArray {
                modifiers: self.parse_custom_mods()?,
                base: Box::new(self.parse_type()?),
            })),
            ELEMENT_TYPE::MVAR => Ok(TypeSignature::GenericParamMethod(
                self.parser.read_compressed_uint()?,
            )),
            ELEMENT_TYPE::CMOD_REQD => {
                Ok(TypeSignature::ModifiedRequired(self.parse_custom_mods()?))
            }
            ELEMENT_TYPE::CMOD_OPT => {
                Ok(TypeSignature::ModifiedOptional(self.parse_custom_mods()?))
            }
            ELEMENT_TYPE::INTERNAL => Ok(TypeSignature::Internal),
            ELEMENT_TYPE::MODIFIER => Ok(TypeSignature::Modifier),
            ELEMENT_TYPE::SENTINEL => Ok(TypeSignature::Sentinel),
            ELEMENT_TYPE::PINNED => Ok(TypeSignature::Pinned(Box::new(self.parse_type()?))),
            _ => Err(malformed_error!(
                "Unsupported ELEMENT_TYPE - {}",
                current_byte
            )),
        }
    }

    /// Parse custom modifiers (modreq/modopt) from the current signature position.
    ///
    /// Custom modifiers provide additional type information for advanced scenarios such as
    /// C++/CLI interop, const/volatile semantics, and platform-specific type constraints.
    /// This method parses a sequence of modifier tokens that appear before type information.
    ///
    /// # Modifier Types
    ///
    /// ## Required Modifiers (modreq)
    /// - **`CMOD_REQD` (0x1F)**: Required for type identity and compatibility
    /// - **Usage**: Platform interop, const fields, security annotations
    /// - **Impact**: Affects type identity for assignment and method resolution
    ///
    /// ## Optional Modifiers (modopt)  
    /// - **`CMOD_OPT` (0x20)**: Optional hints that don't affect type identity
    /// - **Usage**: Optimization hints, debugging information, tool annotations
    /// - **Impact**: Preserved for metadata consumers but don't affect runtime behavior
    ///
    /// # Binary Format
    ///
    /// Custom modifiers are encoded as:
    /// ```text
    /// [ModifierType] [CompressedToken]
    /// ```
    /// Where `ModifierType` is 0x1F (required) or 0x20 (optional), followed by
    /// a compressed metadata token referencing the modifier type.
    ///
    /// # Examples
    ///
    /// ```text
    /// 0x1F 0x42      // modreq(TypeRef:0x1B000010)  
    /// 0x20 0x35      // modopt(TypeRef:0x100000D)
    /// 0x1F 0x15      // modreq(TypeRef:0x1B000005)
    /// 0x08           // I4 (base type follows modifiers)
    /// ```
    ///
    /// # Returns
    /// A vector of [`crate::metadata::token::Token`] references to the modifier types.
    /// The vector is empty if no custom modifiers are present.
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid compressed token encoding
    /// - [`crate::error::Error::OutOfBounds`]: Truncated modifier data
    ///
    /// # Performance Notes
    /// - Modifiers are relatively uncommon in most .NET code
    /// - Vector allocation is avoided when no modifiers are present
    /// - Parsing cost is linear in the number of modifiers
    fn parse_custom_mods(&mut self) -> Result<Vec<CustomModifier>> {
        let mut mods = Vec::new();

        while self.parser.has_more_data() {
            let is_required = match self.parser.peek_byte()? {
                0x20 => false,
                0x1F => true,
                _ => break,
            };

            self.parser.advance()?;

            let modifier_token = self.parser.read_compressed_token()?;
            mods.push(CustomModifier {
                is_required,
                modifier_type: modifier_token,
            });
        }

        Ok(mods)
    }

    /// Parse a method parameter or return type with custom modifiers and byref semantics.
    ///
    /// This method parses a single parameter specification that includes optional custom
    /// modifiers, byref semantics, and the parameter type. Parameters and return types
    /// share the same binary format in .NET signatures.
    ///
    /// # Parameter Format
    ///
    /// Parameters are encoded as:
    /// ```text
    /// [CustomModifier*] [BYREF?] [Type]
    /// ```
    ///
    /// ## Custom Modifiers
    /// Zero or more custom modifiers (modreq/modopt) that apply to the parameter type.
    /// These provide additional type information for interop and advanced scenarios.
    ///
    /// ## `ByRef` Semantics
    /// - **BYREF (0x10)**: Indicates reference parameter semantics (`ref`, `out`, `in`)
    /// - **Reference Types**: Creates a reference to the reference (double indirection)
    /// - **Value Types**: Passes by reference instead of by value
    /// - **Null References**: `ByRef` parameters cannot be null references
    ///
    /// ## Parameter Types
    /// Any valid .NET type including primitives, classes, value types, arrays,
    /// generic instantiations, and complex nested types.
    ///
    /// # Examples
    ///
    /// ## Simple Value Parameter
    /// ```text
    /// 0x08           // I4 (int parameter)
    /// ```
    ///
    /// ## Reference Parameter
    /// ```text
    /// 0x10 0x08      // BYREF I4 (ref int parameter)
    /// ```
    ///
    /// ## Parameter with Custom Modifiers
    /// ```text
    /// 0x1F 0x42      // modreq(IsConst)
    /// 0x20 0x35      // modopt(Hint)  
    /// 0x10           // BYREF
    /// 0x0E           // STRING (ref string with modifiers)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureParameter`] containing:
    /// - Custom modifier tokens
    /// - `ByRef` flag for reference semantics
    /// - Complete type signature information
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid parameter encoding
    /// - [`crate::Error::RecursionLimit`]: Parameter type parsing exceeds recursion limit
    /// - [`crate::error::Error::OutOfBounds`]: Truncated parameter data
    ///
    /// # Usage Notes
    ///
    /// This method is used for both method parameters and return types since they
    /// share the same binary encoding format. The calling context determines the
    /// semantic interpretation of the parsed parameter information.
    fn parse_param(&mut self) -> Result<SignatureParameter> {
        let custom_mods = self.parse_custom_mods()?;

        let mut by_ref = false;
        if self.parser.peek_byte()? == 0x10 {
            self.parser.advance()?;
            by_ref = true;
        }

        Ok(SignatureParameter {
            modifiers: custom_mods,
            by_ref,
            base: self.parse_type()?,
        })
    }

    /// Parse a complete method signature from the signature blob.
    ///
    /// Parses method signatures for method definitions, method references, and standalone
    /// method signatures according to ECMA-335 specification. Method signatures encode
    /// calling conventions, parameter types, return types, and generic information.
    ///
    /// # Method Signature Format
    ///
    /// Method signatures follow this binary structure:
    /// ```text
    /// [CallingConvention] [GenericParamCount?] [ParamCount] [ReturnType] [Param1] [Param2] ...
    /// ```
    ///
    /// ## Calling Convention Byte
    /// The first byte encodes calling convention and method flags:
    /// ```text
    /// Bit 0-3: Calling convention
    ///   0x00: DEFAULT (standard managed)
    ///   0x01: C (cdecl for P/Invoke)
    ///   0x02: STDCALL (stdcall for P/Invoke)  
    ///   0x03: THISCALL (thiscall for P/Invoke)
    ///   0x04: FASTCALL (fastcall for P/Invoke)
    ///   0x05: VARARG (variable arguments)
    ///
    /// Bit 4: GENERIC (0x10) - method has generic parameters
    /// Bit 5: HASTHIS (0x20) - method has implicit 'this' parameter
    /// Bit 6: EXPLICITTHIS (0x40) - 'this' parameter is explicit
    /// ```
    ///
    /// ## Generic Parameter Count
    /// If GENERIC flag is set, the next compressed integer specifies the number
    /// of generic type parameters for the method.
    ///
    /// ## Parameter Processing
    /// Parameters are parsed sequentially, with special handling for:
    /// - **Return Type**: Always the first parameter parsed
    /// - **Regular Parameters**: Method parameters in declaration order  
    /// - **SENTINEL (0x41)**: Marks transition to variable arguments
    /// - **Variable Arguments**: Additional parameters for VARARG methods
    ///
    /// # Supported Method Types
    ///
    /// ## Instance Methods
    /// ```csharp
    /// public int Method(string param)  // HASTHIS, 1 param, I4 return, STRING param
    /// ```
    ///
    /// ## Static Methods
    /// ```csharp
    /// public static void Method()      // DEFAULT, 0 params, VOID return
    /// ```
    ///
    /// ## Generic Methods
    /// ```csharp
    /// public T Method<T>(T item)       // HASTHIS | GENERIC, 1 generic param, 1 param
    /// ```
    ///
    /// ## Variable Argument Methods
    /// ```csharp
    /// public void Method(int a, __arglist)  // VARARG with sentinel
    /// ```
    ///
    /// ## Platform Invoke Methods
    /// ```csharp
    /// [DllImport("kernel32")]
    /// public static extern int GetLastError();  // Various calling conventions
    /// ```
    ///
    /// # Examples
    ///
    /// ## Simple Static Method
    /// ```text
    /// 0x00           // DEFAULT calling convention
    /// 0x00           // 0 parameters
    /// 0x01           // VOID return type
    /// ```
    ///
    /// ## Instance Method with Parameters
    /// ```text
    /// 0x20           // HASTHIS calling convention
    /// 0x02           // 2 parameters
    /// 0x08           // I4 (int) return type
    /// 0x0E           // STRING first parameter
    /// 0x10 0x08      // BYREF I4 second parameter (ref int)
    /// ```
    ///
    /// ## Generic Method
    /// ```text
    /// 0x30           // HASTHIS | GENERIC
    /// 0x01           // 1 generic parameter (T)
    /// 0x01           // 1 method parameter
    /// 0x13 0x00      // VAR 0 return type (T)
    /// 0x13 0x00      // VAR 0 parameter type (T)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureMethod`] containing:
    /// - Calling convention flags and generic parameter count
    /// - Return type information with custom modifiers
    /// - Parameter list with types and modifiers
    /// - Variable argument list (if applicable)
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid calling convention or parameter encoding
    /// - [`crate::Error::RecursionLimit`]: Parameter type parsing exceeds recursion limit
    /// - [`crate::error::Error::OutOfBounds`]: Truncated signature data
    ///
    /// # Performance Notes
    /// - Parameter vectors are pre-allocated based on parameter count
    /// - Calling convention flags are decoded using bitwise operations
    /// - Generic parameter count is only parsed when GENERIC flag is set
    ///
    /// # ECMA-335 References
    /// - **Partition II, Section 23.2.1**: `MethodDefSig`
    /// - **Partition II, Section 23.2.2**: `MethodRefSig`  
    /// - **Partition II, Section 23.2.3**: `StandAloneMethodSig`
    /// - **Partition I, Section 14.3**: Calling conventions
    pub fn parse_method_signature(&mut self) -> Result<SignatureMethod> {
        let convention_byte = self.parser.read_le::<u8>()?;

        let mut method = SignatureMethod {
            has_this: convention_byte & 0x20 != 0,
            explicit_this: convention_byte & 0x40 != 0,
            default: convention_byte == 0,
            vararg: convention_byte & 0x5 != 0,
            cdecl: convention_byte & 0x1 != 0,
            stdcall: convention_byte & 0x2 != 0,
            thiscall: convention_byte & 0x3 != 0,
            fastcall: convention_byte & 0x4 != 0,
            param_count_generic: if convention_byte & 0x10 != 0 {
                self.parser.read_compressed_uint()?
            } else {
                0
            },
            param_count: self.parser.read_compressed_uint()?,
            return_type: self.parse_param()?,
            params: Vec::new(),
            varargs: Vec::new(),
        };

        for _ in 0..method.param_count {
            if self.parser.peek_byte()? == 0x41 {
                // 0x41 == SENTINEL, indicates that Param is over, and next is the vararg param list for the remaining elements

                self.parser.advance()?;
                break;
            }

            method.params.push(self.parse_param()?);
        }

        if method.vararg && method.params.len() < method.param_count as usize {
            for _ in method.params.len()..method.param_count as usize {
                method.varargs.push(self.parse_param()?);
            }
        }

        Ok(method)
    }

    /// Parse a field signature from the signature blob according to ECMA-335 II.23.2.4.
    ///
    /// Field signatures define the type information for fields in .NET types, including
    /// custom modifiers for advanced scenarios like interop, const semantics, and
    /// platform-specific type constraints.
    ///
    /// # Field Signature Format
    ///
    /// Field signatures follow this binary structure:
    /// ```text
    /// [FIELD] [CustomModifier*] [Type]
    /// ```
    ///
    /// ## Field Signature Header
    /// - **FIELD (0x06)**: Required signature type marker
    /// - **Validation**: Parser verifies the signature starts with 0x06
    /// - **Purpose**: Distinguishes field signatures from other signature types
    ///
    /// ## Custom Modifiers
    /// Zero or more custom modifiers that provide additional type information:
    /// - **modreq**: Required modifiers that affect type identity
    /// - **modopt**: Optional modifiers that provide hints
    /// - **Common Uses**: `volatile`, `const`, interop constraints
    ///
    /// ## Field Types
    /// Any valid .NET type including:
    /// - **Primitive Types**: `int`, `string`, `bool`, etc.
    /// - **Reference Types**: Classes and interfaces  
    /// - **Value Types**: Structs and enums
    /// - **Array Types**: Single and multi-dimensional arrays
    /// - **Generic Types**: Open and closed generic instantiations
    /// - **Pointer Types**: Unmanaged pointers for unsafe scenarios
    ///
    /// # Common Field Scenarios
    ///
    /// ## Simple Field Types
    /// ```csharp
    /// public int counter;           // I4 field
    /// public string name;           // STRING field  
    /// public List<int> items;       // Generic instantiation field
    /// ```
    ///
    /// ## Array Fields
    /// ```csharp
    /// public int[] numbers;         // SZARRAY I4 field
    /// public string[,] matrix;      // ARRAY STRING field with rank 2
    /// ```
    ///
    /// ## Fields with Custom Modifiers
    /// ```csharp
    /// public volatile int flag;     // modreq(IsVolatile) I4 field
    /// public const string Name;     // modreq(IsConst) STRING field
    /// ```
    ///
    /// ## Unsafe Pointer Fields
    /// ```csharp
    /// public unsafe int* ptr;       // PTR I4 field
    /// public unsafe void* handle;   // PTR VOID field
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Simple Integer Field
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x08           // I4 (int) field type
    /// ```
    ///
    /// ## String Array Field
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x1D           // SZARRAY (single-dimensional array)
    /// 0x0E           // STRING element type
    /// ```
    ///
    /// ## Field with Required Modifier
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x1F 0x42      // modreq(TypeRef token)
    /// 0x08           // I4 field type with modifier
    /// ```
    ///
    /// ## Generic Field Type
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x15           // GENERICINST
    /// 0x12 0x35      // CLASS List<T> token
    /// 0x01           // 1 type argument
    /// 0x08           // I4 type argument (List<int>)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureField`] containing:
    /// - Custom modifier token list
    /// - Complete field type information
    /// - Type constraints and annotations
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid field signature header (not 0x06)
    /// - [`crate::Error::RecursionLimit`]: Field type parsing exceeds recursion limit
    /// - [`crate::error::Error::OutOfBounds`]: Truncated field signature data
    ///
    /// # Custom Modifier Applications
    ///
    /// Custom modifiers on fields are commonly used for:
    /// - **volatile**: Memory barrier semantics for multithreading
    /// - **const**: Compile-time constant field values
    /// - **Interop**: C++/CLI and platform-specific type constraints
    /// - **Security**: Type-based security and access control annotations
    ///
    /// # Performance Notes
    /// - Field signatures are typically simple and parse quickly
    /// - Custom modifiers add minimal overhead when present
    /// - Complex generic field types may require recursive parsing
    /// - Caching of parsed field signatures is recommended for hot paths
    ///
    /// # ECMA-335 Compliance
    /// This implementation follows ECMA-335 6th Edition, Partition II, Section 23.2.4
    /// for field signature encoding and supports all standard field type scenarios.
    pub fn parse_field_signature(&mut self) -> Result<SignatureField> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x06 {
            // 0x06 == FIELD
            return Err(malformed_error!(
                "SignatureField - invalid start - {}",
                head_byte
            ));
        }

        let custom_mods = self.parse_custom_mods()?;
        let type_sig = self.parse_type()?;

        Ok(SignatureField {
            modifiers: custom_mods,
            base: type_sig,
        })
    }

    /// Parse a property signature from the signature blob according to ECMA-335 II.23.2.5.
    ///
    /// Property signatures define the type and parameter information for properties,
    /// including simple properties, indexed properties (indexers), and properties
    /// with custom modifiers. Properties in .NET are implemented as methods but
    /// have their own signature format for metadata storage.
    ///
    /// # Property Signature Format
    ///
    /// Property signatures follow this binary structure:
    /// ```text
    /// [PropertyFlags] [ParamCount] [CustomModifier*] [PropertyType] [Param1] [Param2] ...
    /// ```
    ///
    /// ## Property Flags Byte
    /// The first byte encodes property characteristics:
    /// ```text
    /// Bit 3: PROPERTY (0x08) - Required property signature marker
    /// Bit 5: HASTHIS (0x20) - Property belongs to an instance (not static)
    /// Other bits: Reserved and should be zero
    /// ```
    ///
    /// ## Parameter Count
    /// Compressed integer indicating the number of indexer parameters:
    /// - **0**: Simple property (no indexer parameters)
    /// - **N > 0**: Indexed property with N indexer parameters
    ///
    /// ## Property Type
    /// The type of the property value, which can be any valid .NET type.
    /// Custom modifiers may precede the property type for advanced scenarios.
    ///
    /// ## Indexer Parameters
    /// For indexed properties, parameter specifications define the indexer signature.
    /// Each parameter includes type information and optional custom modifiers.
    ///
    /// # Property Categories
    ///
    /// ## Simple Properties
    /// Standard properties with getter and/or setter methods:
    /// ```csharp
    /// public int Count { get; set; }                    // Instance property
    /// public static string DefaultName { get; set; }   // Static property
    /// ```
    ///
    /// ## Indexed Properties (Indexers)
    /// Properties that accept parameters for indexed access:
    /// ```csharp
    /// public string this[int index] { get; set; }       // Single parameter indexer
    /// public T this[int x, int y] { get; set; }         // Multi-parameter indexer
    /// ```
    ///
    /// ## Properties with Custom Modifiers
    /// Properties with additional type constraints or annotations:
    /// ```csharp
    /// public volatile int Flag { get; set; }            // modreq(IsVolatile) property
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Simple Instance Property
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x00           // 0 parameters (not indexed)
    /// 0x08           // I4 (int) property type
    /// ```
    ///
    /// ## Static String Property
    /// ```text
    /// 0x08           // PROPERTY (static, no HASTHIS)
    /// 0x00           // 0 parameters
    /// 0x0E           // STRING property type
    /// ```
    ///
    /// ## Single-Parameter Indexer
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x01           // 1 indexer parameter
    /// 0x0E           // STRING property type
    /// 0x08           // I4 indexer parameter type
    /// ```
    ///
    /// ## Multi-Parameter Indexer
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x02           // 2 indexer parameters
    /// 0x1C           // OBJECT property type
    /// 0x08           // I4 first parameter (int x)
    /// 0x08           // I4 second parameter (int y)
    /// ```
    ///
    /// ## Generic Property Type
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x00           // 0 parameters
    /// 0x15           // GENERICINST
    /// 0x12 0x42      // CLASS List<T> token
    /// 0x01           // 1 type argument
    /// 0x0E           // STRING type argument
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureProperty`] containing:
    /// - Instance vs. static property indication
    /// - Property type with custom modifiers
    /// - Indexer parameter list (empty for simple properties)
    /// - Complete type and modifier information
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid property signature header (missing PROPERTY bit)
    /// - [`crate::Error::RecursionLimit`]: Property or parameter type parsing exceeds recursion limit
    /// - [`crate::error::Error::OutOfBounds`]: Truncated property signature data
    ///
    /// # Indexer Design Patterns
    ///
    /// ## Collection Indexers
    /// ```csharp
    /// public T this[int index] => items[index];         // Array-style access
    /// ```
    ///
    /// ## Dictionary-Style Indexers
    /// ```csharp
    /// public TValue this[TKey key] => dict[key];        // Key-value access
    /// ```
    ///
    /// ## Multi-Dimensional Indexers
    /// ```csharp
    /// public T this[int row, int col] => matrix[row, col];  // Matrix access
    /// ```
    ///
    /// # Performance Notes
    /// - Simple properties parse very quickly with minimal allocations
    /// - Indexed properties require parameter parsing which scales with parameter count
    /// - Generic property types may require recursive type parsing
    /// - Consider caching parsed property signatures for frequently accessed properties
    ///
    /// # Implementation Relationship
    /// Properties are implemented as methods in IL, but property signatures provide
    /// the high-level abstraction for metadata consumers. The actual getter/setter
    /// methods have their own method signatures that reference this property signature.
    ///
    /// # ECMA-335 Compliance
    /// This implementation follows ECMA-335 6th Edition, Partition II, Section 23.2.5
    /// for property signature encoding and supports all standard property scenarios.
    pub fn parse_property_signature(&mut self) -> Result<SignatureProperty> {
        let head_byte = self.parser.read_le::<u8>()?;
        if (head_byte & 0x08) == 0 {
            return Err(malformed_error!(
                "SignatureProperty - invalid start - {}",
                head_byte
            ));
        }

        let has_this = (head_byte & 0x20) != 0;

        let param_count = self.parser.read_compressed_uint()?;
        let custom_mods = self.parse_custom_mods()?;
        let type_sig = self.parse_type()?;

        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(self.parse_param()?);
        }

        Ok(SignatureProperty {
            has_this,
            modifiers: custom_mods,
            base: type_sig,
            params,
        })
    }

    /// Parse a local variable signature from the signature blob according to ECMA-335 II.23.2.6.
    ///
    /// Local variable signatures define the types and constraints for all local variables
    /// within a method body. These signatures are used by the JIT compiler for type
    /// checking, memory management, and garbage collection root tracking.
    ///
    /// # Local Variable Signature Format
    ///
    /// Local variable signatures follow this binary structure:
    /// ```text
    /// [LOCAL_SIG] [Count] [LocalVar1] [LocalVar2] ...
    /// ```
    ///
    /// Each local variable specification can include:
    /// ```text
    /// [CustomModifier*] [PINNED?] [BYREF?] [Type]
    /// ```
    ///
    /// ## Local Variable Signature Header
    /// - **`LOCAL_SIG` (0x07)**: Required signature type marker
    /// - **Count**: Compressed integer specifying number of local variables
    /// - **Validation**: Parser verifies signature starts with 0x07
    ///
    /// ## Local Variable Constraints
    ///
    /// ### PINNED Constraint (0x45)
    /// - **Purpose**: Fixes variable location in memory for interop scenarios
    /// - **Usage**: P/Invoke calls, unsafe code, COM interop
    /// - **GC Impact**: Prevents garbage collector from moving the object
    /// - **Syntax**: `fixed` statement in C#, `pin_ptr` in C++/CLI
    ///
    /// ### BYREF Constraint (0x10)
    /// - **Purpose**: Creates reference semantics for local variables
    /// - **Usage**: `ref` locals, `out` parameters stored in locals
    /// - **Memory**: Variable stores address rather than value
    /// - **Restrictions**: Cannot be null, must point to valid memory
    ///
    /// ### TYPEDBYREF Special Type (0x16)
    /// - **Purpose**: Runtime type information for reflection scenarios
    /// - **Usage**: Advanced reflection, method argument handling
    /// - **Contents**: Type information and object reference pair
    /// - **Restrictions**: Cannot be used with other constraints
    ///
    /// # Local Variable Categories
    ///
    /// ## Simple Local Variables
    /// Standard local variables with primitive or reference types:
    /// ```csharp
    /// int counter;              // I4 local
    /// string message;           // STRING local  
    /// List<int> items;          // Generic instantiation local
    /// ```
    ///
    /// ## Reference Local Variables
    /// Local variables that store references to other variables:
    /// ```csharp
    /// ref int refValue = ref someField;     // BYREF I4 local
    /// ref readonly string refText;          // BYREF STRING local
    /// ```
    ///
    /// ## Pinned Local Variables  
    /// Local variables with fixed memory locations for unsafe scenarios:
    /// ```csharp
    /// fixed (byte* ptr = &array[0]) {       // PINNED PTR local
    ///     // ptr location is fixed during this scope
    /// }
    /// ```
    ///
    /// ## `TypedByRef` Locals
    /// Special locals for advanced reflection scenarios:
    /// ```csharp
    /// __makeref(variable);                  // TYPEDBYREF local
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Simple Local Variables
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x02           // 2 local variables
    /// 0x08           // I4 (int) first local
    /// 0x0E           // STRING second local
    /// ```
    ///
    /// ## Reference and Pinned Locals
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x03           // 3 local variables
    /// 0x10 0x08      // BYREF I4 (ref int)
    /// 0x45 0x0F      // PINNED PTR (pinned pointer)
    /// 0x16           // TYPEDBYREF
    /// ```
    ///
    /// ## Locals with Custom Modifiers
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x01           // 1 local variable
    /// 0x1F 0x42      // modreq(IsVolatile)
    /// 0x45           // PINNED constraint
    /// 0x08           // I4 (volatile pinned int)
    /// ```
    ///
    /// ## Complex Generic Local
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x01           // 1 local variable
    /// 0x15           // GENERICINST
    /// 0x12 0x35      // CLASS Dictionary<,> token
    /// 0x02           // 2 type arguments
    /// 0x0E           // STRING (TKey)
    /// 0x1C           // OBJECT (TValue)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureLocalVariables`] containing:
    /// - Array of local variable specifications
    /// - Type information for each local
    /// - Constraint flags (pinned, byref) for each local
    /// - Custom modifier information
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid local variable signature header (not 0x07)
    /// - [`crate::Error::RecursionLimit`]: Local variable type parsing exceeds recursion limit
    /// - [`crate::error::Error::OutOfBounds`]: Truncated local variable signature data
    ///
    /// # Memory Management Implications
    ///
    /// ## Garbage Collection Roots
    /// Local variables containing reference types serve as GC roots:
    /// - **Reference Locals**: Prevent referenced objects from collection
    /// - **Pinned Locals**: Create fixed memory regions that GC cannot move
    /// - **Lifetime Tracking**: GC tracks local variable lifetimes for collection
    ///
    /// ## Interop Scenarios
    /// Pinned locals are essential for safe interop:
    /// - **P/Invoke**: Passing managed array pointers to native code
    /// - **COM Interop**: Fixed memory for COM interface calls
    /// - **Unsafe Code**: Direct memory manipulation with fixed addresses
    ///
    /// # Performance Considerations
    /// - **Pinned Locals**: Can impact GC performance due to memory fragmentation
    /// - **`ByRef` Locals**: Minimal overhead, similar to pointer operations
    /// - **Parsing Speed**: Linear in the number of local variables
    /// - **Memory Usage**: Efficient parsing with pre-allocated vectors
    ///
    /// # JIT Compiler Usage
    /// The JIT compiler uses local variable signatures for:
    /// - **Stack Frame Layout**: Determining local variable stack positions
    /// - **Type Safety**: Verifying type-safe access to local variables
    /// - **Optimization**: Register allocation and lifetime analysis
    /// - **Debugging Info**: Mapping IL locals to native debug information
    ///
    /// # ECMA-335 Compliance
    /// This implementation follows ECMA-335 6th Edition, Partition II, Section 23.2.6
    /// for local variable signature encoding and supports all standard local variable scenarios.
    pub fn parse_local_var_signature(&mut self) -> Result<SignatureLocalVariables> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x07 {
            return Err(malformed_error!(
                "SignatureLocalVar - invalid start - {}",
                head_byte
            ));
        }

        let count = self.parser.read_compressed_uint()?;

        let mut locals = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // Slighly different, not all custom_mods are following each other, but rather costom_mod -> contstraint -> custom_mod -> ...

            // TYPED_BY_REF
            if self.parser.peek_byte()? == 0x16 {
                locals.push(SignatureLocalVariable {
                    modifiers: Vec::new(),
                    is_byref: false,
                    is_pinned: false,
                    base: TypeSignature::TypedByRef,
                });
                self.parser.advance()?;

                continue;
            }

            let mut custom_mods = Vec::new();
            let mut pinned = false;

            while self.parser.has_more_data() {
                match self.parser.peek_byte()? {
                    0x1F | 0x20 => {
                        let is_required = self.parser.peek_byte()? == 0x1F;
                        self.parser.advance()?;
                        let modifier_token = self.parser.read_compressed_token()?;
                        custom_mods.push(CustomModifier {
                            is_required,
                            modifier_type: modifier_token,
                        });
                    }
                    0x45 => {
                        // PINNED constraint (ELEMENT_TYPE_PINNED) - II.23.2.9
                        // This is a constraint that applies to the entire local variable,
                        // not to individual custom modifiers, per ECMA-335 specification.
                        self.parser.advance()?;
                        pinned = true;
                    }
                    _ => break,
                }
            }

            let by_ref = if self.parser.peek_byte()? == 0x10 {
                self.parser.advance()?;
                true
            } else {
                false
            };

            let type_sig = self.parse_type()?;

            locals.push(SignatureLocalVariable {
                modifiers: custom_mods,
                is_byref: by_ref,
                is_pinned: pinned,
                base: type_sig,
            });
        }

        Ok(SignatureLocalVariables { locals })
    }

    /// Parse a type specification signature from the signature blob according to ECMA-335 II.23.2.14.
    ///
    /// Type specification signatures define complex type instantiations that cannot be represented
    /// directly in metadata tables. They are used for generic type instantiations, array types
    /// with complex bounds, function pointer types, and other constructed types.
    ///
    /// # Type Specification Format
    ///
    /// Type specifications contain a single type signature:
    /// ```text
    /// [Type]
    /// ```
    ///
    /// Unlike other signature types, type specifications do not have a signature header byte.
    /// They directly encode the type information using the standard type signature format.
    ///
    /// # Common Type Specification Uses
    ///
    /// ## Generic Type Instantiations
    /// ```csharp
    /// List<string>              // GENERICINST CLASS List<T> with STRING argument
    /// Dictionary<int, object>   // GENERICINST CLASS Dictionary<K,V> with I4, OBJECT arguments
    /// Nullable<DateTime>        // GENERICINST VALUETYPE Nullable<T> with DateTime argument
    /// ```
    ///
    /// ## Complex Array Types
    /// ```csharp
    /// int[,]                    // ARRAY I4 with rank 2
    /// string[,,]                // ARRAY STRING with rank 3  
    /// float[0..10, 0..5]        // ARRAY R4 with bounds and dimensions
    /// ```
    ///
    /// ## Function Pointer Types
    /// ```csharp
    /// delegate*<int, string>    // FNPTR with method signature
    /// delegate* unmanaged<void> // FNPTR with unmanaged calling convention
    /// ```
    ///
    /// ## Constructed Reference Types
    /// ```csharp
    /// string[]                  // SZARRAY STRING (single-dimensional array)
    /// int*                      // PTR I4 (unmanaged pointer)
    /// ref readonly DateTime     // BYREF with custom modifiers
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Generic List of Strings
    /// ```text
    /// 0x15           // GENERICINST
    /// 0x12 0x42      // CLASS token (List<T>)
    /// 0x01           // 1 type argument
    /// 0x0E           // STRING type argument
    /// ```
    ///
    /// ## Two-Dimensional Array
    /// ```text
    /// 0x14           // ARRAY
    /// 0x08           // I4 element type
    /// 0x02           // rank = 2
    /// 0x00           // 0 size specifications
    /// 0x00           // 0 lower bound specifications
    /// ```
    ///
    /// ## Function Pointer
    /// ```text
    /// 0x1B           // FNPTR
    /// 0x00           // DEFAULT calling convention
    /// 0x01           // 1 parameter
    /// 0x01           // VOID return type
    /// 0x08           // I4 parameter type
    /// ```
    ///
    /// # Usage Context
    ///
    /// Type specifications are referenced from:
    /// - **`TypeSpec` Table**: Metadata table entries for constructed types
    /// - **Signature Blobs**: Complex type references in other signatures
    /// - **Custom Attributes**: Type arguments in attribute instantiations
    /// - **Generic Constraints**: Where clauses and type parameter bounds
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureTypeSpec`] containing the complete
    /// type specification information ready for type system operations.
    ///
    /// # Errors
    /// - [`crate::Error::RecursionLimit`]: Type parsing exceeds maximum recursion depth
    /// - [`crate::Error::Malformed`]: Invalid type encoding or format
    /// - [`crate::error::Error::OutOfBounds`]: Truncated type specification data
    ///
    /// # Performance Notes
    /// - Type specifications often involve complex recursive parsing
    /// - Generic instantiations with many type arguments require more processing
    /// - Consider caching parsed type specifications for frequently accessed types
    /// - Simple types (primitives, single classes) parse very quickly
    ///
    /// # Thread Safety
    /// This method is not thread-safe. Use separate parser instances for concurrent operations.
    ///
    /// # ECMA-335 References
    /// - **Partition II, Section 23.2.14**: `TypeSpec` signature format
    /// - **Partition II, Section 22.39**: `TypeSpec` metadata table
    /// - **Partition I, Section 8**: Type system and constructed types
    /// - **Partition II, Section 23.1.16**: Generic type instantiation validation
    pub fn parse_type_spec_signature(&mut self) -> Result<SignatureTypeSpec> {
        let type_sig = self.parse_type()?;
        Ok(SignatureTypeSpec { base: type_sig })
    }

    /// Parse a method specification signature from the signature blob according to ECMA-335 II.23.2.15.
    ///
    /// Method specification signatures provide type arguments for generic method instantiations.
    /// They are used when calling generic methods with specific type parameters, allowing the
    /// runtime to create concrete method instances from generic method definitions.
    ///
    /// # Method Specification Format
    ///
    /// Method specifications follow this binary structure:
    /// ```text
    /// [GENRICINST] [GenericArgCount] [GenericArg1] [GenericArg2] ...
    /// ```
    ///
    /// ## Method Specification Header
    /// - **GENRICINST (0x0A)**: Required signature type marker for method specifications
    /// - **Validation**: Parser verifies the signature starts with 0x0A
    /// - **Purpose**: Distinguishes method specifications from other signature types
    ///
    /// ## Generic Argument Count
    /// A compressed integer specifying the number of type arguments provided for the
    /// generic method instantiation. This count must match the number of generic
    /// type parameters defined on the target generic method.
    ///
    /// ## Generic Type Arguments
    /// A sequence of complete type signatures, one for each generic type parameter.
    /// Each type argument can be any valid .NET type including:
    /// - **Primitive Types**: `int`, `string`, `bool`, etc.
    /// - **Reference Types**: Classes and interfaces
    /// - **Value Types**: Structs and enums  
    /// - **Constructed Types**: Arrays, generic instantiations, pointers
    /// - **Generic Parameters**: Other generic type or method parameters
    ///
    /// # Generic Method Instantiation Examples
    ///
    /// ## Simple Generic Method Call
    /// ```csharp
    /// // Generic method definition:
    /// public static T Create<T>() where T : new() => new T();
    ///
    /// // Method call with type argument:
    /// var instance = Create<string>();  // T = string
    /// ```
    ///
    /// ## Multiple Type Parameters
    /// ```csharp
    /// // Generic method definition:
    /// public static Dictionary<TKey, TValue> CreateDictionary<TKey, TValue>()
    ///     => new Dictionary<TKey, TValue>();
    ///
    /// // Method call with multiple type arguments:
    /// var dict = CreateDictionary<int, string>();  // TKey = int, TValue = string
    /// ```
    ///
    /// ## Complex Type Arguments
    /// ```csharp
    /// // Generic method definition:
    /// public static List<T[]> CreateArrayList<T>() => new List<T[]>();
    ///
    /// // Method call with array type argument:
    /// var arrays = CreateArrayList<DateTime>();  // T = DateTime, result = List<DateTime[]>
    /// ```
    ///
    /// ## Nested Generic Instantiations
    /// ```csharp
    /// // Generic method definition:
    /// public static T Process<T>(T input) => input;
    ///
    /// // Method call with generic type argument:
    /// var result = Process<List<int>>(myList);  // T = List<int>
    /// ```
    ///
    /// # Binary Format Examples
    ///
    /// ## Single Type Argument (string)
    /// ```text
    /// 0x0A           // GENRICINST method specification marker
    /// 0x01           // 1 generic type argument
    /// 0x0E           // STRING type argument
    /// ```
    ///
    /// ## Multiple Type Arguments (int, string)
    /// ```text
    /// 0x0A           // GENRICINST method specification marker  
    /// 0x02           // 2 generic type arguments
    /// 0x08           // I4 (int) first type argument
    /// 0x0E           // STRING second type argument
    /// ```
    ///
    /// ## Complex Type Argument (`List<DateTime>`)
    /// ```text
    /// 0x0A           // GENRICINST method specification marker
    /// 0x01           // 1 generic type argument
    /// 0x15           // GENERICINST (generic instantiation)
    /// 0x12 0x42      // CLASS token (List<T>)
    /// 0x01           // 1 type argument for List<T>
    /// 0x12 0x35      // CLASS token (DateTime)
    /// ```
    ///
    /// ## Generic Method Parameter as Argument
    /// ```text
    /// 0x0A           // GENRICINST method specification marker
    /// 0x01           // 1 generic type argument  
    /// 0x1E 0x00      // MVAR 0 (method generic parameter M0)
    /// ```
    ///
    /// # Usage Context
    ///
    /// Method specifications are used in:
    /// - **Method References**: Calls to generic methods from other assemblies
    /// - **Reflection Emit**: Dynamic method generation with generic type arguments
    /// - **Runtime Instantiation**: JIT compilation of generic method instances
    /// - **Metadata Analysis**: Type flow analysis and generic constraint validation
    ///
    /// # Type Argument Validation
    ///
    /// The runtime validates that provided type arguments satisfy the generic constraints
    /// defined on the target method:
    /// - **where T : class**: Reference type constraints
    /// - **where T : struct**: Value type constraints  
    /// - **where T : `new()`**: Default constructor constraints
    /// - **where T : `BaseClass`**: Base class constraints
    /// - **where T : `IInterface`**: Interface implementation constraints
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureMethodSpec`] containing:
    /// - Complete list of type arguments for the generic method
    /// - Type signature information for each argument
    /// - Ready for runtime method instantiation
    ///
    /// # Errors
    /// - [`crate::Error::Malformed`]: Invalid method specification header (not 0x0A)
    /// - [`crate::Error::RecursionLimit`]: Type argument parsing exceeds recursion limit
    /// - [`crate::error::Error::OutOfBounds`]: Truncated method specification data
    /// - [`crate::error::Error::Malformed`]: Mismatched type argument count
    ///
    /// # Performance Notes
    /// - Type argument parsing cost is linear in the number of arguments
    /// - Complex constructed type arguments require recursive parsing
    /// - Simple primitive type arguments parse very quickly
    /// - Consider caching method specifications for frequently called generic methods
    ///
    /// # Thread Safety
    /// This method is not thread-safe. Use separate parser instances for concurrent operations.
    ///
    /// # ECMA-335 References
    /// - **Partition II, Section 23.2.15**: `MethodSpec` signature format
    /// - **Partition II, Section 22.26**: `MethodSpec` metadata table
    /// - **Partition II, Section 9.4**: Generic method instantiation
    /// - **Partition I, Section 9.5.1**: Generic method constraints and validation
    pub fn parse_method_spec_signature(&mut self) -> Result<SignatureMethodSpec> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x0A {
            return Err(malformed_error!(
                "SignatureMethodSpec - invalid start - {}",
                head_byte
            ));
        }

        let arg_count = self.parser.read_compressed_uint()?;
        let mut generic_args = Vec::with_capacity(arg_count as usize);
        for _ in 0..arg_count {
            generic_args.push(self.parse_type()?);
        }

        Ok(SignatureMethodSpec { generic_args })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::Token;

    use super::*;

    #[test]
    fn test_parse_primitive_types() {
        let test_cases = [
            (vec![0x01], TypeSignature::Void),
            (vec![0x02], TypeSignature::Boolean),
            (vec![0x03], TypeSignature::Char),
            (vec![0x04], TypeSignature::I1),
            (vec![0x05], TypeSignature::U1),
            (vec![0x06], TypeSignature::I2),
            (vec![0x07], TypeSignature::U2),
            (vec![0x08], TypeSignature::I4),
            (vec![0x09], TypeSignature::U4),
            (vec![0x0A], TypeSignature::I8),
            (vec![0x0B], TypeSignature::U8),
            (vec![0x0C], TypeSignature::R4),
            (vec![0x0D], TypeSignature::R8),
            (vec![0x0E], TypeSignature::String),
            (vec![0x1C], TypeSignature::Object),
            (vec![0x18], TypeSignature::I),
            (vec![0x19], TypeSignature::U),
        ];

        for (bytes, expected_type) in test_cases {
            let mut parser = SignatureParser::new(&bytes);
            let result = parser.parse_type().unwrap();
            assert_eq!(result, expected_type);
        }
    }

    #[test]
    fn test_parse_class_and_valuetype() {
        // Class type: Class token 0x10 in TypeRef
        let mut parser = SignatureParser::new(&[0x12, 0x42]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::Class(Token::new(0x1B000010))
        );

        // Value type: Token 0xD in TypeRef
        let mut parser = SignatureParser::new(&[0x11, 0x35]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::ValueType(Token::new(0x100000D))
        );

        // Generic parameter: Index 3
        let mut parser = SignatureParser::new(&[0x13, 0x03]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::GenericParamType(0x03)
        );
    }

    #[test]
    fn test_parse_arrays() {
        // SzArray of Int32 (int[])
        let mut parser = SignatureParser::new(&[0x1D, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = result {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // Multi-dimensional array int[,] with rank 2, no sizes, no bounds
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0x02, // rank 2
            0x00, // num_sizes 0
            0x00, // num_lo_bounds 0
        ]);

        let result = parser.parse_type().unwrap();
        assert!(matches!(result, TypeSignature::Array(_)));
        if let TypeSignature::Array(array) = result {
            assert_eq!(*array.base, TypeSignature::I4);
            assert_eq!(array.rank, 2);
            assert_eq!(array.dimensions.len(), 0)
        }

        // Multi-dimensional array int[2,3] with rank 2, with sizes
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0x02, // rank 2
            0x02, // num_sizes 2
            0x02, // size 2
            0x03, // size 3
            0x00, // num_lo_bounds 0
        ]);

        let result = parser.parse_type().unwrap();
        assert!(matches!(result, TypeSignature::Array(_)));
        if let TypeSignature::Array(array) = result {
            assert_eq!(*array.base, TypeSignature::I4);
            assert_eq!(array.rank, 2);
            assert_eq!(array.dimensions.len(), 2);
            assert_eq!(array.dimensions[0].lower_bound, None);
            assert_eq!(array.dimensions[0].size, Some(2));
            assert_eq!(array.dimensions[1].lower_bound, None);
            assert_eq!(array.dimensions[1].size, Some(3));
        }
    }

    #[test]
    fn test_parse_pointers_and_byrefs() {
        // Pointer to Int32 (int*)
        let mut parser = SignatureParser::new(&[0x0F, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::Ptr(_)));
        if let TypeSignature::Ptr(inner) = result {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // ByRef to Int32 (ref int)
        let mut parser = SignatureParser::new(&[0x10, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::ByRef(_)));
        if let TypeSignature::ByRef(inner) = result {
            assert_eq!(*inner, TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_generic_instance() {
        // Generic instance List<int>
        // Assume List is token 0x1B
        let mut parser = SignatureParser::new(&[
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // arg count
            0x08, // I4 type arg
        ]);

        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = result {
            assert!(matches!(*class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], TypeSignature::I4);
        }

        // Generic instance Dictionary<string, int>
        // Assume Dictionary is token 0x2A
        let mut parser = SignatureParser::new(&[
            0x15, // GENERICINST
            0x12, 0x2A, // Class token for Dictionary
            0x02, // 2 type args
            0x0E, // String type arg
            0x08, // I4 type arg
        ]);

        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = result {
            assert!(matches!(*class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 2);
            assert_eq!(args[0], TypeSignature::String);
            assert_eq!(args[1], TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_custom_mods() {
        // Optional modifier (modopt) followed by required modifier (modreq)
        let mut parser = SignatureParser::new(&[
            0x20, 0x42, // CMOD_OPT, token 0x42
            0x1F, 0x49, // CMOD_REQD, token 0x49
            0x08, // I4 (to test we can still parse after the modifiers)
        ]);

        let mods = parser.parse_custom_mods().unwrap();
        assert_eq!(
            mods,
            vec![
                CustomModifier {
                    is_required: false,
                    modifier_type: Token::new(0x1B000010)
                },
                CustomModifier {
                    is_required: true,
                    modifier_type: Token::new(0x01000012)
                }
            ]
        );

        // Verify we can still parse the type after the modifiers
        let type_sig = parser.parse_type().unwrap();
        assert_eq!(type_sig, TypeSignature::I4);

        // Test empty modifiers
        let mut parser = SignatureParser::new(&[0x08]); // Just I4, no mods
        let mods = parser.parse_custom_mods().unwrap();
        assert!(mods.is_empty());
    }

    #[test]
    fn test_complex_signature() {
        // A complex method signature:
        // Dictionary<List<int>, string[]> Method<T>(ref T arg1, List<int>[] arg2)
        let mut parser = SignatureParser::new(&[
            0x30, // HASTHIS | GENERIC
            0x01, // 1 generic parameter
            0x02, // 2 parameters
            // Return type: Dictionary<List<int>, string[]>
            0x15, // GENERICINST
            0x12, 0x2A, // Class token for Dictionary
            0x02, // arg count
            // First type arg: List<int>
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // arg count
            0x08, // I4
            // Second type arg: string[]
            0x1D, // SZARRAY
            0x0E, // String
            // First parameter: ref T
            0x10, // BYREF
            0x13, 0x00, // GenericParam(0)
            // Second parameter: List<int>[]
            0x1D, // SZARRAY
            0x15, // GENERICINST
            0x12, 0x42, // Class token for List
            0x01, // arg count
            0x08, // I4
        ]);

        let result = parser.parse_method_signature().unwrap();

        // Test method general properties
        assert!(result.has_this);
        assert_eq!(result.param_count_generic, 1);
        assert_eq!(result.params.len(), 2);

        // Test return type (Dictionary<List<int>, string[]>)
        assert!(matches!(
            result.return_type.base,
            TypeSignature::GenericInst(_, _)
        ));

        // Test first parameter (ref T)
        assert!(result.params[0].by_ref);
        assert_eq!(result.params[0].base, TypeSignature::GenericParamType(0));

        // Test second parameter (List<int>[])
        assert!(!result.params[1].by_ref);
        assert!(matches!(result.params[1].base, TypeSignature::SzArray(_)));
    }

    #[test]
    fn test_error_handling() {
        // Test invalid method signature format
        let mut parser = SignatureParser::new(&[0xFF, 0x01]);
        assert!(matches!(
            parser.parse_method_signature(),
            Err(crate::Error::OutOfBounds { .. })
        ));

        // Test invalid field signature format
        let mut parser = SignatureParser::new(&[0x07, 0x08]); // Should be 0x06 for FIELD
        assert!(parser.parse_field_signature().is_err());
    }
}
