//! Core types and constants for .NET marshalling.
//!
//! This module defines the fundamental types, constants, and data structures used in .NET
//! marshalling for P/Invoke, COM interop, and Windows Runtime scenarios according to
//! ECMA-335 II.23.2.9 and CoreCLR extensions.

#[allow(non_snake_case)]
/// Native type constants as defined in ECMA-335 II.23.2.9 and `CoreCLR` extensions.
///
/// This module contains byte constants representing all native types used in .NET marshalling
/// descriptors. The constants are organized according to the ECMA-335 specification with
/// additional types from `CoreCLR` runtime and Windows Runtime (`WinRT`) support.
///
/// # Constant Categories
///
/// - **Primitive Types** (0x01-0x0c): Basic numeric and boolean types
/// - **String Types** (0x13-0x16, 0x30): Various string encodings and formats
/// - **COM Types** (0x0e-0x12, 0x19-0x1a, 0x2e): COM and OLE automation types
/// - **Array Types** (0x1d-0x1e, 0x2a): Fixed and variable arrays
/// - **Pointer Types** (0x10, 0x2b): Raw and structured pointers
/// - **Special Types** (0x17-0x2d): Structured types, interfaces, and custom marshaling
/// - **`WinRT` Types** (0x2e-0x30): Windows Runtime specific types
///
/// # Usage in Marshalling Descriptors
///
/// These constants appear as the first byte(s) in marshalling descriptors, followed by
/// optional parameter data depending on the specific native type requirements.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::marshalling::NATIVE_TYPE;
///
/// // Simple types have no additional parameters
/// let simple_descriptor = &[NATIVE_TYPE::I4];
///
/// // Complex types may have parameters
/// let string_descriptor = &[NATIVE_TYPE::LPSTR, 0x05]; // LPSTR with size param 5
/// let array_descriptor = &[NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03]; // Array of I4
/// ```
pub mod NATIVE_TYPE {
    /// End marker (0x00) - Indicates the end of a marshalling descriptor
    pub const END: u8 = 0x00;
    /// Void type (0x01) - Represents no type or void return
    pub const VOID: u8 = 0x01;
    /// Boolean type (0x02) - 1-byte boolean value
    pub const BOOLEAN: u8 = 0x02;
    /// Signed 8-bit integer (0x03) - sbyte in C#
    pub const I1: u8 = 0x03;
    /// Unsigned 8-bit integer (0x04) - byte in C#
    pub const U1: u8 = 0x04;
    /// Signed 16-bit integer (0x05) - short in C#
    pub const I2: u8 = 0x05;
    /// Unsigned 16-bit integer (0x06) - ushort in C#
    pub const U2: u8 = 0x06;
    /// Signed 32-bit integer (0x07) - int in C#
    pub const I4: u8 = 0x07;
    /// Unsigned 32-bit integer (0x08) - uint in C#
    pub const U4: u8 = 0x08;
    /// Signed 64-bit integer (0x09) - long in C#
    pub const I8: u8 = 0x09;
    /// Unsigned 64-bit integer (0x0a) - ulong in C#
    pub const U8: u8 = 0x0a;
    /// 32-bit floating point (0x0b) - float in C#
    pub const R4: u8 = 0x0b;
    /// 64-bit floating point (0x0c) - double in C#
    pub const R8: u8 = 0x0c;
    /// System character type (0x0d) - Platform-dependent character
    pub const SYSCHAR: u8 = 0x0d;
    /// COM VARIANT type (0x0e) - OLE automation variant
    pub const VARIANT: u8 = 0x0e;
    /// Currency type (0x0f) - OLE automation currency (8-byte scaled integer)
    pub const CURRENCY: u8 = 0x0f;
    /// Pointer type (0x10) - Raw pointer, may have optional target type
    pub const PTR: u8 = 0x10;
    /// Decimal type (0x11) - .NET decimal (16-byte scaled integer)
    pub const DECIMAL: u8 = 0x11;
    /// Date type (0x12) - OLE automation date (8-byte floating point)
    pub const DATE: u8 = 0x12;
    /// BSTR type (0x13) - OLE automation string (length-prefixed wide string)
    pub const BSTR: u8 = 0x13;
    /// LPSTR type (0x14) - Null-terminated ANSI string pointer
    pub const LPSTR: u8 = 0x14;
    /// LPWSTR type (0x15) - Null-terminated Unicode string pointer
    pub const LPWSTR: u8 = 0x15;
    /// LPTSTR type (0x16) - Null-terminated platform string pointer (ANSI/Unicode)
    pub const LPTSTR: u8 = 0x16;
    /// Fixed system string (0x17) - Fixed-length character array
    pub const FIXEDSYSSTRING: u8 = 0x17;
    /// Object reference (0x18) - Managed object reference
    pub const OBJECTREF: u8 = 0x18;
    /// `IUnknown` interface (0x19) - COM `IUnknown` interface pointer
    pub const IUNKNOWN: u8 = 0x19;
    /// `IDispatch` interface (0x1a) - COM `IDispatch` interface pointer
    pub const IDISPATCH: u8 = 0x1a;
    /// Struct type (0x1b) - Native structure with optional packing/size info
    pub const STRUCT: u8 = 0x1b;
    /// Interface type (0x1c) - COM interface with optional IID parameter
    pub const INTERFACE: u8 = 0x1c;
    /// Safe array (0x1d) - COM safe array with variant type information
    pub const SAFEARRAY: u8 = 0x1d;
    /// Fixed array (0x1e) - Fixed-size array with element count
    pub const FIXEDARRAY: u8 = 0x1e;
    /// Platform integer (0x1f) - Platform-dependent signed integer (32/64-bit)
    pub const INT: u8 = 0x1f;
    /// Platform unsigned integer (0x20) - Platform-dependent unsigned integer (32/64-bit)
    pub const UINT: u8 = 0x20;
    /// Nested struct (0x21) - Nested structure (value type)
    pub const NESTEDSTRUCT: u8 = 0x21;
    /// By-value string (0x22) - Fixed-length string embedded in structure
    pub const BYVALSTR: u8 = 0x22;
    /// ANSI BSTR (0x23) - ANSI version of BSTR
    pub const ANSIBSTR: u8 = 0x23;
    /// TBSTR type (0x24) - Platform-dependent BSTR (ANSI/Unicode)
    pub const TBSTR: u8 = 0x24;
    /// Variant boolean (0x25) - COM `VARIANT_BOOL` (2-byte boolean)
    pub const VARIANTBOOL: u8 = 0x25;
    /// Function pointer (0x26) - Native function pointer
    pub const FUNC: u8 = 0x26;
    /// `AsAny` type (0x28) - Marshal as any compatible type
    pub const ASANY: u8 = 0x28;
    /// Array type (0x2a) - Variable array with element type and optional parameters
    pub const ARRAY: u8 = 0x2a;
    /// Pointer to struct (0x2b) - Pointer to native structure
    pub const LPSTRUCT: u8 = 0x2b;
    /// Custom marshaler (0x2c) - User-defined custom marshaling
    pub const CUSTOMMARSHALER: u8 = 0x2c;
    /// Error type (0x2d) - HRESULT or error code
    pub const ERROR: u8 = 0x2d;
    /// `IInspectable` interface (0x2e) - Windows Runtime `IInspectable` interface
    pub const IINSPECTABLE: u8 = 0x2e;
    /// HSTRING type (0x2f) - Windows Runtime string handle
    pub const HSTRING: u8 = 0x2f;
    /// UTF-8 string pointer (0x30) - Null-terminated UTF-8 string pointer
    pub const LPUTF8STR: u8 = 0x30;
    /// Maximum valid native type (0x50) - Upper bound for validation
    pub const MAX: u8 = 0x50;
}

#[allow(non_snake_case)]
/// COM VARIANT type constants for safe array marshalling.
///
/// This module contains constants representing COM VARIANT types (VARTYPE) as defined
/// in the OLE automation specification. These types are used primarily with safe arrays
/// and COM interop scenarios to specify the element type of collections.
///
/// # Constant Categories
///
/// - **Basic Types** (0-25): Fundamental types like integers, floats, strings
/// - **Pointer Types** (26-31): Pointer variants of basic types
/// - **Complex Types** (36-38): Records and platform-specific pointer types
/// - **Extended Types** (64-72): File times, blobs, and storage types
/// - **Modifiers** (0x1000-0x4000): Type modifiers for vectors, arrays, and references
///
/// # Usage with Safe Arrays
///
/// When marshalling safe arrays, the VARTYPE specifies the element type:
///
/// ```rust,ignore
/// use dotscope::metadata::marshalling::VARIANT_TYPE;
///
/// // Safe array of 32-bit integers
/// let element_type = VARIANT_TYPE::I4;
///
/// // Safe array of BSTRs (COM strings)
/// let string_array_type = VARIANT_TYPE::BSTR;
/// ```
///
/// # Type Modifiers
///
/// The high-order bits can modify the base type:
/// - [`VARIANT_TYPE::VECTOR`]: One-dimensional array
/// - [`VARIANT_TYPE::ARRAY`]: Multi-dimensional array  
/// - [`VARIANT_TYPE::BYREF`]: Passed by reference
/// - [`VARIANT_TYPE::TYPEMASK`]: Mask to extract base type
pub mod VARIANT_TYPE {
    /// Empty/uninitialized variant (0)
    pub const EMPTY: u16 = 0;
    /// Null variant (1) - Represents SQL NULL
    pub const NULL: u16 = 1;
    /// 16-bit signed integer (2) - short
    pub const I2: u16 = 2;
    /// 32-bit signed integer (3) - long
    pub const I4: u16 = 3;
    /// 32-bit floating point (4) - float
    pub const R4: u16 = 4;
    /// 64-bit floating point (5) - double
    pub const R8: u16 = 5;
    /// Currency type (6) - 64-bit scaled integer
    pub const CY: u16 = 6;
    /// Date type (7) - 64-bit floating point date
    pub const DATE: u16 = 7;
    /// BSTR string (8) - Length-prefixed Unicode string
    pub const BSTR: u16 = 8;
    /// `IDispatch` interface (9) - COM automation interface
    pub const DISPATCH: u16 = 9;
    /// Error code (10) - HRESULT or SCODE
    pub const ERROR: u16 = 10;
    /// Boolean type (11) - `VARIANT_BOOL` (16-bit)
    pub const BOOL: u16 = 11;
    /// Variant type (12) - Nested VARIANT
    pub const VARIANT: u16 = 12;
    /// `IUnknown` interface (13) - Base COM interface
    pub const UNKNOWN: u16 = 13;
    /// Decimal type (14) - 128-bit decimal number
    pub const DECIMAL: u16 = 14;
    /// 8-bit signed integer (16) - char
    pub const I1: u16 = 16;
    /// 8-bit unsigned integer (17) - byte
    pub const UI1: u16 = 17;
    /// 16-bit unsigned integer (18) - ushort
    pub const UI2: u16 = 18;
    /// 32-bit unsigned integer (19) - ulong
    pub const UI4: u16 = 19;
    /// 64-bit signed integer (20) - __int64
    pub const I8: u16 = 20;
    /// 64-bit unsigned integer (21) - unsigned __int64
    pub const UI8: u16 = 21;
    /// Machine integer (22) - Platform-dependent signed integer
    pub const INT: u16 = 22;
    /// Machine unsigned integer (23) - Platform-dependent unsigned integer
    pub const UINT: u16 = 23;
    /// Void type (24) - No value
    pub const VOID: u16 = 24;
    /// HRESULT type (25) - COM error result code
    pub const HRESULT: u16 = 25;
    /// Pointer type (26) - Generic pointer to any type
    pub const PTR: u16 = 26;
    /// Safe array type (27) - COM safe array container
    pub const SAFEARRAY: u16 = 27;
    /// C-style array (28) - Fixed-size array
    pub const CARRAY: u16 = 28;
    /// User-defined type (29) - Custom type definition
    pub const USERDEFINED: u16 = 29;
    /// ANSI string pointer (30) - Null-terminated ANSI string
    pub const LPSTR: u16 = 30;
    /// Unicode string pointer (31) - Null-terminated Unicode string
    pub const LPWSTR: u16 = 31;
    /// Record type (36) - User-defined record/structure
    pub const RECORD: u16 = 36;
    /// Integer pointer (37) - Platform-dependent integer pointer
    pub const INT_PTR: u16 = 37;
    /// Unsigned integer pointer (38) - Platform-dependent unsigned integer pointer
    pub const UINT_PTR: u16 = 38;

    /// File time (64) - 64-bit file time value
    pub const FILETIME: u16 = 64;
    /// Binary blob (65) - Arbitrary binary data
    pub const BLOB: u16 = 65;
    /// Stream (66) - `IStream` interface
    pub const STREAM: u16 = 66;
    /// Storage (67) - `IStorage` interface
    pub const STORAGE: u16 = 67;
    /// Streamed object (68) - Object stored in stream
    pub const STREAMED_OBJECT: u16 = 68;
    /// Stored object (69) - Object stored in storage
    pub const STORED_OBJECT: u16 = 69;
    /// Blob object (70) - Object stored as blob
    pub const BLOB_OBJECT: u16 = 70;
    /// Clipboard format (71) - Windows clipboard format
    pub const CF: u16 = 71;
    /// Class ID (72) - COM class identifier (GUID)
    pub const CLSID: u16 = 72;

    /// Vector modifier (0x1000) - One-dimensional array modifier
    pub const VECTOR: u16 = 0x1000;
    /// Array modifier (0x2000) - Multi-dimensional array modifier
    pub const ARRAY: u16 = 0x2000;
    /// By-reference modifier (0x4000) - Pass by reference modifier
    pub const BYREF: u16 = 0x4000;
    /// Type mask (0xfff) - Mask to extract base type from modifiers
    pub const TYPEMASK: u16 = 0xfff;
}

/// Represents a complete marshaling descriptor.
///
/// A marshalling descriptor contains all the information needed to marshal a managed type
/// to/from a native type during P/Invoke, COM interop, or other native interop scenarios.
/// The descriptor consists of a primary type and optional additional types for complex
/// marshalling scenarios.
///
/// # Structure
///
/// - **Primary Type**: The main [`NativeType`] that represents the target native type
/// - **Additional Types**: Secondary types used for complex marshalling (e.g., array element types)
///
/// # Usage Patterns
///
/// Most marshalling descriptors contain only a primary type:
/// ```rust,ignore
/// // Simple LPSTR marshalling
/// let descriptor = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: None },
///     additional_types: vec![],
/// };
/// ```
///
/// Complex scenarios may include additional type information:
/// ```rust,ignore
/// // Array marshalling with element type
/// let descriptor = MarshallingInfo {
///     primary_type: NativeType::Array { /* ... */ },
///     additional_types: vec![NativeType::I4], // Element type
/// };
/// ```
///
/// # Parsing
///
/// Use [`crate::metadata::marshalling::parse_marshalling_descriptor`] to parse from binary format:
/// ```rust,ignore
/// let bytes = &[NATIVE_TYPE::LPSTR, 0x05]; // LPSTR with size param 5
/// let info = parse_marshalling_descriptor(bytes)?;
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct MarshallingInfo {
    /// The primary native type for this marshalling descriptor
    pub primary_type: NativeType,
    /// Additional type information for complex marshalling scenarios
    pub additional_types: Vec<NativeType>,
}

/// Represents a native type for marshalling between managed and unmanaged code.
///
/// This enum encompasses all native types supported by .NET marshalling as defined in ECMA-335
/// and extended by `CoreCLR`. Each variant represents a specific native type with associated
/// parameters for size information, element types, or other marshalling metadata.
///
/// # Type Categories
///
/// ## Primitive Types
/// Basic value types with direct managed-to-native mapping:
/// - Integers: I1, U1, I2, U2, I4, U4, I8, U8
/// - Floating Point: R4, R8
/// - Platform Types: Int, `UInt`, `SysChar`
/// - Special: Void, Boolean, Error
///
/// ## String Types
/// Various string encodings and formats:
/// - Unicode: `LPWStr`, `BStr`, `HString`
/// - ANSI: `LPStr`, `AnsiBStr`
/// - Platform: `LPTStr`, `TBStr`
/// - UTF-8: `LPUtf8Str`
/// - Fixed: `FixedSysString`, `ByValStr`
///
/// ## Array Types
/// Collection types with size and element information:
/// - `FixedArray`: Fixed-size arrays with compile-time size
/// - Array: Variable arrays with runtime size parameters
/// - `SafeArray`: COM safe arrays with variant type information
///
/// ## Interface Types
/// COM and Windows Runtime interface pointers:
/// - `IUnknown`, `IDispatch`: Base COM interfaces
/// - `IInspectable`: Windows Runtime base interface
/// - Interface: Generic interface with IID parameter
///
/// ## Structured Types
/// Complex types with layout information:
/// - Struct: Native structures with packing and size
/// - `NestedStruct`: Value type embedded in structure
/// - `LPStruct`: Pointer to native structure
///
/// ## Pointer Types
/// Pointer and reference types:
/// - Ptr: Raw pointer with optional target type
/// - `ObjectRef`: Managed object reference
///
/// ## Special Types
/// Advanced marshalling scenarios:
/// - `CustomMarshaler`: User-defined custom marshalling
/// - Func: Function pointer
/// - `AsAny`: Marshal as any compatible type
/// - End: Descriptor termination marker
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::marshalling::NativeType;
///
/// // Simple string marshalling
/// let lpstr = NativeType::LPStr { size_param_index: Some(2) };
///
/// // Array marshalling
/// let array = NativeType::Array {
///     element_type: Box::new(NativeType::I4),
///     num_param: Some(1),
///     num_element: Some(10),
/// };
///
/// // COM interface
/// let interface = NativeType::Interface { iid_param_index: Some(0) };
/// ```
///
/// Parameter Handling
///
/// Many types include parameter indices that reference method parameters for runtime
/// size or type information. Use the `has_parameters` method to check if a type
/// requires additional parameter data.
#[derive(Debug, PartialEq, Clone)]
pub enum NativeType {
    // Basic types
    /// Void type - represents no value or void return type
    Void,
    /// Boolean type - 1-byte boolean value (0 = false, non-zero = true)
    Boolean,
    /// Signed 8-bit integer - sbyte in C#, char in C
    I1,
    /// Unsigned 8-bit integer - byte in C#, unsigned char in C
    U1,
    /// Signed 16-bit integer - short in C#, short in C
    I2,
    /// Unsigned 16-bit integer - ushort in C#, unsigned short in C
    U2,
    /// Signed 32-bit integer - int in C#, int/long in C
    I4,
    /// Unsigned 32-bit integer - uint in C#, unsigned int/long in C
    U4,
    /// Signed 64-bit integer - long in C#, __int64 in C
    I8,
    /// Unsigned 64-bit integer - ulong in C#, unsigned __int64 in C
    U8,
    /// 32-bit floating point - float in C#, float in C
    R4,
    /// 64-bit floating point - double in C#, double in C
    R8,
    /// System character type - platform-dependent character encoding
    SysChar,
    /// COM VARIANT type - OLE automation variant for dynamic typing
    Variant,
    /// Currency type - OLE automation currency (64-bit scaled integer)
    Currency,
    /// Decimal type - .NET decimal (128-bit scaled integer)
    Decimal,
    /// Date type - OLE automation date (64-bit floating point)
    Date,
    /// Platform integer - 32-bit on 32-bit platforms, 64-bit on 64-bit platforms
    Int,
    /// Platform unsigned integer - 32-bit on 32-bit platforms, 64-bit on 64-bit platforms
    UInt,
    /// Error type - HRESULT or SCODE for COM error handling
    Error,

    // String types
    /// BSTR - OLE automation string (length-prefixed Unicode string)
    BStr,
    /// LPSTR - Null-terminated ANSI string pointer with optional size parameter
    LPStr {
        /// Optional parameter index for string length
        size_param_index: Option<u32>,
    },
    /// LPWSTR - Null-terminated Unicode string pointer with optional size parameter
    LPWStr {
        /// Optional parameter index for string length
        size_param_index: Option<u32>,
    },
    /// LPTSTR - Platform-dependent string pointer (ANSI on ANSI systems, Unicode on Unicode systems)
    LPTStr {
        /// Optional parameter index for string length
        size_param_index: Option<u32>,
    },
    /// LPUTF8STR - Null-terminated UTF-8 string pointer with optional size parameter
    LPUtf8Str {
        /// Optional parameter index for string length
        size_param_index: Option<u32>,
    },
    /// Fixed system string - Fixed-length character array embedded in structure
    FixedSysString {
        /// Fixed size of the string buffer in characters
        size: u32,
    },
    /// ANSI BSTR - ANSI version of BSTR for legacy compatibility
    AnsiBStr,
    /// TBSTR - Platform-dependent BSTR (ANSI on ANSI systems, Unicode on Unicode systems)
    TBStr,
    /// By-value string - Fixed-length string embedded directly in structure
    ByValStr {
        /// Fixed size of the string buffer in characters
        size: u32,
    },
    /// Variant boolean - COM `VARIANT_BOOL` (16-bit boolean: 0 = false, -1 = true)
    VariantBool,

    // Array types
    /// Fixed array - Fixed-size array with compile-time known size
    FixedArray {
        /// Number of elements in the fixed array
        size: u32,
        /// Optional element type specification
        element_type: Option<Box<NativeType>>,
    },
    /// Variable array - Runtime-sized array with parameter-based sizing
    Array {
        /// Type of array elements
        element_type: Box<NativeType>,
        /// Optional parameter index for array size
        num_param: Option<u32>,
        /// Optional fixed number of elements
        num_element: Option<u32>,
    },
    /// Safe array - COM safe array with variant type information
    SafeArray {
        /// VARIANT type constant for array elements
        variant_type: u16,
        /// Optional user-defined type name
        user_defined_name: Option<String>,
    },

    // Pointer types
    /// Pointer - Raw pointer with optional target type information
    Ptr {
        /// Optional type that the pointer references
        ref_type: Option<Box<NativeType>>,
    },

    // Interface types
    /// `IUnknown` interface - Base COM interface for reference counting
    IUnknown,
    /// `IDispatch` interface - COM automation interface for dynamic dispatch
    IDispatch,
    /// `IInspectable` interface - Windows Runtime base interface
    IInspectable,
    /// Generic interface - COM interface with runtime IID specification
    Interface {
        /// Optional parameter index for interface IID
        iid_param_index: Option<u32>,
    },

    // Structured types
    /// Native structure - C-style struct with layout information
    Struct {
        /// Optional structure packing size in bytes
        packing_size: Option<u8>,
        /// Optional total structure size in bytes
        class_size: Option<u32>,
    },
    /// Nested structure - Value type embedded within another structure
    NestedStruct,
    /// Pointer to structure - Pointer to native structure
    LPStruct,

    // Custom marshaling
    /// Custom marshaler - User-defined marshalling with custom logic
    CustomMarshaler {
        /// GUID identifying the custom marshaler
        guid: String,
        /// Native type name for the marshaler
        native_type_name: String,
        /// Cookie string passed to the marshaler
        cookie: String,
        /// Type reference for the custom marshaler
        type_reference: String,
    },

    // Special types
    /// Object reference - Managed object reference for COM interop
    ObjectRef,
    /// Function pointer - Pointer to native function
    Func,
    /// As any - Marshal as any compatible native type
    AsAny,
    /// Windows Runtime string - HSTRING handle for `WinRT` strings
    HString,

    // End marker
    /// End marker - Indicates the end of a marshalling descriptor
    End,
}

impl NativeType {
    /// Returns true if this type requires additional parameter data.
    ///
    /// Many native types include runtime parameters such as size information, parameter indices,
    /// or type specifications. This method indicates whether the type carries such additional data
    /// that may need special handling during marshalling or code generation.
    ///
    /// # Returns
    ///
    /// `true` if the type includes parameter data (size, indices, nested types), `false` for
    /// simple types with no additional information.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::marshalling::NativeType;
    ///
    /// // Simple types have no parameters
    /// assert!(!NativeType::I4.has_parameters());
    /// assert!(!NativeType::Boolean.has_parameters());
    ///
    /// // String types with size parameters
    /// let lpstr = NativeType::LPStr { size_param_index: Some(5) };
    /// assert!(lpstr.has_parameters());
    ///
    /// // Array types always have parameters
    /// let array = NativeType::Array {
    ///     element_type: Box::new(NativeType::I4),
    ///     num_param: None,
    ///     num_element: Some(10),
    /// };
    /// assert!(array.has_parameters());
    /// ```
    ///
    /// # Usage
    ///
    /// This method is useful for:
    /// - **Code Generation**: Determining if additional parameter handling is needed
    /// - **Validation**: Ensuring all required parameters are provided
    /// - **Optimization**: Applying different handling strategies for simple vs. complex types
    #[must_use]
    pub fn has_parameters(&self) -> bool {
        matches!(
            self,
            NativeType::LPStr { .. }
                | NativeType::LPWStr { .. }
                | NativeType::LPTStr { .. }
                | NativeType::LPUtf8Str { .. }
                | NativeType::FixedSysString { .. }
                | NativeType::ByValStr { .. }
                | NativeType::FixedArray { .. }
                | NativeType::Array { .. }
                | NativeType::SafeArray { .. }
                | NativeType::Ptr { .. }
                | NativeType::Interface { .. }
                | NativeType::Struct { .. }
                | NativeType::CustomMarshaler { .. }
        )
    }
}

/// Maximum recursion depth for parsing marshaling descriptors.
///
/// This constant limits the depth of nested type parsing to prevent stack overflow from
/// maliciously crafted or corrupted marshalling descriptors. The limit is set conservatively
/// to handle legitimate complex types while preventing denial-of-service attacks.
///
/// # Security Considerations
///
/// Without recursion limits, an attacker could create deeply nested type descriptors that
/// cause stack overflow during parsing. This limit provides defense against such attacks
/// while still supporting reasonable nesting scenarios.
///
/// # Practical Limits
///
/// In practice, .NET marshalling descriptors rarely exceed 10-15 levels of nesting.
/// The limit of 50 provides substantial headroom for complex legitimate scenarios.
pub const MAX_RECURSION_DEPTH: usize = 50;
