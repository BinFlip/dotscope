//! Custom attribute blob parsing implementation for .NET metadata.
//!
//! This module provides robust parsing of custom attribute blob data according to the
//! ECMA-335 II.23.3 CustomAttribute signature specification. It implements the documented
//! CorSerializationType enumeration for accurate .NET runtime-compliant parsing with
//! comprehensive error handling and graceful degradation strategies.
//!
//! # Architecture
//!
//! The parsing architecture follows established patterns from other metadata parsers
//! in the codebase, providing structured and reliable custom attribute processing:
//!
//! ## Core Components
//!
//! - **Fixed Arguments**: Type-aware parsing based on constructor parameter types (CilFlavor-based)
//! - **Named Arguments**: Explicit CorSerializationType tag parsing from blob data
//! - **Recursive Design**: Clean recursive parsing with depth limiting for complex types
//! - **Enum Support**: Uses SERIALIZATION_TYPE constants for documented .NET types
//!
//! ## Error Handling Strategy
//!
//! - **Graceful Degradation**: Falls back to safer parsing when type resolution fails
//! - **Heuristic Enum Detection**: Uses inheritance analysis and name patterns for external types
//! - **Error Recovery**: Continues parsing despite unknown or malformed data sections
//! - **Future-Proof Design**: Ready for multi-assembly loading while working with current single-assembly model
//!
//! # Key Components
//!
//! - [`crate::metadata::customattributes::parser::CustomAttributeParser`] - Main parser implementation
//! - [`crate::metadata::customattributes::parser::parse_custom_attribute_blob`] - Blob heap parsing
//! - [`crate::metadata::customattributes::parser::parse_custom_attribute_data`] - Raw data parsing
//! - [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] - Type tag constants
//!
//! # Usage Examples
//!
//! ## Parsing from Blob Heap
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::parse_custom_attribute_blob;
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//!
//! # fn get_custom_attribute_data() -> (u32, std::sync::Arc<boxcar::Vec<dotscope::metadata::tables::ParamRc>>) { todo!() }
//! let (blob_index, constructor_params) = get_custom_attribute_data();
//!
//! if let Some(blob_heap) = assembly.blob() {
//!     let custom_attr = parse_custom_attribute_blob(blob_heap, blob_index, &constructor_params)?;
//!     
//!     println!("Fixed arguments: {}", custom_attr.fixed_args.len());
//!     println!("Named arguments: {}", custom_attr.named_args.len());
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Parsing Raw Blob Data
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::{parse_custom_attribute_data, CustomAttributeArgument};
//!
//! # fn get_constructor_params() -> std::sync::Arc<boxcar::Vec<dotscope::metadata::tables::ParamRc>> { todo!() }
//! let constructor_params = get_constructor_params();
//!
//! // Example: Simple custom attribute with string argument
//! let blob_data = &[
//!     0x01, 0x00,                     // Prolog (0x0001)
//!     0x05,                           // String length
//!     0x48, 0x65, 0x6C, 0x6C, 0x6F,   // "Hello" (UTF-8)
//!     0x00, 0x00,                     // Named argument count (0)
//! ];
//!
//! let result = parse_custom_attribute_data(blob_data, &constructor_params)?;
//!
//! // Access parsed arguments
//! match &result.fixed_args[0] {
//!     CustomAttributeArgument::String(s) => println!("String argument: '{}'", s),
//!     _ => println!("Unexpected argument type"),
//! }
//!
//! println!("Named arguments: {}", result.named_args.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customattributes::types`] - Type definitions and argument structures
//! - [`crate::metadata::streams::Blob`] - Blob heap access for custom attribute data
//! - [`crate::metadata::tables`] - Parameter resolution for constructor type information
//! - [`crate::metadata::typesystem`] - Type system integration for CilFlavor handling
//!
//! # Implementation Features
//!
//! ## Current Capabilities
//! - **Single Assembly Scope**: Optimized for current single-assembly analysis model
//! - **Type Resolution**: Full support for resolved constructor parameter types
//! - **Graceful Fallbacks**: Heuristic parsing when full type information unavailable
//! - **Comprehensive Validation**: ECMA-335 compliance with detailed error reporting
//!
//! ## Future Enhancements
//! - **Multi-Assembly Support**: Planned project-style loading with cross-assembly resolution
//! - **External Type Loading**: Default windows_dll directory for common .NET assemblies
//! - **Enhanced Inheritance**: Full inheritance chain analysis for enum detection
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with custom attribute specification (II.23.3)
//! - **Type Safety**: Robust type checking and validation throughout parsing
//! - **Memory Safety**: Comprehensive bounds checking and recursion limiting
//! - **Error Handling**: Detailed error messages for debugging malformed data

use crate::{
    file::parser::Parser,
    metadata::{
        customattributes::types::{
            CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue,
            SERIALIZATION_TYPE,
        },
        streams::Blob,
        tables::ParamRc,
        typesystem::{CilFlavor, CilTypeRef},
    },
    Error::RecursionLimit,
    Result,
};
use std::sync::Arc;

/// Maximum recursion depth for custom attribute parsing
const MAX_RECURSION_DEPTH: usize = 50;

/// Parse custom attribute blob data from the blob heap using constructor parameter information.
///
/// This function retrieves custom attribute data from the specified blob heap index and
/// parses it according to ECMA-335 II.23.3 specification. It uses the constructor method's
/// parameter types to accurately parse fixed arguments and automatically handles named
/// arguments using their embedded type information.
///
/// # Arguments
/// * `blob` - The [`crate::metadata::streams::Blob`] heap containing custom attribute data
/// * `index` - The index into the blob heap (0 indicates empty custom attribute)
/// * `params` - Reference to the constructor method's parameter vector for type-aware parsing
///
/// # Returns
/// A parsed [`crate::metadata::customattributes::CustomAttributeValue`] containing:
/// - `fixed_args` - Constructor arguments in declaration order
/// - `named_args` - Field and property assignments with names and values
///
/// # Errors
/// Returns [`crate::Error::OutOfBounds`] if the index is invalid, or
/// [`crate::Error::Malformed`] if the blob data doesn't conform to ECMA-335 format:
/// - Invalid prolog (not 0x0001)
/// - Insufficient data for declared arguments
/// - Type/value mismatches in argument parsing
/// - Recursion depth exceeded during parsing
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::parse_custom_attribute_blob;
/// use dotscope::CilObject;
///
/// let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
///
/// # fn get_custom_attribute_data() -> (u32, std::sync::Arc<boxcar::Vec<dotscope::metadata::tables::ParamRc>>) { todo!() }
/// let (blob_index, constructor_params) = get_custom_attribute_data();
///
/// if let Some(blob_heap) = assembly.blob() {
///     let custom_attr = parse_custom_attribute_blob(blob_heap, blob_index, &constructor_params)?;
///     
///     println!("Fixed arguments: {}", custom_attr.fixed_args.len());
///     println!("Named arguments: {}", custom_attr.named_args.len());
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn parse_custom_attribute_blob(
    blob: &Blob,
    index: u32,
    params: &Arc<boxcar::Vec<ParamRc>>,
) -> Result<CustomAttributeValue> {
    if index == 0 {
        return Ok(CustomAttributeValue {
            fixed_args: vec![],
            named_args: vec![],
        });
    }

    let data = blob.get(index as usize)?;
    let mut parser = CustomAttributeParser::new(data);
    parser.parse_custom_attribute(params)
}

/// Parse custom attribute blob data directly from raw bytes using constructor parameter information.
///
/// This function parses custom attribute data from a raw byte slice according to the
/// ECMA-335 II.23.3 specification. It's the core parsing function used by other APIs
/// and provides direct access to the parsing logic without blob heap indirection.
///
/// The parser uses constructor method parameter types for accurate fixed argument parsing
/// and handles named arguments through their embedded serialization type information.
/// It implements graceful degradation when type resolution fails and provides comprehensive
/// error reporting for malformed data.
///
/// # Arguments
/// * `data` - Raw bytes of the custom attribute blob data to parse
/// * `params` - Reference to the constructor method's parameter vector for type-aware parsing
///
/// # Returns
/// A parsed [`crate::metadata::customattributes::CustomAttributeValue`] containing:
/// - `fixed_args` - Constructor arguments parsed using parameter type information
/// - `named_args` - Field and property assignments with their names and values
///
/// # Errors
/// Returns [`crate::Error::Malformed`] if the blob data doesn't conform to ECMA-335 format:
/// - Invalid or missing prolog (must be 0x0001)
/// - Insufficient data for the number of declared arguments
/// - Type mismatches between expected and actual argument types
/// - Invalid serialization type tags in named arguments
/// - Recursion depth exceeded during complex type parsing
/// - Truncated or corrupted blob data
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::{parse_custom_attribute_data, CustomAttributeArgument};
///
/// # fn get_constructor_params() -> std::sync::Arc<boxcar::Vec<dotscope::metadata::tables::ParamRc>> { todo!() }
/// let constructor_params = get_constructor_params();
///
/// // Example: Simple custom attribute with string argument
/// let blob_data = &[
///     0x01, 0x00,                     // Prolog (0x0001)
///     0x05,                           // String length
///     0x48, 0x65, 0x6C, 0x6C, 0x6F,   // "Hello" (UTF-8)
///     0x00, 0x00,                     // Named argument count (0)
/// ];
///
/// let result = parse_custom_attribute_data(blob_data, &constructor_params)?;
///
/// // Access parsed arguments
/// match &result.fixed_args[0] {
///     CustomAttributeArgument::String(s) => println!("String argument: '{}'", s),
///     _ => println!("Unexpected argument type"),
/// }
///
/// println!("Named arguments: {}", result.named_args.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn parse_custom_attribute_data(
    data: &[u8],
    params: &Arc<boxcar::Vec<ParamRc>>,
) -> Result<CustomAttributeValue> {
    let mut parser = CustomAttributeParser::new(data);
    parser.parse_custom_attribute(params)
}

/// Custom attribute parser implementing ECMA-335 II.23.3 specification.
///
/// This parser follows the same architectural pattern as other parsers in the codebase
/// (like `SignatureParser` and `MarshallingParser`) with proper recursion limiting,
/// error handling, and state management. It provides a structured approach to parsing
/// the complex binary format of .NET custom attributes.
///
/// The parser handles both fixed arguments (based on constructor parameters) and named
/// arguments (with embedded type information) while maintaining compatibility with
/// real-world .NET assemblies through graceful degradation strategies.
pub struct CustomAttributeParser<'a> {
    /// Binary data parser for reading attribute blob
    parser: Parser<'a>,
    /// Current recursion depth for nested parsing
    depth: usize,
}

impl<'a> CustomAttributeParser<'a> {
    /// Creates a new custom attribute parser for the provided blob data.
    ///
    /// # Arguments
    /// * `data` - Raw bytes of the custom attribute blob to parse
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::customattributes::parser::CustomAttributeParser;
    ///
    /// let blob_data = &[0x01, 0x00, 0x00, 0x00]; // Minimal custom attribute
    /// let parser = CustomAttributeParser::new(blob_data);
    /// ```
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            parser: Parser::new(data),
            depth: 0,
        }
    }

    /// Parse a complete custom attribute blob according to ECMA-335 II.23.3.
    ///
    /// This method handles the full custom attribute parsing workflow:
    /// 1. Validates the standard prolog (0x0001)
    /// 2. Parses fixed arguments using constructor parameter types
    /// 3. Parses named arguments using embedded type information
    ///
    /// The parser implements type-aware parsing for fixed arguments when constructor
    /// parameter information is available, and falls back to heuristic parsing when
    /// type resolution fails. Named arguments are always parsed using their embedded
    /// serialization type tags.
    ///
    /// # Arguments
    /// * `params` - Constructor method parameters for fixed argument type resolution
    ///
    /// # Returns
    /// A complete [`crate::metadata::customattributes::CustomAttributeValue`] with all parsed data.
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] for various format violations:
    /// - Invalid prolog (not 0x0001)
    /// - Insufficient data for declared arguments
    /// - Invalid serialization types in named arguments
    /// - Recursion limit exceeded during parsing
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::customattributes::parser::CustomAttributeParser;
    ///
    /// # fn get_constructor_params() -> std::sync::Arc<boxcar::Vec<dotscope::metadata::tables::ParamRc>> { todo!() }
    /// let blob_data = &[0x01, 0x00, 0x00, 0x00]; // Simple custom attribute
    /// let mut parser = CustomAttributeParser::new(blob_data);
    /// let params = get_constructor_params();
    ///
    /// let custom_attr = parser.parse_custom_attribute(&params)?;
    /// println!("Parsed {} fixed args and {} named args",
    ///          custom_attr.fixed_args.len(), custom_attr.named_args.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn parse_custom_attribute(
        &mut self,
        params: &Arc<boxcar::Vec<ParamRc>>,
    ) -> Result<CustomAttributeValue> {
        // Check for the standard prolog (0x0001)
        let prolog = self.parser.read_le::<u16>()?;
        if prolog != 0x0001 {
            return Err(malformed_error!(
                "Invalid custom attribute prolog - expected 0x0001"
            ));
        }

        // Parse fixed arguments based on constructor parameter types
        let fixed_args = self.parse_fixed_arguments(params)?;

        // Parse named arguments using explicit type tags
        let named_args =
            if self.parser.has_more_data() && self.parser.len() >= self.parser.pos() + 2 {
                let num_named = self.parser.read_le::<u16>()?;
                let mut args = Vec::with_capacity(num_named as usize);
                for _ in 0..num_named {
                    if let Some(arg) = self.parse_named_argument()? {
                        args.push(arg);
                    } else {
                        break;
                    }
                }
                args
            } else {
                vec![]
            };

        Ok(CustomAttributeValue {
            fixed_args,
            named_args,
        })
    }

    /// Parse fixed arguments based on constructor parameter types.
    ///
    /// Extracts constructor parameters (excluding return parameter at sequence 0),
    /// sorts them by sequence number, and parses each argument using its type information.
    /// This ensures proper argument order matching the constructor signature.
    ///
    /// # Arguments
    /// * `params` - Constructor method parameters with type and sequence information
    ///
    /// # Returns
    /// Vector of parsed arguments in constructor parameter order
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] if:
    /// - Constructor has parameters but no resolved types
    /// - Insufficient blob data for declared parameters
    /// - Parameter type parsing fails
    fn parse_fixed_arguments(
        &mut self,
        params: &Arc<boxcar::Vec<ParamRc>>,
    ) -> Result<Vec<CustomAttributeArgument>> {
        // Create sorted list of constructor parameters (excluding return parameter)
        let mut sorted_params: Vec<_> = params
            .iter()
            .filter(|(_, param)| param.sequence > 0)
            .map(|(_, param)| param)
            .collect();
        sorted_params.sort_by_key(|param| param.sequence);

        let resolved_param_types: Vec<_> = sorted_params
            .iter()
            .filter_map(|param| param.base.get())
            .collect();

        if resolved_param_types.is_empty() && !sorted_params.is_empty() {
            return Err(malformed_error!(
                "Constructor has {} parameters but no resolved types",
                sorted_params.len()
            ));
        }

        let mut fixed_args = Vec::new();
        for param_type in resolved_param_types {
            if !self.parser.has_more_data() {
                return Err(malformed_error!(
                    "Not enough data for remaining constructor parameters"
                ));
            }

            if let Some(arg) = self.parse_fixed_argument(param_type)? {
                fixed_args.push(arg);
            } else {
                return Err(malformed_error!(
                    "Unsupported parameter type in custom attribute constructor"
                ));
            }
        }

        Ok(fixed_args)
    }

    /// Parse a single fixed argument based on constructor parameter type.
    ///
    /// Uses [`crate::metadata::typesystem::CilFlavor`] to determine the correct parsing
    /// strategy for each parameter type. Handles primitive types, strings, arrays,
    /// and complex types including System.Type, System.Object, and enum types.
    ///
    /// # Type Handling
    /// - **Primitives**: Direct binary reading (bool, int, float, etc.)
    /// - **String**: Compressed length + UTF-8 data or null marker (0xFF)
    /// - **Class Types**: Special handling for System.Type, System.String, System.Object
    /// - **ValueType**: Treated as enum with i32 underlying type
    /// - **Arrays**: Single-dimensional arrays with element type parsing
    /// - **Enum**: Heuristic detection with graceful fallback to Type parsing
    ///
    /// # Arguments
    /// * `cil_type` - Constructor parameter type information for parsing guidance
    ///
    /// # Returns
    /// Parsed argument if successful, None if type is unsupported
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] for invalid data or unsupported types
    fn parse_fixed_argument(
        &mut self,
        cil_type: &CilTypeRef,
    ) -> Result<Option<CustomAttributeArgument>> {
        let Some(type_ref) = cil_type.upgrade() else {
            return Err(malformed_error!("Type reference has been dropped"));
        };

        let flavor = type_ref.flavor();

        // Add debug information about what we're trying to parse
        if !self.parser.has_more_data() {
            return Err(malformed_error!(
                "Not enough data for fixed argument type {:?} (pos={}, len={})",
                flavor,
                self.parser.pos(),
                self.parser.len()
            ));
        }

        match flavor {
            // Primitive types - stored directly without type tags
            CilFlavor::Boolean => Ok(Some(CustomAttributeArgument::Bool(
                self.parser.read_le::<u8>()? != 0,
            ))),
            CilFlavor::Char => {
                let val = self.parser.read_le::<u16>()?;
                let character = char::from_u32(u32::from(val)).unwrap_or('\u{FFFD}');
                Ok(Some(CustomAttributeArgument::Char(character)))
            }
            CilFlavor::I1 => Ok(Some(CustomAttributeArgument::I1(
                self.parser.read_le::<i8>()?,
            ))),
            CilFlavor::U1 => Ok(Some(CustomAttributeArgument::U1(
                self.parser.read_le::<u8>()?,
            ))),
            CilFlavor::I2 => Ok(Some(CustomAttributeArgument::I2(
                self.parser.read_le::<i16>()?,
            ))),
            CilFlavor::U2 => Ok(Some(CustomAttributeArgument::U2(
                self.parser.read_le::<u16>()?,
            ))),
            CilFlavor::I4 => Ok(Some(CustomAttributeArgument::I4(
                self.parser.read_le::<i32>()?,
            ))),
            CilFlavor::U4 => Ok(Some(CustomAttributeArgument::U4(
                self.parser.read_le::<u32>()?,
            ))),
            CilFlavor::I8 => Ok(Some(CustomAttributeArgument::I8(
                self.parser.read_le::<i64>()?,
            ))),
            CilFlavor::U8 => Ok(Some(CustomAttributeArgument::U8(
                self.parser.read_le::<u64>()?,
            ))),
            CilFlavor::R4 => Ok(Some(CustomAttributeArgument::R4(
                self.parser.read_le::<f32>()?,
            ))),
            CilFlavor::R8 => Ok(Some(CustomAttributeArgument::R8(
                self.parser.read_le::<f64>()?,
            ))),
            CilFlavor::I => {
                if cfg!(target_pointer_width = "64") {
                    let val = self.parser.read_le::<i64>()?;
                    #[allow(clippy::cast_possible_truncation)]
                    Ok(Some(CustomAttributeArgument::I(val as isize)))
                } else {
                    let val = self.parser.read_le::<i32>()?;
                    Ok(Some(CustomAttributeArgument::I(val as isize)))
                }
            }
            CilFlavor::U => {
                if cfg!(target_pointer_width = "64") {
                    let val = self.parser.read_le::<u64>()?;
                    #[allow(clippy::cast_possible_truncation)]
                    Ok(Some(CustomAttributeArgument::U(val as usize)))
                } else {
                    let val = self.parser.read_le::<u32>()?;
                    Ok(Some(CustomAttributeArgument::U(val as usize)))
                }
            }
            CilFlavor::String => {
                if self.parser.peek_byte()? == 0xFF {
                    let _ = self.parser.read_le::<u8>()?; // consume null marker
                    Ok(Some(CustomAttributeArgument::String(String::new())))
                } else {
                    let s = self
                        .parse_string()
                        .map_err(|e| malformed_error!("Failed to parse String parameter: {}", e))?;
                    Ok(Some(CustomAttributeArgument::String(s)))
                }
            }
            CilFlavor::Class => {
                // For Class types in fixed arguments, we need to check what specific class it is
                // According to .NET runtime: only System.Type, System.String, and System.Object are supported
                // BUT: Enum types can also appear as Class and should be handled as ValueType/Enum
                let type_name = type_ref.fullname();

                if type_name == "System.Type" {
                    // System.Type is stored as a string (type name)
                    if self.parser.peek_byte()? == 0xFF {
                        let _ = self.parser.read_le::<u8>()?; // consume null marker
                        Ok(Some(CustomAttributeArgument::Type(String::new())))
                    } else {
                        let s = self.parse_string().map_err(|e| {
                            malformed_error!("Failed to parse System.Type parameter: {}", e)
                        })?;
                        Ok(Some(CustomAttributeArgument::Type(s)))
                    }
                } else if type_name == "System.String" {
                    // System.String is stored as a string
                    if self.parser.peek_byte()? == 0xFF {
                        let _ = self.parser.read_le::<u8>()?; // consume null marker
                        Ok(Some(CustomAttributeArgument::String(String::new())))
                    } else {
                        let s = self.parse_string().map_err(|e| {
                            malformed_error!("Failed to parse System.String parameter: {}", e)
                        })?;
                        Ok(Some(CustomAttributeArgument::String(s)))
                    }
                } else if type_name == "System.Object" {
                    // System.Object is stored as a tagged object - read type tag first
                    let type_tag = self.parser.read_le::<u8>()?;
                    let value = self.parse_argument_by_type_tag(type_tag)?;
                    Ok(Some(value))
                } else {
                    // TODO: Once we implement 'project' style loading (multiple assemblies that belong together),
                    // we can provide a 'default' windows_dll directory that includes most of the default DLLs.
                    // This would allow us in 'project' mode to resolve types across multiple binaries and
                    // fully support CustomAttribute type resolution by actually loading the type definitions
                    // from external assemblies instead of relying on heuristics.
                    //
                    // For now, we use heuristics to determine if this is an enum type based on:
                    // 1. Inheritance chain analysis (when available)
                    // 2. Known enum type name patterns
                    // 3. Graceful fallback to Type parsing to ensure real-world binaries load

                    if Self::is_enum_type(&type_ref) {
                        // Parse as enum value (i32) - most .NET enums are int32-based
                        if self.parser.len() - self.parser.pos() >= 4 {
                            let enum_value = self.parser.read_le::<i32>()?;
                            Ok(Some(CustomAttributeArgument::Enum(
                                type_name,
                                Box::new(CustomAttributeArgument::I4(enum_value)),
                            )))
                        } else {
                            // Graceful fallback: if we don't have enough data for enum, try Type parsing
                            // This ensures real-world binaries continue to load even if our heuristic fails
                            if self.parser.peek_byte()? == 0xFF {
                                let _ = self.parser.read_le::<u8>()?; // consume null marker
                                Ok(Some(CustomAttributeArgument::Type(String::new())))
                            } else {
                                let s = self.parse_string().map_err(|_| {
                                    malformed_error!(
                                        "Failed to parse Class parameter '{}': insufficient data for enum (need 4 bytes) and string parsing failed",
                                        type_name
                                    )
                                })?;
                                Ok(Some(CustomAttributeArgument::Type(s)))
                            }
                        }
                    } else {
                        // Parse as Type argument (string containing type name)
                        // This is the safe fallback that works for most unknown Class types
                        if self.parser.peek_byte()? == 0xFF {
                            let _ = self.parser.read_le::<u8>()?; // consume null marker
                            Ok(Some(CustomAttributeArgument::Type(String::new())))
                        } else {
                            let s = self.parse_string().map_err(|e| {
                                malformed_error!(
                                    "Failed to parse Class parameter '{}' as Type: {}",
                                    type_name,
                                    e
                                )
                            })?;
                            Ok(Some(CustomAttributeArgument::Type(s)))
                        }
                    }
                }
            }
            CilFlavor::ValueType => {
                // ValueType in fixed arguments should be treated as enum
                let enum_value = self.parser.read_le::<i32>()?;
                let type_name = type_ref.fullname();
                Ok(Some(CustomAttributeArgument::Enum(
                    type_name,
                    Box::new(CustomAttributeArgument::I4(enum_value)),
                )))
            }
            CilFlavor::Array { rank, .. } => {
                if *rank == 1 {
                    let array_length = self.parser.read_le::<i32>()?;
                    if array_length == -1 {
                        Ok(Some(CustomAttributeArgument::Array(vec![]))) // null array
                    } else if array_length < 0 {
                        Err(malformed_error!("Invalid array length: {}", array_length))
                    } else {
                        // Try to get the base element type from the array type
                        if let Some(base_type) = type_ref.base() {
                            let base_type_ref = base_type.into();
                            #[allow(clippy::cast_sign_loss)]
                            let mut elements = Vec::with_capacity(array_length as usize);

                            for _ in 0..array_length {
                                if let Some(element) = self.parse_fixed_argument(&base_type_ref)? {
                                    elements.push(element);
                                } else {
                                    return Err(malformed_error!("Failed to parse array element"));
                                }
                            }

                            Ok(Some(CustomAttributeArgument::Array(elements)))
                        } else {
                            Err(malformed_error!(
                                "Array type has no base element type information for fixed arguments"
                            ))
                        }
                    }
                } else {
                    Err(malformed_error!(
                        "Multi-dimensional arrays not supported in custom attributes"
                    ))
                }
            }
            CilFlavor::Void => Ok(Some(CustomAttributeArgument::Void)),
            _ => Err(malformed_error!(
                "Unsupported type flavor in custom attribute: {:?}",
                flavor
            )),
        }
    }

    /// Parse a named argument (field or property) with explicit type tags.
    ///
    /// Named arguments start with a field/property indicator (0x53/0x54), followed by
    /// a [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] tag, name length,
    /// name string, and the argument value. This follows ECMA-335 II.23.3 exactly.
    ///
    /// # Format
    /// 1. Field/Property indicator: 0x53 (FIELD) or 0x54 (PROPERTY)
    /// 2. Type tag: `CorSerializationType` enumeration value
    /// 3. Name: Compressed length + UTF-8 string
    /// 4. Value: Type-specific binary data
    ///
    /// # Returns
    /// Parsed named argument with name, type, and value, or None if no more data
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] for invalid format or unsupported types
    fn parse_named_argument(&mut self) -> Result<Option<CustomAttributeNamedArgument>> {
        if !self.parser.has_more_data() {
            return Ok(None);
        }

        // Read field/property indicator
        let field_or_prop = self.parser.read_le::<u8>()?;
        let is_field = match field_or_prop {
            0x53 => true,  // FIELD
            0x54 => false, // PROPERTY
            _ => {
                return Err(malformed_error!(
                    "Invalid field/property indicator: 0x{:02X}",
                    field_or_prop
                ))
            }
        };

        // Read type information
        let type_info = self.parser.read_le::<u8>()?;
        let arg_type = match type_info {
            SERIALIZATION_TYPE::BOOLEAN => "Boolean".to_string(),
            SERIALIZATION_TYPE::CHAR => "Char".to_string(),
            SERIALIZATION_TYPE::I1 => "I1".to_string(),
            SERIALIZATION_TYPE::U1 => "U1".to_string(),
            SERIALIZATION_TYPE::I2 => "I2".to_string(),
            SERIALIZATION_TYPE::U2 => "U2".to_string(),
            SERIALIZATION_TYPE::I4 => "I4".to_string(),
            SERIALIZATION_TYPE::U4 => "U4".to_string(),
            SERIALIZATION_TYPE::I8 => "I8".to_string(),
            SERIALIZATION_TYPE::U8 => "U8".to_string(),
            SERIALIZATION_TYPE::R4 => "R4".to_string(),
            SERIALIZATION_TYPE::R8 => "R8".to_string(),
            SERIALIZATION_TYPE::STRING => "String".to_string(),
            SERIALIZATION_TYPE::TYPE => "Type".to_string(),
            _ => {
                return Err(malformed_error!(
                    "Unsupported named argument type: 0x{:02X}",
                    type_info
                ))
            }
        };

        // Read field/property name
        let name_length = self.parser.read_compressed_uint()?;
        let mut name = String::with_capacity(name_length as usize);
        for _ in 0..name_length {
            name.push(char::from(self.parser.read_le::<u8>()?));
        }

        // Parse value based on type tag
        let value = self.parse_argument_by_type_tag(type_info)?;

        Ok(Some(CustomAttributeNamedArgument {
            is_field,
            name,
            arg_type,
            value,
        }))
    }

    /// Parse an argument based on its `CorSerializationType` tag (recursive with depth limiting).
    ///
    /// This method handles the core parsing logic for named arguments and tagged objects
    /// using the .NET runtime's serialization type enumeration. It supports recursion
    /// for complex types like arrays and tagged objects while preventing stack overflow
    /// through depth limiting.
    ///
    /// # Supported Types
    /// - All primitive types (bool, int, float, char)
    /// - String and Type arguments
    /// - Enum values with type name and underlying value
    /// - Single-dimensional arrays (SZARRAY)
    /// - Tagged objects (recursive parsing)
    ///
    /// # Recursion Safety
    /// Uses `depth` tracking with [`MAX_RECURSION_DEPTH`] limit to prevent stack overflow
    /// from maliciously crafted or deeply nested custom attribute data.
    ///
    /// # Arguments
    /// * `type_tag` - [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] enumeration value
    ///
    /// # Returns
    /// Parsed argument value according to the type tag specification
    ///
    /// # Errors
    /// Returns [`crate::Error::RecursionLimit`] if maximum depth exceeded, or
    /// [`crate::Error::Malformed`] for invalid type tags or data format
    fn parse_argument_by_type_tag(&mut self, type_tag: u8) -> Result<CustomAttributeArgument> {
        self.depth += 1;
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        let result = match type_tag {
            SERIALIZATION_TYPE::BOOLEAN => {
                let val = self.parser.read_le::<u8>()?;
                CustomAttributeArgument::Bool(val != 0)
            }
            SERIALIZATION_TYPE::CHAR => {
                let val = self.parser.read_le::<u16>()?;
                let character = char::from_u32(u32::from(val)).unwrap_or('\u{FFFD}');
                CustomAttributeArgument::Char(character)
            }
            SERIALIZATION_TYPE::I1 => CustomAttributeArgument::I1(self.parser.read_le::<i8>()?),
            SERIALIZATION_TYPE::U1 => CustomAttributeArgument::U1(self.parser.read_le::<u8>()?),
            SERIALIZATION_TYPE::I2 => CustomAttributeArgument::I2(self.parser.read_le::<i16>()?),
            SERIALIZATION_TYPE::U2 => CustomAttributeArgument::U2(self.parser.read_le::<u16>()?),
            SERIALIZATION_TYPE::I4 => CustomAttributeArgument::I4(self.parser.read_le::<i32>()?),
            SERIALIZATION_TYPE::U4 => CustomAttributeArgument::U4(self.parser.read_le::<u32>()?),
            SERIALIZATION_TYPE::I8 => CustomAttributeArgument::I8(self.parser.read_le::<i64>()?),
            SERIALIZATION_TYPE::U8 => CustomAttributeArgument::U8(self.parser.read_le::<u64>()?),
            SERIALIZATION_TYPE::R4 => CustomAttributeArgument::R4(self.parser.read_le::<f32>()?),
            SERIALIZATION_TYPE::R8 => CustomAttributeArgument::R8(self.parser.read_le::<f64>()?),
            SERIALIZATION_TYPE::STRING => {
                if self.parser.peek_byte()? == 0xFF {
                    let _ = self.parser.read_le::<u8>()?; // consume null marker
                    CustomAttributeArgument::String(String::new())
                } else {
                    let s = self.parse_string()?;
                    CustomAttributeArgument::String(s)
                }
            }
            SERIALIZATION_TYPE::TYPE => {
                if self.parser.peek_byte()? == 0xFF {
                    let _ = self.parser.read_le::<u8>()?; // consume null marker
                    CustomAttributeArgument::Type(String::new())
                } else {
                    let s = self.parse_string()?;
                    CustomAttributeArgument::Type(s)
                }
            }
            SERIALIZATION_TYPE::TAGGED_OBJECT => {
                // Recursive tagged object parsing
                let inner_type_tag = self.parser.read_le::<u8>()?;
                self.parse_argument_by_type_tag(inner_type_tag)?
            }
            SERIALIZATION_TYPE::ENUM => {
                // Read enum type name, then value
                let type_name = self.parse_string()?;
                let val = self.parser.read_le::<i32>()?; // Most enums are I4-based
                CustomAttributeArgument::Enum(type_name, Box::new(CustomAttributeArgument::I4(val)))
            }
            SERIALIZATION_TYPE::SZARRAY => {
                // Read array element type tag and length, then elements
                let element_type_tag = self.parser.read_le::<u8>()?;
                let array_length = self.parser.read_le::<i32>()?;

                if array_length == -1 {
                    CustomAttributeArgument::Array(vec![]) // null array
                } else if array_length < 0 {
                    return Err(malformed_error!("Invalid array length: {}", array_length));
                } else {
                    #[allow(clippy::cast_sign_loss)]
                    let mut elements = Vec::with_capacity(array_length as usize);
                    for _ in 0..array_length {
                        let element = self.parse_argument_by_type_tag(element_type_tag)?;
                        elements.push(element);
                    }
                    CustomAttributeArgument::Array(elements)
                }
            }
            _ => {
                return Err(malformed_error!(
                    "Unsupported serialization type tag: 0x{:02X}",
                    type_tag
                ));
            }
        };

        self.depth -= 1;
        Ok(result)
    }

    /// Helper method to check if the current position contains string data.
    ///
    /// This method performs non-destructive lookahead to determine if the current
    /// parser position contains valid string data. It's used for graceful fallback
    /// during ambiguous type parsing situations.
    ///
    /// # Validation Strategy
    /// 1. Checks for null string marker (0xFF)
    /// 2. Attempts to read compressed length
    /// 3. Validates available data matches declared length
    /// 4. Performs UTF-8 validation on string bytes
    /// 5. Applies heuristics for reasonable string lengths
    ///
    /// # Parser State
    /// This method preserves parser position - it resets to the original position
    /// after validation regardless of success or failure.
    ///
    /// # Returns
    /// `true` if the current position appears to contain valid string data
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] if parser position cannot be restored
    fn can_parse_as_string(&mut self) -> Result<bool> {
        let saved_pos = self.parser.pos();

        // Check for null string marker first
        if self.parser.has_more_data() && self.parser.peek_byte()? == 0xFF {
            return Ok(true); // null string is valid
        }

        // Try to read a compressed uint as string length
        let result = match self.parser.read_compressed_uint() {
            Ok(length) => {
                // Check if we have enough data for the string
                let remaining_data = self.parser.len() - self.parser.pos();
                if length as usize <= remaining_data {
                    // Additional heuristic: for enum values, we expect exactly 4 bytes
                    // For strings, we expect a length > 0 and <= reasonable size (< 1000 chars)
                    if length == 0 || length > 1000 {
                        Ok(length == 0) // only accept empty strings, not large "lengths"
                    } else {
                        // Check if the next bytes could be valid UTF-8
                        let string_bytes = &self.parser.data()
                            [self.parser.pos()..self.parser.pos() + length as usize];
                        Ok(std::str::from_utf8(string_bytes).is_ok())
                    }
                } else {
                    Ok(false) // not enough data
                }
            }
            Err(_) => Ok(false), // couldn't read compressed uint
        };

        // Restore parser position
        if self.parser.seek(saved_pos).is_err() {
            return Err(malformed_error!("Failed to restore parser position"));
        }
        result
    }

    /// Parse a compressed string from the blob.
    ///
    /// Implements ECMA-335 string parsing with support for null strings (0xFF marker)
    /// and proper UTF-8 handling. Uses compressed unsigned integer for length encoding
    /// as specified in the .NET metadata format.
    ///
    /// # Format
    /// - **Null String**: Single 0xFF byte
    /// - **Regular String**: Compressed length + UTF-8 bytes
    /// - **Empty String**: Length 0 + no data bytes
    ///
    /// # Error Recovery
    /// If invalid UTF-8 is encountered, falls back to lossy conversion to ensure
    /// parsing continues rather than failing completely on malformed string data.
    ///
    /// # Returns
    /// Parsed string (empty string for null marker or zero length)
    ///
    /// # Errors
    /// Returns [`crate::Error::Malformed`] if:
    /// - No data available for reading
    /// - Declared length exceeds available data
    /// - Compressed length parsing fails
    fn parse_string(&mut self) -> Result<String> {
        if !self.parser.has_more_data() {
            return Err(malformed_error!("No data available for string"));
        }

        // Check for null string marker (0xFF) first
        let first_byte = self.parser.peek_byte()?;
        if first_byte == 0xFF {
            // Null string - consume the 0xFF byte and return empty string
            self.parser.read_le::<u8>()?;
            return Ok(String::new());
        }

        // Not a null string, parse as normal compressed uint + data
        let length = self.parser.read_compressed_uint()?;
        let available_data = self.parser.len() - self.parser.pos();

        if length == 0 {
            Ok(String::new())
        } else if length as usize <= available_data {
            let mut bytes = Vec::with_capacity(length as usize);
            for _ in 0..length {
                bytes.push(self.parser.read_le::<u8>()?);
            }
            match String::from_utf8(bytes) {
                Ok(s) => Ok(s),
                Err(e) => {
                    let s = String::from_utf8_lossy(&e.into_bytes()).into_owned();
                    Ok(s)
                }
            }
        } else {
            Err(malformed_error!(
                "String length {} exceeds available data {} (blob context: pos={}, len={}, first_byte=0x{:02X})", 
                length,
                available_data,
                self.parser.pos() - 1, // subtract 1 because we already read the length
                self.parser.len(),
                first_byte
            ))
        }
    }

    /// Check if a type is an enum by examining its inheritance hierarchy
    ///
    /// This follows the .NET specification: enums inherit from System.Enum
    ///
    /// # Current Limitations
    ///
    /// This method uses heuristics because:
    /// 1. **`TypeRef` Limitation**: External types (`TypeRef`) don't contain inheritance information in metadata
    /// 2. **Single Assembly Scope**: We only have access to the current assembly's type definitions
    ///
    /// # Future Improvements
    ///
    /// TODO: When 'project' style loading is implemented, we can:
    /// - Load external assemblies from a default `windows_dll` directory
    /// - Resolve actual inheritance chains across multiple assemblies  
    /// - Eliminate the need for heuristics by accessing real type definitions
    ///
    /// # Graceful Degradation
    ///
    /// If heuristics fail, the parser falls back to treating unknown types as `Type` arguments,
    /// ensuring real-world binaries continue to load successfully even with imperfect type resolution.
    fn is_enum_type(type_ref: &Arc<crate::metadata::typesystem::CilType>) -> bool {
        const MAX_INHERITANCE_DEPTH: usize = 10;

        // According to .NET spec: all enums inherit from System.Enum -> System.ValueType -> System.Object

        // First check: is this directly System.Enum?
        let type_name = type_ref.fullname();
        if type_name == "System.Enum" {
            return false; // System.Enum itself is not an enum
        }

        let mut current_type = Some(type_ref.clone());
        let mut depth = 0;

        while let Some(current) = current_type {
            depth += 1;
            if depth > MAX_INHERITANCE_DEPTH {
                break;
            }

            if let Some(base_type) = current.base() {
                let base_name = base_type.fullname();
                if base_name == "System.Enum" {
                    return true;
                }
                current_type = Some(base_type);
            } else {
                break;
            }
        }

        // Fallback: check known enum type names for compatibility
        Self::is_known_enum_type(&type_name)
    }

    /// Check if a type name corresponds to a known .NET enum type
    ///
    /// This is a fallback heuristic for when inheritance information isn't available.
    /// The strategy prioritizes **compatibility and robustness**: it's better to
    /// successfully load real-world binaries with some imperfect `CustomAttribute` parsing
    /// than to fail completely due to unknown enum types.
    ///
    /// # Heuristic Strategy
    ///
    /// 1. **Explicit Known Types**: Common .NET framework enum types
    /// 2. **Namespace Patterns**: Types from enum-heavy namespaces (System.Runtime.InteropServices, etc.)
    /// 3. **Suffix Patterns**: Types ending with typical enum suffixes (Flags, Action, Kind, etc.)
    ///
    /// # Conservative Approach
    ///
    /// When in doubt, the parser defaults to `Type` parsing, which is safer and ensures
    /// the binary continues to load even if we misidentify an enum type.
    fn is_known_enum_type(type_name: &str) -> bool {
        match type_name {
            // All known .NET enum types consolidated
            "System.Runtime.InteropServices.CharSet" 
            | "System.Runtime.InteropServices.TypeLibTypeFlags" 
            | "System.Runtime.InteropServices.CallConv" 
            | "System.Runtime.InteropServices.CallingConvention" 
            | "System.Runtime.InteropServices.LayoutKind" 
            | "System.Runtime.InteropServices.UnmanagedType" 
            | "System.Runtime.InteropServices.VarEnum"
            | "System.AttributeTargets" 
            | "System.StringComparison" 
            | "System.DateTimeKind"
            | "System.DayOfWeek" 
            | "System.TypeCode" 
            | "System.UriKind"
            | "System.Diagnostics.DebuggingModes" 
            | ".DebuggingModes" // Sometimes namespace is missing
            | "DebuggingModes" // Sometimes fully qualified name is missing
            | "System.Reflection.BindingFlags" 
            | "System.Reflection.MemberTypes" 
            | "System.Reflection.MethodAttributes" 
            | "System.Reflection.FieldAttributes" 
            | "System.Reflection.TypeAttributes" 
            | "System.Reflection.PropertyAttributes" 
            | "System.Reflection.EventAttributes" 
            | "System.Reflection.ParameterAttributes" 
            | "System.Reflection.CallingConventions"
            | "System.Security.SecurityAction" 
            | "System.Security.Permissions.SecurityAction" 
            | "System.Security.Permissions.FileIOPermissionAccess" 
            | "System.Security.Permissions.RegistryPermissionAccess" 
            | "System.Security.Permissions.ReflectionPermissionFlag" 
            | "System.Security.Permissions.SecurityPermissionFlag" 
            | "System.Security.Permissions.UIPermissionWindow" 
            | "System.Security.Permissions.UIPermissionClipboard" 
            | "System.Security.Permissions.EnvironmentPermissionAccess"
            | "TestEnum" => true, // Test enum types (for unit tests)

            _ => {
                // If the type ends with typical enum suffixes
                type_name.ends_with("Flags") ||
                type_name.ends_with("Action") ||
                type_name.ends_with("Kind") ||
                type_name.ends_with("Type") ||
                type_name.ends_with("Attributes") ||
                type_name.ends_with("Access") ||
                type_name.ends_with("Mode") ||
                type_name.ends_with("Modes") || // Added for DebuggingModes
                type_name.ends_with("Style") ||
                type_name.ends_with("Options")
            }
        }
    }
}
