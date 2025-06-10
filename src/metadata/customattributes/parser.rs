//! `CustomAttribute` blob parsing implementation.
//!
//! This module provides parsing of custom attribute blob data strictly according to
//! ECMA-335 II.23.3 `CustomAttribute` signature specification. It requires constructor method
//! information to determine parameter types for accurate parsing.
//!
//! # Parsing Strategy
//!
//! The parsing follows the ECMA-335 standard strictly:
//! 1. **Type-Aware Parsing**: Uses constructor method information with resolved parameter types
//!    to perform precise CilFlavor-based parsing according to the specification
//! 2. **Standard Compliance**: Only accepts well-formed custom attribute blobs with proper
//!    type information

use crate::{
    file::parser::Parser,
    metadata::{
        customattributes::types::{
            CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue,
        },
        streams::{Blob, ParamRc},
        typesystem::{CilFlavor, CilTypeRef},
    },
    Result,
};
use std::sync::Arc;

/// Parameter information for custom attribute parsing
///
/// This internal structure provides access to parameter information
struct ParameterInfo {
    params: Arc<boxcar::Vec<ParamRc>>,
}

impl ParameterInfo {
    /// Create `ParameterInfo` from a parameter vector reference
    fn new(params: &Arc<boxcar::Vec<ParamRc>>) -> Self {
        Self {
            params: params.clone(),
        }
    }

    /// Get parameter count (excluding return parameter)
    fn param_count(&self) -> usize {
        // Count parameters with sequence > 0 (actual parameters, not return parameter)
        self.params
            .iter()
            .filter(|(_, param)| param.sequence > 0)
            .count()
    }

    /// Get parameter at index (0-based, excluding return parameter)
    fn get_param(&self, index: usize) -> Option<&ParamRc> {
        // Find parameter with sequence number = index + 1 (since sequence 0 is return parameter)
        #[allow(clippy::cast_possible_truncation)]
        let target_sequence = (index + 1) as u32;
        self.params
            .iter()
            .find(|(_, param)| param.sequence == target_sequence)
            .map(|(_, param)| param)
    }
}

/// Parse custom attribute blob data from blob heap with parameter vector
///
/// This function takes a reference to the parameter vector and parses
/// the custom attribute data according to ECMA-335 II.23.3.
///
/// # Arguments
/// * `blob` - The blob heap containing custom attribute data
/// * `index` - The index into the blob heap
/// * `params` - Reference to the boxcar parameter vector for type information
///
/// # Returns
/// A parsed `CustomAttributeValue` with fixed and named arguments
///
/// # Errors
/// Returns an error if the blob data is malformed or parsing fails
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
    let param_info = ParameterInfo::new(params);
    parse_custom_attribute_data_internal(data, &param_info)
}

/// Parse custom attribute blob data directly from raw bytes with parameter vector
///
/// This function takes a reference to the parameter vector and parses
/// the custom attribute data according to ECMA-335 II.23.3.
///
/// # Arguments
/// * `data` - The custom attribute blob data to parse
/// * `params` - Reference to the boxcar parameter vector for type information
///
/// # Returns
/// A parsed `CustomAttributeValue` with fixed and named arguments
///
/// # Errors
/// Returns an error if the blob data is malformed or parsing fails
pub fn parse_custom_attribute_data(
    data: &[u8],
    params: &Arc<boxcar::Vec<ParamRc>>,
) -> Result<CustomAttributeValue> {
    let param_info = ParameterInfo::new(params);
    parse_custom_attribute_data_internal(data, &param_info)
}

/// Internal function to parse custom attribute blob data with parameter information
///
/// This function uses parameter information to determine parameter types
/// for accurate parsing according to ECMA-335 II.23.3.
///
/// # Arguments
/// * `data` - The custom attribute blob data to parse
/// * `param_info` - Parameter information with cloned Arc reference
///
/// # Returns
/// A parsed `CustomAttributeValue` with fixed and named arguments
///
/// # Errors
/// Returns an error if the blob data is malformed or parsing fails
fn parse_custom_attribute_data_internal(
    data: &[u8],
    param_info: &ParameterInfo,
) -> Result<CustomAttributeValue> {
    let mut parser = Parser::new(data);

    // Check for the standard prolog (0x0001) using Parser
    let prolog = parser.read_le::<u16>()?;
    if prolog != 0x0001 {
        return Err(malformed_error!(
            "Invalid custom attribute prolog - expected 0x0001"
        ));
    }

    // Create a vector of parameters sorted by sequence (excluding return parameter)
    let mut sorted_params: Vec<_> = param_info
        .params
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
        // This indicates a systematic issue where constructor parameter types haven't been resolved
        // This should not happen if the loading sequence is correct (StandAloneSig before CustomAttribute)
        return Err(malformed_error!(
            "Constructor has {} parameters but no resolved types. This indicates a metadata loading issue where parameter types were not resolved before custom attribute parsing.",
            sorted_params.len()
        ));
    }

    let fixed_args =
        parse_fixed_args_with_resolved_types(&mut parser, resolved_param_types.into_iter())?;

    // Parse named arguments with type information
    let mut named_args = vec![];
    if parser.has_more_data() && data.len() >= parser.pos() + 2 {
        if let Ok(num_named) = parser.read_le::<u16>() {
            for _ in 0..num_named {
                match parse_named_argument(&mut parser) {
                    Ok(Some(named_arg)) => named_args.push(named_arg),
                    Ok(None) => break, // No more data
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(CustomAttributeValue {
        fixed_args,
        named_args,
    })
}

/// Parse fixed arguments with resolved type information
///
/// This function converts resolved `CilTypeReference` types from constructor
/// parameters to precise parsing logic using the `CilFlavor` type system.
/// It provides type-aware custom attribute blob parsing according to ECMA-335 II.23.3.
///
/// # Arguments
/// * `parser` - The parser positioned at the fixed arguments data
/// * `param_types` - Iterator of resolved parameter types from constructor Method.params
///
/// # Returns
/// A vector of parsed `CustomAttributeArgument` values based on the resolved types
///
/// # Errors
/// Returns an error if parsing fails or type conversion is not supported
fn parse_fixed_args_with_resolved_types<'a, I>(
    parser: &mut Parser,
    param_types: I,
) -> Result<Vec<CustomAttributeArgument>>
where
    I: Iterator<Item = &'a crate::metadata::typesystem::CilTypeRef>,
{
    let mut fixed_args = Vec::new();

    for param_type in param_types {
        if !parser.has_more_data() {
            return Err(malformed_error!(
                "Not enough data for remaining constructor parameters"
            ));
        }

        // Convert CilTypeRef to parsing logic using the type system infrastructure
        if let Some(arg) = parse_argument_from_cil_type(parser, param_type)? {
            fixed_args.push(arg);
        } else {
            return Err(malformed_error!(
                "Unsupported parameter type in custom attribute constructor"
            ));
        }
    }

    Ok(fixed_args)
}

/// Parse a single argument from a resolved `CilTypeRef`
///
/// This function converts a resolved `CilTypeRef` to parsing instructions
/// by examining the type's `CilFlavor` and using precise type-aware argument parsing
/// according to ECMA-335 II.23.3.
///
/// # Arguments
/// * `parser` - The parser positioned at the argument data
/// * `cil_type` - The resolved `CilTypeRef` containing type information
///
/// # Returns
/// Some(CustomAttributeArgument) if the type was successfully parsed,
/// None if the type is not supported in custom attributes
///
/// # Errors
/// Returns an error if parsing the specific type fails
fn parse_argument_from_cil_type(
    parser: &mut Parser,
    cil_type: &CilTypeRef,
) -> Result<Option<CustomAttributeArgument>> {
    // Get the type's flavor to determine parsing strategy
    let Some(type_ref) = cil_type.upgrade() else {
        return Err(malformed_error!("Type reference has been dropped"));
    };

    let flavor_guard = type_ref
        .flavor
        .read()
        .map_err(|_| malformed_error!("Unable to read type flavor"))?;

    match &*flavor_guard {
        // Primitive types - use direct parsing
        CilFlavor::Void => {
            // Void type - used rarely in custom attributes but included for completeness
            Ok(Some(CustomAttributeArgument::Void))
        }
        CilFlavor::Boolean => {
            if parser.has_more_data() {
                let val = parser.read_le::<u8>()?;
                Ok(Some(CustomAttributeArgument::Bool(val != 0)))
            } else {
                Err(malformed_error!("Not enough data for Boolean argument"))
            }
        }
        CilFlavor::Char => {
            if parser.len() - parser.pos() >= 2 {
                let val = parser.read_le::<u16>()?;
                // Convert u16 to char, handling invalid UTF-16 gracefully
                let character = char::from_u32(u32::from(val)).unwrap_or('\u{FFFD}'); // Replacement character for invalid
                Ok(Some(CustomAttributeArgument::Char(character)))
            } else {
                Err(malformed_error!("Not enough data for Char argument"))
            }
        }
        CilFlavor::I1 => {
            if parser.has_more_data() {
                let val = parser.read_le::<i8>()?;
                Ok(Some(CustomAttributeArgument::I1(val)))
            } else {
                Err(malformed_error!("Not enough data for I1 argument"))
            }
        }
        CilFlavor::U1 => {
            if parser.has_more_data() {
                let val = parser.read_le::<u8>()?;
                Ok(Some(CustomAttributeArgument::U1(val)))
            } else {
                Err(malformed_error!("Not enough data for U1 argument"))
            }
        }
        CilFlavor::I2 => {
            if parser.len() - parser.pos() >= 2 {
                let val = parser.read_le::<i16>()?;
                Ok(Some(CustomAttributeArgument::I2(val)))
            } else {
                Err(malformed_error!("Not enough data for I2 argument"))
            }
        }
        CilFlavor::U2 => {
            if parser.len() - parser.pos() >= 2 {
                let val = parser.read_le::<u16>()?;
                Ok(Some(CustomAttributeArgument::U2(val)))
            } else {
                Err(malformed_error!("Not enough data for U2 argument"))
            }
        }
        CilFlavor::I4 => {
            if parser.len() - parser.pos() >= 4 {
                let val = parser.read_le::<i32>()?;
                Ok(Some(CustomAttributeArgument::I4(val)))
            } else {
                Err(malformed_error!("Not enough data for I4 argument"))
            }
        }
        CilFlavor::U4 => {
            if parser.len() - parser.pos() >= 4 {
                let val = parser.read_le::<u32>()?;
                Ok(Some(CustomAttributeArgument::U4(val)))
            } else {
                Err(malformed_error!("Not enough data for U4 argument"))
            }
        }
        CilFlavor::I8 => {
            if parser.len() - parser.pos() >= 8 {
                let val = parser.read_le::<i64>()?;
                Ok(Some(CustomAttributeArgument::I8(val)))
            } else {
                Err(malformed_error!("Not enough data for I8 argument"))
            }
        }
        CilFlavor::U8 => {
            if parser.len() - parser.pos() >= 8 {
                let val = parser.read_le::<u64>()?;
                Ok(Some(CustomAttributeArgument::U8(val)))
            } else {
                Err(malformed_error!("Not enough data for U8 argument"))
            }
        }
        CilFlavor::R4 => {
            if parser.len() - parser.pos() >= 4 {
                let val = parser.read_le::<f32>()?;
                Ok(Some(CustomAttributeArgument::R4(val)))
            } else {
                Err(malformed_error!("Not enough data for R4 argument"))
            }
        }
        CilFlavor::R8 => {
            if parser.len() - parser.pos() >= 8 {
                let val = parser.read_le::<f64>()?;
                Ok(Some(CustomAttributeArgument::R8(val)))
            } else {
                Err(malformed_error!("Not enough data for R8 argument"))
            }
        }
        CilFlavor::I => {
            // Native signed integer (platform-dependent size)
            // ToDo: This should be handled based in the bitness of the input sample
            if cfg!(target_pointer_width = "64") {
                if parser.len() - parser.pos() >= 8 {
                    let val = parser.read_le::<i64>()?;
                    #[allow(clippy::cast_possible_truncation)]
                    Ok(Some(CustomAttributeArgument::I(val as isize)))
                } else {
                    Err(malformed_error!("Not enough data for I argument"))
                }
            } else if parser.len() - parser.pos() >= 4 {
                let val = parser.read_le::<i32>()?;
                Ok(Some(CustomAttributeArgument::I(val as isize)))
            } else {
                Err(malformed_error!("Not enough data for I argument"))
            }
        }
        CilFlavor::U => {
            // Native unsigned integer (platform-dependent size)
            // ToDo: This should be handled based in the bitness of the input sample
            if cfg!(target_pointer_width = "64") {
                if parser.len() - parser.pos() >= 8 {
                    let val = parser.read_le::<u64>()?;
                    #[allow(clippy::cast_possible_truncation)]
                    Ok(Some(CustomAttributeArgument::U(val as usize)))
                } else {
                    Err(malformed_error!("Not enough data for U argument"))
                }
            } else if parser.len() - parser.pos() >= 4 {
                let val = parser.read_le::<u32>()?;
                Ok(Some(CustomAttributeArgument::U(val as usize)))
            } else {
                Err(malformed_error!("Not enough data for U argument"))
            }
        }
        CilFlavor::String => {
            // Parse string with compressed length prefix according to ECMA-335
            if let Ok(length) = parser.read_compressed_uint() {
                if length as usize <= parser.len() - parser.pos() {
                    let mut arg = String::with_capacity(length as usize);
                    for _ in 0..length as usize {
                        arg.push(char::from(parser.read_le::<u8>()?));
                    }

                    Ok(Some(CustomAttributeArgument::String(arg)))
                } else {
                    Err(malformed_error!("String length exceeds available data"))
                }
            } else {
                Err(malformed_error!("Failed to read string length"))
            }
        }
        CilFlavor::Class => {
            // For class types in custom attributes, they are typically represented as Type arguments
            // According to ECMA-335, Type arguments are serialized as strings containing the type name
            // Parse as string with compressed length prefix
            if let Ok(length) = parser.read_compressed_uint() {
                if length as usize <= parser.len() - parser.pos() {
                    let mut arg = String::with_capacity(length as usize);
                    for _ in 0..length as usize {
                        arg.push(char::from(parser.read_le::<u8>()?));
                    }

                    Ok(Some(CustomAttributeArgument::Type(arg)))
                } else {
                    Err(malformed_error!("Type name length exceeds available data"))
                }
            } else {
                Err(malformed_error!("Failed to read type name length"))
            }
        }
        CilFlavor::ValueType => {
            // Value types (enums) in custom attributes are typically serialized as their underlying type
            // According to ECMA-335, enum values are stored as their underlying primitive type
            // For now, we'll attempt to parse as I4 (the most common enum underlying type)
            // ToDo: A fully compliant implementation would need to resolve the enum's underlying type
            if parser.len() - parser.pos() >= 4 {
                let val = parser.read_le::<i32>()?;
                // Store as enum with unknown type name and I4 value
                Ok(Some(CustomAttributeArgument::Enum(
                    "Unknown".to_string(),
                    Box::new(CustomAttributeArgument::I4(val)),
                )))
            } else {
                Err(malformed_error!(
                    "Not enough data for ValueType (enum) argument"
                ))
            }
        }
        CilFlavor::Array { rank, .. } => {
            // Parse array: NumElems followed by elements
            // For single-dimensional arrays (rank=1), parse as simple array
            // According to ECMA-335 II.23.3, array element count is encoded as I4 (4 bytes)
            if *rank == 1 {
                // Read array element count as 4-byte integer (not compressed)
                if parser.len() - parser.pos() < 4 {
                    return Err(malformed_error!(
                        "Not enough data for array element count (I4)"
                    ));
                }

                let num_elems = parser.read_le::<u32>()?;

                // Get the array element type from the base type
                if let Some(element_type_rc) = type_ref.base() {
                    let element_type_ref = CilTypeRef::from(element_type_rc);
                    let mut array_elements = Vec::new();

                    // Parse each array element
                    for _i in 0..num_elems {
                        if let Some(element) =
                            parse_argument_from_cil_type(parser, &element_type_ref)?
                        {
                            array_elements.push(element);
                        } else {
                            return Err(malformed_error!("Unsupported element type in array"));
                        }
                    }

                    Ok(Some(CustomAttributeArgument::Array(array_elements)))
                } else {
                    Err(malformed_error!(
                        "Array type has no base element type information"
                    ))
                }
            } else {
                Err(malformed_error!(
                    "Multi-dimensional arrays not supported in custom attributes"
                ))
            }
        }
        _ => Err(malformed_error!(
            "Unsupported type flavor in custom attribute: {:?}",
            *flavor_guard
        )),
    }
}

/// Parse a named argument (field or property) from the blob
///
/// This function parses named arguments according to ECMA-335 II.23.3
/// specification, including field/property indicator, type information, name, and value.
///
/// # Arguments
/// * `parser` - The parser positioned at the named argument data
///
/// # Returns
/// Some(CustomAttributeNamedArgument) if successfully parsed, None if no more data
///
/// # Errors
/// Returns an error if parsing fails or data is malformed
fn parse_named_argument(parser: &mut Parser) -> Result<Option<CustomAttributeNamedArgument>> {
    if !parser.has_more_data() {
        return Ok(None);
    }

    // Read field/property indicator (0x53 = field, 0x54 = property)
    let field_or_prop = parser.read_le::<u8>()?;

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
    let type_info = parser.read_le::<u8>()?;
    let arg_type = match type_info {
        0x02 => "Boolean".to_string(),
        0x03 => "Char".to_string(),
        0x04 => "I1".to_string(),
        0x05 => "U1".to_string(),
        0x06 => "I2".to_string(),
        0x07 => "U2".to_string(),
        0x08 => "I4".to_string(),
        0x09 => "U4".to_string(),
        0x0A => "I8".to_string(),
        0x0B => "U8".to_string(),
        0x0C => "R4".to_string(),
        0x0D => "R8".to_string(),
        0x0E => "String".to_string(),
        0x50 => "Type".to_string(),
        _ => {
            return Err(malformed_error!(
                "Unsupported named argument type: 0x{:02X}",
                type_info
            ))
        }
    };

    // Read field/property name (string with compressed length)
    let name_length = parser
        .read_compressed_uint()
        .map_err(|_| malformed_error!("Failed to read named argument name length"))?;

    if name_length as usize > parser.len() - parser.pos() {
        return Err(malformed_error!(
            "Named argument name length exceeds available data"
        ));
    }

    let mut name = String::with_capacity(name_length as usize);
    for _ in 0..name_length as usize {
        name.push(char::from(parser.read_le::<u8>()?));
    }

    // Parse value based on type
    let value = match type_info {
        0x02 => {
            // Boolean
            let val = parser.read_le::<u8>()?;
            CustomAttributeArgument::Bool(val != 0)
        }
        0x03 => {
            // Char
            let val = parser.read_le::<u16>()?;
            let character = char::from_u32(u32::from(val)).unwrap_or('\u{FFFD}'); // Replacement character for invalid
            CustomAttributeArgument::Char(character)
        }
        0x04 => {
            // I1
            let val = parser.read_le::<i8>()?;
            CustomAttributeArgument::I1(val)
        }
        0x05 => {
            // U1
            let val = parser.read_le::<u8>()?;
            CustomAttributeArgument::U1(val)
        }
        0x06 => {
            // I2
            let val = parser.read_le::<i16>()?;
            CustomAttributeArgument::I2(val)
        }
        0x07 => {
            // U2
            let val = parser.read_le::<u16>()?;
            CustomAttributeArgument::U2(val)
        }
        0x08 => {
            // I4
            let val = parser.read_le::<i32>()?;
            CustomAttributeArgument::I4(val)
        }
        0x09 => {
            // U4
            let val = parser.read_le::<u32>()?;
            CustomAttributeArgument::U4(val)
        }
        0x0A => {
            // I8
            let val = parser.read_le::<i64>()?;
            CustomAttributeArgument::I8(val)
        }
        0x0B => {
            // U8
            let val = parser.read_le::<u64>()?;
            CustomAttributeArgument::U8(val)
        }
        0x0C => {
            // R4
            let val = parser.read_le::<f32>()?;
            CustomAttributeArgument::R4(val)
        }
        0x0D => {
            // R8
            let val = parser.read_le::<f64>()?;
            CustomAttributeArgument::R8(val)
        }
        0x0E => {
            // String
            let str_length = parser
                .read_compressed_uint()
                .map_err(|_| malformed_error!("Failed to read string value length"))?;

            if str_length as usize > parser.len() - parser.pos() {
                return Err(malformed_error!(
                    "String value length exceeds available data"
                ));
            }

            let mut str = String::with_capacity(str_length as usize);
            for _ in 0..str_length as usize {
                str.push(char::from(parser.read_le::<u8>()?));
            }
            CustomAttributeArgument::String(str)
        }
        0x50 => {
            // Type
            let type_length = parser
                .read_compressed_uint()
                .map_err(|_| malformed_error!("Failed to read type value length"))?;

            if type_length as usize > parser.len() - parser.pos() {
                return Err(malformed_error!("Type value length exceeds available data"));
            }

            let mut type_name = String::with_capacity(type_length as usize);
            for _ in 0..type_length as usize {
                type_name.push(char::from(parser.read_le::<u8>()?));
            }
            CustomAttributeArgument::Type(type_name)
        }
        _ => {
            return Err(malformed_error!(
                "Unsupported named argument type for parsing: 0x{:02X}",
                type_info
            ))
        }
    };

    Ok(Some(CustomAttributeNamedArgument {
        is_field,
        name,
        arg_type,
        value,
    }))
}
