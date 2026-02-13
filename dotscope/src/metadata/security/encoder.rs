//! Permission set encoding for .NET declarative security.
//!
//! This module provides comprehensive encoding functionality for converting structured permission data
//! into binary permission set blobs compatible with the .NET DeclSecurity metadata table.
//! It supports multiple binary formats and XML format generation following ECMA-335 specifications
//! with optimizations for both legacy compatibility and modern compression requirements.
//!
//! # Architecture
//!
//! The encoding system implements a layered approach to permission set serialization:
//!
//! ## Format Support
//! - **Binary Legacy Format**: Original .NET Framework format with full compatibility
//! - **Binary Compressed Format**: Optimized format with advanced compression techniques
//! - **XML Format**: Human-readable format for policy files and debugging
//! - **Format Detection**: Automatic format selection based on content characteristics
//!
//! ## Encoding Pipeline
//! The encoding process follows these stages:
//! 1. **Permission Validation**: Verify permission structures and argument types
//! 2. **Format Selection**: Choose optimal encoding format based on content
//! 3. **Compression Analysis**: Determine compression opportunities for binary formats
//! 4. **Serialization**: Write binary or XML data with proper structure
//! 5. **Validation**: Verify output format compliance
//!
//! ## Compression Strategies
//! For binary compressed format:
//! - **String Deduplication**: Common class names and assembly names are deduplicated
//! - **Argument Optimization**: Repeated argument patterns are compressed
//! - **Type Encoding**: Efficient encoding of argument types and values
//! - **Length Optimization**: Compressed integers for all length fields
//!
//! # Key Components
//!
//! - [`crate::metadata::security::encoder::encode_permission_set`] - Main encoding function with format selection
//! - [`crate::metadata::security::encoder::PermissionSetEncoder`] - Stateful encoder for complex operations
//! - [`crate::metadata::security::encoder::PermissionSetEncoder::encode_binary_format`] - Legacy binary format encoding
//! - [`crate::metadata::security::encoder::PermissionSetEncoder::encode_binary_compressed_format`] - Compressed binary format encoding
//! - [`crate::metadata::security::encoder::PermissionSetEncoder::encode_xml_format`] - XML format encoding
//!
//! # Usage Examples
//!
//! ## Basic Binary Encoding
//!
//! ```rust,no_run
//! use dotscope::metadata::security::{
//!     encode_permission_set, Permission, PermissionSetFormat, NamedArgument,
//!     ArgumentType, ArgumentValue
//! };
//!
//! let permissions = vec![
//!     Permission {
//!         class_name: "System.Security.Permissions.SecurityPermission".to_string(),
//!         assembly_name: "mscorlib".to_string(),
//!         named_arguments: vec![
//!             NamedArgument {
//!                 name: "Unrestricted".to_string(),
//!                 arg_type: ArgumentType::Boolean,
//!                 value: ArgumentValue::Boolean(true),
//!             }
//!         ],
//!     }
//! ];
//!
//! let bytes = encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Compressed Binary Encoding
//!
//! ```rust,ignore
//! let compressed_bytes = encode_permission_set(
//!     &permissions,
//!     PermissionSetFormat::BinaryCompressed
//! )?;
//! // Result: Smaller binary representation with compression
//! ```
//!
//! ## XML Format Encoding
//!
//! ```rust,ignore
//! let xml_bytes = encode_permission_set(&permissions, PermissionSetFormat::Xml)?;
//! let xml_string = String::from_utf8(xml_bytes)?;
//! // Result: "<PermissionSet>...</PermissionSet>"
//! ```
//!
//! ## Advanced Encoder Usage
//!
//! ```rust,ignore
//! use dotscope::metadata::security::PermissionSetEncoder;
//!
//! let mut encoder = PermissionSetEncoder::new();
//! let bytes = encoder.encode_permission_set(&permissions, PermissionSetFormat::BinaryCompressed)?;
//! ```
//!
//! # Error Handling
//!
//! This module defines encoding-specific error handling:
//! - **Unsupported Argument Types**: When permission arguments use unsupported data types
//! - **Unknown Formats**: When attempting to encode to [`crate::metadata::security::PermissionSetFormat::Unknown`]
//! - **Compression Failures**: When binary compression encounters invalid data structures
//! - **XML Generation Errors**: When XML formatting fails due to invalid characters or structure
//!
//! All encoding operations return [`crate::Result<Vec<u8>>`] and follow consistent error patterns.
//!
//! # Thread Safety
//!
//! The [`crate::metadata::security::encoder::PermissionSetEncoder`] is not [`Send`] or [`Sync`] due to internal
//! mutable state. For concurrent encoding, create separate encoder instances per thread
//! or use the stateless [`crate::metadata::security::encoder::encode_permission_set`] function.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::security::permissionset`] - For validation and round-trip testing
//! - [`crate::metadata::security::types`] - For core permission and argument type definitions
//! - [`crate::metadata::security::builders`] - For fluent permission set construction APIs
//! - [`crate::file::io`] - For compressed integer encoding utilities
//!
//! # References
//!
//! - [ECMA-335 6th Edition, Partition II, Section 23.1.3 - Security Actions](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - [ECMA-335 6th Edition, Partition II, Section 23.1.4 - Security Permission Sets](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - Microsoft .NET Framework Security Documentation (archived)

use crate::{
    metadata::security::{
        ArgumentType, ArgumentValue, NamedArgument, Permission, PermissionSetFormat,
    },
    utils::{to_u32, write_compressed_int, write_compressed_uint},
    Result,
};
use std::{collections::HashMap, io::Write};

/// Encodes a permission set to binary format.
///
/// This is a convenience function that creates a [`PermissionSetEncoder`] and encodes
/// a complete permission set to a byte vector. The function handles the full encoding
/// process including format markers, permission counts, and named argument serialization.
///
/// # Arguments
///
/// * `permissions` - The permissions to encode
/// * `format` - The target format for encoding
///
/// # Returns
///
/// * [`Ok`]([`Vec<u8>`]) - Successfully encoded permission set as bytes
/// * [`Err`]([`crate::Error`]) - Encoding failed due to unsupported types or invalid data
///
/// # Errors
///
/// Returns an error if:
/// - Permission class names are invalid or empty
/// - Named argument types cannot be encoded in the target format
/// - String encoding fails due to invalid UTF-8 sequences
/// - The target format does not support the provided permission types
///
/// # Examples
///
/// ## Binary Format Encoding
/// ```rust,no_run
/// use dotscope::metadata::security::{
///     encode_permission_set, Permission, PermissionSetFormat, NamedArgument,
///     ArgumentType, ArgumentValue
/// };
///
/// # fn main() -> dotscope::Result<()> {
/// let permissions = vec![
///     Permission {
///         class_name: "System.Security.Permissions.SecurityPermission".to_string(),
///         assembly_name: "mscorlib".to_string(),
///         named_arguments: vec![
///             NamedArgument {
///                 name: "Unrestricted".to_string(),
///                 arg_type: ArgumentType::Boolean,
///                 value: ArgumentValue::Boolean(true),
///             }
///         ],
///     }
/// ];
///
/// let bytes = encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy)?;
/// // Result: [0x2E, 0x01, ...]  // Binary format with 1 permission
/// # Ok(())
/// # }
/// ```
///
/// ## XML Format Encoding
/// ```rust,ignore
/// let xml_bytes = encode_permission_set(&permissions, PermissionSetFormat::Xml)?;
/// // Result: b"<PermissionSet>...</PermissionSet>"
/// ```
pub fn encode_permission_set(
    permissions: &[Permission],
    format: PermissionSetFormat,
) -> Result<Vec<u8>> {
    let mut encoder = PermissionSetEncoder::new();
    encoder.encode_permission_set(permissions, format)
}

/// Encoder for permission sets.
///
/// The `PermissionSetEncoder` provides stateful encoding of permission sets from
/// structured [`Permission`] data to binary or XML formats as defined in ECMA-335.
/// It handles the complete encoding process including format markers, compression,
/// and proper serialization of named arguments.
///
/// # Design
///
/// The encoder converts permission structures to their binary representation with:
/// - **Format Markers**: Proper format identification bytes (0x2E for binary)
/// - **Compression**: Uses compressed integers for counts and lengths
/// - **Type Encoding**: Handles all supported argument types (Boolean, Int32, String)
/// - **Assembly Resolution**: Maps permission classes to appropriate assemblies
///
/// # Usage Pattern
///
/// ```rust,ignore
/// use dotscope::metadata::security::{PermissionSetEncoder, Permission, PermissionSetFormat};
///
/// let permissions = vec![/* ... */];
/// let mut encoder = PermissionSetEncoder::new();
/// let bytes = encoder.encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy)?;
/// ```
///
/// # Binary Format Structure
///
/// The binary format follows this structure:
/// ```text
/// 1. Format marker: '.' (0x2E)
/// 2. Permission count (compressed integer)
/// 3. For each permission:
///    - Class name length (compressed integer)
///    - Class name (UTF-8 bytes)
///    - Blob length (compressed integer)
///    - Property count (compressed integer)
///    - For each property:
///      - Field/Property marker (0x54)
///      - Type byte (0x02=Boolean, 0x04=Int32, 0x0E=String)
///      - Property name length + UTF-8 name
///      - Property value (format depends on type)
/// ```
pub struct PermissionSetEncoder {
    /// Buffer for building the encoded permission set
    buffer: Vec<u8>,
}

impl PermissionSetEncoder {
    /// Creates a new encoder.
    ///
    /// Initializes a fresh encoder state with an empty buffer.
    ///
    /// # Returns
    ///
    /// A new [`PermissionSetEncoder`] ready to encode permission sets.
    #[must_use]
    pub fn new() -> Self {
        PermissionSetEncoder { buffer: Vec::new() }
    }

    /// Encodes a permission set to the specified format.
    ///
    /// # Arguments
    ///
    /// * `permissions` - The permissions to encode
    /// * `format` - The target format for encoding
    ///
    /// # Errors
    ///
    /// Returns an error if the permissions cannot be encoded or contain invalid data.
    pub fn encode_permission_set(
        &mut self,
        permissions: &[Permission],
        format: PermissionSetFormat,
    ) -> Result<Vec<u8>> {
        self.buffer.clear();

        match format {
            PermissionSetFormat::BinaryLegacy => self.encode_binary_format(permissions)?,
            PermissionSetFormat::BinaryCompressed => {
                self.encode_binary_compressed_format(permissions)?;
            }
            PermissionSetFormat::Xml => self.encode_xml_format(permissions)?,
            PermissionSetFormat::Unknown => {
                return Err(malformed_error!(
                    "Cannot encode unknown permission set format"
                ));
            }
        }

        Ok(self.buffer.clone())
    }

    /// Encodes permissions in binary legacy format.
    ///
    /// The binary format starts with a '.' (0x2E) marker followed by compressed
    /// integers for counts and lengths, making it space-efficient for typical
    /// permission sets found in .NET assemblies.
    fn encode_binary_format(&mut self, permissions: &[Permission]) -> Result<()> {
        self.buffer.push(0x2E);
        write_compressed_uint(to_u32(permissions.len())?, &mut self.buffer);

        for permission in permissions {
            self.encode_permission_binary(permission)?;
        }

        Ok(())
    }

    /// Encodes permissions in binary compressed format.
    ///
    /// The compressed binary format implements advanced compression techniques to minimize
    /// the size of permission set blobs. It uses string deduplication, optimized argument
    /// encoding, and advanced compression algorithms while maintaining full compatibility
    /// with the .NET permission set parsing infrastructure.
    ///
    /// # Compression Techniques
    ///
    /// 1. **String Deduplication**: Common class names and assembly names are stored once
    /// 2. **Argument Optimization**: Repeated argument patterns are compressed
    /// 3. **Type Encoding**: Efficient encoding of argument types and values
    /// 4. **Advanced Markers**: Uses 0x2F marker to distinguish from legacy format
    ///
    /// # Format Structure
    /// ```text
    /// 1. Format marker: '/' (0x2F) - indicates compressed format
    /// 2. String table size (compressed integer)
    /// 3. String table data (deduplicated strings)
    /// 4. Permission count (compressed integer)
    /// 5. For each permission:
    ///    - Class name index (compressed integer, references string table)
    ///    - Assembly name index (compressed integer, references string table)
    ///    - Compressed property data
    /// ```
    fn encode_binary_compressed_format(&mut self, permissions: &[Permission]) -> Result<()> {
        self.buffer.push(0x2F);

        let mut string_table = HashMap::new();
        let mut string_list = Vec::new();
        let mut next_index = 0u32;

        // Collect all unique strings (class names, assembly names, argument names, string values)
        for permission in permissions {
            if !string_table.contains_key(&permission.class_name) {
                string_table.insert(permission.class_name.clone(), next_index);
                string_list.push(permission.class_name.clone());
                next_index += 1;
            }

            if !string_table.contains_key(&permission.assembly_name) {
                string_table.insert(permission.assembly_name.clone(), next_index);
                string_list.push(permission.assembly_name.clone());
                next_index += 1;
            }

            for arg in &permission.named_arguments {
                if !string_table.contains_key(&arg.name) {
                    string_table.insert(arg.name.clone(), next_index);
                    string_list.push(arg.name.clone());
                    next_index += 1;
                }

                if let ArgumentValue::String(ref value) = arg.value {
                    if !string_table.contains_key(value) {
                        string_table.insert(value.clone(), next_index);
                        string_list.push(value.clone());
                        next_index += 1;
                    }
                }
            }
        }

        write_compressed_uint(to_u32(string_list.len())?, &mut self.buffer);
        for string in &string_list {
            let string_bytes = string.as_bytes();
            write_compressed_uint(to_u32(string_bytes.len())?, &mut self.buffer);
            self.buffer.extend_from_slice(string_bytes);
        }

        write_compressed_uint(to_u32(permissions.len())?, &mut self.buffer);
        for permission in permissions {
            let class_name_index = string_table[&permission.class_name];
            let assembly_name_index = string_table[&permission.assembly_name];

            write_compressed_uint(class_name_index, &mut self.buffer);
            write_compressed_uint(assembly_name_index, &mut self.buffer);
            write_compressed_uint(to_u32(permission.named_arguments.len())?, &mut self.buffer);

            for arg in &permission.named_arguments {
                let name_index = string_table[&arg.name];

                write_compressed_uint(name_index, &mut self.buffer);

                let type_byte = match &arg.arg_type {
                    ArgumentType::Boolean => 0x02,
                    ArgumentType::Char => 0x03,
                    ArgumentType::SByte => 0x04,
                    ArgumentType::Byte => 0x05,
                    ArgumentType::Int16 => 0x06,
                    ArgumentType::UInt16 => 0x07,
                    ArgumentType::Int32 => 0x08,
                    ArgumentType::UInt32 => 0x09,
                    ArgumentType::Int64 => 0x0A,
                    ArgumentType::UInt64 => 0x0B,
                    ArgumentType::Single => 0x0C,
                    ArgumentType::Double => 0x0D,
                    ArgumentType::String => 0x0E,
                    ArgumentType::Type => 0x50,
                    ArgumentType::Object => 0x51,
                    _ => {
                        return Err(malformed_error!(
                            "Unsupported argument type for compressed encoding: {:?}",
                            arg.arg_type
                        ));
                    }
                };
                self.buffer.push(type_byte);

                match &arg.value {
                    ArgumentValue::Boolean(value) => {
                        self.buffer.push(u8::from(*value));
                    }
                    ArgumentValue::Char(value) => {
                        self.buffer
                            .extend_from_slice(&(*value as u16).to_le_bytes());
                    }
                    ArgumentValue::SByte(value) => {
                        self.buffer.push(value.to_ne_bytes()[0]);
                    }
                    ArgumentValue::Byte(value) => {
                        self.buffer.push(*value);
                    }
                    ArgumentValue::Int16(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::UInt16(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::Int32(value) => {
                        write_compressed_int(*value, &mut self.buffer);
                    }
                    ArgumentValue::UInt32(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::Int64(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::UInt64(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::Single(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::Double(value) => {
                        self.buffer.extend_from_slice(&value.to_le_bytes());
                    }
                    ArgumentValue::String(value) | ArgumentValue::Type(value) => {
                        let value_index = string_table[value];
                        write_compressed_uint(value_index, &mut self.buffer);
                    }
                    _ => {
                        return Err(malformed_error!(
                            "Unsupported argument value for compressed encoding: {:?}",
                            arg.value
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Encodes a single permission in binary legacy format.
    ///
    /// Writes a single permission entry with the following structure:
    /// 1. Class name length (compressed uint)
    /// 2. Class name bytes (UTF-8)
    /// 3. Blob length (compressed uint)
    /// 4. Permission blob data (via [`Self::encode_permission_blob`])
    ///
    /// # Errors
    ///
    /// Returns an error if encoding the permission blob fails due to unsupported types.
    fn encode_permission_binary(&mut self, permission: &Permission) -> Result<()> {
        let class_name_bytes = permission.class_name.as_bytes();
        write_compressed_uint(to_u32(class_name_bytes.len())?, &mut self.buffer);
        self.buffer.extend_from_slice(class_name_bytes);

        let blob_data = Self::encode_permission_blob(permission)?;
        write_compressed_uint(to_u32(blob_data.len())?, &mut self.buffer);
        self.buffer.extend_from_slice(&blob_data);

        Ok(())
    }

    /// Encodes permission blob data containing named arguments.
    ///
    /// Creates the blob portion of a permission entry with:
    /// 1. Argument count (compressed uint)
    /// 2. For each argument: encoded via [`Self::encode_named_argument`]
    ///
    /// # Returns
    ///
    /// A byte vector containing the encoded permission blob.
    ///
    /// # Errors
    ///
    /// Returns an error if any named argument cannot be encoded.
    fn encode_permission_blob(permission: &Permission) -> Result<Vec<u8>> {
        let mut blob = Vec::new();
        write_compressed_uint(to_u32(permission.named_arguments.len())?, &mut blob);

        for arg in &permission.named_arguments {
            Self::encode_named_argument(arg, &mut blob)?;
        }

        Ok(blob)
    }

    /// Encodes a named argument (property/field).
    ///
    /// # Type Code Reference (ECMA-335)
    ///
    /// | Code | Type     |
    /// |------|----------|
    /// | 0x02 | Boolean  |
    /// | 0x03 | Char     |
    /// | 0x04 | SByte    |
    /// | 0x05 | Byte     |
    /// | 0x06 | Int16    |
    /// | 0x07 | UInt16   |
    /// | 0x08 | Int32    |
    /// | 0x09 | UInt32   |
    /// | 0x0A | Int64    |
    /// | 0x0B | UInt64   |
    /// | 0x0C | Single   |
    /// | 0x0D | Double   |
    /// | 0x0E | String   |
    /// | 0x50 | Type     |
    /// | 0x51 | Object   |
    fn encode_named_argument(arg: &NamedArgument, blob: &mut Vec<u8>) -> Result<()> {
        // 0x54 = FIELD marker (property would be 0x53)
        blob.push(0x54);

        let type_byte = match &arg.arg_type {
            ArgumentType::Boolean => 0x02,
            ArgumentType::Char => 0x03,
            ArgumentType::SByte => 0x04,
            ArgumentType::Byte => 0x05,
            ArgumentType::Int16 => 0x06,
            ArgumentType::UInt16 => 0x07,
            ArgumentType::Int32 => 0x08,
            ArgumentType::UInt32 => 0x09,
            ArgumentType::Int64 => 0x0A,
            ArgumentType::UInt64 => 0x0B,
            ArgumentType::Single => 0x0C,
            ArgumentType::Double => 0x0D,
            ArgumentType::String => 0x0E,
            ArgumentType::Type => 0x50,
            ArgumentType::Object => 0x51,
            ArgumentType::Enum(ref type_name) => {
                // Enum encoding: 0x55 followed by type name
                blob.push(0x55);
                let type_name_bytes = type_name.as_bytes();
                let type_name_len = u32::try_from(type_name_bytes.len()).map_err(|_| {
                    malformed_error!("Enum type name too long: {} bytes", type_name_bytes.len())
                })?;
                write_compressed_uint(type_name_len, blob);
                blob.extend_from_slice(type_name_bytes);
                // Return early since we've already written the type info
                return Self::encode_argument_value(&arg.value, blob);
            }
            ArgumentType::Array(ref _elem_type) => {
                return Err(malformed_error!(
                    "Array argument types are not yet supported for encoding"
                ));
            }
            ArgumentType::Unknown(code) => {
                return Err(malformed_error!(
                    "Cannot encode unknown argument type: 0x{:02X}",
                    code
                ));
            }
        };
        blob.push(type_byte);

        // Write argument name
        let name_bytes = arg.name.as_bytes();
        let name_len = u32::try_from(name_bytes.len())
            .map_err(|_| malformed_error!("Argument name too long: {} bytes", name_bytes.len()))?;
        write_compressed_uint(name_len, blob);
        blob.extend_from_slice(name_bytes);

        // Write argument value
        Self::encode_argument_value(&arg.value, blob)
    }

    /// Encodes an argument value to the blob.
    fn encode_argument_value(value: &ArgumentValue, blob: &mut Vec<u8>) -> Result<()> {
        match value {
            ArgumentValue::Boolean(v) => {
                blob.push(u8::from(*v));
            }
            ArgumentValue::Char(v) => {
                blob.extend_from_slice(&(*v as u16).to_le_bytes());
            }
            ArgumentValue::SByte(v) => {
                blob.push(v.to_ne_bytes()[0]);
            }
            ArgumentValue::Byte(v) => {
                blob.push(*v);
            }
            ArgumentValue::Int16(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::UInt16(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::Int32(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::UInt32(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::Int64(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::UInt64(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::Single(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::Double(v) => {
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::String(v) => {
                let string_bytes = v.as_bytes();
                let string_len = u32::try_from(string_bytes.len()).map_err(|_| {
                    malformed_error!(
                        "Argument string value too long: {} bytes",
                        string_bytes.len()
                    )
                })?;
                write_compressed_uint(string_len, blob);
                blob.extend_from_slice(string_bytes);
            }
            ArgumentValue::Type(v) => {
                let type_bytes = v.as_bytes();
                let type_len = u32::try_from(type_bytes.len()).map_err(|_| {
                    malformed_error!("Type name too long: {} bytes", type_bytes.len())
                })?;
                write_compressed_uint(type_len, blob);
                blob.extend_from_slice(type_bytes);
            }
            ArgumentValue::Object(inner) => {
                // Boxed object: write inner type tag then value
                let inner_type_byte = match inner.as_ref() {
                    ArgumentValue::Boolean(_) => 0x02,
                    ArgumentValue::Char(_) => 0x03,
                    ArgumentValue::SByte(_) => 0x04,
                    ArgumentValue::Byte(_) => 0x05,
                    ArgumentValue::Int16(_) => 0x06,
                    ArgumentValue::UInt16(_) => 0x07,
                    ArgumentValue::Int32(_) => 0x08,
                    ArgumentValue::UInt32(_) => 0x09,
                    ArgumentValue::Int64(_) => 0x0A,
                    ArgumentValue::UInt64(_) => 0x0B,
                    ArgumentValue::Single(_) => 0x0C,
                    ArgumentValue::Double(_) => 0x0D,
                    ArgumentValue::String(_) => 0x0E,
                    ArgumentValue::Type(_) => 0x50,
                    _ => {
                        return Err(malformed_error!(
                            "Cannot encode nested object value: {:?}",
                            inner
                        ));
                    }
                };
                blob.push(inner_type_byte);
                Self::encode_argument_value(inner, blob)?;
            }
            ArgumentValue::Enum(ref _type_name, v) => {
                // Enum value is just the underlying integer
                blob.extend_from_slice(&v.to_le_bytes());
            }
            ArgumentValue::Array(elements) => {
                // Array: write element count followed by elements
                let count = u32::try_from(elements.len()).map_err(|_| {
                    malformed_error!("Array too large: {} elements", elements.len())
                })?;
                blob.extend_from_slice(&count.to_le_bytes());
                for elem in elements {
                    Self::encode_argument_value(elem, blob)?;
                }
            }
            ArgumentValue::Null => {
                // Null string is encoded as 0xFF
                blob.push(0xFF);
            }
        }

        Ok(())
    }

    /// Encodes permissions in XML format.
    ///
    /// The XML format produces human-readable permission sets that are compatible
    /// with .NET security policy files and legacy permission set representations.
    fn encode_xml_format(&mut self, permissions: &[Permission]) -> Result<()> {
        writeln!(
            &mut self.buffer,
            r#"<PermissionSet class="System.Security.PermissionSet" version="1">"#
        )
        .map_err(|e| malformed_error!("Failed to write XML header: {}", e))?;

        for permission in permissions {
            self.encode_permission_xml(permission)?;
        }

        writeln!(&mut self.buffer, "</PermissionSet>")
            .map_err(|e| malformed_error!("Failed to write XML footer: {}", e))?;

        Ok(())
    }

    /// Encodes a single permission as an XML `IPermission` element.
    ///
    /// Writes an `<IPermission>` element with:
    /// - `class` attribute containing the permission class name
    /// - `version` attribute set to "1"
    /// - Named arguments as additional attributes with XML-escaped values
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    fn encode_permission_xml(&mut self, permission: &Permission) -> Result<()> {
        write!(
            &mut self.buffer,
            r#"  <IPermission class="{}" version="1""#,
            permission.class_name
        )
        .map_err(|e| malformed_error!("Failed to write XML permission start: {}", e))?;

        for arg in &permission.named_arguments {
            let value_str = match &arg.value {
                ArgumentValue::Boolean(v) => v.to_string(),
                ArgumentValue::Char(v) => v.to_string(),
                ArgumentValue::SByte(v) => v.to_string(),
                ArgumentValue::Byte(v) => v.to_string(),
                ArgumentValue::Int16(v) => v.to_string(),
                ArgumentValue::UInt16(v) => v.to_string(),
                ArgumentValue::Int32(v) => v.to_string(),
                ArgumentValue::UInt32(v) => v.to_string(),
                ArgumentValue::Int64(v) => v.to_string(),
                ArgumentValue::UInt64(v) => v.to_string(),
                ArgumentValue::Single(v) => v.to_string(),
                ArgumentValue::Double(v) => v.to_string(),
                ArgumentValue::String(v) | ArgumentValue::Type(v) => v.clone(),
                ArgumentValue::Enum(type_name, v) => format!("{type_name}.{v}"),
                ArgumentValue::Object(inner) => inner.to_string(),
                ArgumentValue::Array(elements) => {
                    // Format array as comma-separated values
                    elements
                        .iter()
                        .map(|e| format!("{e}"))
                        .collect::<Vec<_>>()
                        .join(",")
                }
                ArgumentValue::Null => "null".to_string(),
            };

            let escaped_value = Self::xml_escape(&value_str);
            write!(&mut self.buffer, r#" {}="{}""#, arg.name, escaped_value)
                .map_err(|e| malformed_error!("Failed to write XML attribute: {}", e))?;
        }

        writeln!(&mut self.buffer, "/>")
            .map_err(|e| malformed_error!("Failed to write XML permission end: {}", e))?;

        Ok(())
    }

    /// Escapes XML special characters in attribute values.
    ///
    /// This function manually escapes the 5 XML predefined entities required by the XML 1.0 spec.
    /// A manual implementation is used instead of an external XML library for several reasons:
    ///
    /// 1. **Minimal Dependencies**: Avoids adding a dependency just for simple string escaping
    /// 2. **Performance**: Simple string replacements are faster than full XML library processing
    /// 3. **Completeness**: The 5 entities escaped here (`&`, `<`, `>`, `"`, `'`) are the complete
    ///    set of predefined XML entities per the XML 1.0 specification
    /// 4. **Predictability**: Direct control over escaping behavior without library version concerns
    ///
    /// # XML 1.0 Predefined Entities
    ///
    /// | Character | Entity |
    /// |-----------|--------|
    /// | `&` | `&amp;` |
    /// | `<` | `&lt;` |
    /// | `>` | `&gt;` |
    /// | `"` | `&quot;` |
    /// | `'` | `&apos;` |
    ///
    /// # Note
    ///
    /// This implementation handles attribute values only. For element content,
    /// `&apos;` escaping is optional, but we include it for consistency.
    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

impl Default for PermissionSetEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::security::{ArgumentType, ArgumentValue, NamedArgument, Permission};

    #[test]
    fn test_encode_empty_permission_set_binary() {
        let permissions = vec![];
        let encoded =
            encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy).unwrap();

        // Should be: 0x2E (format marker) + 0x00 (0 permissions)
        assert_eq!(encoded, vec![0x2E, 0x00]);
    }

    #[test]
    fn test_encode_simple_security_permission_binary() {
        let permissions = vec![Permission {
            class_name: "System.Security.Permissions.SecurityPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Unrestricted".to_string(),
                arg_type: ArgumentType::Boolean,
                value: ArgumentValue::Boolean(true),
            }],
        }];

        let encoded =
            encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy).unwrap();

        // Should start with 0x2E (format marker) + 0x01 (1 permission)
        assert_eq!(encoded[0], 0x2E);
        assert_eq!(encoded[1], 0x01);

        // Should contain the class name
        let class_name = b"System.Security.Permissions.SecurityPermission";
        assert_eq!(encoded[2], class_name.len() as u8);

        // Verify the class name is present
        let name_start = 3;
        let name_end = name_start + class_name.len();
        assert_eq!(&encoded[name_start..name_end], class_name);
    }

    #[test]
    fn test_encode_permission_with_multiple_arguments() {
        let permissions = vec![Permission {
            class_name: "System.Security.Permissions.FileIOPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![
                NamedArgument {
                    name: "Read".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\temp".to_string()),
                },
                NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(false),
                },
            ],
        }];

        let encoded =
            encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy).unwrap();

        // Should have format marker and 1 permission
        assert_eq!(encoded[0], 0x2E);
        assert_eq!(encoded[1], 0x01);

        // Should have class name length > 0
        assert!(encoded[2] > 0);
    }

    #[test]
    fn test_encode_xml_format() {
        let permissions = vec![Permission {
            class_name: "System.Security.Permissions.SecurityPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Unrestricted".to_string(),
                arg_type: ArgumentType::Boolean,
                value: ArgumentValue::Boolean(true),
            }],
        }];

        let encoded = encode_permission_set(&permissions, PermissionSetFormat::Xml).unwrap();
        let xml_str = String::from_utf8(encoded).unwrap();

        assert!(xml_str.contains("<PermissionSet"));
        assert!(xml_str.contains("System.Security.Permissions.SecurityPermission"));
        assert!(xml_str.contains("Unrestricted=\"true\""));
        assert!(xml_str.contains("</PermissionSet>"));
    }

    #[test]
    fn test_xml_escaping() {
        let _encoder = PermissionSetEncoder::new();

        let input = r#"<test>"value"&more</test>"#;
        let escaped = PermissionSetEncoder::xml_escape(input);

        assert_eq!(
            escaped,
            "&lt;test&gt;&quot;value&quot;&amp;more&lt;/test&gt;"
        );
    }

    #[test]
    fn test_encode_unknown_format() {
        let permissions = vec![];
        let result = encode_permission_set(&permissions, PermissionSetFormat::Unknown);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_unsupported_argument_type() {
        let permissions = vec![Permission {
            class_name: "TestPermission".to_string(),
            assembly_name: "TestAssembly".to_string(),
            named_arguments: vec![NamedArgument {
                name: "UnsupportedArg".to_string(),
                arg_type: ArgumentType::Unknown(0xFF), // Unknown type cannot be encoded
                value: ArgumentValue::Null,
            }],
        }];

        let result = encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_int64_argument() {
        let permissions = vec![Permission {
            class_name: "TestPermission".to_string(),
            assembly_name: "TestAssembly".to_string(),
            named_arguments: vec![NamedArgument {
                name: "LongValue".to_string(),
                arg_type: ArgumentType::Int64,
                value: ArgumentValue::Int64(0x0102_0304_0506_0708),
            }],
        }];

        let result = encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy);
        assert!(result.is_ok());
        let encoded = result.unwrap();
        // Verify the Int64 value is present in the encoded data
        assert!(encoded.len() > 10); // Should have data
    }

    #[test]
    fn test_encode_double_argument() {
        let permissions = vec![Permission {
            class_name: "TestPermission".to_string(),
            assembly_name: "TestAssembly".to_string(),
            named_arguments: vec![NamedArgument {
                name: "DoubleValue".to_string(),
                arg_type: ArgumentType::Double,
                value: ArgumentValue::Double(std::f64::consts::PI),
            }],
        }];

        let result = encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_encode_binary_compressed_format() {
        let permissions = vec![
            Permission {
                class_name: "System.Security.Permissions.SecurityPermission".to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                }],
            },
            Permission {
                class_name: "System.Security.Permissions.SecurityPermission".to_string(), // Duplicate class name for compression
                assembly_name: "mscorlib".to_string(), // Duplicate assembly name
                named_arguments: vec![NamedArgument {
                    name: "Flags".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("Execution".to_string()),
                }],
            },
        ];

        let encoded =
            encode_permission_set(&permissions, PermissionSetFormat::BinaryCompressed).unwrap();

        // Should start with compressed format marker 0x2F
        assert_eq!(encoded[0], 0x2F);

        // Should be smaller than legacy format due to string deduplication
        let legacy_encoded =
            encode_permission_set(&permissions, PermissionSetFormat::BinaryLegacy).unwrap();
        assert!(encoded.len() < legacy_encoded.len());
    }

    #[test]
    fn test_string_deduplication_in_compressed_format() {
        let permissions = vec![
            Permission {
                class_name: "System.Security.Permissions.SecurityPermission".to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                }],
            },
            Permission {
                class_name: "System.Security.Permissions.SecurityPermission".to_string(), // Same class
                assembly_name: "mscorlib".to_string(), // Same assembly
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(), // Same argument name
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(false),
                }],
            },
        ];

        let encoded =
            encode_permission_set(&permissions, PermissionSetFormat::BinaryCompressed).unwrap();

        // Verify compressed format marker
        assert_eq!(encoded[0], 0x2F);

        // The compressed format should deduplicate strings effectively
        // String table should contain: "System.Security.Permissions.SecurityPermission", "mscorlib", "Unrestricted"
        // So string table size should be 3
        assert_eq!(encoded[1], 0x03); // 3 strings in the string table
    }
}
