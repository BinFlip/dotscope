//! .NET resource file parsing infrastructure.
//!
//! This module provides comprehensive parsing capabilities for .NET resource files,
//! implementing the full .NET `ResourceManager` and `RuntimeResourceReader` format
//! specifications. It handles both V1 and V2 resource formats with support for
//! debug builds and all standard resource types.
//!
//! # Resource Format Overview
//!
//! .NET resources use a complex binary format optimized for efficient lookup and
//! type-safe deserialization. The format consists of multiple sections:
//!
//! ## Header Structure
//! 1. **Resource Manager Header**: Contains magic number, version, and type information
//! 2. **Runtime Resource Reader Header**: Contains resource count, type table, and section offsets
//! 3. **Name Section**: Contains resource names and their data offsets
//! 4. **Data Section**: Contains the actual resource data with type information
//!
//! ## Format Versions
//! - **Version 1**: Standard release format
//! - **Version 2**: Enhanced format with optional debug information
//!
//! # Key Components
//!
//! - [`parse_dotnet_resource()`] - High-level parsing function for complete resource extraction
//! - [`Resource`] - Low-level parser that exposes all format details
//! - [`crate::metadata::resources::ResourceEntry`] - Individual resource representation
//! - [`crate::metadata::resources::ResourceType`] - Typed resource data representation
//!
//! # Usage Patterns
//!
//! ## High-Level Resource Parsing
//!
//! ```rust,ignore
//! use dotscope::metadata::resources::parser::parse_dotnet_resource;
//!
//! // Parse complete resource file
//! let resource_data = /* ... resource file bytes ... */;
//! let resources = parse_dotnet_resource(resource_data)?;
//!
//! for (name, entry) in resources {
//!     println!("Resource: {} (Hash: 0x{:X})", name, entry.name_hash);
//!     match entry.data {
//!         ResourceType::String(ref s) => println!("  String: {}", s),
//!         ResourceType::ByteArray(ref bytes) => println!("  Binary: {} bytes", bytes.len()),
//!         _ => println!("  Other type"),
//!     }
//! }
//! ```
//!
//! ## Low-Level Resource Analysis
//!
//! ```rust,ignore
//! use dotscope::metadata::resources::parser::Resource;
//!
//! // Parse resource header and examine structure
//! let resource_data = /* ... resource file bytes ... */;
//! let mut resource = Resource::parse(resource_data)?;
//!
//! println!("Resource Manager Version: {}", resource.res_mgr_header_version);
//! println!("Resource Reader Version: {}", resource.rr_version);
//! println!("Resource Count: {}", resource.resource_count);
//! println!("Type Count: {}", resource.type_names.len());
//! println!("Debug Build: {}", resource.is_debug);
//!
//! // Parse individual resources
//! let resources = resource.read_resources(resource_data)?;
//! ```
//!
//! # Error Handling
//!
//! The parser implements comprehensive validation:
//! - **Magic Number Verification**: Ensures correct file format
//! - **Bounds Checking**: All data access is bounds-checked
//! - **Format Validation**: Header consistency and section alignment checks
//! - **Type Safety**: Resource type validation during deserialization

use std::collections::BTreeMap;

use crate::{
    file::parser::Parser,
    metadata::resources::{ResourceEntry, ResourceType, RESOURCE_MAGIC},
    Result,
};

/// Parse a complete .NET resource buffer into a collection of named resources.
///
/// This is the primary entry point for resource parsing, providing a high-level
/// interface that handles all the complexity of the .NET resource format. It
/// performs complete parsing and returns a map of resource names to their
/// corresponding data and metadata.
///
/// # Format Support
///
/// - **V1 Resources**: Standard release format
/// - **V2 Resources**: Enhanced format with optional debug information
/// - **All Resource Types**: Strings, primitives, byte arrays, and complex objects
///
/// # Arguments
///
/// * `data` - Complete resource file data starting with the resource header
///
/// # Returns
///
/// A `BTreeMap<String, ResourceEntry>` containing all parsed resources, sorted
/// by name for consistent iteration order.
///
/// # Errors
///
/// Returns an error if:
/// - The data is too small to contain a valid resource header
/// - The magic number doesn't match the expected value (0xBEEFCACE)
/// - Header versions are unsupported or malformed
/// - Resource data sections are truncated or corrupted
/// - Individual resource entries cannot be parsed
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::resources::parser::parse_dotnet_resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resources = parse_dotnet_resource(&resource_data)?;
///
/// println!("Found {} resources:", resources.len());
/// for (name, entry) in &resources {
///     println!("  {}: {:?}", name, entry.data);
/// }
/// ```
pub fn parse_dotnet_resource(data: &[u8]) -> Result<BTreeMap<String, ResourceEntry>> {
    let mut resource = Resource::parse(data)?;
    resource.read_resources(data)
}

/// Low-level parser for .NET `ResourceManager` format with complete format exposure.
///
/// This struct provides direct access to all aspects of the .NET resource format,
/// enabling detailed analysis and custom parsing scenarios. It implements the full
/// specification from `CoreCLR` for both V1 and V2 resource formats.
///
/// # Format Structure
///
/// The `Resource` parser exposes all sections of the .NET resource format:
///
/// ## Resource Manager Header
/// - Magic number validation (0xBEEFCACE)
/// - Version information and header sizing
/// - Type information for resource reader and resource set classes
///
/// ## Runtime Resource Reader Header  
/// - Resource reader version (1 or 2)
/// - Optional debug information for V2 debug builds
/// - Resource and type counts
/// - Type name table for all resource types used
///
/// ## Hash and Position Tables
/// - Pre-computed hash values for fast resource lookup
/// - Virtual offsets into the name section for each resource
/// - Data section absolute offset
///
/// ## Use Cases
///
/// - **Format Analysis**: Examining resource file structure and metadata
/// - **Custom Parsing**: Implementing specialized resource extraction logic
/// - **Debugging**: Investigating resource file corruption or format issues
/// - **Research**: Understanding .NET resource format implementation details
///
/// # Examples
///
/// ## Format Analysis
///
/// ```rust,ignore
/// use dotscope::metadata::resources::parser::Resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let resource = Resource::parse(&resource_data)?;
///
/// println!("=== Resource Format Analysis ===");
/// println!("Manager Version: {}", resource.res_mgr_header_version);
/// println!("Reader Version: {}", resource.rr_version);
/// println!("Header Size: {} bytes", resource.header_size);
/// println!("Debug Build: {}", resource.is_debug);
/// println!("Resources: {}", resource.resource_count);
/// println!("Types: {}", resource.type_names.len());
/// println!("Padding: {} bytes", resource.padding);
///
/// println!("\nType Table:");
/// for (i, type_name) in resource.type_names.iter().enumerate() {
///     println!("  [{}] {}", i, type_name);
/// }
/// ```
///
/// ## Custom Resource Processing
///
/// ```rust,ignore
/// use dotscope::metadata::resources::parser::Resource;
///
/// let resource_data = std::fs::read("MyApp.resources")?;
/// let mut resource = Resource::parse(&resource_data)?;
///
/// // Access hash table for fast lookups
/// for (i, hash) in resource.name_hashes.iter().enumerate() {
///     println!("Resource {}: Hash=0x{:08X}, Offset={}",
///              i, hash, resource.name_positions[i]);
/// }
///
/// // Parse all resources with full control
/// let resources = resource.read_resources(&resource_data)?;
/// ```
///
/// # Format Details from `CoreCLR`
///
/// From `CoreCLR` documentation, the system default file format (V1) is:
///
/// ```text
/// What                                               Type of Data
/// ====================================================   ===========
///
///                        Resource Manager header
/// Magic Number (0xBEEFCACE)                               Int32
/// Resource Manager header version                         Int32
/// Num bytes to skip from here to get past this header     Int32
/// Class name of IResourceReader to parse this file        String
/// Class name of ResourceSet to parse this file            String
///
///                       RuntimeResourceReader header
/// ResourceReader version number                           Int32
/// [Only in debug V2 builds - "***DEBUG***"]               String
/// Number of resources in the file                         Int32
/// Number of types in the type table                       Int32
/// Name of each type                                       Set of Strings
/// Padding bytes for 8-byte alignment (use PAD)            Bytes (0-7)
/// Hash values for each resource name                      Int32 array, sorted
/// Virtual offset of each resource name                    Int32 array, coupled with hash values
/// Absolute location of Data section                       Int32
///
///                     RuntimeResourceReader Name Section
/// Name & virtual offset of each resource                  Set of (UTF-16 String, Int32) pairs
///
///                     RuntimeResourceReader Data Section
/// Type and Value of each resource                         Set of (Int32, blob of bytes) pairs
/// ```
///
/// # Thread Safety
///
/// `Resource` is not thread-safe due to mutable parsing state. Create separate
/// instances for concurrent parsing operations.
///
/// # Memory Efficiency
///
/// The parser uses streaming techniques to minimize memory allocation:
/// - String data is parsed directly from source buffer when possible
/// - Binary data maintains references to original data
/// - Type information is stored efficiently in vectors
#[derive(Default)]
pub struct Resource {
    /// Resource Manager header version
    pub res_mgr_header_version: u32,
    /// Size of the header
    pub header_size: u32,
    /// Class name of `IResourceReader` to parse this file
    pub reader_type: String,
    /// Class name of `ResourceSet` to parse this file
    pub resource_set_type: String,
    /// Offset of the `ResourceReader` Header
    pub rr_header_offset: usize,
    /// `ResourceReader` version number
    pub rr_version: u32,
    /// Number of resources in the file
    pub resource_count: u32,
    /// The type table - names of the types used in resources
    pub type_names: Vec<String>,
    /// The amount of padding used
    pub padding: usize,
    /// The name hash table - for faster lookups of resources by name
    pub name_hashes: Vec<u32>,
    /// Virtual offset of each resource name (in `RuntimeResourceReader` Name Section)
    pub name_positions: Vec<u32>,
    /// Absolute location of Data section
    pub data_section_offset: usize,
    /// Beginning of the name section
    pub name_section_offset: usize,
    /// Is a debug build
    pub is_debug: bool,
    /// Is this an embedded resource (with size prefix) vs standalone .resources file
    pub is_embedded_resource: bool,
}

impl Resource {
    /// Parse resource header and structure from raw data with comprehensive validation.
    ///
    /// This method performs complete parsing of the resource file header structure,
    /// including all sections up to but not including the actual resource data.
    /// It validates the format, extracts metadata, and prepares for resource enumeration.
    ///
    /// # Parsing Process
    ///
    /// 1. **Size Validation**: Verifies the data buffer is large enough
    /// 2. **Magic Number Check**: Confirms the file is a valid .NET resource
    /// 3. **Header Parsing**: Extracts version and type information
    /// 4. **Structure Analysis**: Parses type tables, hash arrays, and section offsets
    /// 5. **Offset Calculation**: Determines positions for name and data sections
    ///
    /// # Arguments
    ///
    /// * `data` - Complete resource file data buffer starting with the size header
    ///
    /// # Returns
    ///
    /// A fully initialized `Resource` parser ready for resource enumeration via
    /// [`read_resources()`](Resource::read_resources).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Data buffer is smaller than 12 bytes (minimum header size)
    /// - Size field indicates invalid or truncated data
    /// - Magic number is not 0xBEEFCACE
    /// - Header structure is malformed or truncated
    /// - Type table or hash array data is corrupted
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::resources::parser::Resource;
    ///
    /// let resource_data = std::fs::read("MyApp.resources")?;
    /// let resource = Resource::parse(&resource_data)?;
    ///
    /// println!("Parsed resource file:");
    /// println!("  Manager Version: {}", resource.res_mgr_header_version);
    /// println!("  Reader Version: {}", resource.rr_version);
    /// println!("  Resource Count: {}", resource.resource_count);
    /// println!("  Type Count: {}", resource.type_names.len());
    /// println!("  Debug Build: {}", resource.is_debug);
    /// ```
    ///
    /// # Format Validation
    ///
    /// The parser performs extensive validation:
    /// - **Size Consistency**: Header size fields must be consistent with data length
    /// - **Magic Number**: Must be exactly 0xBEEFCACE for valid .NET resources
    /// - **Version Support**: Supports V1 and V2 resource reader formats
    /// - **Alignment Checks**: Validates padding and alignment requirements
    /// - **Array Bounds**: Ensures hash and position arrays match resource count
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            // Need at least magic + header version + skip bytes + basic header
            return Err(malformed_error!("Resource data too small"));
        }

        let mut parser = Parser::new(data);
        let is_embedded_resource;

        // Auto-detect format: embedded resource (size + magic) vs standalone (.resources file)
        let first_u32 = parser.read_le::<u32>()?;
        let second_u32 = parser.read_le::<u32>()?;

        if second_u32 == RESOURCE_MAGIC {
            // Embedded resource format: [size][magic][header...]
            let size = first_u32 as usize;
            if size > (data.len() - 4) || size < 8 {
                return Err(malformed_error!("Invalid embedded resource size: {}", size));
            }
            is_embedded_resource = true;
            // parser is already positioned after magic number
        } else if first_u32 == RESOURCE_MAGIC {
            // Standalone .resources file format: [magic][header...]
            parser.seek(4)?; // Reset to after magic number
            is_embedded_resource = false;
        } else {
            return Err(malformed_error!(
                "Invalid resource format - no magic number found"
            ));
        }

        let res_mgr_header_version = parser.read_le::<u32>()?;
        let num_bytes_to_skip = parser.read_le::<u32>()?;

        let (reader_type, resource_set_type) = if res_mgr_header_version > 1 {
            // For future versions, skip the specified number of bytes
            if num_bytes_to_skip > (1 << 30) {
                return Err(malformed_error!(
                    "Invalid skip bytes: {}",
                    num_bytes_to_skip
                ));
            }
            parser.advance_by(num_bytes_to_skip as usize)?;
            (String::new(), String::new())
        } else {
            // V1 header: read reader type and resource set type
            let reader_type = parser.read_prefixed_string_utf8()?;
            let resource_set_type = parser.read_prefixed_string_utf8()?;

            if !Self::validate_reader_type(&reader_type) {
                return Err(malformed_error!("Unsupported reader type: {}", reader_type));
            }

            (reader_type, resource_set_type)
        };

        let mut res: Resource = Resource {
            res_mgr_header_version,
            header_size: num_bytes_to_skip,
            reader_type,
            resource_set_type,
            is_embedded_resource,
            ..Default::default()
        };

        res.rr_header_offset = parser.pos();

        // Read RuntimeResourceReader header
        res.rr_version = parser.read_le::<u32>()?;

        if res.rr_version != 1 && res.rr_version != 2 {
            return Err(malformed_error!(
                "Unsupported resource reader version: {}",
                res.rr_version
            ));
        }

        // Check for debug string in V2 debug builds
        if res.rr_version == 2 && (data.len() - parser.pos()) >= 11 {
            // Check if next bytes look like "***DEBUG***"
            let peek_pos = parser.pos();
            if let Ok(debug_string) = parser.read_prefixed_string_utf8() {
                if debug_string == "***DEBUG***" {
                    res.is_debug = true;
                } else {
                    parser.seek(peek_pos)?;
                }
            } else {
                parser.seek(peek_pos)?;
            }
        }
        res.resource_count = parser.read_le::<u32>()?;

        let type_count = parser.read_le::<u32>()?;
        for _ in 0..type_count {
            res.type_names.push(parser.read_prefixed_string_utf8()?);
        }

        // Align to 8-byte boundary exactly as per .NET Framework implementation
        // From .NET source: "Skip over alignment stuff. All public .resources files
        // should be aligned. No need to verify the byte values."
        let pos = parser.pos();
        let align_bytes = pos & 7;
        let mut padding_count = 0;

        if align_bytes != 0 {
            let padding_to_skip = 8 - align_bytes;
            padding_count = padding_to_skip;
            parser.advance_by(padding_to_skip)?;
        }

        // Check for additional PAD pattern bytes that may exist in the file
        // Some .NET resource files include explicit PAD patterns beyond 8-byte alignment
        while parser.pos() < data.len() - 4 {
            let peek_bytes = &data[parser.pos()..parser.pos() + 3.min(data.len() - parser.pos())];
            if peek_bytes.len() >= 3
                && peek_bytes[0] == b'P'
                && peek_bytes[1] == b'A'
                && peek_bytes[2] == b'D'
            {
                // Found PAD pattern, skip it
                parser.advance_by(3)?;
                padding_count += 3;
                // Check for additional padding byte after PAD
                if parser.pos() < data.len()
                    && (data[parser.pos()] == b'P' || data[parser.pos()] == 0)
                {
                    parser.advance()?;
                    padding_count += 1;
                }
            } else {
                break;
            }
        }

        res.padding = padding_count;

        for _ in 0..res.resource_count {
            res.name_hashes.push(parser.read_le::<u32>()?);
        }

        for _ in 0..res.resource_count {
            res.name_positions.push(parser.read_le::<u32>()?);
        }

        res.data_section_offset = parser.read_le::<u32>()? as usize;
        res.name_section_offset = parser.pos();

        Ok(res)
    }

    /// Parse all resources into a name-indexed collection with full type resolution.
    ///
    /// This method performs the actual resource data parsing, extracting resource names,
    /// types, and values from the name and data sections. It uses the hash table and
    /// position information parsed by [`parse()`](Resource::parse) to efficiently
    /// locate and decode each resource.
    ///
    /// # Parsing Process
    ///
    /// For each resource:
    /// 1. **Name Resolution**: Uses position table to locate UTF-16 resource name
    /// 2. **Offset Calculation**: Extracts data section offset for the resource
    /// 3. **Type Identification**: Reads type code and resolves to concrete type
    /// 4. **Data Extraction**: Parses typed resource data based on type information
    /// 5. **Entry Creation**: Creates complete `ResourceEntry` with metadata
    ///
    /// # Arguments
    ///
    /// * `data` - The same complete resource file data buffer used for parsing
    ///
    /// # Returns
    ///
    /// A `BTreeMap<String, ResourceEntry>` containing all resources indexed by name.
    /// The map maintains sorted order for consistent iteration and enables efficient
    /// lookups by resource name.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Name section offsets point beyond the data buffer
    /// - UTF-16 resource names are malformed or truncated
    /// - Data section offsets are invalid or out of bounds
    /// - Resource type codes are unsupported or corrupted
    /// - Individual resource data cannot be parsed
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::resources::parser::Resource;
    ///
    /// let resource_data = std::fs::read("MyApp.resources")?;
    /// let mut resource = Resource::parse(&resource_data)?;
    /// let resources = resource.read_resources(&resource_data)?;
    ///
    /// println!("Found {} resources:", resources.len());
    /// for (name, entry) in &resources {
    ///     println!("Resource: {} (Hash: 0x{:08X})", name, entry.name_hash);
    ///     
    ///     match &entry.data {
    ///         ResourceType::String(s) => {
    ///             println!("  String: '{}'", s);
    ///         }
    ///         ResourceType::ByteArray(bytes) => {
    ///             println!("  Binary data: {} bytes", bytes.len());
    ///         }
    ///         ResourceType::Int32(value) => {
    ///             println!("  Integer: {}", value);
    ///         }
    ///         _ => {
    ///             println!("  Other type: {:?}", entry.data);
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// # Resource Types
    ///
    /// Supports all standard .NET resource types:
    /// - **Primitive Types**: `bool`, `byte`, `sbyte`, `char`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `single`, `double`, `decimal`
    /// - **String Types**: UTF-16 strings with length prefixes
    /// - **`DateTime`**: .NET `DateTime` binary format
    /// - **`TimeSpan`**: .NET `TimeSpan` binary format
    /// - **Byte Arrays**: Raw binary data with length prefixes
    /// - **Custom Objects**: Serialized .NET objects (parsing depends on type)
    pub fn read_resources(&mut self, data: &[u8]) -> Result<BTreeMap<String, ResourceEntry>> {
        let mut resources = BTreeMap::new();
        let mut parser = Parser::new(data);

        for i in 0..self.resource_count as usize {
            let name_pos = self.name_section_offset + self.name_positions[i] as usize;
            parser.seek(name_pos)?;

            let name = parser.read_prefixed_string_utf16()?;
            let type_offset = parser.read_le::<u32>()?;

            let data_pos = if self.is_embedded_resource {
                // Embedded resources: offset calculated from magic number position, need +4 for size field
                self.data_section_offset + type_offset as usize + 4
            } else {
                // Standalone .resources files: use direct offset
                self.data_section_offset + type_offset as usize
            };

            // Validate data position bounds
            if data_pos >= data.len() {
                return Err(malformed_error!(
                    "Resource data offset {} is beyond file bounds",
                    data_pos
                ));
            }

            parser.seek(data_pos)?;

            let resource_data = if self.rr_version == 1 {
                // V1 format: type index (7-bit encoded) followed by data
                let type_index = parser.read_7bit_encoded_int()?;
                if type_index == u32::MAX {
                    // -1 encoded as 7-bit represents null
                    ResourceType::Null
                } else if (type_index as usize) < self.type_names.len() {
                    let type_name = &self.type_names[type_index as usize];
                    ResourceType::from_type_name(type_name, &mut parser)?
                } else {
                    return Err(malformed_error!("Invalid type index: {}", type_index));
                }
            } else {
                // V2 format: type code (7-bit encoded) followed by data
                #[allow(clippy::cast_possible_truncation)]
                let type_code = parser.read_7bit_encoded_int()? as u8;

                if self.type_names.is_empty() {
                    // No type table - this file uses only primitive types (direct type codes)
                    // Common in resource files that contain only strings/primitives
                    ResourceType::from_type_byte(type_code, &mut parser)?
                } else {
                    // Has type table - type code is an index into the type table
                    if (type_code as usize) < self.type_names.len() {
                        let type_name = &self.type_names[type_code as usize];
                        ResourceType::from_type_name(type_name, &mut parser)?
                    } else {
                        return Err(malformed_error!("Invalid type index: {}", type_code));
                    }
                }
            };

            let result = ResourceEntry {
                name: name.clone(),
                name_hash: self.name_hashes[i],
                data: resource_data,
            };

            resources.insert(name, result);
        }

        Ok(resources)
    }

    /// Validate that the reader type is supported by this parser.
    ///
    /// Based on .NET Framework validation, accepts:
    /// - System.Resources.ResourceReader (with or without assembly qualification)
    /// - System.Resources.Extensions.DeserializingResourceReader
    fn validate_reader_type(reader_type: &str) -> bool {
        match reader_type {
            "System.Resources.ResourceReader"
            | "System.Resources.Extensions.DeserializingResourceReader" => true,
            // Accept fully qualified names with mscorlib assembly info
            s if s.starts_with("System.Resources.ResourceReader,") => true,
            s if s.starts_with("System.Resources.Extensions.DeserializingResourceReader,") => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::verify_wbdll_resource_buffer;

    #[test]
    fn wb_example() {
        let data =
            include_bytes!("../../../tests/samples/WB_FxResources.WindowsBase.SR.resources.bin");
        verify_wbdll_resource_buffer(data);
    }
}
