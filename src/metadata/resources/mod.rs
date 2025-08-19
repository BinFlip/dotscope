//! Embedded resources and manifest resource management for .NET assemblies.
//!
//! This module provides comprehensive support for parsing, storing, and accessing embedded resources
//! in .NET assemblies, including manifest resources, resource streams, and resource data management.
//! It handles the three primary resource storage mechanisms in .NET: embedded resources, linked files,
//! and assembly references.
//!
//! # Resource Types in .NET
//!
//! .NET assemblies can contain resources in several forms:
//! - **Embedded Resources**: Binary data directly embedded within the assembly
//! - **Linked Files**: References to external files that should be included during deployment
//! - **Assembly References**: Resources located in other .NET assemblies
//!
//! This module currently focuses on embedded resources, which are the most common type.
//!
//! # Architecture Overview
//!
//! The resource management system uses a multi-layered approach:
//! - **Storage Layer**: [`crate::metadata::resources::Resources`] provides thread-safe resource collection management
//! - **Parsing Layer**: Internal parser handles resource data extraction and parsing
//! - **Type Layer**: Resource-related data structures accessible via public re-exports
//! - **Metadata Integration**: Seamless integration with .NET metadata table system
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::metadata::resources::Resources`] - Thread-safe container for all resources in an assembly
//! - [`crate::metadata::resources::Resource`] - Parsed resource entry with metadata
//! - [`crate::metadata::tables::ManifestResourceRc`] - Reference-counted manifest resource from metadata tables
//!
//! ## Resource Access Patterns
//! - **By Name**: Direct lookup using resource names from manifest
//! - **Iteration**: Efficient traversal of all available resources
//! - **Data Access**: Safe data slice extraction with bounds checking
//!
//! # Usage Patterns
//!
//! ## Basic Resource Enumeration
//!
//! ```ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//! let resources = assembly.resources();
//!
//! println!("Assembly contains {} resources", resources.len());
//!
//! for resource_entry in resources.iter() {
//!     let (name, resource) = (resource_entry.key(), resource_entry.value());
//!     println!("Resource: {} (Size: {} bytes, Offset: 0x{:X})",
//!              name, resource.data_size, resource.data_offset);
//!     
//!     // Check resource visibility using flags
//!     if resource.flags_visibility.is_public() {
//!         println!("  - Public resource");
//!     } else {
//!         println!("  - Private resource");
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Resource Data Access
//!
//! ```rust,ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//! let resources = assembly.resources();
//!
//! // Access specific resource by name
//! if let Some(resource) = resources.get("MyResource.xml") {
//!     if let Some(data) = resources.get_data(&resource) {
//!         println!("Resource data: {} bytes", data.len());
//!         
//!         // Process the resource data
//!         match std::str::from_utf8(data) {
//!             Ok(text) => println!("Text resource content: {}", text),
//!             Err(_) => println!("Binary resource data"),
//!         }
//!     } else {
//!         println!("Resource data not available (may be external)");
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Comprehensive Resource Analysis
//!
//! ```ignore
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
//! let resources = assembly.resources();
//!
//! let mut total_size = 0u64;
//! let mut embedded_count = 0;
//! let mut external_count = 0;
//!
//! for resource_entry in resources.iter() {
//!     let resource = resource_entry.value();
//!     total_size += resource.data_size as u64;
//!     
//!     match resource.source {
//!         None => {
//!             embedded_count += 1;
//!             println!("Embedded: {} ({} bytes)", resource.name, resource.data_size);
//!         }
//!         Some(ref source) => {
//!             external_count += 1;
//!             println!("External: {} -> {}", resource.name, source.name);
//!         }
//!     }
//! }
//!
//! println!("Total: {} resources, {} embedded, {} external, {} total bytes",
//!          resources.len(), embedded_count, external_count, total_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Resource Storage Mechanisms
//!
//! ## Embedded Resources (Currently Supported)
//! - Stored directly in the assembly's data section
//! - Accessible via RVA (Relative Virtual Address) and size
//! - Most common type for application resources
//! - Fully supported by this implementation
//!
//! ## Linked Files (Future Enhancement)
//! - References to external files in the same directory
//! - Metadata contains filename and hash information
//! - Requires file system access during resource loading
//! - Currently returns `None` for data access
//!
//! ## Assembly References (Future Enhancement)
//! - Resources located in other .NET assemblies
//! - Requires loading and parsing additional assemblies
//! - Cross-assembly resource resolution
//! - Currently returns `None` for data access
//!
//! # Thread Safety
//!
//! All resource operations are thread-safe:
//! - **Concurrent Access**: Multiple threads can safely read resources
//! - **Atomic Operations**: Resource insertion and lookup are atomic
//! - **Reference Counting**: `Arc`-based sharing prevents data races
//! - **Iterator Safety**: Iteration can happen concurrently with reads
//!
//! # Error Handling
//!
//! Resource access is designed to be robust:
//! - **Graceful Degradation**: Invalid resources return `None` rather than panicking
//! - **Bounds Checking**: All data access is bounds-checked for safety
//! - **Format Validation**: Resource headers validated during parsing
//! - **Memory Safety**: No unsafe code in resource data access paths
mod encoder;
mod parser;
mod types;

use dashmap::DashMap;
pub use encoder::*;
pub use parser::Resource;
pub use types::*;

use std::sync::Arc;

use crate::{file::File, metadata::tables::ManifestResourceRc};

/// Container for all resources in an assembly with thread-safe access and efficient lookup.
///
/// `Resources` provides a comprehensive resource management system for .NET assemblies,
/// supporting concurrent access, efficient lookup by name, and safe data access with
/// proper bounds checking. It serves as the central hub for all resource operations
/// within an assembly.
///
/// # Architecture
///
/// The container uses a two-layer architecture:
/// - **Storage Layer**: Thread-safe hash map for O(1) resource lookup
/// - **Data Layer**: Direct file access for zero-copy resource data retrieval
///
/// # Resource Lifecycle
///
/// 1. **Loading**: Resources are discovered during metadata table parsing
/// 2. **Registration**: [`insert()`](Resources::insert) adds resources to the collection
/// 3. **Access**: Resources accessed by name or through iteration
/// 4. **Data Retrieval**: [`get_data()`](Resources::get_data) provides access to actual resource bytes
///
/// # Thread Safety
///
/// All operations are thread-safe and can be performed concurrently:
/// - Multiple threads can safely read resources simultaneously
/// - Resource insertion is atomic and doesn't block readers
/// - Iteration can happen concurrently with other operations
///
/// # Examples
///
/// ## Basic Resource Management
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
/// let resources = assembly.resources();
///
/// // Check if assembly has resources
/// if !resources.is_empty() {
///     println!("Assembly has {} resources", resources.len());
///     
///     // Access specific resource
///     if let Some(resource) = resources.get("MyResource") {
///         println!("Found resource: {} ({} bytes)",
///                  resource.name, resource.data_size);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Resource Data Processing
///
/// ```rust,ignore
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
/// let resources = assembly.resources();
///
/// for resource_entry in resources.iter() {
///     let resource = resource_entry.value();
///     
///     if let Some(data) = resources.get_data(&resource) {
///         println!("Processing resource: {} ({} bytes)",
///                  resource.name, data.len());
///         
///         // Determine resource type based on content
///         if data.starts_with(b"<?xml") {
///             println!("  - XML resource");
///         } else if data.starts_with(b"\x89PNG") {
///             println!("  - PNG image resource");
///         } else {
///             println!("  - Binary resource");
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct Resources {
    /// Reference to the originally loaded file
    file: Arc<File>,
    /// Map of all resources by name
    data: DashMap<String, ManifestResourceRc>,
}

impl Resources {
    /// Creates a new empty Resources container.
    ///
    /// Initializes an empty resource collection that will be populated during
    /// the metadata loading process. The container maintains a reference to the
    /// source file for efficient data access.
    ///
    /// # Arguments
    ///
    /// * `file` - Arc-wrapped reference to the originally loaded PE file,
    ///   used for accessing embedded resource data
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::resources::Resources;
    /// use std::sync::Arc;
    ///
    /// let file = Arc::new(file_instance);
    /// let resources = Resources::new(file);
    /// assert!(resources.is_empty());
    /// ```
    #[must_use]
    pub fn new(file: Arc<File>) -> Self {
        Resources {
            file,
            data: DashMap::new(),
        }
    }

    /// Gets a resource by name.
    ///
    /// Performs a thread-safe lookup in the internal hash map to find a resource
    /// with the specified name. Returns a cloned reference-counted pointer to the
    /// resource if found.
    ///
    /// # Arguments
    ///
    /// * `name` - The exact name of the resource to look for (case-sensitive)
    ///
    /// # Returns
    ///
    /// - `Some(ManifestResourceRc)` if a resource with the given name exists
    /// - `None` if no resource with the given name is found
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// // Look for specific resources
    /// if let Some(config) = resources.get("app.config") {
    ///     println!("Found configuration resource: {}", config.name);
    /// }
    ///
    /// if let Some(icon) = resources.get("app.ico") {
    ///     println!("Found icon resource: {} ({} bytes)",
    ///              icon.name, icon.data_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<ManifestResourceRc> {
        self.data.get(name).map(|entry| entry.clone())
    }

    /// Gets a reference to all resources for advanced iteration patterns.
    ///
    /// Returns a direct reference to the internal `DashMap` for advanced use cases
    /// that require direct map operations. For simple iteration, prefer using the
    /// [`iter()`](Resources::iter) method or the `IntoIterator` implementation.
    ///
    /// # Returns
    ///
    /// A reference to the internal `DashMap<String, ManifestResourceRc>`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// // Advanced map operations
    /// let all_resources = resources.all();
    /// let resource_names: Vec<String> = all_resources.iter()
    ///     .map(|entry| entry.key().clone())
    ///     .collect();
    ///
    /// println!("All resource names: {:?}", resource_names);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn all(&self) -> &DashMap<String, ManifestResourceRc> {
        &self.data
    }

    /// Get a slice to the data of a resource with bounds checking and safety guarantees.
    ///
    /// Attempts to access the actual data bytes of a resource. Currently supports
    /// embedded resources only; linked files and assembly references will return
    /// `None` until future implementation.
    ///
    /// The method performs comprehensive bounds checking to ensure safe access to
    /// the resource data without buffer overruns.
    ///
    /// # Arguments
    ///
    /// * `resource` - The manifest resource to read data from
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the resource data for embedded resources
    /// - `None` for linked files, assembly references, or if bounds checking fails
    ///
    /// # Resource Types
    ///
    /// - **Embedded (Supported)**: Data stored directly in the assembly
    /// - **Linked Files (Future)**: External files referenced by the assembly
    /// - **Assembly References (Future)**: Resources in other .NET assemblies
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// for resource_entry in resources.iter() {
    ///     let resource = resource_entry.value();
    ///     
    ///     match resources.get_data(&resource) {
    ///         Some(data) => {
    ///             println!("Resource '{}': {} bytes of data available",
    ///                      resource.name, data.len());
    ///             
    ///             // Analyze resource content
    ///             if let Ok(text) = std::str::from_utf8(data) {
    ///                 if text.len() <= 100 {
    ///                     println!("  Content preview: {}", text);
    ///                 }
    ///             }
    ///         }
    ///         None => {
    ///             println!("Resource '{}': data not accessible (external resource)",
    ///                      resource.name);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_data(&self, resource: &ManifestResourceRc) -> Option<&[u8]> {
        match resource.source {
            // ToDo: The only case we currently handle, is if the resource is embedded in the current file.
            //       Other cases, like File or AssemblyRef, will require us to implement loading multiple binaries
            //       and reading the data from there
            None => self
                .file
                .data_slice(resource.data_offset, resource.data_size)
                .ok(),
            _ => None,
        }
    }

    /// Inserts a manifest resource into the collection.
    ///
    /// This method is typically called by the `ManifestResource` table loader during
    /// the metadata parsing process. It performs an atomic insertion that doesn't
    /// block concurrent readers.
    ///
    /// # Arguments
    ///
    /// * `resource` - The manifest resource to insert into the collection
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple
    /// threads without synchronization. The insertion is atomic and won't interfere
    /// with ongoing read operations.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // This is typically called internally during metadata loading
    /// let resource = ManifestResourceRc::new(/* ... */);
    /// resources.insert(resource);
    /// ```
    pub fn insert(&self, resource: ManifestResourceRc) {
        self.data.insert(resource.name.clone(), resource);
    }

    /// Returns the number of resources in the collection.
    ///
    /// This operation is thread-safe and provides an exact count of resources
    /// currently stored in the collection.
    ///
    /// # Returns
    ///
    /// The total number of resources in the collection
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// let count = resources.len();
    /// if count > 0 {
    ///     println!("Assembly contains {} resources", count);
    /// } else {
    ///     println!("Assembly contains no embedded resources");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no resources in the collection.
    ///
    /// This is equivalent to checking if `len() == 0` but may be more efficient
    /// and provides better semantic clarity for emptiness checks.
    ///
    /// # Returns
    ///
    /// `true` if the collection contains no resources, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// if resources.is_empty() {
    ///     println!("This assembly has no embedded resources");
    /// } else {
    ///     println!("This assembly has {} resources", resources.len());
    ///     
    ///     // Process resources...
    ///     for resource_entry in resources.iter() {
    ///         let resource = resource_entry.value();
    ///         println!("  - {}", resource.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over all resources for efficient traversal.
    ///
    /// Returns an iterator that yields references to each resource entry in the
    /// collection. The iterator is thread-safe and can be used concurrently with
    /// other operations on the same `Resources` instance.
    ///
    /// # Returns
    ///
    /// An iterator over `(String, ManifestResourceRc)` pairs representing
    /// resource names and their corresponding resource objects
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_file(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// // Iterate over all resources
    /// for resource_entry in resources.iter() {
    ///     let (name, resource) = (resource_entry.key(), resource_entry.value());
    ///     
    ///     println!("Resource: {} (Offset: 0x{:X}, Size: {} bytes)",
    ///              name, resource.data_offset, resource.data_size);
    ///     
    ///     // Check resource properties
    ///     if resource.flags.contains(dotscope::metadata::tables::ManifestResourceAttributes::PUBLIC) {
    ///         println!("  - Public resource");
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> dashmap::iter::Iter<'_, String, ManifestResourceRc> {
        self.data.iter()
    }
}

impl<'a> IntoIterator for &'a Resources {
    type Item = dashmap::mapref::multiple::RefMulti<'a, String, ManifestResourceRc>;
    type IntoIter = dashmap::iter::Iter<'a, String, ManifestResourceRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::resources::parser::parse_dotnet_resource;

    use super::*;

    #[test]
    fn test_string_roundtrip() {
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string("TestString", "Hello, World!").unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 1);
        assert!(parsed_resources.contains_key("TestString"));

        let resource = &parsed_resources["TestString"];
        match &resource.data {
            ResourceType::String(s) => assert_eq!(s, "Hello, World!"),
            _ => panic!("Expected string resource"),
        }
    }

    #[test]
    fn test_multiple_types_roundtrip() {
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string("StringRes", "Test").unwrap();
        encoder.add_int32("IntRes", 42).unwrap();
        encoder.add_boolean("BoolRes", true).unwrap();
        encoder.add_byte_array("ByteRes", &[1, 2, 3, 4]).unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 4);

        // Check each resource type
        match &parsed_resources["StringRes"].data {
            ResourceType::String(s) => assert_eq!(s, "Test"),
            _ => panic!("Expected string resource"),
        }

        match &parsed_resources["IntRes"].data {
            ResourceType::Int32(i) => assert_eq!(*i, 42),
            _ => panic!("Expected int32 resource"),
        }

        match &parsed_resources["BoolRes"].data {
            ResourceType::Boolean(b) => assert!(*b),
            _ => panic!("Expected boolean resource"),
        }

        match &parsed_resources["ByteRes"].data {
            ResourceType::ByteArray(data) => assert_eq!(data, &[1, 2, 3, 4]),
            _ => panic!("Expected byte array resource"),
        }
    }

    #[test]
    fn test_all_primitive_types_roundtrip() {
        let mut encoder = DotNetResourceEncoder::new();

        // Add all supported primitive types
        encoder.add_boolean("bool_true", true).unwrap();
        encoder.add_boolean("bool_false", false).unwrap();
        encoder.add_byte("byte_val", 255).unwrap();
        encoder.add_sbyte("sbyte_val", -128).unwrap();
        encoder.add_char("char_val", 'A').unwrap();
        encoder.add_int16("int16_val", -32768).unwrap();
        encoder.add_uint16("uint16_val", 65535).unwrap();
        encoder.add_int32("int32_val", -2147483648).unwrap();
        encoder.add_uint32("uint32_val", 4294967295).unwrap();
        encoder
            .add_int64("int64_val", -9223372036854775808i64)
            .unwrap();
        encoder
            .add_uint64("uint64_val", 18446744073709551615u64)
            .unwrap();
        encoder
            .add_single("single_val", std::f32::consts::PI)
            .unwrap();
        encoder
            .add_double("double_val", std::f64::consts::E)
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 13);

        // Verify all types
        match &parsed_resources["bool_true"].data {
            ResourceType::Boolean(b) => assert!(*b),
            _ => panic!("Expected boolean resource"),
        }

        match &parsed_resources["bool_false"].data {
            ResourceType::Boolean(b) => assert!(!(*b)),
            _ => panic!("Expected boolean resource"),
        }

        match &parsed_resources["byte_val"].data {
            ResourceType::Byte(b) => assert_eq!(*b, 255),
            _ => panic!("Expected byte resource"),
        }

        match &parsed_resources["sbyte_val"].data {
            ResourceType::SByte(b) => assert_eq!(*b, -128),
            _ => panic!("Expected sbyte resource"),
        }

        match &parsed_resources["char_val"].data {
            ResourceType::Char(c) => assert_eq!(*c, 'A'),
            _ => panic!("Expected char resource"),
        }

        match &parsed_resources["int16_val"].data {
            ResourceType::Int16(i) => assert_eq!(*i, -32768),
            _ => panic!("Expected int16 resource"),
        }

        match &parsed_resources["uint16_val"].data {
            ResourceType::UInt16(i) => assert_eq!(*i, 65535),
            _ => panic!("Expected uint16 resource"),
        }

        match &parsed_resources["int32_val"].data {
            ResourceType::Int32(i) => assert_eq!(*i, -2147483648),
            _ => panic!("Expected int32 resource"),
        }

        match &parsed_resources["uint32_val"].data {
            ResourceType::UInt32(i) => assert_eq!(*i, 4294967295),
            _ => panic!("Expected uint32 resource"),
        }

        match &parsed_resources["int64_val"].data {
            ResourceType::Int64(i) => assert_eq!(*i, -9223372036854775808i64),
            _ => panic!("Expected int64 resource"),
        }

        match &parsed_resources["uint64_val"].data {
            ResourceType::UInt64(i) => assert_eq!(*i, 18446744073709551615u64),
            _ => panic!("Expected uint64 resource"),
        }

        match &parsed_resources["single_val"].data {
            ResourceType::Single(f) => assert!((f - std::f32::consts::PI).abs() < 1e-5),
            _ => panic!("Expected single resource"),
        }

        match &parsed_resources["double_val"].data {
            ResourceType::Double(f) => assert!((f - std::f64::consts::E).abs() < 1e-14),
            _ => panic!("Expected double resource"),
        }
    }

    #[test]
    fn test_string_edge_cases_roundtrip() {
        let mut encoder = DotNetResourceEncoder::new();

        // Test various string edge cases - simpler version
        encoder.add_string("empty", "").unwrap();
        encoder.add_string("single_char", "X").unwrap();
        encoder.add_string("basic_ascii", "Hello World").unwrap();
        encoder
            .add_string("medium_string", &"A".repeat(100))
            .unwrap();
        encoder.add_string("special_chars", "\n\r\t\\\"'").unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 5);

        match &parsed_resources["empty"].data {
            ResourceType::String(s) => assert_eq!(s, ""),
            _ => panic!("Expected string resource"),
        }

        match &parsed_resources["single_char"].data {
            ResourceType::String(s) => assert_eq!(s, "X"),
            _ => panic!("Expected string resource"),
        }

        match &parsed_resources["basic_ascii"].data {
            ResourceType::String(s) => assert_eq!(s, "Hello World"),
            _ => panic!("Expected string resource"),
        }

        match &parsed_resources["medium_string"].data {
            ResourceType::String(s) => assert_eq!(s, &"A".repeat(100)),
            _ => panic!("Expected string resource"),
        }

        match &parsed_resources["special_chars"].data {
            ResourceType::String(s) => assert_eq!(s, "\n\r\t\\\"'"),
            _ => panic!("Expected string resource"),
        }
    }

    #[test]
    fn test_byte_array_edge_cases_roundtrip() {
        let mut encoder = DotNetResourceEncoder::new();

        // Test various byte array edge cases
        encoder.add_byte_array("empty", &[]).unwrap();
        encoder.add_byte_array("single_byte", &[42]).unwrap();
        encoder.add_byte_array("all_zeros", &[0; 100]).unwrap();
        encoder.add_byte_array("all_ones", &[255; 50]).unwrap();
        encoder
            .add_byte_array("pattern", &(0u8..=255).collect::<Vec<_>>())
            .unwrap();
        encoder
            .add_byte_array("large", &vec![123u8; 10000])
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 6);

        match &parsed_resources["empty"].data {
            ResourceType::ByteArray(data) => assert_eq!(data.len(), 0),
            _ => panic!("Expected byte array resource"),
        }

        match &parsed_resources["single_byte"].data {
            ResourceType::ByteArray(data) => assert_eq!(data, &[42]),
            _ => panic!("Expected byte array resource"),
        }

        match &parsed_resources["all_zeros"].data {
            ResourceType::ByteArray(data) => assert_eq!(data, &[0; 100]),
            _ => panic!("Expected byte array resource"),
        }

        match &parsed_resources["all_ones"].data {
            ResourceType::ByteArray(data) => assert_eq!(data, &[255; 50]),
            _ => panic!("Expected byte array resource"),
        }

        match &parsed_resources["pattern"].data {
            ResourceType::ByteArray(data) => assert_eq!(data, &(0u8..=255).collect::<Vec<_>>()),
            _ => panic!("Expected byte array resource"),
        }

        match &parsed_resources["large"].data {
            ResourceType::ByteArray(data) => {
                assert_eq!(data.len(), 10000);
                assert!(data.iter().all(|&b| b == 123));
            }
            _ => panic!("Expected byte array resource"),
        }
    }

    #[test]
    fn test_mixed_large_resource_set_roundtrip() {
        let mut encoder = DotNetResourceEncoder::new();

        // Create a large mixed resource set (100 resources of various types)
        for i in 0..100 {
            match i % 13 {
                0 => encoder
                    .add_string(&format!("str_{i}"), &format!("String value {i}"))
                    .unwrap(),
                1 => encoder
                    .add_boolean(&format!("bool_{i}"), i % 2 == 0)
                    .unwrap(),
                2 => encoder
                    .add_byte(&format!("byte_{i}"), (i % 256) as u8)
                    .unwrap(),
                3 => encoder
                    .add_sbyte(
                        &format!("sbyte_{i}"),
                        ((i % 256) as u8).wrapping_sub(128) as i8,
                    )
                    .unwrap(),
                4 => encoder
                    .add_char(
                        &format!("char_{i}"),
                        char::from_u32((65 + (i % 26)) as u32).unwrap(),
                    )
                    .unwrap(),
                5 => encoder
                    .add_int16(&format!("int16_{i}"), ((i % 32768) as i16) - 16384)
                    .unwrap(),
                6 => encoder
                    .add_uint16(&format!("uint16_{i}"), (i % 65536) as u16)
                    .unwrap(),
                7 => encoder
                    .add_int32(&format!("int32_{i}"), i as i32 - 50)
                    .unwrap(),
                8 => encoder
                    .add_uint32(&format!("uint32_{i}"), i as u32 * 1000)
                    .unwrap(),
                9 => encoder
                    .add_int64(&format!("int64_{i}"), (i as i64) * 1000000)
                    .unwrap(),
                10 => encoder
                    .add_uint64(&format!("uint64_{i}"), (i as u64) * 2000000)
                    .unwrap(),
                11 => encoder
                    .add_single(&format!("single_{i}"), i as f32 * 0.1)
                    .unwrap(),
                12 => encoder
                    .add_byte_array(&format!("bytes_{i}"), &vec![i as u8; i % 20 + 1])
                    .unwrap(),
                _ => unreachable!(),
            }
        }

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 100);

        // Verify a few key resources to ensure integrity
        match &parsed_resources["str_0"].data {
            ResourceType::String(s) => assert_eq!(s, "String value 0"),
            _ => panic!("Expected string resource"),
        }

        // i=1 creates bool_1, 1 % 2 != 0 so false
        match &parsed_resources["bool_1"].data {
            ResourceType::Boolean(b) => assert!(!(*b)),
            _ => panic!("Expected boolean resource"),
        }

        match &parsed_resources["bytes_64"].data {
            ResourceType::ByteArray(data) => {
                assert_eq!(data.len(), 64 % 20 + 1); // 5 bytes
                assert!(data.iter().all(|&b| b == 64));
            }
            _ => panic!("Expected byte array resource"),
        }
    }
}
