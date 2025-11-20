//! # ManifestResource Builder
//!
//! Provides a fluent API for building ManifestResource table entries that describe resources in .NET assemblies.
//! The ManifestResource table contains information about resources embedded in or linked to assemblies,
//! supporting multiple resource storage models including embedded resources, file-based resources, and
//! resources in external assemblies.
//!
//! ## Overview
//!
//! The `ManifestResourceBuilder` enables creation of resource entries with:
//! - Resource name specification (required)
//! - Resource visibility configuration (public/private)
//! - Resource location setup (embedded, file-based, or external assembly)
//! - Offset management for embedded resources
//! - Automatic heap management and token generation
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create an embedded resource
//! let embedded_token = ManifestResourceBuilder::new()
//!     .name("MyApp.Resources.strings.resources")
//!     .public()
//!     .offset(0x1000)
//!     .build(&mut context)?;
//!
//! // Create a file-based resource
//! let file_token = FileBuilder::new()
//!     .name("Resources.resources")
//!     .contains_no_metadata()
//!     .build(&mut context)?;
//!
//! let file_resource_token = ManifestResourceBuilder::new()
//!     .name("MyApp.FileResources")
//!     .private()
//!     .implementation_file(file_token)
//!     .build(&mut context)?;
//!
//! // Create an external assembly resource
//! let assembly_ref_token = AssemblyRefBuilder::new()
//!     .name("MyApp.Resources")
//!     .version(1, 0, 0, 0)
//!     .build(&mut context)?;
//!
//! let external_resource_token = ManifestResourceBuilder::new()
//!     .name("MyApp.ExternalResources")
//!     .public()
//!     .implementation_assembly_ref(assembly_ref_token)
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Resource name is required
//! - **Heap Management**: Strings are automatically added to heaps
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Implementation Support**: Methods for embedded, file-based, and external resources

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        resources::DotNetResourceEncoder,
        tables::{
            CodedIndex, CodedIndexType, ManifestResourceAttributes, ManifestResourceRaw,
            TableDataOwned, TableId,
        },
        token::Token,
    },
    Error, Result,
};

/// Builder for creating ManifestResource table entries.
///
/// `ManifestResourceBuilder` provides a fluent API for creating entries in the ManifestResource
/// metadata table, which contains information about resources embedded in or linked to assemblies.
///
/// # Purpose
///
/// The ManifestResource table serves several key functions:
/// - **Resource Management**: Defines resources available in the assembly
/// - **Location Tracking**: Specifies where resource data is stored
/// - **Access Control**: Controls resource visibility and accessibility
/// - **Globalization Support**: Enables localized resource access
/// - **Multi-assembly Resources**: Supports resources in external assemblies
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing ManifestResource entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
///
/// let resource_token = ManifestResourceBuilder::new()
///     .name("MyApp.Resources.strings")
///     .public()
///     .offset(0x1000)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: A resource name must be provided
/// - **Name Not Empty**: Resource names cannot be empty strings
/// - **Implementation Consistency**: Only one implementation type can be set
///
/// # Integration
///
/// ManifestResource entries integrate with other metadata structures:
/// - **File**: External file-based resources reference File table entries
/// - **AssemblyRef**: External assembly resources reference AssemblyRef entries
/// - **Resource Data**: Embedded resources reference assembly resource sections
#[derive(Debug, Clone)]
pub struct ManifestResourceBuilder {
    /// The name of the resource
    name: Option<String>,
    /// Resource visibility and access flags
    flags: u32,
    /// Offset for embedded resources
    offset: u32,
    /// Implementation reference for resource location
    implementation: Option<CodedIndex>,
    /// Optional resource data for embedded resources
    resource_data: Option<Vec<u8>>,
    /// Optional resource data encoder for generating resource data
    resource_encoder: Option<DotNetResourceEncoder>,
}

impl Default for ManifestResourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ManifestResourceBuilder {
    /// Creates a new `ManifestResourceBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods. Resource visibility defaults to
    /// `PUBLIC` (0x0001) and implementation defaults to embedded (null).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: ManifestResourceAttributes::PUBLIC.bits(),
            offset: 0,
            implementation: None, // Default to embedded (null implementation)
            resource_data: None,
            resource_encoder: None,
        }
    }

    /// Sets the name of the resource.
    ///
    /// Resource names are typically hierarchical and follow naming conventions
    /// like "Namespace.Type.ResourceType" (e.g., "MyApp.Forms.strings.resources").
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the resource
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("MyApp.Resources.strings.resources");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets resource attributes using a bitmask.
    ///
    /// Resource attributes control visibility and accessibility of the resource.
    /// Use the `ManifestResourceAttributes` constants for standard values.
    ///
    /// # Arguments
    ///
    /// * `flags` - Resource attributes bitmask
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::tables::ManifestResourceAttributes;
    /// let builder = ManifestResourceBuilder::new()
    ///     .flags(ManifestResourceAttributes::PRIVATE.bits());
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Marks the resource as public (accessible from external assemblies).
    ///
    /// Public resources can be accessed by other assemblies and runtime systems,
    /// enabling cross-assembly resource sharing and component integration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("MyApp.PublicResources")
    ///     .public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.flags |= ManifestResourceAttributes::PUBLIC.bits();
        self.flags &= !ManifestResourceAttributes::PRIVATE.bits();
        self
    }

    /// Marks the resource as private (restricted to the declaring assembly).
    ///
    /// Private resources are only accessible within the declaring assembly,
    /// providing encapsulation and preventing external access to sensitive data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("MyApp.InternalResources")
    ///     .private();
    /// ```
    #[must_use]
    pub fn private(mut self) -> Self {
        self.flags |= ManifestResourceAttributes::PRIVATE.bits();
        self.flags &= !ManifestResourceAttributes::PUBLIC.bits();
        self
    }

    /// Sets the offset for embedded resources.
    ///
    /// For embedded resources (implementation.row == 0), this specifies the offset
    /// within the assembly's resource section where the resource data begins.
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset within the resource section
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("EmbeddedResource")
    ///     .offset(0x1000);
    /// ```
    #[must_use]
    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Sets the implementation to reference a File table entry.
    ///
    /// Use this for file-based resources that are stored in external files
    /// referenced through the File table.
    ///
    /// # Arguments
    ///
    /// * `file_token` - Token of the File table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let file_token = FileBuilder::new()
    ///     .name("Resources.resources")
    ///     .build(&mut context)?;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("FileBasedResource")
    ///     .implementation_file(file_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_file(mut self, file_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(
            TableId::File,
            file_token.row(),
            CodedIndexType::Implementation,
        ));
        self
    }

    /// Sets the implementation to reference an AssemblyRef table entry.
    ///
    /// Use this for resources that are stored in external assemblies
    /// referenced through the AssemblyRef table.
    ///
    /// # Arguments
    ///
    /// * `assembly_ref_token` - Token of the AssemblyRef table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let assembly_ref_token = AssemblyRefBuilder::new()
    ///     .name("MyApp.Resources")
    ///     .version(1, 0, 0, 0)
    ///     .build(&mut context)?;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("ExternalResource")
    ///     .implementation_assembly_ref(assembly_ref_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_assembly_ref(mut self, assembly_ref_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(
            TableId::AssemblyRef,
            assembly_ref_token.row(),
            CodedIndexType::Implementation,
        ));
        self
    }

    /// Sets the implementation to embedded (null implementation).
    ///
    /// This is the default for embedded resources stored directly in the assembly.
    /// The resource data is located at the specified offset within the assembly's
    /// resource section.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("EmbeddedResource")
    ///     .implementation_embedded()
    ///     .offset(0x1000);
    /// ```
    #[must_use]
    pub fn implementation_embedded(mut self) -> Self {
        self.implementation = None; // Embedded means null implementation
        self
    }

    /// Sets the resource data for embedded resources.
    ///
    /// Specifies the actual data content for embedded resources. When resource data
    /// is provided, the resource will be stored directly in the assembly's resource
    /// section and the offset will be calculated automatically during assembly generation.
    ///
    /// # Arguments
    ///
    /// * `data` - The resource data as raw bytes
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let resource_data = b"Hello, World!";
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("TextResource")
    ///     .resource_data(resource_data);
    /// ```
    #[must_use]
    pub fn resource_data(mut self, data: &[u8]) -> Self {
        self.resource_data = Some(data.to_vec());
        self.implementation = None; // Force embedded implementation
        self
    }

    /// Sets the resource data from a string for text-based embedded resources.
    ///
    /// Convenience method for setting string content as resource data. The string
    /// is encoded as UTF-8 bytes and stored as embedded resource data.
    ///
    /// # Arguments
    ///
    /// * `content` - The string content to store as resource data
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("ConfigResource")
    ///     .resource_string("key=value\nsetting=option");
    /// ```
    #[must_use]
    pub fn resource_string(mut self, content: &str) -> Self {
        self.resource_data = Some(content.as_bytes().to_vec());
        self.implementation = None; // Force embedded implementation
        self
    }

    /// Adds a string resource using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include a string resource
    /// with the specified name and content. Multiple resources can be added to the
    /// same encoder for efficient bundling.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `content` - String content of the resource
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppResources")
    ///     .add_string_resource("AppTitle", "My Application")
    ///     .add_string_resource("Version", "1.0.0");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the string resource.
    pub fn add_string_resource(mut self, resource_name: &str, content: &str) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_string(resource_name, content)?;
        self.implementation = None; // Force embedded implementation
        Ok(self)
    }

    /// Adds a binary resource using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include a binary resource
    /// with the specified name and data.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `data` - Binary data of the resource
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let icon_data = std::fs::read("icon.png")?;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppResources")
    ///     .add_binary_resource("AppIcon", &icon_data)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the binary resource.
    pub fn add_binary_resource(mut self, resource_name: &str, data: &[u8]) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_byte_array(resource_name, data)?;
        self.implementation = None; // Force embedded implementation
        Ok(self)
    }

    /// Adds an XML resource using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include an XML resource
    /// with the specified name and content. XML resources are treated as structured
    /// data and may receive optimized encoding.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `xml_content` - XML content as a string
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let config_xml = r#"<?xml version="1.0"?>
    /// <configuration>
    ///     <setting name="timeout" value="30" />
    /// </configuration>"#;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppConfig")
    ///     .add_xml_resource("config.xml", config_xml)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the XML resource.
    pub fn add_xml_resource(mut self, resource_name: &str, xml_content: &str) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_string(resource_name, xml_content)?;
        self.implementation = None; // Force embedded implementation
        Ok(self)
    }

    /// Adds a text resource with explicit type specification using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include a text resource
    /// with a specific resource type for encoding optimization.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `content` - Text content of the resource
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let json_config = r#"{"timeout": 30, "retries": 3}"#;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppConfig")
    ///     .add_text_resource("config.json", json_config)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the text resource.
    pub fn add_text_resource(mut self, resource_name: &str, content: &str) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_string(resource_name, content)?;
        self.implementation = None; // Force embedded implementation
        Ok(self)
    }

    /// Configures the resource encoder with specific settings.
    ///
    /// Allows customization of the resource encoding process, including alignment,
    /// compression, and deduplication settings. This method provides access to
    /// advanced encoding options for performance optimization.
    ///
    /// # Arguments
    ///
    /// * `configure_fn` - Closure that configures the resource encoder
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("OptimizedResources")
    ///     .configure_encoder(|encoder| {
    ///         // DotNetResourceEncoder configuration can be added here
    ///         // when additional configuration options are implemented
    ///     });
    /// ```
    #[must_use]
    pub fn configure_encoder<F>(mut self, configure_fn: F) -> Self
    where
        F: FnOnce(&mut DotNetResourceEncoder),
    {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        configure_fn(encoder);
        self.implementation = None; // Force embedded implementation
        self
    }

    /// Builds the ManifestResource entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings to the appropriate heaps,
    /// creates the ManifestResource table entry, and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created ManifestResource entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The resource name is not set
    /// - The resource name is empty
    /// - The implementation reference uses an invalid table type (must be File, AssemblyRef, or ExportedType)
    /// - The implementation reference has a row index of 0 for non-embedded resources
    /// - There are issues adding strings to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    ///
    /// let resource_token = ManifestResourceBuilder::new()
    ///     .name("MyApp.Resources")
    ///     .public()
    ///     .offset(0x1000)
    ///     .build(&mut context)?;
    ///
    /// println!("Created ManifestResource with token: {}", resource_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Resource name is required for ManifestResource".to_string(),
            })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Resource name cannot be empty for ManifestResource".to_string(),
            });
        }

        let name_index = context.string_get_or_add(&name)?;

        let implementation = if let Some(impl_ref) = self.implementation {
            match impl_ref.tag {
                TableId::File | TableId::AssemblyRef => {
                    if impl_ref.row == 0 {
                        return Err(Error::ModificationInvalidOperation {
                            details: "Implementation reference row cannot be 0 for File or AssemblyRef tables".to_string(),
                        });
                    }
                    impl_ref
                }
                TableId::ExportedType => {
                    // ExportedType is valid but rarely used
                    if impl_ref.row == 0 {
                        return Err(Error::ModificationInvalidOperation {
                            details:
                                "Implementation reference row cannot be 0 for ExportedType table"
                                    .to_string(),
                        });
                    }
                    impl_ref
                }
                _ => {
                    return Err(Error::ModificationInvalidOperation {
                        details: format!(
                            "Invalid implementation table type: {:?}. Must be File, AssemblyRef, or ExportedType",
                            impl_ref.tag
                        ),
                    });
                }
            }
        } else {
            // For embedded resources, create a null coded index (row 0)
            CodedIndex::new(TableId::File, 0, CodedIndexType::Implementation) // This will have row = 0, indicating embedded
        };

        // Handle resource data if provided
        let mut final_offset = self.offset;
        if let Some(encoder) = self.resource_encoder {
            let encoded_data = encoder.encode_dotnet_format()?;
            let blob_index = context.blob_add(&encoded_data)?;
            final_offset = blob_index;
        } else if let Some(data) = self.resource_data {
            let blob_index = context.blob_add(&data)?;
            final_offset = blob_index;
        }

        let rid = context.next_rid(TableId::ManifestResource);
        let token = Token::new(((TableId::ManifestResource as u32) << 24) | rid);

        let manifest_resource = ManifestResourceRaw {
            rid,
            token,
            offset: 0,
            offset_field: final_offset,
            flags: self.flags,
            name: name_index,
            implementation,
        };

        let table_data = TableDataOwned::ManifestResource(manifest_resource);
        context.table_row_add(TableId::ManifestResource, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::{ManifestResourceAttributes, TableId},
        test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_manifest_resource_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("MyApp.Resources")
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_default() -> Result<()> {
        let builder = ManifestResourceBuilder::default();
        assert!(builder.name.is_none());
        assert_eq!(builder.flags, ManifestResourceAttributes::PUBLIC.bits());
        assert_eq!(builder.offset, 0);
        assert!(builder.resource_data.is_none());
        assert!(builder.resource_encoder.is_none());
        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = ManifestResourceBuilder::new().public().build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Resource name is required"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_empty_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = ManifestResourceBuilder::new().name("").build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Resource name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_public() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("PublicResource")
            .public()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_private() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("PrivateResource")
            .private()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_offset() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("EmbeddedResource")
            .offset(0x1000)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_flags() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("CustomResource")
            .flags(ManifestResourceAttributes::PRIVATE.bits())
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_embedded() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("EmbeddedResource")
            .implementation_embedded()
            .offset(0x2000)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_multiple_resources() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token1 = ManifestResourceBuilder::new()
            .name("Resource1")
            .public()
            .build(&mut context)?;

        let token2 = ManifestResourceBuilder::new()
            .name("Resource2")
            .private()
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(token1, token2);
        assert_eq!(token1.table(), TableId::ManifestResource as u8);
        assert_eq!(token2.table(), TableId::ManifestResource as u8);
        assert_eq!(token2.row(), token1.row() + 1);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_comprehensive() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("MyApp.Comprehensive.Resources")
            .public()
            .offset(0x4000)
            .implementation_embedded()
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Test fluent API chaining
        let token = ManifestResourceBuilder::new()
            .name("FluentResource")
            .private()
            .offset(0x8000)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_clone() {
        let builder1 = ManifestResourceBuilder::new().name("CloneTest").public();
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.flags, builder2.flags);
        assert_eq!(builder1.offset, builder2.offset);
    }

    #[test]
    fn test_manifest_resource_builder_debug() {
        let builder = ManifestResourceBuilder::new().name("DebugResource");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ManifestResourceBuilder"));
        assert!(debug_str.contains("DebugResource"));
    }

    #[test]
    fn test_manifest_resource_builder_invalid_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a builder with an invalid implementation reference (TypeDef table)
        let mut builder = ManifestResourceBuilder::new().name("InvalidImplementation");

        // Manually set an invalid implementation (TypeDef is not valid for Implementation coded index)
        builder.implementation = Some(CodedIndex::new(
            TableId::TypeDef,
            1,
            CodedIndexType::Implementation,
        ));

        let result = builder.build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid implementation table type"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_zero_row_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a builder with a zero row implementation reference
        let mut builder = ManifestResourceBuilder::new().name("ZeroRowImplementation");

        // Manually set an implementation with row 0 (invalid for non-embedded)
        builder.implementation = Some(CodedIndex::new(
            TableId::File,
            0,
            CodedIndexType::Implementation,
        ));

        let result = builder.build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation reference row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_valid_exported_type_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a builder with a valid ExportedType implementation reference
        let mut builder = ManifestResourceBuilder::new().name("ExportedTypeResource");

        // Set a valid ExportedType implementation (row > 0)
        builder.implementation = Some(CodedIndex::new(
            TableId::ExportedType,
            1,
            CodedIndexType::Implementation,
        ));

        let result = builder.build(&mut context);

        assert!(result.is_ok());
        let token = result?;
        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_resource_data() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let resource_data = b"Hello, World!";
        let token = ManifestResourceBuilder::new()
            .name("TextResource")
            .resource_data(resource_data)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_resource_string() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("ConfigResource")
            .resource_string("key=value\nsetting=option")
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_encoder() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("EncodedResources")
            .add_string_resource("AppTitle", "My Application")?
            .add_string_resource("Version", "1.0.0")?
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_configure_encoder() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let token = ManifestResourceBuilder::new()
            .name("OptimizedResources")
            .configure_encoder(|_encoder| {
                // DotNetResourceEncoder doesn't need deduplication setup
            })
            .add_string_resource("Test", "Content")?
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_mixed_resources() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let binary_data = vec![0x01, 0x02, 0x03, 0x04];
        let xml_content = r#"<?xml version="1.0"?><config><setting value="test"/></config>"#;

        let token = ManifestResourceBuilder::new()
            .name("MixedResources")
            .add_string_resource("title", "My App")?
            .add_binary_resource("data", &binary_data)?
            .add_xml_resource("config.xml", xml_content)?
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }
}
