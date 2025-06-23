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
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use dotscope::metadata::cilassembly::BuilderContext;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(&mut assembly);
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
    metadata::{
        cilassembly::BuilderContext,
        tables::{
            CodedIndex, ManifestResourceAttributes, ManifestResourceRaw, TableDataOwned, TableId,
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
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::cilassembly::BuilderContext;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(&mut assembly);
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
    pub fn new() -> Self {
        Self {
            name: None,
            flags: ManifestResourceAttributes::PUBLIC.bits(),
            offset: 0,
            implementation: None, // Default to embedded (null implementation)
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
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::cilassembly::BuilderContext;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(&mut assembly);
    /// let file_token = FileBuilder::new()
    ///     .name("Resources.resources")
    ///     .build(&mut context)?;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("FileBasedResource")
    ///     .implementation_file(file_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn implementation_file(mut self, file_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(TableId::File, file_token.row()));
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
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::cilassembly::BuilderContext;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(&mut assembly);
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
    pub fn implementation_assembly_ref(mut self, assembly_ref_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(
            TableId::AssemblyRef,
            assembly_ref_token.row(),
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
    pub fn implementation_embedded(mut self) -> Self {
        self.implementation = None; // Embedded means null implementation
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
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::cilassembly::BuilderContext;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(&mut assembly);
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

        let name_index = context.get_or_add_string(&name)?;

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
            CodedIndex::new(TableId::File, 0) // This will have row = 0, indicating embedded
        };

        let rid = context.next_rid(TableId::ManifestResource);
        let token = Token::new(((TableId::ManifestResource as u32) << 24) | rid);

        let manifest_resource = ManifestResourceRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            offset_field: self.offset,
            flags: self.flags,
            name: name_index,
            implementation,
        };

        let table_data = TableDataOwned::ManifestResource(manifest_resource);
        context.add_table_row(TableId::ManifestResource, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        cilassembly::CilAssembly,
        cilassemblyview::CilAssemblyView,
        tables::{ManifestResourceAttributes, TableId},
    };
    use std::path::PathBuf;

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        Ok(CilAssembly::new(view))
    }

    #[test]
    fn test_manifest_resource_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        let result = ManifestResourceBuilder::new().public().build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Resource name is required"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_empty_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        let result = ManifestResourceBuilder::new().name("").build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Resource name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_public() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

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
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("ManifestResourceBuilder"));
        assert!(debug_str.contains("DebugResource"));
    }

    #[test]
    fn test_manifest_resource_builder_invalid_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        // Create a builder with an invalid implementation reference (TypeDef table)
        let mut builder = ManifestResourceBuilder::new().name("InvalidImplementation");

        // Manually set an invalid implementation (TypeDef is not valid for Implementation coded index)
        builder.implementation = Some(CodedIndex::new(TableId::TypeDef, 1));

        let result = builder.build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid implementation table type"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_zero_row_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        // Create a builder with a zero row implementation reference
        let mut builder = ManifestResourceBuilder::new().name("ZeroRowImplementation");

        // Manually set an implementation with row 0 (invalid for non-embedded)
        builder.implementation = Some(CodedIndex::new(TableId::File, 0));

        let result = builder.build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation reference row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_valid_exported_type_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(&mut assembly);

        // Create a builder with a valid ExportedType implementation reference
        let mut builder = ManifestResourceBuilder::new().name("ExportedTypeResource");

        // Set a valid ExportedType implementation (row > 0)
        builder.implementation = Some(CodedIndex::new(TableId::ExportedType, 1));

        let result = builder.build(&mut context);

        assert!(result.is_ok());
        let token = result?;
        assert_eq!(token.table(), TableId::ManifestResource as u8);
        assert!(token.row() > 0);

        Ok(())
    }
}
