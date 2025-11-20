//! Raw `ManifestResource` table structure with unresolved coded indexes.
//!
//! This module provides the [`ManifestResourceRaw`] struct, which represents resource entries
//! as stored in the metadata stream. The structure contains unresolved coded indexes
//! and heap references that require processing to establish resource access mechanisms.
//!
//! # Purpose
//! [`ManifestResourceRaw`] serves as the direct representation of `ManifestResource` table entries
//! from the binary metadata stream, before reference resolution and resource data access
//! establishment. This raw format is processed during metadata loading to create
//! [`ManifestResource`] instances with resolved references and direct resource access.
//!
//! [`ManifestResource`]: crate::metadata::tables::ManifestResource

use std::sync::Arc;

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, ManifestResource, ManifestResourceAttributes,
            ManifestResourceRc, MetadataTable, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw `ManifestResource` table entry with unresolved indexes and heap references.
///
/// This structure represents a resource entry as stored directly in the metadata stream.
/// All references are unresolved coded indexes or heap offsets that require processing
/// during metadata loading to establish resource access and location information.
///
/// # Table Structure (ECMA-335 §22.24)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Offset | 4 bytes | Resource data offset (0 for external resources) |
/// | Flags | 4 bytes | Resource visibility attributes |
/// | Name | String index | Resource identifier name |
/// | Implementation | Implementation coded index | Resource location reference |
///
/// # Coded Index Resolution
/// The `implementation` field uses the Implementation coded index encoding:
/// - **Tag 0**: File table (external file resources)
/// - **Tag 1**: `AssemblyRef` table (external assembly resources)
/// - **Tag 2**: `ExportedType` table (rarely used for resources)
/// - **Row 0**: Special case indicating embedded resource in current assembly
///
/// # Resource Location Logic
/// Resource data location is determined by the implementation field:
/// - **Embedded**: implementation.row == 0, data in current assembly at offset
/// - **File-based**: implementation references File table entry
/// - **Assembly-based**: implementation references `AssemblyRef` table entry
#[derive(Clone, Debug)]
pub struct ManifestResourceRaw {
    /// Row identifier within the `ManifestResource` table.
    ///
    /// Unique identifier for this resource entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `ManifestResource` entry (`TableId` 0x28).
    ///
    /// Computed as `0x28000000 | rid` to create the full token value
    /// for referencing this resource from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Resource data offset within the target storage location.
    ///
    /// For embedded resources (implementation.row == 0), this is the offset within
    /// the assembly's resource section. For external resources, this value is 0
    /// and the location is determined by the implementation reference.
    pub offset_field: u32,

    /// Resource visibility and access control flags.
    ///
    /// Raw flag value that will be converted to [`ManifestResourceAttributes`]
    /// during processing to control resource visibility and accessibility.
    ///
    /// [`ManifestResourceAttributes`]: crate::metadata::tables::ManifestResourceAttributes
    pub flags: u32,

    /// String heap index for the resource name.
    ///
    /// References the resource identifier name in the string heap. Resource names
    /// are typically hierarchical and used for runtime resource lookup.
    pub name: u32,

    /// Implementation coded index for resource location.
    ///
    /// Points to File, `AssemblyRef`, or `ExportedType` tables to specify resource location.
    /// A row value of 0 indicates an embedded resource in the current assembly.
    /// Requires coded index resolution during processing to determine actual resource source.
    pub implementation: CodedIndex,
}

impl ManifestResourceRaw {
    /// Convert an `ManifestResourceRaw`, into a `ManifestResource` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'file'        - The mapped raw data of the loaded binary
    /// * 'cor20'       - The cor20 header of the loaded binary
    /// * 'strings'         - The #String heap
    /// * 'files'           - All parsed `File` entries
    /// * 'assemblies'      - All parsed `AssemblyRef` entries
    ///
    /// # Errors
    /// Returns an error if the resource name cannot be retrieved, if the implementation
    /// reference cannot be resolved, or if the resource data cannot be located.
    pub fn to_owned<F>(
        &self,
        get_ref: F,
        file: &File,
        cor20: &Cor20Header,
        strings: &Strings,
        table: &MetadataTable<ManifestResourceRaw>,
    ) -> Result<ManifestResourceRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let mut data_offset = self.offset_field as usize;
        let mut data_size = 0_usize;

        let source = if self.implementation.row == 0 {
            // Special case, this is actually 'NULL', means that the resource is embedded in the current assembly
            data_offset += file.rva_to_offset(cor20.resource_rva as usize)?;
            data_size = if let Some(next_res) = table.get(self.rid + 1) {
                next_res.offset_field as usize - self.offset_field as usize
            } else {
                // Last resource, use resource section size from CLR header
                cor20.resource_size as usize
            };
            None
        } else {
            let implementation = get_ref(&self.implementation);
            if matches!(implementation, CilTypeReference::None) {
                return Err(malformed_error!(
                    "Failed to resolve implementation token - {}",
                    self.implementation.token.value()
                ));
            }

            Some(implementation)
        };

        Ok(Arc::new(ManifestResource {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            data_offset,
            data_size,
            flags: ManifestResourceAttributes::from_bits_truncate(self.flags),
            name: strings.get(self.name as usize)?.to_string(),
            source,
        }))
    }

    /// Apply a `ManifestResourceRaw` entry to update related metadata structures.
    ///
    /// `ManifestResource` entries define resources that are part of this assembly. They are
    /// primarily metadata descriptors for resource data and don't require cross-table
    /// updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `ManifestResource` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for ManifestResourceRaw {
    /// Calculate the row size for `ManifestResource` table entries
    ///
    /// Returns the total byte size of a single `ManifestResource` table row based on the
    /// table configuration. The size varies depending on the size of heap indexes and
    /// coded index configurations in the metadata.
    ///
    /// # Size Breakdown
    /// - `offset_field`: 4 bytes (resource data offset)
    /// - `flags`: 4 bytes (resource visibility and access flags)
    /// - `name`: 2 or 4 bytes (string heap index for resource name)
    /// - `implementation`: 2 or 4 bytes (coded index for resource location)
    ///
    /// Total: 12-16 bytes depending on heap and coded index size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* offset_field */   4 +
            /* flags */          4 +
            /* name */           sizes.str_bytes() +
            /* implementation */ sizes.coded_index_bytes(CodedIndexType::Implementation)
        )
    }
}
