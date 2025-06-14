use crate::{
    metadata::{tables::ManifestResourceAttributes, token::Token, typesystem::CilTypeReference},
    Result,
};

/// The `ManifestResource` table lists the resources for the assembly. Similar to `ManifestResourceRaw` but
/// with resolved indexes and owned data
pub struct ManifestResource {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// Offset of the resource data, 0 if not embedded, Name and Source needed, to calculate location in different binary
    pub data_offset: usize,
    /// Size of the resource data, 0 if not embedded, Name and Source needed, to calculate location in different binary
    pub data_size: usize,
    /// a 4-byte bitmask of type `ManifestResourceAttributes`, §II.23.1.9
    pub flags: ManifestResourceAttributes,
    /// an index into the String heap
    pub name: String,
    /// Indicates where (in which module / assembly / file) this resources is located
    /// If None - Offset is in the current file, relative to the resource entry of the CIL header of the specified target
    /// Can only be `AssemblyRef` or File
    pub source: Option<CilTypeReference>,
}

impl ManifestResource {
    /// Apply a `ManifestResource` entry to update related metadata structures.
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
