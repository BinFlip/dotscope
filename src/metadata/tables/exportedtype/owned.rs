use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, token::Token, typesystem::CilTypeReference,
    },
    Result,
};

/// The `ExportedType` table contains information about types that are exported from the current assembly,
/// but defined in other modules of the assembly. Similar to `ExportedTypeRaw` but with resolved indexes and
/// owned data
pub struct ExportedType {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte bitmask of type `TypeAttributes`, §II.23.1.15
    pub flags: u32,
    /// a 4-byte index into the (foreign) `TypeDef` table (this is a hint only, name + namespace are used primarily.
    /// If `type_def_id` happens to match, it has been resolved correctly. `type_def_id` can be 0)
    pub type_def_id: u32,
    /// The type name
    pub name: String,
    /// The type namespace
    pub namespace: Option<String>,
    /// A reference to the Implementation
    pub implementation: CilTypeReference,
    /// Custom attributes applied to this `ExportedType`
    pub custom_attributes: CustomAttributeValueList,
}

impl ExportedType {
    /// Apply an `ExportedType` entry to update related metadata structures.
    ///
    /// `ExportedType` entries define types that are exported from this assembly but may be
    /// implemented in other files or assemblies. They are primarily metadata descriptors
    /// and don't require cross-table updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `ExportedType` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}
