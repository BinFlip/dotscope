use crate::metadata::{
    customattributes::CustomAttributeValueList, imports::ImportRc, token::Token,
};

/// The `Module` table provides information about the current module, including its name, GUID (`Mvid`), and generation. There
/// is only one row in this table for each PE file. Similar to `ModuleRaw` but with resolved indexes and owned data.
pub struct Module {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value, reserved, shall be zero
    pub generation: u32,
    /// Name of this module
    pub name: String,
    /// A Guid used to distinguish between two versions of the same module
    pub mvid: uguid::Guid,
    /// an index into the Guid heap; reserved, shall be zero
    pub encid: Option<uguid::Guid>,
    /// an index into the Guid heap; reserved, shall be zero
    pub encbaseid: Option<uguid::Guid>,
    /// All `CilType` and `MethodDef` entries that are imported from this module
    pub imports: Vec<ImportRc>,
    /// Custom attributes attached to this module
    pub custom_attributes: CustomAttributeValueList,
}
