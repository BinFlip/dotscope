use crate::metadata::{customattributes::CustomAttributeValueList, token::Token};

/// The `ModuleRef` table contains references to external modules. Similar to `ModuleRefRaw` but with
/// resolved indexes and owned data
pub struct ModuleRef {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The name of the imported module
    pub name: String,
    /// Custom attributes applied to this `ModuleRef`
    pub custom_attributes: CustomAttributeValueList,
}
