use crate::metadata::{
    customattributes::CustomAttributeValueList, tables::AssemblyRefHash, token::Token,
};

/// The File table lists the files that make up the current assembly. Similar to `FileRaw` but
/// with resolved indexes and owned data
pub struct File {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte bitmask of type `FileAttributes`, §II.23.1.6
    pub flags: u32,
    /// The file name
    pub name: String,
    /// an index into the Blob heap
    pub hash_value: AssemblyRefHash,
    /// Custom attributes applied to this `File`
    pub custom_attributes: CustomAttributeValueList,
}
