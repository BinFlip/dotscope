use std::sync::OnceLock;

use crate::metadata::{
    customattributes::CustomAttributeValueList, security::Security, token::Token,
};

/// Represents a .NET CIL binary (assembly), similar to `AssemblyRaw` but with resolved indexes and owned data
pub struct Assembly {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant of type `AssemblyHashAlgorithm`, §II.23.1.1
    pub hash_alg_id: u32,
    /// a 2-byte value specifying the Major version number
    pub major_version: u32,
    /// a 2-byte value specifying the Minor version number
    pub minor_version: u32,
    /// a 2-byte value specifying the Build number
    pub build_number: u32,
    /// a 2-byte value specifying the Revision number
    pub revision_number: u32,
    /// a 4-byte bitmask of type `AssemblyFlags`, §II.23.1.2
    pub flags: u32,
    /// an index into the Blob heap
    pub public_key: Option<Vec<u8>>,
    /// an index into the String heap
    pub name: String,
    /// an index into the String heap
    pub culture: Option<String>,
    /// The .NET CIL Security Information (if present)
    pub security: OnceLock<Security>,
    /// Custom attributes attached to this assembly
    pub custom_attributes: CustomAttributeValueList,
}
