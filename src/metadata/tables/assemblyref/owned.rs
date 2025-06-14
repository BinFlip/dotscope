use std::sync::atomic::AtomicU32;

use crate::metadata::{
    customattributes::CustomAttributeValueList, identity::Identity, tables::AssemblyRefHash,
    token::Token,
};

/// The `AssemblyRef` table contains references to external assemblies,
/// similar to `AssemblyRefRaw` but with resolved indexes and fully owned data.
pub struct AssemblyRef {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The name of the Assembly
    pub name: String,
    /// Culture string
    pub culture: Option<String>,
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
    /// The identifier of the referenced assembly, either a pub-key or token
    pub identifier: Option<Identity>,
    /// The hash of the referenced assembly (ECMA-335 specifies SHA-1 or MD5, but MS seems to have extended...)
    pub hash: Option<AssemblyRefHash>,
    // --- from AssemblyRefOs ---
    /// a 4-byte constant
    pub os_platform_id: AtomicU32,
    /// a 4-byte constant
    pub os_major_version: AtomicU32,
    /// a 4-byte constant
    pub os_minor_version: AtomicU32,
    // --- from AssemblyRefProcessor ---
    /// a 4-byte constant
    pub processor: AtomicU32,
    /// Custom attributes applied to this `AssemblyRef`
    pub custom_attributes: CustomAttributeValueList,
}
