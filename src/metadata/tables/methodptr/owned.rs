//! Owned `MethodPtr` table structure with resolved references and indirection information.
//!
//! This module provides the [`MethodPtr`] struct, which represents method pointer entries
//! with all references resolved and indirection information established. Unlike [`MethodPtrRaw`],
//! this structure provides direct access to method indirection mapping data for stable
//! method reference resolution.
//!
//! [`MethodPtrRaw`]: crate::metadata::tables::MethodPtrRaw

use crate::metadata::token::Token;

/// Owned `MethodPtr` table entry with resolved references and indirection mapping.
///
/// This structure represents a method pointer entry that provides an additional level
/// of indirection for accessing `MethodDef` table entries. It enables stable method
/// references during scenarios requiring method table reorganization, runtime method
/// modification, or development environment support.
///
/// # Indirection Purpose
/// `MethodPtr` entries serve specialized scenarios requiring method stability:
/// - **Edit-and-continue**: Development environments supporting runtime method modification
/// - **Hot-reload systems**: Runtime environments enabling dynamic method updates
/// - **Debugging support**: Debuggers requiring method interception capabilities
/// - **Method versioning**: Systems supporting method replacement without reference updates
/// - **Table reorganization**: Allows `MethodDef` table modifications without breaking references
///
/// # Resolution Mechanism
/// Method pointer resolution follows a two-step process:
/// - **Logical token**: This `MethodPtr` entry's token serves as the logical method reference
/// - **Physical reference**: The `method` field points to the actual `MethodDef` table entry
/// - **Stable mapping**: Logical tokens remain constant while physical references can change
/// - **Transparent access**: Higher-level systems use logical tokens without awareness of indirection
pub struct MethodPtr {
    /// Row identifier within the `MethodPtr` table.
    ///
    /// Unique identifier for this method pointer entry, used for internal
    /// table management and logical method token generation.
    pub rid: u32,

    /// Metadata token identifying this `MethodPtr` entry.
    ///
    /// This token serves as the logical method reference that remains stable
    /// during method table reorganization. Other metadata structures reference
    /// methods using this logical token rather than direct `MethodDef` tokens.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Physical reference to the `MethodDef` table entry.
    ///
    /// 1-based index into the `MethodDef` table specifying the actual method
    /// definition that this pointer references. This physical reference can
    /// be updated during method table reorganization while keeping the logical
    /// token stable.
    pub method: u32,
}
