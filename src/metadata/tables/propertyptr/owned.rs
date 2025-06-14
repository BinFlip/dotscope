use crate::metadata::token::Token;

/// The `PropertyPtr` table provides an indirection layer for accessing Property table entries
/// in uncompressed metadata streams (`#-`). This table is only present in assemblies
/// that use the `#-` stream format instead of the standard `#~` compressed format.
///
/// Each row contains a single field: a 1-based index into the Property table. When `PropertyPtr`
/// is present, property references should be resolved through this indirection table rather
/// than directly indexing into the Property table.
///
/// Similar to `PropertyPtrRaw` but with resolved indexes and owned data.
pub struct PropertyPtr {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `PropertyPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Property table
    pub property: u32,
}
