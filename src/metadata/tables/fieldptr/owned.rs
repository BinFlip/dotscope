use crate::metadata::token::Token;

/// The `FieldPtr` table provides an indirection layer for accessing Field table entries
/// in uncompressed metadata streams (`#-`). This table is only present in assemblies
/// that use the `#-` stream format instead of the standard `#~` compressed format.
///
/// Each row contains a single field: a 1-based index into the Field table. When `FieldPtr`
/// is present, field references should be resolved through this indirection table rather
/// than directly indexing into the Field table.
///
/// Similar to `FieldPtrRaw` but with resolved indexes and owned data.
pub struct FieldPtr {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `FieldPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Field table
    pub field: u32,
}
