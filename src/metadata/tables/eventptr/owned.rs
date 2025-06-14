use crate::metadata::token::Token;

/// The `EventPtr` table provides an indirection layer for accessing Event table entries
/// in uncompressed metadata streams (`#-`). This table is only present in assemblies
/// that use the `#-` stream format instead of the standard `#~` compressed format.
///
/// Each row contains a single field: a 1-based index into the Event table. When `EventPtr`
/// is present, event references should be resolved through this indirection table rather
/// than directly indexing into the Event table.
///
/// Similar to `EventPtrRaw` but with resolved indexes and owned data.
pub struct EventPtr {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `EventPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Event table
    pub event: u32,
}
