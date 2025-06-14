use crate::metadata::token::Token;

/// The `ParamPtr` table provides an indirection layer for accessing Param table entries
/// in uncompressed metadata streams (`#-`). This table is only present in assemblies
/// that use the `#-` stream format instead of the standard `#~` compressed format.
///
/// Each row contains a single field: a 1-based index into the Param table. When `ParamPtr`
/// is present, parameter references should be resolved through this indirection table rather
/// than directly indexing into the Param table.
///
/// Similar to `ParamPtrRaw` but with resolved indexes and owned data.
pub struct ParamPtr {
    /// Row ID (1-based index)
    pub rid: u32,
    /// Token for this `ParamPtr` entry
    pub token: Token,
    /// Byte offset of this entry in the metadata stream
    pub offset: usize,
    /// 1-based index into the Param table
    pub param: u32,
}
