use crate::metadata::{customattributes::CustomAttributeValueList, token::Token};

/// The `StandAloneSig` table stores signatures that are referenced directly rather than through a member.
/// These are primarily used for local variables and method parameters. Similar to `StandAloneSigRaw` but
/// with resolved indexes and owned data.
pub struct StandAloneSig {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the Blob heap
    pub signature: u32,
    /// Custom attributes applied to this standalone signature
    pub custom_attributes: CustomAttributeValueList,
}
