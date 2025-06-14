use crate::{
    metadata::{signatures::SignatureTypeSpec, token::Token},
    Result,
};

/// The `TypeSpec` table defines type specifications through signatures. Similar to `TypeSpecRaw` but
/// with resolved indexes and owned data
pub struct TypeSpec {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The parsed type specification signature
    pub signature: SignatureTypeSpec,
}

impl TypeSpec {
    /// Apply a `TypeSpec` entry to update related metadata structures.
    ///
    /// `TypeSpec` entries define type specifications through signatures. They are primarily
    /// type definitions and don't require cross-table updates during the dual variant
    /// resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `TypeSpec` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}
