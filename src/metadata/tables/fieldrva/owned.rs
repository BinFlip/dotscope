use crate::{
    metadata::{tables::FieldRc, token::Token},
    Result,
};

/// The `FieldRVA` table specifies the relative virtual address (RVA) of initial data for fields
/// with the `InitialValue` attribute. Similar to `FieldRVARaw` but with resolved indexes and owned
/// data
pub struct FieldRva {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub rva: u32,
    /// an index into the Field table
    pub field: FieldRc,
}

impl FieldRva {
    /// Apply a `FieldRva` to set the RVA on the resolved field.
    /// This uses the already resolved field reference to avoid redundant lookups.
    ///
    /// # Errors
    /// Returns an error if the RVA is already set
    pub fn apply(&self) -> Result<()> {
        self.field
            .rva
            .set(self.rva)
            .map_err(|_| malformed_error!("Field RVA already set"))
    }
}
