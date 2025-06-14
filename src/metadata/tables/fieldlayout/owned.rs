use crate::{
    metadata::{tables::FieldRc, token::Token, validation::FieldValidator},
    Result,
};

/// The `FieldLayout` table specifies the offset of fields within a type with explicit layout. Similar to `FieldLayoutRaw` but
/// with resolved indexes and owned data
pub struct FieldLayout {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte value, specifying the byte offset of the field within the class
    pub field_offset: u32,
    /// The field that this layout applies to
    pub field: FieldRc,
}

impl FieldLayout {
    /// Apply a `FieldLayout` to update the parent field with layout offset.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent field without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the field layout is already set on the target field,
    /// or if the field offset validation fails.
    pub fn apply(&self) -> Result<()> {
        FieldValidator::validate_field_offset(self.field_offset, Some(&self.field))?;

        self.field
            .layout
            .set(self.field_offset)
            .map_err(|_| malformed_error!("Field layout already set"))
    }
}
