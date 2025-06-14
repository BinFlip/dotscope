use crate::{
    metadata::{token::Token, typesystem::CilTypeRc, validation::LayoutValidator},
    Result,
};

/// The `ClassLayout` table specifies the layout of fields within a class (explicit layout),
/// similar to `ClassLayoutRaw` but with resolved indexes and owned data
pub struct ClassLayout {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte value, specifying the alignment of fields
    pub packing_size: u16,
    /// a 4-byte value, specifying the size of the class
    pub class_size: u32,
    /// The type that this layout applies to
    pub parent: CilTypeRc,
}

impl ClassLayout {
    /// Apply a `ClassLayout` to update the parent type with class size and packing size.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the parent type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the class size or packing size is already set on the target type.
    pub fn apply(&self) -> Result<()> {
        LayoutValidator::validate_class_layout(self.class_size, self.packing_size, &self.parent)?;

        self.parent
            .class_size
            .set(self.class_size)
            .map_err(|_| malformed_error!("Class size already set"))?;
        self.parent
            .packing_size
            .set(self.packing_size)
            .map_err(|_| malformed_error!("Packing size already set"))
    }
}
