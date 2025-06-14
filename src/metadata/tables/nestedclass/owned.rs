use crate::{
    metadata::{token::Token, typesystem::CilTypeRc, validation::NestedClassValidator},
    Result,
};

/// The `NestedClass` table defines the relationship between nested types and their enclosing types. Similar to `NestedClassRaw` but
/// with resolved indexes and owned data
pub struct NestedClass {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// an index into the `TypeDef` table
    pub nested_class: CilTypeRc,
    /// an index into the `TypeDef` table
    pub enclosing_class: CilTypeRc,
}

impl NestedClass {
    /// Apply a `NestedClass` to update the enclosing type with the nested type reference.
    ///
    /// Since this is the owned structure, all references are already resolved, so we can
    /// efficiently update the enclosing type without re-resolving anything.
    ///
    /// # Errors
    /// Returns an error if the enclosing class and nested class are the same type,
    /// or if nested class validation fails.
    pub fn apply(&self) -> Result<()> {
        NestedClassValidator::validate_nested_relationship(
            self.nested_class.token,
            self.enclosing_class.token,
        )?;

        self.enclosing_class
            .nested_types
            .push(self.nested_class.clone().into());
        Ok(())
    }
}
