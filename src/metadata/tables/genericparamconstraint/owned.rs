use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, tables::GenericParamRc, token::Token,
        typesystem::CilTypeRc, validation::ConstraintValidator,
    },
    Result,
};

/// The `GenericParamConstraint` table defines constraints on generic parameters. Similar to `GenericParamConstraintRaw` but
/// with resolved indexes and owned data
pub struct GenericParamConstraint {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// The `GenericParam` that this constraint applies to
    pub owner: GenericParamRc,
    /// an index into the `TypeDefOrRef` coding index
    pub constraint: CilTypeRc,
    /// Custom attributes applied to this `GenericParamConstraint`
    pub custom_attributes: CustomAttributeValueList,
}

impl GenericParamConstraint {
    /// Apply an `GenericParamConstraint` - The owner will be updated with the new `GenericParamConstraint` entry
    ///
    /// # Errors
    /// Returns an error if constraint compatibility validation fails
    pub fn apply(&self) -> Result<()> {
        ConstraintValidator::validate_constraint(
            &self.constraint,
            self.owner.flags,
            &self.owner.name,
            self.owner.token.value(),
        )?;

        self.owner.constraints.push(self.constraint.clone().into());
        Ok(())
    }
}
