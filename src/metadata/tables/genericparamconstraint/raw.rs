//! Raw GenericParamConstraint structures for the GenericParamConstraint metadata table.
//!
//! This module provides the [`GenericParamConstraintRaw`] struct for reading constraint data
//! directly from metadata tables before index resolution. The GenericParamConstraint table
//! defines constraints that apply to generic parameters, specifying type requirements.
//!
//! # Table Structure
//! The GenericParamConstraint table (TableId = 0x2C) contains these columns:
//! - `Owner`: Index into GenericParam table for the constrained parameter
//! - `Constraint`: Coded index into TypeDefOrRef for the constraint type
//!
//! # Constraint Context
//! GenericParamConstraint entries enable constraint-based generic programming:
//! - **Base class constraints**: Inheritance requirements for type arguments
//! - **Interface constraints**: Implementation requirements for type arguments
//! - **Multiple constraints**: Parameters can have multiple constraint entries
//! - **Type safety**: Compile-time verification of constraint satisfaction
//! - **Code optimization**: Enabling specialized code generation for constrained types
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.21 for the GenericParamConstraint table specification.
use std::sync::Arc;

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, GenericParamConstraint, GenericParamConstraintRc,
            GenericParamMap, RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::TypeRegistry,
        validation::ConstraintValidator,
    },
    Result,
};

/// Raw generic parameter constraint data read directly from the GenericParamConstraint metadata table.
///
/// This structure represents a constraint entry before index resolution and reference
/// dereferencing. Generic parameter constraints specify type requirements that must
/// be satisfied by type arguments for generic parameters.
///
/// # Binary Format
/// Each row in the GenericParamConstraint table has this layout:
/// ```text
/// Offset | Size | Field      | Description
/// -------|------|------------|----------------------------------
/// 0      | 2/4  | Owner      | GenericParam table index
/// 2/4    | 2/4  | Constraint | TypeDefOrRef coded index
/// ```
///
/// Index sizes depend on table sizes.
///
/// # Constraint Context
/// GenericParamConstraint entries are used for:
/// - **Base class constraints**: `where T : BaseClass` (inheritance requirement)
/// - **Interface constraints**: `where T : IInterface` (implementation requirement)
/// - **Multiple constraints**: Parameters can have multiple constraint entries
/// - **Circular constraints**: `where T : IComparable<T>` (self-referential constraints)
/// - **Nested generic constraints**: `where T : IList<U>` (constraints with generic arguments)
///
/// # Constraint Types
/// The Constraint field uses TypeDefOrRef coded index:
/// - **TypeDef**: For internal types defined in the assembly
/// - **TypeRef**: For external types from other assemblies
/// - **TypeSpec**: For complex type specifications (generics, arrays, etc.)
///
/// # Validation Process
/// Constraints undergo validation during application:
/// - **Compatibility checking**: Ensures constraint types are valid for the parameter
/// - **Accessibility verification**: Confirms constraint types are accessible
/// - **Circular dependency detection**: Prevents invalid constraint cycles
/// - **Attribute consistency**: Validates constraint compatibility with parameter attributes
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.21 for the complete GenericParamConstraint table specification.
#[derive(Clone, Debug)]
pub struct GenericParamConstraintRaw {
    /// The row identifier in the GenericParamConstraint table.
    ///
    /// This 1-based index uniquely identifies this constraint within the GenericParamConstraint table.
    pub rid: u32,

    /// The metadata token for this generic parameter constraint.
    ///
    /// A [`Token`] that uniquely identifies this constraint across the entire assembly.
    /// The token value is calculated as `0x2C000000 + rid`.
    ///
    /// [`Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this constraint in the metadata tables stream.
    ///
    /// This offset points to the start of this constraint's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Index into the GenericParam table for the constrained parameter.
    ///
    /// This index points to the generic parameter that this constraint applies to,
    /// which needs to be resolved during conversion to owned data.
    pub owner: u32,

    /// Coded index into the TypeDefOrRef tables for the constraint type.
    ///
    /// A [`CodedIndex`] that references the type that serves as the constraint:
    /// - **TypeDef**: For internal types defined in the assembly
    /// - **TypeRef**: For external types from other assemblies
    /// - **TypeSpec**: For complex type specifications
    ///
    /// [`CodedIndex`]: crate::metadata::tables::CodedIndex
    pub constraint: CodedIndex,
}

impl GenericParamConstraintRaw {
    /// Apply this constraint directly to the referenced generic parameter.
    ///
    /// This method resolves references and applies the constraint to the target parameter
    /// without creating an owned structure. The constraint undergoes validation to ensure
    /// compatibility with the parameter's attributes.
    ///
    /// # Arguments
    /// * `generic_params` - Collection of all generic parameters for resolving owners
    /// * `types` - Type registry for resolving constraint type references
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Constraint type reference cannot be resolved
    /// - Generic parameter owner cannot be found
    /// - Constraint compatibility validation fails
    /// - Constraint application to parameter fails
    pub fn apply(&self, generic_params: &GenericParamMap, types: &TypeRegistry) -> Result<()> {
        let Some(constraint) = types.get(&self.constraint.token) else {
            return Err(malformed_error!(
                "Failed to resolve constraint token - {}",
                self.constraint.token
            ));
        };

        match generic_params.get(&Token::new(self.owner | 0x2A00_0000)) {
            Some(owner) => {
                ConstraintValidator::validate_constraint(
                    &constraint,
                    owner.value().flags,
                    &owner.value().name,
                    owner.value().token.value(),
                )?;

                owner.value().constraints.push(constraint.into());
                Ok(())
            }
            None => Err(malformed_error!(
                "Invalid owner token - {}",
                self.owner | 0x2A00_0000
            )),
        }
    }

    /// Convert this raw constraint to an owned [`GenericParamConstraint`] with resolved references.
    ///
    /// This method resolves the parameter and type references to create a complete
    /// constraint structure with owned data. The resulting [`GenericParamConstraint`] contains
    /// resolved references to both the target parameter and constraint type.
    ///
    /// # Arguments
    /// * `generic_params` - Collection of all generic parameters for resolving owners
    /// * `types` - Type registry for resolving constraint type references
    ///
    /// # Returns
    /// Returns a reference-counted [`GenericParamConstraint`] with resolved data, or an error if:
    /// - Generic parameter owner reference cannot be resolved
    /// - Constraint type reference cannot be resolved
    /// - Memory allocation fails during conversion
    ///
    /// # Constraint Resolution
    /// The conversion process:
    /// 1. Resolves generic parameter owner from the parameter collection
    /// 2. Resolves constraint type from the type registry
    /// 3. Creates owned [`GenericParamConstraint`] with resolved references
    /// 4. Initializes empty custom attributes collection
    ///
    /// # Reference Resolution
    /// - **Parameter resolution**: Uses token calculation (owner | 0x2A000000) for GenericParam lookup
    /// - **Type resolution**: Uses coded index token for type registry lookup
    /// - **Error handling**: Returns detailed error messages for failed resolutions
    ///
    /// [`GenericParamConstraint`]: crate::metadata::tables::GenericParamConstraint
    /// [`GenericParamMap`]: crate::metadata::tables::GenericParamMap
    /// [`TypeRegistry`]: crate::metadata::typesystem::TypeRegistry
    pub fn to_owned(
        &self,
        generic_params: &GenericParamMap,
        types: &TypeRegistry,
    ) -> Result<GenericParamConstraintRc> {
        Ok(Arc::new(GenericParamConstraint {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            owner: match generic_params.get(&Token::new(self.owner | 0x2A00_0000)) {
                Some(owner) => owner.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to generic_param token - {}",
                        self.owner | 0x2A00_0000
                    ))
                }
            },
            constraint: match types.get(&self.constraint.token) {
                Some(constraint) => constraint,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve constraint type token - {}",
                        self.constraint.token.value()
                    ))
                }
            },
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for GenericParamConstraintRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* owner */      sizes.table_index_bytes(TableId::GenericParam) +
            /* constraint */ sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(GenericParamConstraintRaw {
            rid,
            token: Token::new(0x2C00_0000 + rid),
            offset: *offset,
            owner: read_le_at_dyn(data, offset, sizes.is_large(TableId::GenericParam))?,
            constraint: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeDefOrRef)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // owner
            0x08, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParamConstraint, 1),
                (TableId::GenericParam, 10),
                (TableId::TypeDef, 10),
                (TableId::TypeRef, 10),
                (TableId::TypeSpec, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<GenericParamConstraintRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamConstraintRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2C000001);
            assert_eq!(row.owner, 0x0101);
            assert_eq!(
                row.constraint,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 2,
                    token: Token::new(2 | 0x02000000),
                }
            );
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }

    #[test]
    fn crafted_long() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // owner
            0x08, 0x00, 0x00, 0x00, // constraint (tag 0 = TypeDef, index = 2)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParamConstraint, u16::MAX as u32 + 3),
                (TableId::GenericParam, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::TypeRef, u16::MAX as u32 + 3),
                (TableId::TypeSpec, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<GenericParamConstraintRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamConstraintRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2C000001);
            assert_eq!(row.owner, 0x01010101);
            assert_eq!(
                row.constraint,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 2,
                    token: Token::new(2 | 0x02000000)
                }
            );
        };

        {
            for row in table.iter() {
                eval(row);
            }
        }

        {
            let row = table.get(1).unwrap();
            eval(row);
        }
    }
}
