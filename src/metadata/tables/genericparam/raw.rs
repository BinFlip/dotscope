//! Raw `GenericParam` structures for the `GenericParam` metadata table.
//!
//! This module provides the [`GenericParamRaw`] struct for reading generic parameter data
//! directly from metadata tables before index resolution. The `GenericParam` table defines
//! generic type and method parameters for .NET generic programming support.
//!
//! # Table Structure
//! The `GenericParam` table (`TableId` = 0x2A) contains these columns:
//! - `Number`: 2-byte ordinal position of the parameter (0-based)
//! - `Flags`: 2-byte `GenericParamAttributes` bitmask
//! - `Owner`: Coded index into `TypeOrMethodDef` (`TypeDef` or `MethodDef`)
//! - `Name`: Index into String heap containing parameter name
//!
//! # Generic Parameter Context
//! `GenericParam` entries enable generic programming scenarios:
//! - **Generic types**: Type parameters for classes and interfaces (`List<T>`)
//! - **Generic methods**: Method-level type parameters (`Method<U>()`)
//! - **Constraint specification**: Base class and interface constraints
//! - **Variance annotations**: Covariance and contravariance support
//! - **Reflection metadata**: Runtime access to parameter information
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.20 for the `GenericParam` table specification.

use std::sync::{Arc, OnceLock};

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, GenericParam, GenericParamRc, RowDefinition, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw generic parameter data read directly from the `GenericParam` metadata table.
///
/// This structure represents a generic parameter entry before index resolution and
/// reference dereferencing. Generic parameters define type and method parameters
/// that enable generic programming with type safety and performance benefits.
///
/// # Binary Format
/// Each row in the `GenericParam` table has this layout:
/// ```text
/// Offset | Size | Field  | Description
/// -------|------|--------|----------------------------------
/// 0      | 2    | Number | Parameter ordinal position
/// 2      | 2    | Flags  | GenericParamAttributes bitmask
/// 4      | 2/4  | Owner  | TypeOrMethodDef coded index
/// 6/8    | 2/4  | Name   | String heap index
/// ```
///
/// Owner and Name index sizes depend on table and heap sizes.
///
/// # Generic Parameter Context
/// `GenericParam` entries are used for:
/// - **Type parameters**: Defined on generic types (`class List<T>`)
/// - **Method parameters**: Defined on generic methods (`void Method<U>()`)
/// - **Constraint definitions**: Specifying parameter constraints
/// - **Variance specification**: Covariance and contravariance annotations
/// - **Name resolution**: Parameter names for signatures and reflection
///
/// # Parameter Attributes
/// The Flags field contains `GenericParamAttributes` values:
/// - **Variance**: COVARIANT, CONTRAVARIANT for assignment compatibility
/// - **Constraints**: Reference type, value type, constructor constraints
/// - **Special flags**: Additional constraint and variance information
///
/// # Owner Types
/// The Owner field uses `TypeOrMethodDef` coded index:
/// - **`TypeDef`**: For type-level generic parameters (`class Generic<T>`)
/// - **`MethodDef`**: For method-level generic parameters (`Method<U>()`)
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.20 for the complete `GenericParam` table specification.
#[derive(Clone, Debug)]
pub struct GenericParamRaw {
    /// The row identifier in the `GenericParam` table.
    ///
    /// This 1-based index uniquely identifies this generic parameter within the `GenericParam` table.
    pub rid: u32,

    /// The metadata token for this generic parameter.
    ///
    /// A [`Token`] that uniquely identifies this generic parameter across the entire assembly.
    /// The token value is calculated as `0x2A000000 + rid`.
    ///
    /// [`Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this generic parameter in the metadata tables stream.
    ///
    /// This offset points to the start of this parameter's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// The ordinal position of this parameter in the parameter list.
    ///
    /// A 2-byte index indicating the parameter's position, numbered left-to-right
    /// starting from zero. This determines parameter order in generic instantiations.
    pub number: u32,

    /// Generic parameter attribute flags indicating constraints and variance.
    ///
    /// A 2-byte bitmask of `GenericParamAttributes` values that specify variance,
    /// constraints, and other parameter characteristics.
    pub flags: u32,

    /// Coded index into the `TypeOrMethodDef` tables for the parameter owner.
    ///
    /// A [`CodedIndex`] that references either:
    /// - **`TypeDef`**: For type-level generic parameters
    /// - **`MethodDef`**: For method-level generic parameters
    ///
    /// [`CodedIndex`]: crate::metadata::tables::CodedIndex
    pub owner: CodedIndex,

    /// Index into the String heap for the parameter name.
    ///
    /// This index points to the parameter name string in the strings heap,
    /// which needs to be resolved during conversion to owned data.
    pub name: u32,
}

impl GenericParamRaw {
    /// Convert this raw generic parameter to an owned [`GenericParam`] with resolved references.
    ///
    /// This method resolves the owner reference and string heap reference to create a complete
    /// generic parameter structure with owned data. The resulting [`GenericParam`] contains
    /// the actual parameter name and resolved owner reference.
    ///
    /// # Arguments
    /// * `get_ref` - Function to resolve coded index references to type references
    /// * `strings` - The string heap for resolving parameter names
    ///
    /// # Returns
    /// Returns a reference-counted [`GenericParam`] with resolved data, or an error if:
    /// - Owner reference resolution fails (returns `CilTypeReference::None`)
    /// - String heap lookup fails for the parameter name
    /// - Memory allocation fails during conversion
    ///
    /// # Errors
    /// Returns an error if the owner reference cannot be resolved, the parameter name cannot be found in the string heap, or if memory allocation fails during conversion.
    pub fn to_owned<F>(&self, get_ref: F, strings: &Strings) -> Result<GenericParamRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let owner_ref = get_ref(&self.owner);
        if matches!(owner_ref, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve owner token - {}",
                self.owner.token.value()
            ));
        }

        let owner = OnceLock::new();
        owner.set(owner_ref).ok();

        Ok(Arc::new(GenericParam {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            number: self.number,
            flags: self.flags,
            owner,
            constraints: Arc::new(boxcar::Vec::new()),
            name: strings.get(self.name as usize)?.to_string(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for GenericParamRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* number */ 2 +
            /* flags */  2 +
            /* owner */  sizes.coded_index_bytes(CodedIndexType::TypeOrMethodDef) +
            /* name */   sizes.str_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(GenericParamRaw {
            rid,
            token: Token::new(0x2A00_0000 + rid),
            offset: *offset,
            number: u32::from(read_le_at::<u16>(data, offset)?),
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            owner: CodedIndex::read(data, offset, sizes, CodedIndexType::TypeOrMethodDef)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
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
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, 1),
                (TableId::TypeDef, 10),
                (TableId::MethodDef, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<GenericParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2A000001);
            assert_eq!(row.number, 0x0101);
            assert_eq!(row.flags, 0x0202);
            assert_eq!(
                row.owner,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 1,
                    token: Token::new(1 | 0x02000000),
                }
            );
            assert_eq!(row.name, 0x0404);
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
            0x01, 0x01, // number
            0x02, 0x02, // flags
            0x02, 0x00, 0x00, 0x00, // owner (tag 0 = TypeDef, index = 1)
            0x04, 0x04, 0x04, 0x04, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::GenericParam, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<GenericParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: GenericParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x2A000001);
            assert_eq!(row.number, 0x0101);
            assert_eq!(row.flags, 0x0202);
            assert_eq!(
                row.owner,
                CodedIndex {
                    tag: TableId::TypeDef,
                    row: 1,
                    token: Token::new(1 | 0x02000000),
                }
            );
            assert_eq!(row.name, 0x04040404);
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
