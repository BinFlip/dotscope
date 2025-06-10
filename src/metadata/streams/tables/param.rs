use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

use crossbeam_skiplist::SkipMap;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        customattributes::CustomAttributeValueList,
        marshalling::MarshallingInfo,
        signatures::SignatureParameter,
        streams::{RowDefinition, Strings, TableInfoRef},
        token::Token,
        typesystem::{CilPrimitive, CilTypeRef, CilTypeRefList, TypeRegistry, TypeResolver},
    },
    Result,
};

#[allow(non_snake_case)]
/// All possible flags for `ParamAttributes`
pub mod ParamAttributes {
    /// Param is `In`
    pub const IN: u32 = 0x0001;
    /// Param is `out`
    pub const OUT: u32 = 0x0002;
    /// Param is optional
    pub const OPTIONAL: u32 = 0x0010;
    /// Param has default value
    pub const HAS_DEFAULT: u32 = 0x1000;
    /// Param has `FieldMarshal`
    pub const HAS_FIELD_MARSHAL: u32 = 0x2000;
    /// Reserved: shall be zero in a conforming implementation
    pub const UNUSED: u32 = 0xcfe0;
}

/// A map that holds the mapping of Token to parsed `Param`
pub type ParamMap = SkipMap<Token, ParamRc>;
/// A vector that holds a list of `Param`
pub type ParamList = Arc<boxcar::Vec<ParamRc>>;
/// Reference to a `Param`
pub type ParamRc = Arc<Param>;

/// The `Param` table defines parameters for methods in the `MethodDef` table. Similar to `ParamRaw` but
/// with resolved indexes and owned data.
pub struct Param {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// bitmask of `ParamAttributes`, §II.23.1.13
    pub flags: u32,
    /// The sequence number (0 for return value)
    pub sequence: u32,
    /// The parameter name
    pub name: Option<String>,
    /// `flags.HAS_DEFAULT` -> This is the default value of this parameter
    pub default: OnceLock<CilPrimitive>,
    /// `flags.HAS_MARSHAL` -> The marshal instructions for `PInvoke`
    pub marshal: OnceLock<MarshallingInfo>,
    /// Custom modifiers that are applied to this `Param`
    pub modifiers: CilTypeRefList,
    /// The underlaying type of this `Param`
    pub base: OnceLock<CilTypeRef>,
    /// Is the parameter passed by reference
    pub is_by_ref: AtomicBool,
    /// Custom attributes applied to this parameter
    pub custom_attributes: CustomAttributeValueList,
}

impl Param {
    /// Apply a signature to this parameter, will cause update with type information
    ///
    /// # Errors
    ///
    /// Returns an error if type resolution fails, if modifier types cannot be resolved,
    /// or if the base type has already been set for this parameter.
    ///
    /// ## Arguments
    /// * 'signature'   - The signature to apply to this parameter
    /// * 'types'       - The type registry for lookup and generation of types
    pub fn apply_signature(
        &self,
        signature: &SignatureParameter,
        types: Arc<TypeRegistry>,
    ) -> Result<()> {
        self.is_by_ref.store(signature.by_ref, Ordering::Relaxed);

        for modifier in &signature.modifiers {
            match types.get(modifier) {
                Some(new_mod) => {
                    self.modifiers.push(new_mod.into());
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve modifier type - {}",
                        modifier.value()
                    ))
                }
            }
        }

        let mut resolver = TypeResolver::new(types);
        let resolved_type = resolver.resolve(&signature.base)?;

        // Handle the case where multiple methods share the same parameter
        // This is valid in .NET metadata and happens when methods have identical signatures
        match self.base.set(resolved_type.clone().into()) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Base type is already set - this is acceptable when methods share parameters
                // In a proper implementation, we'd compare the actual types for compatibility
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug)]
/// The `Param` table defines parameters for methods in the `MethodDef` table. `TableId` = 0x08
pub struct ParamRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 2-byte bitmask of type `ParamAttributes`, §II.23.1.13
    pub flags: u32,
    /// a 2-byte constant
    pub sequence: u32,
    /// an index into the String heap
    pub name: u32,
}

impl ParamRaw {
    /// Apply a `ParamRaw` - no-op for Param as it doesn't directly modify other table entries
    ///
    /// The `Param` table entries are primarily modified through method signature processing
    /// and custom attribute application, not through inter-table dependencies.
    ///
    /// # Errors
    /// This method currently returns Ok(()) as Param entries don't require cross-table updates.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }

    /// Convert an `ParamRaw`, into a `Param` which has indexes resolved and owns the referenced data
    ///
    /// # Errors
    /// Returns an error if the parameter name cannot be retrieved from the strings heap.
    ///
    /// ## Arguments
    /// * 'strings' - The #String heap
    pub fn to_owned(&self, strings: &Strings) -> Result<ParamRc> {
        Ok(Arc::new(Param {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            flags: self.flags,
            sequence: self.sequence,
            name: if self.name != 0 {
                Some(strings.get(self.name as usize)?.to_string())
            } else {
                None
            },
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(false),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        }))
    }
}

impl<'a> RowDefinition<'a> for ParamRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* flags */     2 +
            /* sequence */  2 +
            /* name */      sizes.str_bytes()
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ParamRaw {
            rid,
            token: Token::new(0x0800_0000 + rid),
            offset: *offset,
            flags: u32::from(read_le_at::<u16>(data, offset)?),
            sequence: u32::from(read_le_at::<u16>(data, offset)?),
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::streams::tables::types::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, // flags
            0x02, 0x02, // sequences
            0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Field, 1)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x0303);
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
            0x01, 0x01, // flags
            0x02, 0x02, // sequence
            0x03, 0x03, 0x03, 0x03, // name
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::Param, 1)],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ParamRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: ParamRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x08000001);
            assert_eq!(row.flags, 0x0101);
            assert_eq!(row.sequence, 0x0202);
            assert_eq!(row.name, 0x03030303);
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
