//! # MethodSemantics Raw Implementation
//!
//! This module provides the raw variant of MethodSemantics table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        method::MethodMap,
        tables::{
            CodedIndex, CodedIndexType, MethodSemantics, MethodSemanticsAttributes,
            MethodSemanticsRc, RowDefinition, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a MethodSemantics table entry with unresolved indexes.
///
/// This structure represents an unprocessed entry from the MethodSemantics metadata table
/// (ID 0x18), which specifies the relationship between methods and events or properties.
/// It contains raw index values that require resolution to actual metadata objects.
///
/// ## Purpose
///
/// The MethodSemantics table defines which methods serve specific semantic roles for
/// properties and events:
/// - Property getters, setters, and other methods
/// - Event add, remove, fire, and other methods
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved table indexes requiring lookup
/// - Minimal memory footprint for storage
/// - Direct representation of file format
///
/// Use [`MethodSemantics`] for resolved references and runtime access.
///
/// ## ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.28 MethodSemantics table structure.
pub struct MethodSemanticsRaw {
    /// Row identifier within the MethodSemantics table.
    ///
    /// This 1-based index uniquely identifies this entry within the table.
    /// Combined with table ID 0x18, forms the metadata token 0x18XXXXXX.
    pub rid: u32,

    /// Metadata token for this MethodSemantics entry.
    ///
    /// Format: 0x18XXXXXX where XXXXXX is the row ID.
    /// Used for cross-referencing this entry from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Semantic relationship type bitmask.
    ///
    /// 2-byte value defining the method's semantic role using [`MethodSemanticsAttributes`]:
    /// - `SETTER` (0x0001) - Property setter method
    /// - `GETTER` (0x0002) - Property getter method  
    /// - `OTHER` (0x0004) - Other property/event method
    /// - `ADD_ON` (0x0008) - Event add method
    /// - `REMOVE_ON` (0x0010) - Event remove method
    /// - `FIRE` (0x0020) - Event fire method
    ///
    /// As specified in ECMA-335 §II.23.1.12.
    pub semantics: u32,

    /// Raw index into the MethodDef table.
    ///
    /// This unresolved index identifies the method that implements the semantic
    /// behavior. Must be resolved using the MethodDef table to get the actual
    /// [`Method`](crate::metadata::method::Method) reference.
    ///
    /// Index size depends on table size (2 or 4 bytes).
    pub method: u32,

    /// Raw HasSemantics coded index.
    ///
    /// This coded index identifies the associated property or event that this
    /// method provides semantic behavior for. The encoding combines:
    /// - Low 2 bits: Table tag (0=Event, 1=Property)
    /// - High bits: Row index in the target table
    ///
    /// Must be resolved using the appropriate table to get the actual type reference.
    pub association: CodedIndex,
}

impl MethodSemanticsRaw {
    /// Applies the semantic relationship directly using raw data.
    ///
    /// This method resolves the raw indexes and applies the semantic relationship
    /// to the associated property or event without creating an owned instance.
    /// It's more memory-efficient than conversion to owned form when only applying
    /// relationships is needed.
    ///
    /// ## Process
    ///
    /// 1. Resolves the method index to an actual [`Method`](crate::metadata::method::Method) reference
    /// 2. Resolves the association coded index to a property or event
    /// 3. Applies the semantic relationship based on the semantics bitmask
    /// 4. Sets the appropriate method reference on the property/event
    ///
    /// ## Arguments
    ///
    /// * `get_ref` - Closure that resolves coded indices to [`CilTypeReference`]
    /// * `methods` - Map of all parsed MethodDef entries for method resolution
    ///
    /// ## Errors
    ///
    /// - Method token cannot be resolved (invalid index or missing entry)
    /// - Association coded index is malformed or points to invalid entry
    /// - Semantic attributes are invalid or unsupported
    /// - Method is already assigned for this semantic role (duplicate)
    /// - Property/event assignment fails due to type constraints
    pub fn apply<F>(&self, get_ref: F, methods: &MethodMap) -> Result<()>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let Some(method) = methods.get(&Token::new(self.method | 0x0600_0000)) else {
            return Err(malformed_error!(
                "Failed to resolve method token - {}",
                self.method | 0x0600_0000
            ));
        };

        let association = get_ref(&self.association);
        match association {
            CilTypeReference::Property(property) => match self.semantics {
                MethodSemanticsAttributes::SETTER => {
                    property
                        .fn_setter
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Property `setter` already set"))?;
                    Ok(())
                }
                MethodSemanticsAttributes::GETTER => {
                    property
                        .fn_getter
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Property `getter` already set"))?;
                    Ok(())
                }
                MethodSemanticsAttributes::OTHER => {
                    property
                        .fn_other
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Property `other` method already set"))?;
                    Ok(())
                }
                _ => Err(malformed_error!("Invalid property semantics")),
            },
            CilTypeReference::Event(event) => match self.semantics {
                MethodSemanticsAttributes::ADD_ON => {
                    event
                        .fn_on_add
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Event `add` method already set"))?;
                    Ok(())
                }
                MethodSemanticsAttributes::REMOVE_ON => {
                    event
                        .fn_on_remove
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Event `remove` method already set"))?;
                    Ok(())
                }
                MethodSemanticsAttributes::FIRE => {
                    event
                        .fn_on_raise
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Event `raise` method already set"))?;
                    Ok(())
                }
                MethodSemanticsAttributes::OTHER => {
                    event
                        .fn_on_other
                        .set(method.value().clone().into())
                        .map_err(|_| malformed_error!("Event `other` method already set"))?;
                    Ok(())
                }
                _ => Err(malformed_error!("Invalid event semantics")),
            },
            _ => Err(malformed_error!(
                "Invalid association token - {}",
                self.association.token.value()
            )),
        }
    }

    /// Converts this raw entry to an owned [`MethodSemantics`] with resolved references.
    ///
    /// This method performs the conversion from raw indexes to resolved object references,
    /// creating a fully usable [`MethodSemantics`] instance with owned data. The resulting
    /// instance contains resolved method and association references for efficient runtime access.
    ///
    /// ## Arguments
    ///
    /// * `get_ref` - Closure that resolves coded indices to [`CilTypeReference`]
    /// * `methods` - Map of all parsed MethodDef entries for method resolution
    ///
    /// ## Returns
    ///
    /// A reference-counted [`MethodSemanticsRc`] containing the resolved entry.
    ///
    /// ## Errors
    ///
    /// - Method token cannot be resolved (0x06XXXXXX format expected)
    /// - Method index points to non-existent MethodDef entry
    /// - Association coded index is malformed or invalid
    /// - Association resolves to `CilTypeReference::None`
    /// - Required dependency data is missing or corrupted
    pub fn to_owned<F>(&self, get_ref: F, methods: &MethodMap) -> Result<MethodSemanticsRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let method = match methods.get(&Token::new(self.method | 0x0600_0000)) {
            Some(method) => method.value().clone(),
            None => {
                return Err(malformed_error!(
                    "Failed to resolve methoddef token - {}",
                    self.method | 0x0600_0000
                ))
            }
        };

        let association = get_ref(&self.association);
        if matches!(association, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve association token - {}",
                self.association.token.value()
            ));
        }

        Ok(Arc::new(MethodSemantics {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            semantics: self.semantics,
            method,
            association,
        }))
    }
}

impl<'a> RowDefinition<'a> for MethodSemanticsRaw {
    /// Calculates the byte size of a MethodSemantics table row.
    ///
    /// The row size depends on the metadata table sizes and is calculated as:
    /// - `semantics`: 2 bytes (fixed)
    /// - `method`: 2 or 4 bytes (depends on MethodDef table size)
    /// - `association`: 2 or 4 bytes (depends on HasSemantics coded index size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* semantics */   2 +
            /* method */      sizes.table_index_bytes(TableId::MethodDef) +
            /* association */ sizes.coded_index_bytes(CodedIndexType::HasSemantics)
        )
    }

    /// Reads a single MethodSemantics table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.28:
    /// 1. **Semantics** (2 bytes): Bitmask of semantic attributes
    /// 2. **Method** (2-4 bytes): Index into MethodDef table
    /// 3. **Association** (2-4 bytes): HasSemantics coded index
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry (1-based)
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`MethodSemanticsRaw`] instance with populated fields
    ///
    /// ## Errors
    ///
    /// - Insufficient data remaining at offset
    /// - Invalid coded index encoding
    /// - Data corruption or malformed structure
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(MethodSemanticsRaw {
            rid,
            token: Token::new(0x1800_0000 + rid),
            offset: *offset,
            semantics: u32::from(read_le_at::<u16>(data, offset)?),
            method: read_le_at_dyn(data, offset, sizes.is_large(TableId::MethodDef))?,
            association: CodedIndex::read(data, offset, sizes, CodedIndexType::HasSemantics)?,
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
            0x01, 0x01, // semantics
            0x02, 0x02, // method
            0x02, 0x00, // association (tag 0 = Event, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSemantics, 1),
                (TableId::MethodDef, 10),
                (TableId::Event, 10),
                (TableId::Property, 10),
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<MethodSemanticsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSemanticsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x18000001);
            assert_eq!(row.semantics, 0x0101);
            assert_eq!(row.method, 0x0202);
            assert_eq!(
                row.association,
                CodedIndex {
                    tag: TableId::Event,
                    row: 1,
                    token: Token::new(1 | 0x14000000),
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
            0x01, 0x01, // semantics
            0x02, 0x02, 0x02, 0x02, // method
            0x02, 0x00, 0x00, 0x00, // association (tag 0 = Event, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::MethodSemantics, u16::MAX as u32 + 3),
                (TableId::MethodDef, u16::MAX as u32 + 3),
                (TableId::Event, u16::MAX as u32 + 3),
                (TableId::Property, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<MethodSemanticsRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: MethodSemanticsRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x18000001);
            assert_eq!(row.semantics, 0x0101);
            assert_eq!(row.method, 0x02020202);
            assert_eq!(
                row.association,
                CodedIndex {
                    tag: TableId::Event,
                    row: 1,
                    token: Token::new(1 | 0x14000000),
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
