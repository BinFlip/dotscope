//! # NestedClass Raw Implementation
//!
//! This module provides the raw variant of NestedClass table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::{collections::HashMap, sync::Arc};

use crate::{
    file::io::read_le_at_dyn,
    metadata::{
        tables::{MetadataTable, NestedClass, NestedClassRc, RowDefinition, TableId, TableInfoRef},
        token::Token,
        typesystem::TypeRegistry,
        validation::NestedClassValidator,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a NestedClass table entry with unresolved indexes.
///
/// This structure represents the unprocessed entry from the NestedClass metadata table
/// (ID 0x29), which defines the hierarchical relationship between nested types and their
/// enclosing types. It contains raw index values that require resolution to actual type objects.
///
/// ## Purpose
///
/// The NestedClass table establishes type containment relationships:
/// - Defines which types are nested within other types
/// - Establishes type visibility and accessibility scoping
/// - Enables proper type resolution within nested contexts
/// - Supports complex type hierarchies and namespace organization
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved TypeDef indexes requiring lookup in the type registry
/// - Minimal memory footprint for storage
/// - Direct representation of file format
///
/// Use [`NestedClass`] for resolved references and runtime access.
///
/// ## Type Relationships
///
/// NestedClass entries create hierarchical type relationships:
/// - **Containment**: The nested type is contained within the enclosing type
/// - **Scoping**: Nested types inherit accessibility from their container
/// - **Resolution**: Type names are resolved relative to the enclosing context
/// - **Compilation**: Nested types share compilation context with their container
///
/// ## ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.32 NestedClass table structure.
pub struct NestedClassRaw {
    /// Row identifier within the NestedClass table.
    ///
    /// Unique identifier for this NestedClass entry within the table.
    /// Combined with table ID 0x29, forms the metadata token 0x29??????.
    pub rid: u32,

    /// Metadata token for this NestedClass entry.
    ///
    /// Token in the format 0x29??????, where the high byte 0x29 identifies
    /// the NestedClass table and the low 3 bytes contain the row ID.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Raw index into the TypeDef table for the nested type.
    ///
    /// This unresolved index identifies the type that is nested within
    /// the enclosing type. Must be resolved using the type registry to
    /// get the actual type object. Index size depends on TypeDef table size.
    pub nested_class: u32,

    /// Raw index into the TypeDef table for the enclosing type.
    ///
    /// This unresolved index identifies the type that contains the nested type.
    /// Must be resolved using the type registry to get the actual type object.
    /// Index size depends on TypeDef table size.
    pub enclosing_class: u32,
}

impl NestedClassRaw {
    /// Applies all NestedClass entries to establish type containment relationships.
    ///
    /// This static method processes all NestedClass entries from the metadata table,
    /// validating the relationships and updating the type registry to reflect the
    /// nested type hierarchy. The operation groups nested types by their enclosing
    /// types for efficient processing.
    ///
    /// ## Arguments
    ///
    /// * `classes` - The metadata table containing all NestedClass entries
    /// * `types` - The type registry containing all parsed type entries
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` if all relationships are successfully applied.
    ///
    /// ## Errors
    ///
    /// - Nested class validation fails (circular nesting, same type, etc.)
    /// - Referenced types cannot be found in the type registry
    /// - Type tokens are invalid or malformed
    /// - The relationship violates .NET type system constraints
    ///
    pub fn apply(classes: &MetadataTable<NestedClassRaw>, types: &TypeRegistry) -> Result<()> {
        let mut mapping: HashMap<u32, Vec<u32>> = HashMap::new();

        for row in classes {
            let nested_token = Token::new(row.nested_class | 0x0200_0000);
            let enclosing_token = Token::new(row.enclosing_class | 0x0200_0000);

            NestedClassValidator::validate_nested_relationship(nested_token, enclosing_token)?;

            mapping
                .entry(row.enclosing_class | 0x0200_0000)
                .or_default()
                .push(row.nested_class | 0x0200_0000);
        }

        for (enclosing, nested_classes) in mapping {
            match types.get(&Token::new(enclosing)) {
                Some(cil_type) => {
                    for nested_class in nested_classes {
                        match types.get(&Token::new(nested_class)) {
                            Some(nested_type) => {
                                _ = cil_type.nested_types.push(nested_type.clone().into());
                            }
                            None => {
                                return Err(malformed_error!(
                                    "Failed to resolve nested_class type - {}",
                                    nested_class
                                ))
                            }
                        }
                    }
                }
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve enclosing_class type - {}",
                        enclosing
                    ))
                }
            }
        }

        Ok(())
    }

    /// Converts this raw entry to an owned [`NestedClass`] with resolved references.
    ///
    /// This method resolves the raw TypeDef indexes to actual type objects,
    /// creating a fully usable [`NestedClass`] instance for runtime access. The conversion
    /// establishes the containment relationship between nested and enclosing types.
    ///
    /// ## Arguments
    ///
    /// * `types` - The type registry containing all parsed type entries
    ///
    /// ## Returns
    ///
    /// A reference-counted [`NestedClassRc`] containing the resolved nesting relationship.
    ///
    /// ## Errors
    ///
    /// - The nested class type cannot be resolved in the type registry
    /// - The enclosing class type cannot be resolved in the type registry
    /// - Type tokens are invalid or malformed
    /// - Referenced types are corrupted or incomplete
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<NestedClassRc> {
        Ok(Arc::new(NestedClass {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            nested_class: match types.get(&Token::new(self.nested_class | 0x0200_0000)) {
                Some(class) => class.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve nested_class type - {}",
                        self.nested_class | 0x0200_0000
                    ))
                }
            },
            enclosing_class: match types.get(&Token::new(self.enclosing_class | 0x0200_0000)) {
                Some(class) => class.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve enclosing_class - {}",
                        self.enclosing_class | 0x0200_0000
                    ))
                }
            },
        }))
    }
}

impl<'a> RowDefinition<'a> for NestedClassRaw {
    /// Calculates the byte size of a NestedClass table row.
    ///
    /// The row size depends on the TypeDef table size and is calculated as:
    /// - `nested_class`: 2 or 4 bytes (depends on TypeDef table size)
    /// - `enclosing_class`: 2 or 4 bytes (depends on TypeDef table size)
    ///
    /// ## Arguments
    /// * `sizes` - Table size information for calculating index widths
    ///
    /// ## Returns
    /// Total byte size of one table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* nested_class */    sizes.table_index_bytes(TableId::TypeDef) +
            /* enclosing_class */ sizes.table_index_bytes(TableId::TypeDef)
        )
    }

    /// Reads a single NestedClass table row from binary data.
    ///
    /// Parses the binary representation according to ECMA-335 §II.22.32:
    /// 1. **NestedClass** (2-4 bytes): Index into TypeDef table for nested type
    /// 2. **EnclosingClass** (2-4 bytes): Index into TypeDef table for enclosing type
    ///
    /// ## Arguments
    /// * `data` - Binary data containing the table
    /// * `offset` - Current read position (updated by this method)
    /// * `rid` - Row identifier for this entry
    /// * `sizes` - Table size information for proper index width calculation
    ///
    /// ## Returns
    /// Parsed [`NestedClassRaw`] instance with populated fields
    ///
    /// ## Errors
    /// - Insufficient data remaining at offset
    /// - Data corruption or malformed structure
    /// - Invalid TypeDef index values
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(NestedClassRaw {
            rid,
            token: Token::new(0x2900_0000 + rid),
            offset: *offset,
            nested_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
            enclosing_class: read_le_at_dyn(data, offset, sizes.is_large(TableId::TypeDef))?,
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
            0x01, 0x01, // nested_class
            0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::NestedClass, 1), (TableId::TypeDef, 10)],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x0101);
            assert_eq!(row.enclosing_class, 0x0202);
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
            0x01, 0x01, 0x01, 0x01, // nested_class
            0x02, 0x02, 0x02, 0x02, // enclosing_class
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::NestedClass, u16::MAX as u32 + 3),
                (TableId::TypeDef, u16::MAX as u32 + 3),
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<NestedClassRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: NestedClassRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x29000001);
            assert_eq!(row.nested_class, 0x01010101);
            assert_eq!(row.enclosing_class, 0x02020202);
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
