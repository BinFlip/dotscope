//! Raw LocalVariable table representation for Portable PDB format
//!
//! This module provides the [`LocalVariableRaw`] struct that represents
//! the binary format of LocalVariable table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices.

use crate::{
    file::io::{read_le_at, read_le_at_dyn},
    metadata::{
        streams::Strings,
        tables::{types::*, LocalVariable, LocalVariableRc},
        token::Token,
    },
    Result,
};
use std::sync::Arc;

/// Raw binary representation of a LocalVariable table entry
///
/// This structure matches the exact binary layout of LocalVariable table
/// entries in the metadata tables stream. The Name field contains an unresolved
/// index into the #Strings heap that must be resolved during conversion
/// to the owned [`LocalVariable`] variant.
///
/// # Binary Format
///
/// Each LocalVariable table entry consists of:
/// - Attributes: 2-byte unsigned integer with variable flags
/// - Index: 2-byte unsigned integer (variable index within method)
/// - Name: Index into #Strings heap for the variable name
#[derive(Debug, Clone)]
pub struct LocalVariableRaw {
    /// Row identifier (1-based index in the table)
    pub rid: u32,

    /// Metadata token for this LocalVariable entry
    pub token: Token,

    /// Byte offset of this row in the original metadata stream
    pub offset: usize,

    /// Variable attribute flags
    ///
    /// A bitfield containing flags that describe characteristics of the local variable.
    /// Common flags include whether the variable is a compiler-generated temporary,
    /// whether it's a pinned variable, etc.
    pub attributes: u16,

    /// Variable index within the method
    ///
    /// Zero-based index that identifies this variable within the containing method.
    /// This index corresponds to the variable's position in the method's local
    /// variable signature and IL instructions.
    pub index: u16,

    /// Index into #Strings heap for variable name
    ///
    /// Points to the variable's name string in the metadata #Strings heap.
    /// This index must be resolved to get the actual variable name string.
    /// May be 0 for anonymous or compiler-generated variables.
    pub name: u32,
}

impl LocalVariableRaw {
    /// Converts this raw LocalVariable entry to an owned [`LocalVariable`] instance
    ///
    /// This method resolves the raw LocalVariable entry to create a complete LocalVariable
    /// object by resolving the name string from the #Strings heap.
    ///
    /// # Parameters
    /// - `strings`: Reference to the #Strings heap for resolving the name index
    ///
    /// # Returns
    /// Returns `Ok(LocalVariableRc)` with the resolved variable data, or an error if
    /// the name index is invalid or points to malformed string data.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use dotscope::metadata::tables::localvariable::LocalVariableRaw;
    /// # use dotscope::metadata::token::Token;
    /// # fn example() -> dotscope::Result<()> {
    /// let variable_raw = LocalVariableRaw {
    ///     rid: 1,
    ///     token: Token::new(0x33000001),
    ///     offset: 0,
    ///     attributes: 0,      // No special attributes
    ///     index: 0,           // First local variable
    ///     name: 42,           // Index into #Strings heap
    /// };
    ///
    /// let variable = variable_raw.to_owned(strings)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_owned(&self, strings: &Strings) -> Result<LocalVariableRc> {
        let name = if self.name == 0 {
            String::new()
        } else {
            strings.get(self.name as usize)?.to_string()
        };

        let variable = LocalVariable {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            attributes: self.attributes,
            index: self.index,
            name,
        };

        Ok(Arc::new(variable))
    }
}

impl<'a> RowDefinition<'a> for LocalVariableRaw {
    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(LocalVariableRaw {
            rid,
            token: Token::new(0x3300_0000 + rid),
            offset: *offset,
            attributes: read_le_at::<u16>(data, offset)?,
            index: read_le_at::<u16>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
        })
    }

    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            2 +  // attributes (always 2 bytes)
            2 +  // index (always 2 bytes)
            sizes.str_bytes()  // name (strings heap index)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::tables::{MetadataTable, TableId, TableInfo};

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x00, // attributes (2 bytes) - 0x0001
            0x02, 0x00, // index (2 bytes) - 0x0002
            0x03, 0x00, // name (2 bytes, short strings heap) - 0x0003
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalVariable, 1)],
            false, // large tables
            false, // large strings
            false, // large blob
        ));
        let table = MetadataTable::<LocalVariableRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalVariableRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x33000001);
            assert_eq!(row.attributes, 0x0001);
            assert_eq!(row.index, 0x0002);
            assert_eq!(row.name, 0x0003);
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
            0x01, 0x00, // attributes (2 bytes) - 0x0001
            0x02, 0x00, // index (2 bytes) - 0x0002
            0x03, 0x00, 0x00, 0x00, // name (4 bytes, large strings heap) - 0x00000003
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[(TableId::LocalVariable, 1)],
            false, // large tables
            true,  // large strings
            false, // large blob
        ));
        let table = MetadataTable::<LocalVariableRaw>::new(&data, 1, sizes).unwrap();

        let eval = |row: LocalVariableRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x33000001);
            assert_eq!(row.attributes, 0x0001);
            assert_eq!(row.index, 0x0002);
            assert_eq!(row.name, 0x00000003);
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
