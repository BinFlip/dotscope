use bitflags::bitflags;
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

use crate::{
    file::{
        io::{read_le_at, read_le_at_dyn},
        File,
    },
    metadata::{
        cor20header::Cor20Header,
        streams::{
            AssemblyRefMap, CodedIndex, CodedIndexType, FileMap, MetadataTable, RowDefinition,
            Strings, TableId, TableInfoRef,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// A map that holds the mapping of Token to parsed `ManifestResource`
pub type ManifestResourceMap = SkipMap<Token, ManifestResourceRc>;
/// A vector that holds a list of `ManifestResource`
pub type ManifestResourceList = Arc<boxcar::Vec<ManifestResourceRc>>;
/// A reference to a `ManifestResource`
pub type ManifestResourceRc = Arc<ManifestResource>;

bitflags! {
    #[derive(PartialEq, Debug)]
    /// All possible flags for ManifestResourceAttributes
    pub struct ManifestResourceAttributes : u32 {
        /// The Resource is exported from the Assembly
        const PUBLIC = 0x0001;
        /// The Resource is private to the Assembly
        const PRIVATE = 0x0002;
    }
}

/// The `ManifestResource` table lists the resources for the assembly. Similar to `ManifestResourceRaw` but
/// with resolved indexes and owned data
pub struct ManifestResource {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// Offset of the resource data, 0 if not embedded, Name and Source needed, to calculate location in different binary
    pub data_offset: usize,
    /// Size of the resource data, 0 if not embedded, Name and Source needed, to calculate location in different binary
    pub data_size: usize,
    /// a 4-byte bitmask of type `ManifestResourceAttributes`, §II.23.1.9
    pub flags: ManifestResourceAttributes,
    /// an index into the String heap
    pub name: String,
    /// Indicates where (in which module / assembly / file) this resources is located
    /// If None - Offset is in the current file, relative to the resource entry of the CIL header of the specified target
    /// Can only be `AssemblyRef` or File
    pub source: Option<CilTypeReference>,
}

#[derive(Clone, Debug)]
/// The `ManifestResource` table lists the resources for the assembly. `TableId` = 0x28
pub struct ManifestResourceRaw {
    /// `RowID`
    pub rid: u32,
    /// Token
    pub token: Token,
    /// Offset
    pub offset: usize,
    /// a 4-byte constant
    pub offset_field: u32,
    /// a 4-byte bitmask of type `ManifestResourceAttributes`, §II.23.1.9
    pub flags: u32,
    /// an index into the String heap
    pub name: u32,
    /// an index into the Implementation coding index
    pub implementation: CodedIndex,
}

impl ManifestResourceRaw {
    /// Convert an `ManifestResourceRaw`, into a `ManifestResource` which has indexes resolved and owns the referenced data
    ///
    /// ## Arguments
    /// * 'file'        - The mapped raw data of the loaded binary
    /// * 'cor20'       - The cor20 header of the loaded binary
    /// * 'strings'         - The #String heap
    /// * 'files'           - All parsed `File` entries
    /// * 'assemblies'      - All parsed `AssemblyRef` entries
    ///
    /// # Errors
    /// Returns an error if the resource name cannot be retrieved, if the implementation
    /// reference cannot be resolved, or if the resource data cannot be located.
    pub fn to_owned(
        &self,
        file: &File,
        cor20: &Cor20Header,
        strings: &Strings,
        files: &FileMap,
        assemblies: &AssemblyRefMap,
        table: &MetadataTable<ManifestResourceRaw>,
    ) -> Result<ManifestResourceRc> {
        let mut data_offset = self.offset_field as usize;
        let mut data_size = 0_usize;

        let source = match self.implementation.tag {
            TableId::File => {
                if self.implementation.row == 0 {
                    // Special case, this is actually 'NULL', means that the resource is embedded in the current assembly

                    data_offset += file.rva_to_offset(cor20.resource_rva as usize)?;
                    data_size = if let Some(next_res) = table.get(self.rid + 1) {
                        next_res.offset_field as usize - self.offset_field as usize
                    } else {
                        // Last resource, use resource section size from CLR header
                        cor20.resource_size as usize
                    };

                    None
                } else {
                    match files.get(&self.implementation.token) {
                        Some(parent) => Some(CilTypeReference::File(parent.value().clone())),
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve file implementation token - {}",
                                self.implementation.token.value()
                            ))
                        }
                    }
                }
            }
            TableId::AssemblyRef => match assemblies.get(&self.implementation.token) {
                Some(parent) => Some(CilTypeReference::AssemblyRef(parent.value().clone())),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve assemblies implementation token - {}",
                        self.implementation.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid implementation token - {}",
                    self.implementation.token.value()
                ))
            }
        };

        Ok(Arc::new(ManifestResource {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            data_offset,
            data_size,
            flags: ManifestResourceAttributes::from_bits_truncate(self.flags),
            name: strings.get(self.name as usize)?.to_string(),
            source,
        }))
    }

    /// Apply a `ManifestResourceRaw` entry to update related metadata structures.
    ///
    /// `ManifestResource` entries define resources that are part of this assembly. They are
    /// primarily metadata descriptors for resource data and don't require cross-table
    /// updates during the dual variant resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `ManifestResource` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl<'a> RowDefinition<'a> for ManifestResourceRaw {
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* offset_field */   4 +
            /* flags */          4 +
            /* name */           sizes.str_bytes() +
            /* implementation */ sizes.coded_index_bytes(CodedIndexType::Implementation)
        )
    }

    fn read_row(
        data: &'a [u8],
        offset: &mut usize,
        rid: u32,
        sizes: &TableInfoRef,
    ) -> Result<Self> {
        Ok(ManifestResourceRaw {
            rid,
            token: Token::new(0x2800_0000 + rid),
            offset: *offset,
            offset_field: read_le_at::<u32>(data, offset)?,
            flags: read_le_at::<u32>(data, offset)?,
            name: read_le_at_dyn(data, offset, sizes.is_large_str())?,
            implementation: CodedIndex::read(data, offset, sizes, CodedIndexType::Implementation)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::streams::{MetadataTable, TableId, TableInfo};

    use super::*;

    #[test]
    fn crafted_short() {
        let data = vec![
            0x01, 0x01, 0x01, 0x01, // offset_field
            0x02, 0x02, 0x02, 0x02, // flags
            0x03, 0x03, // name
            0x04, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ManifestResource, 1),
                (TableId::File, 10),         // Add File table
                (TableId::AssemblyRef, 10),  // Add AssemblyRef table
                (TableId::ExportedType, 10), // Add ExportedType table
            ],
            false,
            false,
            false,
        ));
        let table = MetadataTable::<ManifestResourceRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ManifestResourceRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x28000001);
            assert_eq!(row.offset_field, 0x01010101);
            assert_eq!(row.flags, 0x02020202);
            assert_eq!(row.name, 0x0303);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
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
            0x01, 0x01, 0x01, 0x01, // offset_field
            0x02, 0x02, 0x02, 0x02, // flags
            0x03, 0x03, 0x03, 0x03, // name
            0x04, 0x00, 0x00, 0x00, // implementation (tag 0 = File, index = 1)
        ];

        let sizes = Arc::new(TableInfo::new_test(
            &[
                (TableId::ManifestResource, u16::MAX as u32 + 3),
                (TableId::File, u16::MAX as u32 + 3), // Add File table
                (TableId::AssemblyRef, u16::MAX as u32 + 3), // Add AssemblyRef table
                (TableId::ExportedType, u16::MAX as u32 + 3), // Add ExportedType table
            ],
            true,
            true,
            true,
        ));
        let table = MetadataTable::<ManifestResourceRaw>::new(&data, 1, sizes.clone()).unwrap();

        let eval = |row: ManifestResourceRaw| {
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x28000001);
            assert_eq!(row.offset_field, 0x01010101);
            assert_eq!(row.flags, 0x02020202);
            assert_eq!(row.name, 0x03030303);
            assert_eq!(
                row.implementation,
                CodedIndex {
                    tag: TableId::File,
                    row: 1,
                    token: Token::new(1 | 0x26000000),
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
