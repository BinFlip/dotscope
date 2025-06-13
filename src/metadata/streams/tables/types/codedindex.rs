use strum::{EnumCount, EnumIter};

use crate::{
    file::io::read_le_at,
    metadata::{
        streams::{TableId, TableInfoRef},
        token::Token,
    },
    Result,
};

/// Represents all possible coded index types
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.6
///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, EnumIter, EnumCount)]
#[repr(usize)]
pub enum CodedIndexType {
    /// `TypeDef`, `TypeRef`, `TypeSpec`
    TypeDefOrRef,
    /// `Field`, `Param`, `Property`
    HasConstant,
    /// `MethodDef`, `Field`, `TypeRef`, `TypeDef`, `Param`, `InterfaceImpl`, `MemberRef`, `Module`, `Permission`,
    /// `Property`, `Event`, `StandAloneSig`, `ModuleRef`, `TypeSpec`, `Assembly`, `AssemblyRef`, `File`, `ExportedType`,
    /// `ManifestResource`, `GenericParam`, `GenericParamConstraint`, `MethodSpec`
    HasCustomAttribute,
    /// `Field`, `Param`
    HasFieldMarshal,
    /// `TypeDef`, `MethodDef`, `Assembly`
    HasDeclSecurity,
    /// `TypeDef`, `TypeRef`, `ModuleRef`, `MethodDef`, `TypeSpec`
    MemberRefParent,
    /// `Event`, `Property`
    HasSemantics,
    /// `MethodDef`, `MemberRef`
    MethodDefOrRef,
    /// `Field`, `MethodDef`
    MemberForwarded,
    /// `File`, `AssemblyRef`, `ExportedType`
    Implementation,
    /// `MethodDef`, `MemberRef`
    CustomAttributeType,
    /// `Module`, `ModuleRef`, `AssemblyRef`, `TypeRef`
    ResolutionScope,
    /// `TypeDef`, `MethodDef`
    TypeOrMethodDef,
}

impl CodedIndexType {
    /// Lookup table for coded combinations of the various types and their table IDs
    #[must_use]
    pub fn tables(&self) -> &'static [TableId] {
        match self {
            CodedIndexType::TypeDefOrRef => {
                &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
            }
            CodedIndexType::HasConstant => &[TableId::Field, TableId::Param, TableId::Property],
            CodedIndexType::HasCustomAttribute => &[
                TableId::MethodDef,
                TableId::Field,
                TableId::TypeRef,
                TableId::TypeDef,
                TableId::Param,
                TableId::InterfaceImpl,
                TableId::MemberRef,
                TableId::Module,
                TableId::DeclSecurity, // In the standard PDF, this is wrongly labeled as 'Permission' (although no such table exists)
                TableId::Property,
                TableId::Event,
                TableId::StandAloneSig,
                TableId::ModuleRef,
                TableId::TypeSpec,
                TableId::Assembly,
                TableId::AssemblyRef,
                TableId::File,
                TableId::ExportedType,
                TableId::ManifestResource,
                TableId::GenericParam,
                TableId::GenericParamConstraint,
                TableId::MethodSpec,
            ],
            CodedIndexType::HasFieldMarshal => &[TableId::Field, TableId::Param],
            CodedIndexType::HasDeclSecurity => {
                &[TableId::TypeDef, TableId::MethodDef, TableId::Assembly]
            }
            CodedIndexType::MemberRefParent => &[
                TableId::TypeDef,
                TableId::TypeRef,
                TableId::ModuleRef,
                TableId::MethodDef,
                TableId::TypeSpec,
            ],
            CodedIndexType::HasSemantics => &[TableId::Event, TableId::Property],
            CodedIndexType::MethodDefOrRef => &[TableId::MethodDef, TableId::MemberRef],
            CodedIndexType::MemberForwarded => &[TableId::Field, TableId::MethodDef],
            CodedIndexType::Implementation => {
                &[TableId::File, TableId::AssemblyRef, TableId::ExportedType]
            }
            // ToDo:  CustomAttributeType - 0, 1 and 4 are normally 'not used'; Although per design, this can't be properly done.
            //        Could result in wrong look ups right now. Given, that 'normally' no CIL file should actually use those...
            CodedIndexType::CustomAttributeType => &[
                TableId::MethodDef,
                TableId::MethodDef,
                TableId::MethodDef,
                TableId::MemberRef,
                TableId::MemberRef,
            ],
            CodedIndexType::ResolutionScope => &[
                TableId::Module,
                TableId::ModuleRef,
                TableId::AssemblyRef,
                TableId::TypeRef,
            ],
            CodedIndexType::TypeOrMethodDef => &[TableId::TypeDef, TableId::MethodDef],
        }
    }
}

/// The decoded version of a coded-index
#[derive(Clone, Debug, PartialEq)]
pub struct CodedIndex {
    /// The `TableId` this index is referring to
    pub tag: TableId,
    /// The row id that this `CodedIndex` is pointing to
    pub row: u32,
    /// The token in that `TableId`, that this `CodedIndex` is referring to
    pub token: Token,
}

impl CodedIndex {
    /// Create a coded-index from a buffer, and decode the value for easier access
    ///
    /// ## Arguments
    /// * `data`    - The buffer to read
    /// * `offset`  - The offset to read from (will be advanced by the amount read)
    /// * `info`    - Lookup table to get information about tables sizes
    /// * `ci_type` - The specific type that this should decode
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or if the coded index value is invalid.
    pub fn read(
        data: &[u8],
        offset: &mut usize,
        info: &TableInfoRef,
        ci_type: CodedIndexType,
    ) -> Result<Self> {
        let size_needed = info.coded_index_bits(ci_type);
        let coded_index = if size_needed > 16 {
            read_le_at::<u32>(data, offset)?
        } else {
            u32::from(read_le_at::<u16>(data, offset)?)
        };

        let (tag, row) = info.decode_coded_index(coded_index, ci_type)?;
        Ok(CodedIndex::new(tag, row))
    }

    /// Create a new `CodedIndex`
    ///
    /// ## Arguments
    /// * `tag` - The `TableId` to encode
    /// * `row` - The row to encode
    #[must_use]
    pub fn new(tag: TableId, row: u32) -> CodedIndex {
        CodedIndex {
            tag,
            row,
            token: match tag {
                TableId::Module => Token::new(row),
                TableId::TypeRef => Token::new(row | 0x0100_0000),
                TableId::TypeDef => Token::new(row | 0x0200_0000),
                TableId::FieldPtr => Token::new(row | 0x0300_0000),
                TableId::Field => Token::new(row | 0x0400_0000),
                TableId::MethodPtr => Token::new(row | 0x0500_0000),
                TableId::MethodDef => Token::new(row | 0x0600_0000),
                TableId::ParamPtr => Token::new(row | 0x0700_0000),
                TableId::Param => Token::new(row | 0x0800_0000),
                TableId::InterfaceImpl => Token::new(row | 0x0900_0000),
                TableId::MemberRef => Token::new(row | 0x0A00_0000),
                TableId::Constant => Token::new(row | 0x0B00_0000),
                TableId::CustomAttribute => Token::new(row | 0x0C00_0000),
                TableId::FieldMarshal => Token::new(row | 0x0D00_0000),
                TableId::DeclSecurity => Token::new(row | 0x0E00_0000),
                TableId::ClassLayout => Token::new(row | 0x0F00_0000),
                TableId::FieldLayout => Token::new(row | 0x1000_0000),
                TableId::StandAloneSig => Token::new(row | 0x1100_0000),
                TableId::EventMap => Token::new(row | 0x1200_0000),
                TableId::EventPtr => Token::new(row | 0x1300_0000),
                TableId::Event => Token::new(row | 0x1400_0000),
                TableId::PropertyMap => Token::new(row | 0x1500_0000),
                TableId::PropertyPtr => Token::new(row | 0x1600_0000),
                TableId::Property => Token::new(row | 0x1700_0000),
                TableId::MethodSemantics => Token::new(row | 0x1800_0000),
                TableId::MethodImpl => Token::new(row | 0x1900_0000),
                TableId::ModuleRef => Token::new(row | 0x1A00_0000),
                TableId::TypeSpec => Token::new(row | 0x1B00_0000),
                TableId::ImplMap => Token::new(row | 0x1C00_0000),
                TableId::FieldRVA => Token::new(row | 0x1D00_0000),
                TableId::Assembly => Token::new(row | 0x2000_0000),
                TableId::AssemblyProcessor => Token::new(row | 0x2100_0000),
                TableId::AssemblyOS => Token::new(row | 0x2200_0000),
                TableId::AssemblyRef => Token::new(row | 0x2300_0000),
                TableId::AssemblyRefProcessor => Token::new(row | 0x2400_0000),
                TableId::AssemblyRefOS => Token::new(row | 0x2500_0000),
                TableId::File => Token::new(row | 0x2600_0000),
                TableId::ExportedType => Token::new(row | 0x2700_0000),
                TableId::ManifestResource => Token::new(row | 0x2800_0000),
                TableId::NestedClass => Token::new(row | 0x2900_0000),
                TableId::GenericParam => Token::new(row | 0x2A00_0000),
                TableId::MethodSpec => Token::new(row | 0x2B00_0000),
                TableId::GenericParamConstraint => Token::new(row | 0x2C00_0000),
            },
        }
    }
}
