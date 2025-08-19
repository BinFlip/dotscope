//! # Coded Index Types Module
//!
//! This module provides types and functionality for handling coded indices in .NET metadata tables.
//! Coded indices are a space-efficient encoding mechanism used in CLI metadata to reference
//! multiple possible table types using a single value.
//!
//! ## Overview
//!
//! Coded indices combine a table identifier and row index into a single value by using the
//! lower bits to encode which table type is being referenced, and the remaining bits for
//! the actual row index. This allows metadata to reference different types of entities
//! (e.g., `TypeDef`, `TypeRef`, or `TypeSpec`) using a unified format.
//!
//! ## Key Components
//!
//! - [`crate::metadata::tables::types::CodedIndexType`]: Enumeration of all possible coded index combinations defined in ECMA-335
//! - [`crate::metadata::tables::types::CodedIndex`]: Decoded representation containing the target table, row, and computed token
//!
//! ## References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Section II.24.2.6

use strum::{EnumCount, EnumIter};

use crate::{
    metadata::{
        tables::{TableId, TableInfoRef},
        token::Token,
    },
    utils::read_le_at,
    Result,
};

/// Represents all possible coded index types defined in the CLI metadata specification.
///
/// A coded index type defines which combination of metadata tables can be referenced
/// by a particular coded index field. Each variant corresponds to a specific set of
/// tables that can be encoded together, allowing for space-efficient cross-references
/// within the metadata stream.
///
/// ## Encoding Scheme
///
/// Coded indices use the lower bits to encode the table type and the remaining bits
/// for the row index. The number of bits required for the table type depends on
/// how many tables are included in the combination.
///
/// ## Examples
///
/// - `TypeDefOrRef` can reference `TypeDef`, `TypeRef`, or `TypeSpec` tables
/// - `HasConstant` can reference `Field`, `Param`, or `Property` tables
/// - `HasCustomAttribute` can reference any of 22 different table types
///
/// ## Reference
///
/// - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Section II.24.2.6
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, EnumIter, EnumCount)]
#[repr(usize)]
pub enum CodedIndexType {
    /// References `TypeDef`, `TypeRef`, or `TypeSpec` tables.
    ///
    /// Used to identify type definitions, references, or specifications
    /// in a unified manner throughout the metadata.
    TypeDefOrRef,

    /// References `Field`, `Param`, or `Property` tables.
    ///
    /// Used to identify entities that can have constant values
    /// assigned to them.
    HasConstant,

    /// References any entity that can have custom attributes attached.
    ///
    /// This is the most comprehensive coded index type, supporting references to:
    /// `MethodDef`, `Field`, `TypeRef`, `TypeDef`, `Param`, `InterfaceImpl`, `MemberRef`,
    /// `Module`, `Permission`, `Property`, `Event`, `StandAloneSig`, `ModuleRef`, `TypeSpec`,
    /// `Assembly`, `AssemblyRef`, `File`, `ExportedType`, `ManifestResource`, `GenericParam`,
    /// `GenericParamConstraint`, `MethodSpec`.
    HasCustomAttribute,

    /// References `Field` or `Param` tables.
    ///
    /// Used to identify entities that can have marshalling information
    /// for interop scenarios.
    HasFieldMarshal,

    /// References `TypeDef`, `MethodDef`, or `Assembly` tables.
    ///
    /// Used to identify entities that can have declarative security
    /// attributes applied.
    HasDeclSecurity,

    /// References `TypeDef`, `TypeRef`, `ModuleRef`, `MethodDef`, or `TypeSpec` tables.
    ///
    /// Used as the parent reference for member references.
    MemberRefParent,

    /// References `Event` or `Property` tables.
    ///
    /// Used to identify entities that can have semantic methods
    /// (getter, setter, etc.) associated with them.
    HasSemantics,

    /// References `MethodDef` or `MemberRef` tables.
    ///
    /// Used to reference method definitions or member references
    /// in a unified manner.
    MethodDefOrRef,

    /// References `Field` or `MethodDef` tables.
    ///
    /// Used to identify members that are forwarded to other assemblies.
    MemberForwarded,

    /// References `File`, `AssemblyRef`, or `ExportedType` tables.
    ///
    /// Used to specify the implementation location for exported types.
    Implementation,

    /// References `MethodDef` or `MemberRef` tables.
    ///
    /// Used to identify the constructor methods for custom attributes.
    /// Note: Some indices (0, 1, 4) are normally unused but supported
    /// by the encoding scheme.
    CustomAttributeType,

    /// References `Module`, `ModuleRef`, `AssemblyRef`, or `TypeRef` tables.
    ///
    /// Used to specify the scope in which a type reference should be resolved.
    ResolutionScope,

    /// References `TypeDef` or `MethodDef` tables.
    ///
    /// Used to reference either type or method definitions in contexts
    /// where both are valid targets.
    TypeOrMethodDef,

    /// References any entity that can have custom debug information attached.
    ///
    /// This coded index supports references to various metadata tables for Portable PDB
    /// custom debug information. According to the Portable PDB specification, this can
    /// reference any of the following tables:
    /// `MethodDef`, `Field`, `TypeRef`, `TypeDef`, `Param`, `InterfaceImpl`, `MemberRef`,
    /// `Module`, `DeclSecurity`, `Property`, `Event`, `StandAloneSig`, `ModuleRef`, `TypeSpec`,
    /// `Assembly`, `AssemblyRef`, `File`, `ExportedType`, `ManifestResource`, `GenericParam`,
    /// `GenericParamConstraint`, `MethodSpec`, `Document`, `LocalScope`, `LocalVariable`,
    /// `LocalConstant`, `ImportScope`.
    HasCustomDebugInformation,
}

impl CodedIndexType {
    /// Returns the array of table IDs that can be referenced by this coded index type.
    ///
    /// This method provides the lookup table that defines which metadata tables
    /// can be encoded using this particular coded index type. The order of tables
    /// in the returned slice corresponds to the encoded values (0, 1, 2, etc.).
    ///
    /// ## Returns
    ///
    /// A static slice containing the [`crate::metadata::tables::types::TableId`] values that can be referenced
    /// by this coded index type, in encoding order.
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
            CodedIndexType::HasCustomDebugInformation => &[
                TableId::MethodDef,
                TableId::Field,
                TableId::TypeRef,
                TableId::TypeDef,
                TableId::Param,
                TableId::InterfaceImpl,
                TableId::MemberRef,
                TableId::Module,
                TableId::DeclSecurity,
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
                TableId::Document,
                TableId::LocalScope,
                TableId::LocalVariable,
                TableId::LocalConstant,
                TableId::ImportScope,
            ],
        }
    }
}

/// A decoded representation of a coded index value.
///
/// This structure contains the decoded components of a coded index, providing
/// direct access to the target table, row index, computed metadata token, and
/// the coded index type information. Coded indices are space-efficient encodings
/// that combine table type and row information into a single value.
///
/// ## Fields
///
/// - `tag`: The specific metadata table being referenced
/// - `row`: The 1-based row index within that table
/// - `token`: The computed metadata token for direct table access
/// - `ci_type`: The coded index type defining allowed target tables
#[derive(Clone, Debug, PartialEq)]
pub struct CodedIndex {
    /// The [`TableId`] this index is referring to.
    ///
    /// Specifies which metadata table contains the referenced entity.
    pub tag: TableId,

    /// The row ID that this `CodedIndex` is pointing to.
    ///
    /// This is a 1-based index into the specified table. Row 0 is reserved
    /// and typically indicates a null reference.
    pub row: u32,

    /// The computed metadata token for this coded index.
    ///
    /// The token combines the table type (in the upper bits) with the row index
    /// (in the lower bits) to create a unique identifier that can be used
    /// for direct table lookups.
    pub token: Token,

    /// The coded index type defining which tables are valid targets.
    ///
    /// This field provides access to the coded index type information, allowing
    /// validation code to determine which tables are valid targets by calling
    /// `ci_type.tables()` instead of manually specifying allowed tables.
    pub ci_type: CodedIndexType,
}

impl CodedIndex {
    /// Reads and decodes a coded index from a byte buffer.
    ///
    /// This method reads a coded index value from the provided buffer, automatically
    /// determining whether to read 2 or 4 bytes based on the table size requirements,
    /// then decodes the value into its constituent table and row components.
    ///
    /// ## Arguments
    ///
    /// * `data` - The byte buffer to read from
    /// * `offset` - Mutable reference to the current read position (updated after reading)
    /// * `info` - Table information reference for size calculations and decoding
    /// * `ci_type` - The specific coded index type to decode
    ///
    /// ## Returns
    ///
    /// Returns a [`crate::Result`] containing the decoded [`crate::metadata::tables::types::CodedIndex`] on success.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The buffer is too small to read the required bytes
    /// - The coded index value is invalid or references a non-existent table/row
    /// - The table information is inconsistent or corrupted
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
        Ok(CodedIndex::new(tag, row, ci_type))
    }

    /// Creates a new `CodedIndex` with the specified table, row, and coded index type.
    ///
    /// This method constructs a new coded index by combining the table identifier,
    /// row index, and coded index type information, automatically computing the
    /// appropriate metadata token based on the ECMA-335 token encoding scheme.
    ///
    /// ## Arguments
    ///
    /// * `tag` - The [`crate::metadata::tables::types::TableId`] specifying which metadata table is being referenced
    /// * `row` - The 1-based row index within the specified table
    /// * `ci_type` - The [`crate::metadata::tables::types::CodedIndexType`] defining the valid target tables
    ///
    /// ## Returns
    ///
    /// A new [`crate::metadata::tables::types::CodedIndex`] instance with the computed token and type information.
    ///
    /// ## Token Encoding
    ///
    /// The token is computed by combining the table-specific prefix (upper 8 bits)
    /// with the row index (lower 24 bits). Each table type has a predefined token
    /// prefix as defined in the ECMA-335 specification.
    #[must_use]
    pub fn new(tag: TableId, row: u32, ci_type: CodedIndexType) -> CodedIndex {
        CodedIndex {
            tag,
            row,
            ci_type,
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
                TableId::EncLog => Token::new(row | 0x1E00_0000),
                TableId::EncMap => Token::new(row | 0x1F00_0000),
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
                TableId::Document => Token::new(row | 0x3000_0000),
                TableId::MethodDebugInformation => Token::new(row | 0x3100_0000),
                TableId::LocalScope => Token::new(row | 0x3200_0000),
                TableId::LocalVariable => Token::new(row | 0x3300_0000),
                TableId::LocalConstant => Token::new(row | 0x3400_0000),
                TableId::ImportScope => Token::new(row | 0x3500_0000),
                TableId::StateMachineMethod => Token::new(row | 0x3600_0000),
                TableId::CustomDebugInformation => Token::new(row | 0x3700_0000),
            },
        }
    }
}
