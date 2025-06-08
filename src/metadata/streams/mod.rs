//! Metadata streams for .NET assemblies.
//!
//! This module implements the parsing and representation of metadata streams according to
//! the ECMA-335 standard. Streams store different types of CIL-related data including
//! metadata tables, string heaps, binary data, and GUIDs.
//!
//! # Stream Types
//!
//! The .NET metadata format defines five standard stream types, each serving a specific purpose:
//!
//! ## String Heaps
//! - **`#Strings`** - UTF-8 identifier strings heap containing type names, member names, etc.
//!   The first entry is always null (`\0`). All valid entries are null-terminated.
//! - **`#US`** - UTF-16 user string heap containing string literals from IL code.
//!   Each entry includes a length prefix and terminal byte for special character handling.
//!
//! ## Binary Data
//! - **`#Blob`** - Binary heap containing signatures, custom attribute data, and other
//!   variable-length binary structures referenced by metadata tables.
//! - **`#GUID`** - Sequence of 128-bit GUIDs used for assembly identity and versioning.
//!
//! ## Metadata Tables
//! - **`#~`** - Compressed metadata tables containing type definitions, method signatures,
//!   field layouts, and all structural information about the assembly.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_file("tests/samples/WindowsBase.dll".as_ref())?;
//! let file = assembly.file();
//!
//! // Access string heap
//! if let Some(strings) = assembly.strings() {
//!     let type_name = strings.get(0x123)?; // Get string at offset 0x123
//! }
//!
//! // Access blob heap for signatures
//! if let Some(blob) = assembly.blob() {
//!     let signature_data = blob.get(1)?; // Get blob at offset 1
//! }
//!
//! // Access metadata tables
//! if let Some(tables) = assembly.tables() {
//!     let table_count = tables.table_count();
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Implementation Notes
//!
//! - All streams use compressed integer encoding for sizes and offsets
//! - String heaps use null-terminated UTF-8/UTF-16 encoding
//! - Blob heap entries are prefixed with compressed length values
//! - Metadata tables use token-based cross-references between entries
//!
//! # References
//!
//! - ECMA-335 6th Edition, Partition II, Section 24.2.2 - Stream Headers
//! - ECMA-335 6th Edition, Partition II, Section 22 - Metadata Tables

/// The header of a stream, indicates location + size + name
mod streamheader;
pub use streamheader::StreamHeader;

/// The '#String' heap implementation
mod strings;
pub use strings::Strings;

/// The '#US' heap implementation
mod userstrings;
pub use userstrings::UserStrings;

/// The '#~' implementation
pub(crate) mod tables;
pub use tables::{
    assembly::{
        Assembly, AssemblyFlags, AssemblyHashAlgorithm, AssemblyList, AssemblyMap, AssemblyRaw,
        AssemblyRc,
    },
    assemblyos::{AssemblyOs, AssemblyOsList, AssemblyOsMap, AssemblyOsRaw, AssemblyOsRc},
    assemblyprocessor::{
        AssemblyProcessor, AssemblyProcessorList, AssemblyProcessorMap, AssemblyProcessorRaw,
        AssemblyProcessorRc,
    },
    assemblyref::{
        AssemblyRef, AssemblyRefHash, AssemblyRefList, AssemblyRefMap, AssemblyRefRaw,
        AssemblyRefRc,
    },
    assemblyrefos::{
        AssemblyRefOs, AssemblyRefOsList, AssemblyRefOsMap, AssemblyRefOsRaw, AssemblyRefOsRc,
    },
    assemblyrefprocessor::{
        AssemblyRefProcessor, AssemblyRefProcessorList, AssemblyRefProcessorMap,
        AssemblyRefProcessorRaw, AssemblyRefProcessorRc,
    },
    classlayout::{ClassLayout, ClassLayoutList, ClassLayoutMap, ClassLayoutRaw, ClassLayoutRc},
    constant::{Constant, ConstantList, ConstantMap, ConstantRaw, ConstantRc},
    customattribute::{
        CustomAttribute, CustomAttributeList, CustomAttributeMap, CustomAttributeRaw,
        CustomAttributeRc,
    },
    declsecurity::{
        DeclSecurity, DeclSecurityList, DeclSecurityMap, DeclSecurityRaw, DeclSecurityRc,
    },
    event::{Event, EventAttributes, EventList, EventMap, EventRaw, EventRc},
    eventmap::EventMapRaw,
    exportedtype::{
        ExportedType, ExportedTypeList, ExportedTypeMap, ExportedTypeRaw, ExportedTypeRc,
    },
    field::{Field, FieldAttributes, FieldList, FieldMap, FieldRaw, FieldRc},
    fieldlayout::{FieldLayout, FieldLayoutList, FieldLayoutMap, FieldLayoutRaw, FieldLayoutRc},
    fieldmarshal::{
        FieldMarshal, FieldMarshalList, FieldMarshalMap, FieldMarshalRaw, FieldMarshalRc,
    },
    fieldrva::{FieldRVAList, FieldRVAMap, FieldRVARc, FieldRva, FieldRvaRaw},
    file::{File, FileAttributes, FileList, FileMap, FileRaw, FileRc},
    genericparam::{
        GenericParam, GenericParamAttributes, GenericParamList, GenericParamMap, GenericParamRaw,
        GenericParamRc,
    },
    genericparamconstraint::{
        GenericParamConstraint, GenericParamConstraintList, GenericParamConstraintMap,
        GenericParamConstraintRaw, GenericParamConstraintRc,
    },
    implmap::{ImplMap, ImplMapList, ImplMapMap, ImplMapRaw, ImplMapRc},
    interfaceimpl::{
        InterfaceImpl, InterfaceImplList, InterfaceImplMap, InterfaceImplRaw, InterfaceImplRc,
    },
    manifestresource::{
        ManifestResource, ManifestResourceAttributes, ManifestResourceList, ManifestResourceMap,
        ManifestResourceRaw, ManifestResourceRc,
    },
    memberref::{
        MemberRef, MemberRefList, MemberRefMap, MemberRefRaw, MemberRefRc, MemberRefSignature,
    },
    methoddef::MethodDefRaw,
    methodimpl::{MethodImpl, MethodImplList, MethodImplMap, MethodImplRaw, MethodImplRc},
    methodsemantics::{
        MethodSemantics, MethodSemanticsAttributes, MethodSemanticsList, MethodSemanticsMap,
        MethodSemanticsRaw, MethodSemanticsRc,
    },
    methodspec::{MethodSpec, MethodSpecList, MethodSpecMap, MethodSpecRaw, MethodSpecRc},
    module::{Module, ModuleList, ModuleMap, ModuleRaw, ModuleRc},
    moduleref::{ModuleRef, ModuleRefList, ModuleRefMap, ModuleRefRaw, ModuleRefRc},
    nestedclass::{NestedClass, NestedClassList, NestedClassMap, NestedClassRaw, NestedClassRc},
    param::{Param, ParamAttributes, ParamList, ParamMap, ParamRaw, ParamRc},
    property::{Property, PropertyAttributes, PropertyList, PropertyMap, PropertyRaw, PropertyRc},
    propertymap::PropertyMapRaw,
    standalonesig::{
        StandAloneSig, StandAloneSigList, StandAloneSigMap, StandAloneSigRaw, StandAloneSigRc,
    },
    typedef::{TypeAttributes, TypeDefRaw},
    typeref::TypeRefRaw,
    types::{
        CodedIndex, CodedIndexType, CodedIndexTypeIter, MetadataTable, RowDefinition, TableData,
        TableId, TableInfo, TableInfoRef, TableIterator, TableRowInfo, TablesHeader,
    },
    typespec::TypeSpecRaw,
};

/// The '#GUID' heap / array implementation
mod guid;
pub use guid::Guid;

/// The '#Blob' heap implementation
mod blob;
pub use blob::Blob;
