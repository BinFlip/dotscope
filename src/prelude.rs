//! # dotscope Prelude
//!
//! This module provides a convenient prelude for the most commonly used types and traits
//! from the dotscope library. Import this module to get quick access to the essential
//! types for .NET assembly analysis.

// ================================================================================================
// Core Types and Error Handling
// ================================================================================================

/// The main error type for all dotscope operations
pub use crate::Error;

/// The result type used throughout dotscope
pub use crate::Result;

/// Configuration for metadata validation during assembly loading
pub use crate::ValidationConfig;

// ================================================================================================
// Main Entry Points
// ================================================================================================

/// Main entry point for .NET assembly analysis
pub use crate::CilObject;

/// Low-level file parsing utilities
pub use crate::{File, Parser};

// ================================================================================================
// Metadata System - Core Types
// ================================================================================================

/// Metadata token type for referencing table entries
pub use crate::metadata::token::Token;

/// Metadata root constants
pub use crate::metadata::root::CIL_HEADER_MAGIC;

/// Import types for external references
pub use crate::metadata::imports::ImportType;

// ================================================================================================
// Type System
// ================================================================================================

/// Core type system components
pub use crate::metadata::typesystem::{
    CilFlavor, CilModifier, CilPrimitive, CilPrimitiveData, CilPrimitiveKind, CilType, CilTypeList,
    CilTypeRc, CilTypeRef, CilTypeRefList, CilTypeReference, TypeRegistry, TypeResolver,
    TypeSource,
};

// ================================================================================================
// Metadata Streams and Tables - High-Level Types
// ================================================================================================

/// Assembly and module information
pub use crate::metadata::tables::{
    Assembly, AssemblyRc, AssemblyRef, AssemblyRefRc, Module, ModuleRc, ModuleRef, ModuleRefRc,
};

/// Type definitions and references
pub use crate::metadata::tables::{ExportedType, ExportedTypeRc};

/// Fields and field-related types
pub use crate::metadata::tables::{
    Field, FieldLayout, FieldList, FieldMap, FieldPtr, FieldPtrList, FieldPtrMap, FieldPtrRc,
    FieldRc, MethodPtr, MethodPtrList, MethodPtrMap, MethodPtrRc,
};

/// Parameters
pub use crate::metadata::tables::{
    Param, ParamList, ParamPtr, ParamPtrList, ParamPtrMap, ParamPtrRc, ParamRc,
};

/// Properties and events
pub use crate::metadata::tables::{
    Event, EventList, EventPtr, EventPtrList, EventPtrMap, EventPtrRc, EventRc, Property,
    PropertyList, PropertyPtr, PropertyPtrList, PropertyPtrMap, PropertyPtrRc, PropertyRc,
};

/// Interfaces and member references
pub use crate::metadata::tables::{InterfaceImpl, InterfaceImplRc, MemberRef, MemberRefRc};

/// Generic types and constraints
pub use crate::metadata::tables::{
    GenericParam, GenericParamConstraint, GenericParamConstraintRc, GenericParamList,
    GenericParamRc, MethodSpec, MethodSpecRc,
};

/// Security and custom attributes
pub use crate::metadata::tables::{
    CustomAttribute, CustomAttributeList, CustomAttributeRc, DeclSecurity, DeclSecurityRc,
};

/// Files and resources
pub use crate::metadata::tables::{
    File as MetadataFile, FileRc, ManifestResource, ManifestResourceRc,
};

/// Standalone signatures
pub use crate::metadata::tables::{StandAloneSig, StandAloneSigRc};

// ================================================================================================
// Raw Metadata Table Types
// ================================================================================================

/// Assembly and module raw table types
pub use crate::metadata::tables::{
    AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw, AssemblyRefProcessorRaw,
    AssemblyRefRaw, ModuleRaw, ModuleRefRaw,
};

/// Type definition raw table types
pub use crate::metadata::tables::{ExportedTypeRaw, TypeDefRaw, TypeRefRaw, TypeSpecRaw};

/// Field and method raw table types
pub use crate::metadata::tables::{
    FieldLayoutRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, MethodDefRaw, MethodPtrRaw, ParamPtrRaw,
    ParamRaw,
};

/// Core metadata raw table types
pub use crate::metadata::tables::{
    ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, DeclSecurityRaw, EventMapRaw, EventPtrRaw,
    EventRaw, FieldMarshalRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw,
    InterfaceImplRaw, ManifestResourceRaw, MemberRefRaw, MethodImplRaw, MethodSemanticsRaw,
    MethodSpecRaw, NestedClassRaw, PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw,
};

/// File system raw table types
pub use crate::metadata::tables::FileRaw;

// ================================================================================================
// Signatures and Type Information
// ================================================================================================

/// Core signature types
pub use crate::metadata::signatures::{
    SignatureArray, SignatureField, SignatureLocalVariable, SignatureLocalVariables,
    SignatureMethod, SignatureMethodSpec, SignatureParameter, SignaturePointer, SignatureProperty,
    SignatureSzArray, SignatureTypeSpec, TypeSignature,
};

/// Signature parsing functions
pub use crate::metadata::signatures::{
    parse_field_signature, parse_local_var_signature, parse_method_signature,
    parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
};

/// Additional signature support types
pub use crate::metadata::tables::MemberRefSignature;

// ================================================================================================
// Method Analysis
// ================================================================================================

/// Method body and IL analysis
pub use crate::metadata::method::{
    ExceptionHandler, ExceptionHandlerFlags, InstructionIterator, Method, MethodBody,
    MethodImplCodeType, MethodImplManagement, MethodImplOptions, MethodList, MethodMap,
    MethodModifiers, MethodRc, MethodRef, MethodRefList,
};

// ================================================================================================
// Disassembler
// ================================================================================================

/// CIL instruction disassembly and analysis
pub use crate::disassembler::{
    decode_blocks, decode_instruction, decode_stream, BasicBlock, FlowType, Immediate, Instruction,
    InstructionCategory, Operand, OperandType, StackBehavior,
};

// ================================================================================================
// Import/Export Analysis
// ================================================================================================

/// Import and export analysis
pub use crate::metadata::{
    exports::Exports,
    imports::{Import, ImportContainer, ImportRc, Imports},
};

// ================================================================================================
// Metadata Streams - Heaps and Headers
// ================================================================================================

/// Metadata heap access
pub use crate::metadata::streams::{Blob, Guid, Strings, UserStrings};

/// Metadata heap iterators for efficient sequential traversal
pub use crate::metadata::streams::{
    BlobIterator, GuidIterator, StringsIterator, UserStringsIterator,
};

/// Metadata tables and stream headers
pub use crate::metadata::streams::{StreamHeader, TablesHeader};

/// Main headers
pub use crate::metadata::{cor20header::Cor20Header, root::Root};

// ================================================================================================
// Attributes and Flags
// ================================================================================================

/// Common attribute flags for metadata tables
pub use crate::metadata::tables::{
    EventAttributes, FieldAttributes, FileAttributes, ParamAttributes, PropertyAttributes,
    TypeAttributes,
};

// ================================================================================================
// Constants and Element Types
// ================================================================================================

/// Element type constants for type system
pub use crate::metadata::typesystem::ELEMENT_TYPE;

/// Native type constants for marshalling
pub use crate::metadata::marshalling::{NATIVE_TYPE, VARIANT_TYPE};

// ================================================================================================
// Table Identifiers and Utilities
// ================================================================================================

/// Metadata table identifiers
pub use crate::metadata::tables::TableId;

/// Coded index types for metadata table relationships
pub use crate::metadata::tables::{
    CodedIndex, CodedIndexType, MetadataTable, TableInfo, TableInfoRef,
};
