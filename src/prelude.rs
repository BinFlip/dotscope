//! dotscope prelude for convenient .NET assembly analysis.
//!
//! The dotscope prelude provides convenient access to the most commonly used types, traits,
//! and functions for .NET assembly analysis. This module serves as a one-stop import for
//! typical dotscope usage patterns, reducing the need for multiple individual imports and
//! providing immediate access to essential functionality.
//!
//! # Architecture
//!
//! The prelude is organized into logical groups covering all major aspects of .NET metadata analysis,
//! from high-level assembly loading to low-level metadata table access. This organization follows
//! the typical workflow of .NET assembly analysis applications.
//!
//! ## Core Components
//!
//! - **Entry Points**: [`crate::CilObject`], [`crate::File`], [`crate::Parser`] - Main interfaces for assembly loading
//! - **Type System**: [`crate::metadata::typesystem::CilType`], [`crate::metadata::typesystem::TypeRegistry`] - Complete type representation
//! - **Metadata Access**: Table types, stream access, and token-based navigation
//! - **Analysis Tools**: Disassembler, method body parsing, signature analysis
//! - **Error Handling**: [`crate::Error`], [`crate::Result`] - Comprehensive error management
//!
//! # Key Components
//!
//! ## Organized Import Groups
//!
//! - **Core Types**: Error handling, results, and main entry points
//! - **Type System**: Complete type representation and resolution
//! - **Metadata Tables**: High-level and raw table access
//! - **Signatures**: Type and method signature parsing
//! - **Method Analysis**: IL disassembly and method body analysis
//! - **Import/Export**: Assembly dependency analysis
//! - **Streams and Headers**: Low-level metadata structure access
//! - **Constants**: Element types, attributes, and metadata identifiers
//!
//! # Usage Examples
//!
//! ## Basic Assembly Analysis
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! // Core functionality immediately available
//! let assembly = CilObject::from_file("example.dll".as_ref())?;
//! let types = assembly.types();
//!
//! // Type system components
//! for entry in types.iter() {
//!     let cil_type = entry.value();
//!     match cil_type.flavor() {
//!         CilFlavor::Class => println!("Class: {}.{}", cil_type.namespace, cil_type.name),
//!         CilFlavor::Interface => println!("Interface: {}.{}", cil_type.namespace, cil_type.name),
//!         _ => {}
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Method Analysis and Disassembly
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! let assembly = CilObject::from_file("example.dll".as_ref())?;
//! let methods = assembly.methods();
//!
//! for entry in methods.iter() {
//!     let method = entry.value();
//!     if let Some(body) = method.body.get() {
//!         if body.size_code > 0 {
//!             println!("Method {} has {} bytes of IL", method.name, body.size_code);
//!             println!("  Max stack: {}", body.max_stack);
//!             
//!             // Access disassembled instructions through blocks
//!             for (block_id, block) in method.blocks() {
//!                 println!("  Block {}: {} instructions", block_id, block.instructions.len());
//!             }
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## CIL Instruction Assembly
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! // High-level fluent API for common instruction patterns
//! let mut assembler = InstructionAssembler::new();
//! assembler
//!     .ldarg_0()?      // Load first argument
//!     .ldarg_1()?      // Load second argument  
//!     .add()?          // Add them
//!     .ret()?;         // Return result
//! let bytecode = assembler.finish()?;
//!
//! // Low-level encoder for any CIL instruction  
//! let mut encoder = InstructionEncoder::new();
//! encoder.emit_instruction("ldarg.0", None)?;
//! encoder.emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(42))))?;
//! encoder.emit_instruction("ret", None)?;
//! let bytecode2 = encoder.finalize()?;
//!
//! // Label resolution and control flow
//! let mut asm = InstructionAssembler::new();
//! asm.ldarg_0()?
//!    .brfalse_s("false_case")?
//!    .ldc_i4_1()?
//!    .br_s("end")?
//!    .label("false_case")?
//!    .ldc_i4_0()?
//!    .label("end")?
//!    .ret()?;
//! let conditional_bytecode = asm.finish()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Metadata Table Access
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! let assembly = CilObject::from_file("example.dll".as_ref())?;
//!
//! // High-level table access
//! if let Some(assembly_info) = assembly.assembly() {
//!     println!("Assembly: {}", assembly_info.name);
//!     println!("Version: {}.{}.{}.{}",
//!              assembly_info.major_version, assembly_info.minor_version,
//!              assembly_info.build_number, assembly_info.revision_number);
//! }
//!
//! // Token-based navigation
//! let typedef_token = Token::new(0x02000001);
//! if let Some(tables) = assembly.tables() {
//!     if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
//!         let row_index = typedef_token.row();
//!         if let Some(typedef) = typedef_table.get(row_index) {
//!             println!("Type name index: {}", typedef.type_name);
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//!
//! # Import Organization
//!
//! The prelude is organized into logical sections for easy navigation:
//!
//! 1. **Core Types**: Essential error handling and configuration
//! 2. **Entry Points**: Main interfaces for assembly loading and parsing
//! 3. **Type System**: Complete .NET type representation and resolution
//! 4. **Metadata Tables**: Both high-level and raw table access
//! 5. **Signatures**: Type and method signature parsing
//! 6. **Method Analysis**: IL analysis and method body parsing
//! 7. **Disassembler**: CIL instruction decoding and control flow
//! 8. **Import/Export**: Assembly dependency analysis
//! 9. **Streams and Headers**: Metadata storage structure access
//! 10. **Constants**: Type system and marshalling constants
//!
//! # Thread Safety
//!
//! Most types in the prelude are either `Send + Sync` or use interior mutability
//! for thread-safe access. Reference-counted types ([`crate::metadata::typesystem::CilTypeRc`], [`crate::metadata::method::MethodRc`], etc.)
//! enable safe sharing across threads without performance penalties.
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with .NET metadata specification
//! - **Type Safety**: Strong typing throughout the API surface
//! - **Memory Safety**: No unsafe code in public interfaces
//! - **Performance**: Zero-cost abstractions and efficient data structures

// ================================================================================================
// Core Types and Error Handling
// ================================================================================================
//
// This section provides the fundamental types for dotscope error handling and configuration.
// These are typically needed in any dotscope application for proper error management and
// assembly loading configuration.

/// The main error type for all dotscope operations.
///
/// Covers parsing errors, type resolution failures, IL validation issues, and I/O problems.
/// Provides detailed error context for debugging and user-friendly error messages.
pub use crate::Error;

/// The result type used throughout dotscope APIs.
///
/// Standard `Result<T, Error>` type alias for consistent error handling across the library.
/// Most dotscope operations return this type for uniform error propagation.
pub use crate::Result;

/// Configuration for metadata validation during assembly loading.
///
/// Controls validation strictness, error handling behavior, and performance trade-offs
/// during metadata parsing and type system construction.
pub use crate::ValidationConfig;

// ================================================================================================
// Main Entry Points
// ================================================================================================
//
// Primary interfaces for loading and analyzing .NET assemblies. These types provide the
// main entry points into dotscope functionality, from high-level assembly analysis to
// low-level file parsing operations.

/// Main entry point for .NET assembly analysis.
///
/// `CilObject` provides high-level access to .NET assembly metadata, type systems,
/// method bodies, and disassembly capabilities. This is typically the starting point
/// for most dotscope applications.
pub use crate::CilObject;

/// Raw assembly view for editing and modification operations.
///
/// `CilAssemblyView` provides direct access to .NET assembly metadata structures
/// while maintaining a 1:1 mapping with the underlying file format. Designed as
/// the foundation for future editing and modification capabilities.
pub use crate::metadata::cilassemblyview::CilAssemblyView;

/// Low-level file parsing utilities.
///
/// `File` and `Parser` provide direct access to raw PE file structure and metadata
/// parsing operations. Used for custom parsing scenarios or when fine-grained control
/// over the parsing process is required.
pub use crate::{File, Parser};

// ================================================================================================
// Metadata System - Core Types
// ================================================================================================
//
// Essential metadata system components for working with .NET metadata tables, tokens,
// and basic metadata structures. These types form the foundation for all metadata
// operations and table navigation.

/// Metadata token type for referencing table entries.
///
/// Tokens are 32-bit identifiers that uniquely reference rows in metadata tables.
/// They encode both the table type and row index, enabling efficient cross-table
/// references throughout the metadata system.
pub use crate::metadata::token::Token;

/// Metadata root constants.
///
/// Magic numbers and signature constants used in .NET metadata headers for format
/// validation and version identification.
pub use crate::metadata::root::CIL_HEADER_MAGIC;

/// Import types for external references.
///
/// Classification of different import mechanisms used by .NET assemblies for
/// referencing external types, methods, and resources.
pub use crate::metadata::imports::ImportType;

// ================================================================================================
// Type System
// ================================================================================================
//
// Complete .NET type system representation including type definitions, references,
// primitives, and resolution mechanisms. This is the core of dotscope's type analysis
// capabilities, providing unified access to all .NET type constructs.

/// Core type system components.
///
/// Includes type representations (`CilType`), primitive types (`CilPrimitive`),
/// type registries (`TypeRegistry`), resolution (`TypeResolver`), and all supporting
/// types for comprehensive .NET type system analysis.
pub use crate::metadata::typesystem::{
    CilFlavor, CilModifier, CilPrimitive, CilPrimitiveData, CilPrimitiveKind, CilType, CilTypeList,
    CilTypeRc, CilTypeRef, CilTypeRefList, CilTypeReference, TypeRegistry, TypeResolver,
    TypeSignatureEncoder, TypeSource,
};

// ================================================================================================
// Metadata Streams and Tables - High-Level Types
// ================================================================================================
//
// This section provides high-level, safe wrappers around metadata tables. These types
// include reference counting, validation, and convenient accessor methods. They are the
// recommended interface for most metadata operations, providing safety and ease of use
// over raw table access.

/// Assembly and module information.
///
/// Core assembly metadata including version info, culture, public keys, and module definitions.
/// These types provide the foundation for assembly identity and module organization.
pub use crate::metadata::tables::{
    Assembly, AssemblyRc, AssemblyRef, AssemblyRefRc, Module, ModuleRc, ModuleRef, ModuleRefRc,
};

/// Type definitions and references.
///
/// Types for working with exported types and type resolution across assembly boundaries.
/// Essential for analyzing type dependencies and assembly composition.
pub use crate::metadata::tables::{ExportedType, ExportedTypeRc};

/// Fields and field-related types.
///
/// Complete field metadata including layout information, RVA data, and pointer tables.
/// Also includes method pointer types for efficient method table navigation.
pub use crate::metadata::tables::{
    Field, FieldLayout, FieldList, FieldMap, FieldPtr, FieldPtrList, FieldPtrMap, FieldPtrRc,
    FieldRc, MethodPtr, MethodPtrList, MethodPtrMap, MethodPtrRc,
};

/// Parameters.
///
/// Method parameter metadata including attributes, default values, and marshalling information.
/// Essential for method signature analysis and parameter validation.
pub use crate::metadata::tables::{
    Param, ParamList, ParamPtr, ParamPtrList, ParamPtrMap, ParamPtrRc, ParamRc,
};

/// Properties and events.
///
/// Property and event metadata including accessors, modifiers, and event handlers.
/// Core components for analyzing .NET type members and their behaviors.
pub use crate::metadata::tables::{
    Event, EventList, EventPtr, EventPtrList, EventPtrMap, EventPtrRc, EventRc, Property,
    PropertyList, PropertyPtr, PropertyPtrList, PropertyPtrMap, PropertyPtrRc, PropertyRc,
};

/// Interfaces and member references.
///
/// Interface implementation tracking and cross-assembly member references.
/// Critical for understanding type relationships and external dependencies.
pub use crate::metadata::tables::{InterfaceImpl, InterfaceImplRc, MemberRef, MemberRefRc};

/// Generic types and constraints.
///
/// Generic parameter definitions, constraints, and method specializations.
/// Essential for analyzing generic types and their instantiation constraints.
pub use crate::metadata::tables::{
    GenericParam, GenericParamConstraint, GenericParamConstraintRc, GenericParamList,
    GenericParamRc, MethodSpec, MethodSpecRc,
};

/// Security and custom attributes.
///
/// Security declarations and custom attribute metadata.
/// Important for analyzing assembly security policies and annotation information.
pub use crate::metadata::tables::{
    CustomAttribute, CustomAttributeList, CustomAttributeRc, DeclSecurity, DeclSecurityRc,
};

/// .NET Code Access Security (CAS) implementation.
///
/// Complete support for parsing and representing .NET Code Access Security permissions,
/// permission sets, and security actions. Essential for analyzing legacy .NET Framework
/// assemblies that use declarative security attributes and CAS policies.
pub use crate::metadata::security::{
    ArgumentType, ArgumentValue, NamedArgument, Permission, PermissionSet, PermissionSetFormat,
    Security, SecurityAction, SecurityPermissionFlags,
};

/// Files and resources.
///
/// File references and manifest resources embedded in or referenced by the assembly.
/// Essential for analyzing resource dependencies and multi-file assemblies.
pub use crate::metadata::tables::{
    File as MetadataFile, FileRc, ManifestResource, ManifestResourceRc,
};

/// Standalone signatures.
///
/// Independent signature definitions used for indirect calls and marshalling scenarios.
pub use crate::metadata::tables::{StandAloneSig, StandAloneSigRc};

// ================================================================================================
// Portable PDB Debug Information Tables
// ================================================================================================
//
// This section provides access to Portable PDB format debug information tables. These tables
// enable rich debugging experiences with source line mapping, local variable information,
// scope tracking, and custom debug data. Essential for debugger integration and development
// tool support.

/// Document and source file information.
///
/// Document table entries provide information about source files referenced in debug information,
/// including file names, language identifiers, hash algorithms, and source content.
pub use crate::metadata::tables::{Document, DocumentRc};

/// Method debugging information.
///
/// Links methods to their sequence points for source code mapping and debugging.
/// Essential for providing line-by-line debugging and source code visualization.
pub use crate::metadata::tables::{MethodDebugInformation, MethodDebugInformationRc};

/// Local variable and constant scope tracking.
///
/// `LocalScope` defines the IL instruction ranges where local variables and constants are active.
/// Critical for proper variable visibility and lifetime tracking during debugging.
pub use crate::metadata::tables::{LocalScope, LocalScopeRc, LocalScopeRef};

/// Local variable debug information.
///
/// Provides names, signatures, and debugging attributes for local variables within methods.
/// Enables debuggers to display meaningful variable information during execution.
pub use crate::metadata::tables::{LocalVariable, LocalVariableRc};

/// Local constant debug information.
///
/// Contains information about local constants including names, signatures, and values.
/// Allows debuggers to display constant values and provide comprehensive local state information.
pub use crate::metadata::tables::{LocalConstant, LocalConstantRc};

/// Namespace import scope information.
///
/// Tracks namespace imports (using statements) and their active ranges for proper name resolution
/// during debugging and `IntelliSense` operations.
pub use crate::metadata::tables::{ImportScope, ImportScopeRc};

/// State machine method mappings.
///
/// Links compiler-generated state machine methods (async/await, iterators) back to their original
/// user-written methods for seamless debugging experiences.
pub use crate::metadata::tables::{StateMachineMethod, StateMachineMethodRc};

/// Custom debugging information.
///
/// Extensible debug information that can be defined by compilers or tools for specialized
/// debugging scenarios beyond the standard Portable PDB format.
pub use crate::metadata::tables::{CustomDebugInformation, CustomDebugInformationRc};

// ================================================================================================
// Raw Metadata Table Types
// ================================================================================================
//
// This section provides direct access to raw metadata table structures as they appear
// in the assembly file. These types offer maximum performance and direct memory access
// but require careful handling. Use high-level types above unless you need specific
// performance characteristics or are implementing low-level tools.

/// Assembly and module raw table types.
///
/// Direct access to assembly and module table rows with minimal overhead.
/// Use for performance-critical scenarios or when implementing metadata parsers.
pub use crate::metadata::tables::{
    AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw, AssemblyRefProcessorRaw,
    AssemblyRefRaw, ModuleRaw, ModuleRefRaw,
};

/// Type definition raw table types.
///
/// Raw access to type definition and reference tables for direct metadata manipulation.
pub use crate::metadata::tables::{ExportedTypeRaw, TypeDefRaw, TypeRefRaw, TypeSpecRaw};

/// Field and method raw table types.
///
/// Direct access to field and method metadata without high-level wrapper overhead.
pub use crate::metadata::tables::{
    FieldLayoutRaw, FieldPtrRaw, FieldRaw, FieldRvaRaw, MethodDefRaw, MethodPtrRaw, ParamPtrRaw,
    ParamRaw,
};

/// Core metadata raw table types.
///
/// Raw access to all fundamental metadata tables. These provide the most direct
/// interface to the underlying metadata structure with minimal processing overhead.
pub use crate::metadata::tables::{
    ClassLayoutRaw, ConstantRaw, CustomAttributeRaw, DeclSecurityRaw, EventMapRaw, EventPtrRaw,
    EventRaw, FieldMarshalRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw,
    InterfaceImplRaw, ManifestResourceRaw, MemberRefRaw, MethodImplRaw, MethodSemanticsRaw,
    MethodSpecRaw, NestedClassRaw, PropertyMapRaw, PropertyPtrRaw, PropertyRaw, StandAloneSigRaw,
};

/// File system raw table types.
///
/// Raw access to file reference metadata for multi-file assembly analysis.
pub use crate::metadata::tables::FileRaw;

// ================================================================================================
// Signatures and Type Information
// ================================================================================================
//
// This section provides comprehensive signature parsing and type information handling.
// Signatures are encoded type descriptions used throughout .NET metadata for methods,
// fields, properties, and local variables. These types handle the complex parsing and
// representation of .NET type signatures.

/// Core signature types.
///
/// Comprehensive set of signature structures for representing method signatures,
/// field types, local variables, and complex type constructs like arrays and pointers.
pub use crate::metadata::signatures::{
    SignatureArray, SignatureField, SignatureLocalVariable, SignatureLocalVariables,
    SignatureMethod, SignatureMethodSpec, SignatureParameter, SignaturePointer, SignatureProperty,
    SignatureSzArray, SignatureTypeSpec, TypeSignature,
};

/// Signature parsing functions.
///
/// High-level parsing functions for converting binary signature data into structured
/// type information. These functions handle the complex binary encoding used in .NET metadata.
pub use crate::metadata::signatures::{
    parse_field_signature, parse_local_var_signature, parse_method_signature,
    parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
};

/// Additional signature support types.
///
/// Specialized signature types for member references and complex signature scenarios.
pub use crate::metadata::tables::MemberRefSignature;

// ================================================================================================
// Method Analysis
// ================================================================================================
//
// This section provides comprehensive method analysis capabilities including method body
// parsing, exception handler analysis, and instruction-level access. These types enable
// deep analysis of method implementations and control flow.

/// Method body and IL analysis.
///
/// Complete method analysis including method bodies, exception handlers, implementation
/// attributes, and instruction-level access for CIL analysis and manipulation.
pub use crate::metadata::method::{
    ExceptionHandler, ExceptionHandlerFlags, InstructionIterator, Method, MethodBody,
    MethodImplCodeType, MethodImplManagement, MethodImplOptions, MethodList, MethodMap,
    MethodModifiers, MethodRc, MethodRef, MethodRefList,
};

// ================================================================================================
// Assembly - CIL Instruction Processing
// ================================================================================================
//
// This section provides CIL (Common Intermediate Language) instruction processing capabilities.
// The assembly module can parse method bodies into individual instructions, analyze control
// flow, and provide detailed instruction-level analysis for reverse engineering and
// program analysis scenarios, as well as assemble instructions back into bytecode.

/// CIL instruction analysis, disassembly, and assembly.
///
/// Complete toolkit for CIL instruction processing, including disassembly of bytecode into
/// structured representations, control flow analysis, and assembly of instructions back to bytecode.
/// The assembly system provides both high-level fluent APIs and low-level encoding capabilities.
pub use crate::assembly::{
    decode_blocks, decode_instruction, decode_stream, BasicBlock, FlowType, Immediate, Instruction,
    InstructionAssembler, InstructionCategory, InstructionEncoder, LabelFixup, Operand,
    OperandType, StackBehavior,
};

// ================================================================================================
// Import/Export Analysis
// ================================================================================================
//
// This section provides analysis of assembly dependencies through both managed (.NET) and
// native PE import/export tables. These types enable understanding of inter-assembly
// relationships, dependency analysis, assembly composition patterns, and native DLL dependencies.
//
// The unified containers provide a single interface for both CIL and native imports/exports,
// while individual containers allow focused analysis of specific import/export types.

/// Import and export analysis.
///
/// Tools for analyzing assembly dependencies, exported types, and import relationships
/// essential for understanding assembly composition and dependency graphs. Includes both
/// managed (.NET) imports/exports and native PE import/export table support.
pub use crate::metadata::{
    exports::{
        ExportEntry, ExportFunction, ExportSource, ExportTarget, ExportedFunction, Exports,
        NativeExportRef, NativeExports, UnifiedExportContainer,
    },
    imports::{
        DllDependency, DllSource, Import, ImportContainer, ImportEntry, ImportRc, Imports,
        NativeImportRef, NativeImports, UnifiedImportContainer,
    },
};

// ================================================================================================
// Metadata Streams - Heaps and Headers
// ================================================================================================
//
// This section provides access to the fundamental storage structures of .NET metadata.
// Metadata is organized into heaps (string, blob, GUID, user string) and tables, with
// headers describing the layout and organization. These types provide both direct access
// and efficient iteration over metadata structures.

/// Metadata heap access.
///
/// Direct access to the four metadata heaps containing strings, binary data, GUIDs,
/// and user strings. These heaps store the actual data referenced by metadata tables.
pub use crate::metadata::streams::{Blob, Guid, Strings, UserStrings};

/// Metadata heap iterators for efficient sequential traversal.
///
/// Performance-optimized iterators for sequential access to heap contents when
/// processing large amounts of metadata or performing bulk analysis operations.
pub use crate::metadata::streams::{
    BlobIterator, GuidIterator, StringsIterator, UserStringsIterator,
};

/// Metadata tables and stream headers.
///
/// Header structures that describe the organization and layout of metadata streams
/// and tables, essential for understanding metadata structure and navigation.
pub use crate::metadata::streams::{StreamHeader, TablesHeader};

/// Main headers.
///
/// Primary assembly headers including CLR header and metadata root structures.
pub use crate::metadata::{cor20header::Cor20Header, root::Root};

// ================================================================================================
// Attributes and Flags
// ================================================================================================
//
// This section provides attribute flag enumerations used throughout .NET metadata.
// These flags control visibility, behavior, and characteristics of types, methods,
// fields, and other metadata elements according to ECMA-335 specifications.

/// Common attribute flags for metadata tables.
///
/// Comprehensive set of attribute enumerations for controlling type, method, field,
/// parameter, property, event, and file characteristics as defined by ECMA-335.
pub use crate::metadata::tables::{
    EventAttributes, FieldAttributes, FileAttributes, ParamAttributes, PropertyAttributes,
    TypeAttributes,
};

/// Method and implementation flag constants.
///
/// Specialized flag enumerations for method definitions including access modifiers
/// used with MethodDefBuilder. Other method flags are exported in the method section.
pub use crate::metadata::method::MethodAccessFlags;

// ================================================================================================
// Constants and Element Types
// ================================================================================================
//
// This section provides fundamental constants used throughout the .NET type system
// and marshalling infrastructure. These constants define element types, native types,
// and variant types as specified in ECMA-335 and Win32 marshalling specifications.

/// Element type constants for type system.
///
/// ECMA-335 element type constants used in signatures and type encoding throughout
/// the .NET metadata system for identifying primitive and complex types.
pub use crate::metadata::typesystem::ELEMENT_TYPE;

/// Native type constants for marshalling.
///
/// Win32 native type and variant type constants used in P/Invoke marshalling
/// and COM interop scenarios for type conversion and memory layout.
pub use crate::metadata::marshalling::{NATIVE_TYPE, VARIANT_TYPE};

// ================================================================================================
// Table Identifiers and Utilities
// ================================================================================================
//
// This section provides metadata table identification and utility types for working
// with the underlying table structure. These types enable table enumeration, coded
// index resolution, and direct table manipulation for advanced metadata operations.

/// Metadata table identifiers.
///
/// Enumeration of all ECMA-335 metadata table types for table identification
/// and navigation throughout the metadata system.
pub use crate::metadata::tables::TableId;

/// Coded index types for metadata table relationships.
///
/// Coded index mechanisms for efficient cross-table references as defined by ECMA-335,
/// enabling compact encoding of table relationships and metadata navigation.
pub use crate::metadata::tables::{
    CodedIndex, CodedIndexType, MetadataTable, TableInfo, TableInfoRef,
};

// ================================================================================================
// Metadata Builders
// ================================================================================================
//
// This section provides metadata builder types for creating and modifying .NET assemblies.
// These builders use a fluent API pattern where the BuilderContext is passed to the build()
// method, enabling ergonomic creation of multiple metadata entries in sequence.
//
// All builders follow the established pattern:
// - Builder structs do NOT hold references to BuilderContext
// - Context is passed as a parameter to the build() method
// - All builders implement Default trait for clippy compliance
// - Multiple builders can be used in sequence without borrow checker issues

/// Core builder infrastructure.
///
/// BuilderContext coordinates metadata creation across all builders, managing heap operations,
/// table modifications, and cross-reference resolution. CilAssembly provides the mutable assembly
/// interface required for metadata modification operations. ReferenceHandlingStrategy controls
/// how references are handled when removing heap entries or table rows.
pub use crate::{BuilderContext, CilAssembly, ReferenceHandlingStrategy};

/// Assembly validation pipeline components.
///
/// Conflict resolvers handle operation conflicts with different strategies (last-write-wins, etc.).
/// For validation, use the unified ValidationEngine from the metadata::validation module.
pub use crate::LastWriteWinsResolver;

/// Assembly and module builders.
///
/// Create assembly metadata, module definitions, and assembly identity information.
/// AssemblyBuilder handles version numbers, culture settings, and strong naming.
pub use crate::metadata::tables::AssemblyBuilder;

/// Type system builders.
///
/// Create type definitions, type references, and type specifications. These builders
/// handle class, interface, value type, and enum creation with proper inheritance
/// relationships and generic type parameters.
pub use crate::metadata::tables::{TypeDefBuilder, TypeRefBuilder, TypeSpecBuilder};

/// Member definition builders.
///
/// Create field definitions, method definitions, parameter definitions, property
/// definitions, event definitions, and custom attribute annotations with proper
/// signatures, attributes, and implementation details. These builders handle all
/// aspects of type member creation including accessibility, static/instance behavior,
/// method implementation, parameter information, property encapsulation, event
/// notification mechanisms, and declarative metadata annotations.
pub use crate::metadata::tables::{
    AssemblyRefBuilder, ClassLayoutBuilder, ConstantBuilder, CustomAttributeBuilder,
    DeclSecurityBuilder, DocumentBuilder, EventBuilder, EventMapBuilder, ExportedTypeBuilder,
    FieldBuilder, FieldLayoutBuilder, FieldMarshalBuilder, FieldRVABuilder, FileBuilder,
    GenericParamBuilder, GenericParamConstraintBuilder, ImplMapBuilder, InterfaceImplBuilder,
    LocalScopeBuilder, LocalVariableBuilder, ManifestResourceBuilder, MemberRefBuilder,
    MethodDebugInformationBuilder, MethodDefBuilder, MethodImplBuilder, MethodSemanticsBuilder,
    MethodSpecBuilder, ModuleBuilder, ModuleRefBuilder, NestedClassBuilder, ParamBuilder,
    PropertyBuilder, PropertyMapBuilder, StandAloneSigBuilder,
};

/// High-level builders for .NET constructs.
///
/// Create complete class, interface, property, event, and method definitions with implementations, signatures, local variables,
/// exception handlers, and parameter tables. These builders compose the low-level metadata
/// builders to provide convenient APIs for creating complete .NET types, interfaces, properties, events, and methods with full
/// implementation details.
pub use crate::cilassembly::{
    ClassBuilder, EnumBuilder, EventBuilder as CilEventBuilder, InterfaceBuilder,
    MethodBodyBuilder, MethodBuilder, PropertyBuilder as CilPropertyBuilder,
};

/// Native PE import and export builders.
///
/// Create native PE import and export tables that integrate with the dotscope builder pattern.
/// These builders handle native DLL dependencies, function imports by name and ordinal,
/// export functions, and export forwarders for mixed-mode assemblies and PE files.
pub use crate::metadata::{exports::NativeExportsBuilder, imports::NativeImportsBuilder};

/// Method semantic relationship constants.
///
/// Constants defining the semantic roles methods can play in relation to properties
/// and events. Used with MethodSemanticsBuilder to specify getter, setter, add, remove,
/// fire, and other semantic relationships.
pub use crate::metadata::tables::MethodSemanticsAttributes;

// ================================================================================================
// PE File Structures
// ================================================================================================
//
// Complete set of owned PE (Portable Executable) file structures for direct manipulation
// and analysis of Windows executables and .NET assemblies. These structures provide owned
// representations that don't borrow from the underlying file data, enabling flexible
// analysis and modification workflows.

/// Complete PE file representation and core structures.
///
/// Owned PE file structures including headers, sections, and import/export tables.
/// These provide direct access to PE file components without borrowing from source data.
pub use crate::file::pe::{
    CoffHeader, DataDirectories, DataDirectory, DataDirectoryType, DosHeader, Export as PeExport,
    Import as PeImport, OptionalHeader, Pe, SectionTable, StandardFields, WindowsFields,
};
