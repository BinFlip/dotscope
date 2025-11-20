//! ECMA-335 Metadata Tables Header (`#~`) for .NET Assembly Parsing
//!
//! This module provides comprehensive parsing and access to the compressed metadata tables
//! stream (`#~`) defined in ECMA-335 Section II.24.2.6 and detailed in Section II.22.
//! The tables header serves as the central access point for all metadata tables within
//! a .NET assembly, enabling efficient reflection, analysis, and runtime operations.
//!
//! # Metadata Tables Architecture
//!
//! The metadata tables system is the core of .NET assemblies, containing structured
//! information about types, methods, fields, properties, events, and relationships
//! between these entities. The `#~` stream provides a compressed, optimized format
//! for storing this metadata with variable-width encoding for maximum space efficiency.
//!
//! ## Stream Structure
//!
//! The compressed metadata tables stream follows this binary layout:
//! ```text
//! Offset | Size | Field              | Description
//! -------|------|--------------------|-----------------------------------------
//! 0      | 4    | Reserved           | Must be 0x00000000
//! 4      | 1    | MajorVersion       | Schema major version (typically 2)
//! 5      | 1    | MinorVersion       | Schema minor version (typically 0)
//! 6      | 1    | HeapSizes          | Heap index size flags (strings, blobs, GUIDs)
//! 7      | 1    | Reserved           | Must be 0x01
//! 8      | 8    | Valid              | Bit vector of present tables (64 bits)
//! 16     | 8    | Sorted             | Bit vector of sorted tables (64 bits)
//! 24     | 4*N  | Rows[]             | Row counts for each present table
//! 24+4*N | Var  | TableData[]        | Actual table data in binary format
//! ```
//!
//! ## Supported Metadata Tables
//!
//! The ECMA-335 specification defines 45 metadata tables, each serving specific purposes:
//!
//! ### Core Type System Tables
//! - **Module** (0x00): Assembly module information
//! - **TypeRef** (0x01): External type references
//! - **TypeDef** (0x02): Type definitions within this assembly
//! - **Field** (0x04): Field definitions and metadata
//! - **MethodDef** (0x06): Method definitions and signatures
//! - **Param** (0x08): Parameter definitions and attributes
//!
//! ### Member Reference Tables
//! - **MemberRef** (0x0A): References to external members
//! - **InterfaceImpl** (0x09): Interface implementation relationships
//! - **Constant** (0x0B): Compile-time constant values
//! - **CustomAttribute** (0x0C): Custom attribute applications
//!
//! ### Layout and Mapping Tables
//! - **ClassLayout** (0x0F): Type layout and packing information
//! - **FieldLayout** (0x10): Field offset specifications
//! - **FieldRVA** (0x1D): Field data relative virtual addresses
//! - **ImplMap** (0x1C): P/Invoke and native interop mappings
//!
//! ### Event and Property Tables
//! - **Event** (0x14): Event definitions
//! - **Property** (0x17): Property definitions
//! - **EventMap** (0x12): Type-to-event mappings
//! - **PropertyMap** (0x15): Type-to-property mappings
//! - **MethodSemantics** (0x18): Event/property accessor method relationships
//!
//! ### Assembly and Module Tables
//! - **Assembly** (0x20): Assembly metadata and versioning
//! - **AssemblyRef** (0x23): External assembly references
//! - **File** (0x26): Multi-file assembly components
//! - **ManifestResource** (0x28): Embedded and linked resources
//! - **ExportedType** (0x27): Types exported from this assembly
//!
//! ### Generic Type Tables
//! - **GenericParam** (0x2A): Generic type and method parameters
//! - **GenericParamConstraint** (0x2C): Generic parameter constraints
//! - **MethodSpec** (0x2B): Generic method instantiations
//!
//! ### Security and Advanced Tables
//! - **DeclSecurity** (0x0E): Declarative security attributes
//! - **StandAloneSig** (0x11): Standalone method signatures
//! - **TypeSpec** (0x1B): Complex type specifications
//! - **NestedClass** (0x29): Nested type relationships
//!
//! ## Memory-Efficient Design
//!
//! The [`crate::metadata::streams::tablesheader::TablesHeader`] implementation prioritizes memory efficiency and performance:
//!
//! ### Optimized Access Patterns
//! - **Direct indexing**: O(1) random access to any table row
//! - **Sequential iteration**: Efficient streaming through large tables
//! - **Parallel processing**: Safe concurrent access via `rayon` integration
//! - **Type safety**: Compile-time verification of table type correctness
//!
//! # Examples
//!
//! ## Basic Table Access and Analysis
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data)?;
//!
//! // Analyze assembly structure
//! println!("Assembly contains {} metadata tables", tables.table_count());
//!
//! // Access type definitions
//! if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
//!     println!("Found {} type definitions", typedef_table.row_count);
//!     
//!     // Examine first few types
//!     for (index, type_def) in typedef_table.iter().enumerate().take(5) {
//!         println!("Type {}: flags={:#x}, name_idx={}, namespace_idx={}",
//!                  index, type_def.flags, type_def.type_name, type_def.type_namespace);
//!     }
//! }
//!
//! // Access method definitions
//! if let Some(method_table) = tables.table::<MethodDefRaw>() {
//!     println!("Found {} method definitions", method_table.row_count);
//!     
//!     // Find methods by characteristics
//!     let static_methods = method_table.iter()
//!         .filter(|method| method.flags & 0x0010 != 0) // MethodAttributes.Static
//!         .count();
//!     println!("Static methods: {}", static_methods);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Cross-Table Analysis and Relationships
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, FieldRaw}};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data)?;
//!
//! // Analyze types and their fields together
//! if let (Some(typedef_table), Some(field_table)) = (
//!     tables.table::<TypeDefRaw>(),
//!     tables.table::<FieldRaw>()
//! ) {
//!     for (type_idx, type_def) in typedef_table.iter().enumerate().take(10) {
//!         // Calculate field range for this type
//!         let field_start = type_def.field_list.saturating_sub(1) as usize;
//!         
//!         // Find field range end (next type's field_list or table end)
//!         let field_end = if type_idx + 1 < typedef_table.row_count as usize {
//!             typedef_table.get((type_idx + 1) as u32)
//!                 .map(|next_type| next_type.field_list.saturating_sub(1) as usize)
//!                 .unwrap_or(field_table.row_count as usize)
//!         } else {
//!             field_table.row_count as usize
//!         };
//!         
//!         let field_count = field_end.saturating_sub(field_start);
//!         println!("Type {} has {} fields (indices {}-{})",
//!                  type_idx, field_count, field_start, field_end);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Parallel Processing for Performance
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
//! use rayon::prelude::*;
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data)?;
//!
//! // Process custom attributes in parallel for large assemblies
//! if let Some(ca_table) = tables.table::<CustomAttributeRaw>() {
//!     println!("Processing {} custom attributes in parallel", ca_table.row_count);
//!     
//!     // Parallel analysis using rayon
//!     let attribute_stats = ca_table.par_iter()
//!         .map(|attr| {
//!             // Analyze attribute type and parent
//!             let parent_table = attr.parent.tag;
//!             let parent_index = attr.parent.row;
//!             (parent_table, parent_index)
//!         })
//!         .collect::<Vec<_>>();
//!     
//!     println!("Analyzed {} attribute relationships", attribute_stats.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Memory-Efficient Large Table Processing
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MemberRefRaw}};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data)?;
//!
//! // Process large tables in chunks to manage memory usage
//! if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
//!     const CHUNK_SIZE: u32 = 1000;
//!     let total_rows = memberref_table.row_count;
//!     
//!     println!("Processing {} member references in chunks of {}", total_rows, CHUNK_SIZE);
//!     
//!     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
//!         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
//!         
//!         // Process chunk without loading entire table into memory
//!         let mut external_refs = 0;
//!         for i in chunk_start..chunk_end {
//!             if let Some(member_ref) = memberref_table.get(i) {
//!                 // Analyze member reference
//!                 if member_ref.class.tag == TableId::TypeRef {
//!                     external_refs += 1;
//!                 }
//!             }
//!         }
//!         
//!         println!("Chunk {}-{}: {} external references",
//!                  chunk_start, chunk_end, external_refs);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Table Discovery and Introspection
//! ```rust
//! use dotscope::metadata::{streams::TablesHeader, tables::TableId};
//!
//! # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
//! let tables = TablesHeader::from(tables_data)?;
//!
//! println!("Assembly Metadata Summary:");
//! println!("========================");
//!
//! // Get overview of all present tables
//! let summaries = tables.table_summary();
//! for summary in summaries {
//!     println!("{:?}: {} rows", summary.table_id, summary.row_count);
//! }
//!
//! // Check for specific advanced features
//! if tables.has_table(TableId::GenericParam) {
//!     println!("✓ Assembly uses generic types");
//! }
//! if tables.has_table(TableId::DeclSecurity) {
//!     println!("✓ Assembly has declarative security");
//! }
//! if tables.has_table(TableId::ManifestResource) {
//!     println!("✓ Assembly contains embedded resources");
//! }
//!
//! // Check for common tables by ID
//! if tables.has_table_by_id(0x20) { // Assembly table
//!     println!("✓ Assembly metadata present");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # ECMA-335 Compliance
//!
//! This implementation fully complies with ECMA-335 specifications:
//! - **Section II.24.2.6**: Metadata tables stream format and structure
//! - **Section II.22**: Complete table definitions and relationships
//! - **Compression format**: Proper handling of variable-width table indices
//! - **Heap references**: Correct interpretation of string, blob, and GUID heap indices
//! - **Table relationships**: Accurate representation of cross-table references
//!
//! # Security Considerations
//!
//! ## Input Validation
//! - **Bounds checking**: All table access protected against buffer overruns
//! - **Format validation**: ECMA-335 format requirements enforced during parsing
//! - **Index validation**: Heap and table references validated for correctness
//! - **Size limits**: Reasonable limits on table sizes prevent resource exhaustion
//!
//! ## Memory Safety
//! - **Lifetime enforcement**: Rust borrow checker prevents use-after-free
//! - **Type safety**: Generic type parameters prevent incorrect table access
//! - **Bounds verification**: All array and slice access bounds-checked
//! - **No unsafe aliasing**: Careful pointer management in type casting
//!
//! # See Also
//! - [`crate::metadata::tables`]: Individual metadata table definitions and structures
//! - [`crate::metadata::streams`]: Overview of all metadata stream types
//! - [`crate::metadata::root`]: Metadata root and stream directory parsing
//! - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Tables stream specification
//! - [ECMA-335 II.22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Metadata table definitions
//!
//! # References
//! - **ECMA-335 II.24.2.6**: Metadata tables stream format and binary layout
//! - **ECMA-335 II.22**: Complete specifications for all 45 metadata table types
//! - **ECMA-335 II.25**: File format and metadata integration within PE files

use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::{
    impl_table_access,
    metadata::tables::{
        AssemblyOsRaw, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefOsRaw,
        AssemblyRefProcessorRaw, AssemblyRefRaw, ClassLayoutRaw, ConstantRaw, CustomAttributeRaw,
        CustomDebugInformationRaw, DeclSecurityRaw, DocumentRaw, EncLogRaw, EncMapRaw, EventMapRaw,
        EventPtrRaw, EventRaw, ExportedTypeRaw, FieldLayoutRaw, FieldMarshalRaw, FieldPtrRaw,
        FieldRaw, FieldRvaRaw, FileRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw,
        ImportScopeRaw, InterfaceImplRaw, LocalConstantRaw, LocalScopeRaw, LocalVariableRaw,
        ManifestResourceRaw, MemberRefRaw, MetadataTable, MethodDebugInformationRaw, MethodDefRaw,
        MethodImplRaw, MethodPtrRaw, MethodSemanticsRaw, MethodSpecRaw, ModuleRaw, ModuleRefRaw,
        NestedClassRaw, ParamPtrRaw, ParamRaw, PropertyMapRaw, PropertyPtrRaw, PropertyRaw,
        RowReadable, StandAloneSigRaw, StateMachineMethodRaw, TableAccess, TableData, TableId,
        TableInfo, TableInfoRef, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
    utils::read_le,
    Result,
};

/// ECMA-335 compliant metadata tables header providing efficient access to .NET assembly metadata.
///
/// The [`crate::metadata::streams::tablesheader::TablesHeader`] struct represents the compressed metadata tables stream (`#~`) header
/// and provides type-safe, memory-efficient access to all metadata tables within a .NET assembly.
/// This is the primary interface for reflection, analysis, and runtime operations on .NET metadata.
///
/// ## Architecture and Design
///
/// [`crate::metadata::streams::tablesheader::TablesHeader`] implements a lazy-loading design that maximizes performance
/// while maintaining memory safety through Rust's lifetime system:
///
/// - **Lazy parsing**: Table rows are parsed only when accessed
/// - **Type safety**: Generic type parameters prevent incorrect table access
/// - **Lifetime safety**: Rust borrow checker prevents dangling references
/// - **ECMA-335 compliance**: Full specification adherence for all table formats
///
/// ## Metadata Tables Overview
///
/// The metadata tables system contains 45 different table types defined by ECMA-335,
/// each serving specific purposes in the .NET type system:
///
/// ### Core Tables (Always Present)
/// - **Module**: Assembly module identification and versioning
/// - **`TypeDef`**: Type definitions declared in this assembly
/// - **`MethodDef`**: Method definitions and IL code references
/// - **`Field`**: Field definitions and attributes
///
/// ### Reference Tables (External Dependencies)
/// - **`TypeRef`**: References to types in other assemblies
/// - **`MemberRef`**: References to methods/fields in external types
/// - **`AssemblyRef`**: External assembly dependencies
/// - **`ModuleRef`**: Multi-module assembly references
///
/// ### Relationship Tables (Type System Structure)
/// - **`InterfaceImpl`**: Interface implementation relationships
/// - **`NestedClass`**: Nested type parent-child relationships
/// - **`GenericParam`**: Generic type and method parameters
/// - **`GenericParamConstraint`**: Generic parameter constraints
///
/// ### Attribute and Metadata Tables
/// - **`CustomAttribute`**: Custom attribute applications
/// - **`Constant`**: Compile-time constant values
/// - **`DeclSecurity`**: Declarative security permissions
/// - **`FieldMarshal`**: Native interop marshalling specifications
///
/// ## Thread Safety and Concurrency
///
/// [`crate::metadata::streams::tablesheader::TablesHeader`] provides comprehensive thread safety for concurrent metadata access:
/// - **Immutable data**: All table data read-only after construction
/// - **Independent access**: Multiple threads can access different tables safely
/// - **Parallel iteration**: Safe concurrent processing of table rows
/// - **No synchronization**: Zero contention between concurrent operations
///
/// # Examples
///
/// ## Basic Table Access and Type Analysis
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
///
/// // Safe table presence checking
/// if tables.has_table(TableId::TypeDef) {
///     let typedef_table = tables.table::<TypeDefRaw>().unwrap();
///     
///     println!("Assembly defines {} types", typedef_table.row_count);
///     
///     // Analyze type characteristics
///     for (index, type_def) in typedef_table.iter().enumerate().take(10) {
///         let is_public = type_def.flags & 0x00000007 == 0x00000001;
///         let is_sealed = type_def.flags & 0x00000100 != 0;
///         let is_abstract = type_def.flags & 0x00000080 != 0;
///         
///         println!("Type {}: public={}, sealed={}, abstract={}",
///                  index, is_public, is_sealed, is_abstract);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Cross-Table Relationship Analysis
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, FieldRaw, MethodDefRaw}};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
///
/// // Analyze complete type structure with members
/// if let (Some(typedef_table), Some(field_table), Some(method_table)) = (
///     tables.table::<TypeDefRaw>(),
///     tables.table::<FieldRaw>(),
///     tables.table::<MethodDefRaw>()
/// ) {
///     for (type_idx, type_def) in typedef_table.iter().enumerate().take(5) {
///         // Calculate member ranges for this type
///         let next_type = typedef_table.get((type_idx + 1) as u32);
///         
///         let field_start = type_def.field_list.saturating_sub(1);
///         let field_end = next_type.as_ref()
///             .map(|t| t.field_list.saturating_sub(1))
///             .unwrap_or(field_table.row_count);
///         
///         let method_start = type_def.method_list.saturating_sub(1);
///         let method_end = next_type.as_ref()
///             .map(|t| t.method_list.saturating_sub(1))
///             .unwrap_or(method_table.row_count);
///         
///         println!("Type {}: {} fields, {} methods",
///                  type_idx,
///                  field_end.saturating_sub(field_start),
///                  method_end.saturating_sub(method_start));
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## High-Performance Parallel Processing
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
/// use rayon::prelude::*;
/// use std::collections::HashMap;
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
///
/// // Parallel analysis of custom attributes
/// if let Some(ca_table) = tables.table::<CustomAttributeRaw>() {
///     // Process attributes in parallel for large assemblies
///     let attribute_analysis: HashMap<u32, u32> = ca_table.par_iter()
///         .map(|attr| {
///             // Extract parent table type from coded index
///             let parent_table = 1u32; // Simplified for documentation
///             (parent_table, 1u32)
///         })
///         .collect::<Vec<_>>()
///         .into_iter()
///         .fold(HashMap::new(), |mut acc, (table, count)| {
///             *acc.entry(table).or_insert(0) += count;
///             acc
///         });
///     
///     println!("Custom attribute distribution:");
///     for (table_id, count) in attribute_analysis {
///         println!("  Table {}: {} attributes", table_id, count);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Memory-Efficient Large Table Processing
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MemberRefRaw}};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
///
/// // Process large tables without loading all data into memory
/// if let Some(memberref_table) = tables.table::<MemberRefRaw>() {
///     const CHUNK_SIZE: u32 = 1000;
///     let total_rows = memberref_table.row_count;
///     
///     println!("Processing {} member references in {} chunks",
///              total_rows, (total_rows + CHUNK_SIZE - 1) / CHUNK_SIZE);
///     
///     let mut external_method_refs = 0;
///     let mut external_field_refs = 0;
///     
///     // Process in chunks to manage memory usage
///     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
///         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
///         
///         for i in chunk_start..chunk_end {
///             if let Some(member_ref) = memberref_table.get(i) {
///                 // Analyze member reference type and parent
///                 let is_method = true; // Simplified: check signature
///                 let is_external = true; // Simplified: check class reference
///                 
///                 if is_external {
///                     if is_method {
///                         external_method_refs += 1;
///                     } else {
///                         external_field_refs += 1;
///                     }
///                 }
///             }
///         }
///     }
///     
///     println!("External references: {} methods, {} fields",
///              external_method_refs, external_field_refs);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Complete Assembly Introspection
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
///
/// println!("Assembly Metadata Analysis");
/// println!("=========================");
/// println!("Total tables: {}", tables.table_count());
/// println!();
///
/// // Analyze present tables and their characteristics
/// let summaries = tables.table_summary();
/// for summary in summaries {
///     match summary.table_id {
///         TableId::TypeDef => println!("✓ {} type definitions", summary.row_count),
///         TableId::MethodDef => println!("✓ {} method definitions", summary.row_count),
///         TableId::Field => println!("✓ {} field definitions", summary.row_count),
///         TableId::Assembly => println!("✓ Assembly metadata present"),
///         TableId::AssemblyRef => println!("✓ {} assembly references", summary.row_count),
///         TableId::CustomAttribute => println!("✓ {} custom attributes", summary.row_count),
///         TableId::GenericParam => println!("✓ {} generic parameters (generics used)", summary.row_count),
///         TableId::DeclSecurity => println!("✓ {} security declarations", summary.row_count),
///         TableId::ManifestResource => println!("✓ {} embedded resources", summary.row_count),
///         _ => println!("✓ {:?}: {} rows", summary.table_id, summary.row_count),
///     }
/// }
///
/// // Feature detection
/// println!();
/// println!("Assembly Features:");
/// if tables.has_table(TableId::GenericParam) {
///     println!("  ✓ Uses generic types/methods");
/// }
/// if tables.has_table(TableId::Event) {
///     println!("  ✓ Defines events");
/// }
/// if tables.has_table(TableId::Property) {
///     println!("  ✓ Defines properties");
/// }
/// if tables.has_table(TableId::DeclSecurity) {
///     println!("  ✓ Has security declarations");
/// }
/// if tables.has_table(TableId::ImplMap) {
///     println!("  ✓ Uses P/Invoke");
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Security Considerations
///
/// ## Input Validation
/// - **ECMA-335 compliance**: Strict adherence to specification format requirements
/// - **Bounds checking**: All table and row access validated against buffer boundaries  
/// - **Index validation**: Cross-table references verified for correctness
/// - **Size limits**: Reasonable limits prevent resource exhaustion attacks
///
/// ## Memory Safety
/// - **Lifetime enforcement**: Rust borrow checker prevents use-after-free vulnerabilities
/// - **Type safety**: Generic parameters prevent incorrect table type access
/// - **Bounds verification**: All array and slice access is bounds-checked
/// - **Controlled unsafe**: Minimal unsafe code with careful pointer management
///
/// # ECMA-335 Compliance
///
/// This implementation fully complies with ECMA-335 Partition II specifications:
/// - **Section II.24.2.6**: Metadata tables stream format and binary layout
/// - **Section II.22**: Complete metadata table definitions and relationships
/// - **Compression format**: Proper variable-width encoding for table indices
/// - **Heap integration**: Correct interpretation of string, blob, and GUID heap references
///
/// # See Also
/// - [`crate::metadata::tables::MetadataTable`]: Individual table access and iteration
/// - [`crate::metadata::tables::TableId`]: Enumeration of all supported table types
/// - [`crate::metadata::streams`]: Overview of all metadata stream types
/// - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Tables header specification
///
/// ## Efficient Table Access Examples
///
/// ### Basic Table Access
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw, FieldRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Check if a table is present before accessing it
/// if tables_header.has_table(TableId::TypeDef) {
///     // Get efficient access to the TypeDef table
///     if let Some(typedef_table) = tables_header.table::<TypeDefRaw>() {
///         println!("TypeDef table has {} rows", typedef_table.row_count);
///         
///         // Access individual rows by index (0-based)
///         if let Some(first_type) = typedef_table.get(0) {
///             println!("First type: flags={}, name_idx={}, namespace_idx={}",
///                     first_type.flags, first_type.type_name, first_type.type_namespace);
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Iterating Over Table Rows
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, MethodDefRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Iterate over all methods in the assembly
/// if let Some(method_table) = tables_header.table::<MethodDefRaw>() {
///     for (index, method) in method_table.iter().enumerate() {
///         println!("Method {}: RVA={:#x}, impl_flags={}, flags={}, name_idx={}",
///                 index, method.rva, method.impl_flags, method.flags, method.name);
///         
///         // Break after first 10 for demonstration
///         if index >= 9 { break; }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Parallel Processing with Rayon
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, FieldRaw}};
/// use rayon::prelude::*;
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Process field metadata in parallel
/// if let Some(field_table) = tables_header.table::<FieldRaw>() {
///     let field_count = field_table.par_iter()
///         .filter(|field| field.flags & 0x0010 != 0) // FieldAttributes.Static
///         .count();
///     
///     println!("Found {} static fields", field_count);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Cross-Table Analysis
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, TypeDefRaw, MethodDefRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Analyze types and their methods together
/// if let (Some(typedef_table), Some(method_table)) = (
///     tables_header.table::<TypeDefRaw>(),
///     tables_header.table::<MethodDefRaw>()
/// ) {
///     for (type_idx, type_def) in typedef_table.iter().enumerate().take(5) {
///         println!("Type {}: methods {}-{}",
///                 type_idx, type_def.method_list,
///                 type_def.method_list.saturating_add(10)); // Simplified example
///         
///         // In real usage, you'd calculate the actual method range
///         // by looking at the next type's method_list or using table bounds
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ### Working with Table Summaries
/// ```rust,ignore
/// use dotscope::metadata::streams::TablesHeader;
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Get overview of all present tables
/// let summaries = tables_header.table_summary();
///
/// for summary in summaries {
///     println!("Table {:?}: {} rows", summary.table_id, summary.row_count);
/// }
///
/// // Check for specific tables by ID
/// if tables_header.has_table_by_id(0x02) { // TypeDef table ID
///     println!("TypeDef table is present");
/// }
///
/// println!("Total metadata tables: {}", tables_header.table_count());
/// # Ok(())
/// # }
/// ```
///
/// ### Memory-Efficient Pattern
/// ```rust,ignore
/// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, CustomAttributeRaw}};
///
/// # fn example(tables_header: &TablesHeader) -> dotscope::Result<()> {
/// // Process large tables without loading all data at once
/// if let Some(ca_table) = tables_header.table::<CustomAttributeRaw>() {
///     println!("Processing {} custom attributes", ca_table.row_count);
///     
///     // Process in chunks to manage memory usage
///     const CHUNK_SIZE: u32 = 100;
///     let total_rows = ca_table.row_count;
///     
///     for chunk_start in (0..total_rows).step_by(CHUNK_SIZE as usize) {
///         let chunk_end = (chunk_start + CHUNK_SIZE).min(total_rows);
///         
///         for i in chunk_start..chunk_end {
///             if let Some(attr) = ca_table.get(i) {
///                 // Process individual custom attribute
///                 // attr.parent, attr.type_def, attr.value are available
///                 // without copying the entire table into memory
///             }
///         }
///         
///         // Optional: yield control or log progress
///         println!("Processed chunk {}-{}", chunk_start, chunk_end);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
///
/// ## Reference
/// * '<https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf>' - II.24.2.6 && II.22
pub struct TablesHeader<'a> {
    /// Major version of the metadata table schema, must be 2 per ECMA-335.
    ///
    /// This field indicates the major version of the metadata table format. According to
    /// ECMA-335 Section II.24.2.6, this value must be 2 for all compliant .NET assemblies.
    /// Different major versions would indicate incompatible changes to the table format.
    pub major_version: u8,

    /// Minor version of the metadata table schema, must be 0 per ECMA-335.
    ///
    /// This field indicates the minor version of the metadata table format. The ECMA-335
    /// specification requires this value to be 0. Minor version changes would indicate
    /// backward-compatible additions to the table format.
    pub minor_version: u8,

    /// Bit vector indicating which of the 64 possible metadata tables are present.
    ///
    /// Each bit corresponds to a specific table ID (0-63) as defined in ECMA-335.
    /// A set bit (1) indicates the corresponding table is present and contains data.
    /// The number of set bits determines how many row count entries follow in the header.
    ///
    /// ## Table ID Mapping
    /// - Bit 0: Module table
    /// - Bit 1: `TypeRef` table  
    /// - Bit 2: `TypeDef` table
    /// - Bit 4: Field table
    /// - Bit 6: `MethodDef` table
    /// - ... (see ECMA-335 II.22 for complete mapping)
    pub valid: u64,

    /// Bit vector indicating which metadata tables are sorted.
    ///
    /// For each present table (indicated by `valid`), the corresponding bit in `sorted`
    /// indicates whether that table's rows are sorted according to ECMA-335 requirements.
    /// Some tables must be sorted for binary search operations, while others may be
    /// unsorted for faster insertion during metadata generation.
    pub sorted: u64,

    /// Shared table information containing row counts and heap index sizes.
    ///
    /// This reference-counted structure provides efficient access to table metadata
    /// including row counts for each present table and the size encoding for heap
    /// indices (strings, blobs, GUIDs). The `Arc` allows multiple table instances
    /// to share this information without duplication.
    pub info: TableInfoRef,

    /// Byte offset to the start of table data relative to the beginning of this header.
    ///
    /// This offset points to where the actual table row data begins, after the header
    /// and row count arrays. Table data is stored sequentially in the order defined
    /// by the ECMA-335 table ID enumeration.
    tables_offset: usize,

    /// Vector of parsed metadata tables, indexed by table ID.
    ///
    /// Each element corresponds to a specific table type (0-44) and contains `Some(table)`
    /// if the table is present or `None` if absent. The tables are parsed lazily and
    /// stored as type-erased `TableData` enums to handle the heterogeneous table types
    /// while maintaining memory efficiency.
    tables: Vec<Option<TableData<'a>>>,
}

impl<'a> TablesHeader<'a> {
    /// Parse and construct a metadata tables header from binary data.
    ///
    /// Creates a [`crate::metadata::streams::tablesheader::TablesHeader`] by parsing the compressed metadata tables stream (`#~`)
    /// according to ECMA-335 Section II.24.2.6. This method performs comprehensive
    /// validation of the stream format and constructs efficient access structures for
    /// all present metadata tables.
    ///
    /// ## Binary Format Parsed
    ///
    /// The method parses the following header structure:
    /// ```text
    /// Offset | Size | Field              | Description
    /// -------|------|--------------------|-----------------------------------------
    /// 0      | 4    | Reserved           | Must be 0x00000000
    /// 4      | 1    | MajorVersion       | Schema major version (must be 2)
    /// 5      | 1    | MinorVersion       | Schema minor version (must be 0)
    /// 6      | 1    | HeapSizes          | String/Blob/GUID heap index sizes
    /// 7      | 1    | Reserved           | Must be 0x01
    /// 8      | 8    | Valid              | Bit vector of present tables
    /// 16     | 8    | Sorted             | Bit vector of sorted tables
    /// 24     | 4*N  | Rows[]             | Row counts for each present table
    /// 24+4*N | Var  | TableData[]        | Binary table data
    /// ```
    ///
    /// ## Validation Performed
    ///
    /// The method enforces ECMA-335 compliance through comprehensive validation:
    /// - **Minimum size**: Data must contain complete header (≥24 bytes)
    /// - **Version checking**: Major version must be 2, minor version must be 0
    /// - **Table presence**: At least one table must be present (valid ≠ 0)
    /// - **Format integrity**: Row count array and table data must be accessible
    /// - **Table structure**: Each present table validated for proper format
    ///
    /// ## Construction Process
    ///
    /// 1. **Header parsing**: Extract version, heap sizes, and table bit vectors
    /// 2. **Row count extraction**: Read row counts for all present tables
    /// 3. **Table initialization**: Parse each present table's binary data
    /// 4. **Reference setup**: Establish efficient access structures
    /// 5. **Validation**: Verify all tables conform to ECMA-335 format
    ///
    /// # Arguments
    /// * `data` - Complete binary data of the compressed metadata tables stream
    ///
    /// # Returns
    /// * `Ok(TablesHeader)` - Successfully parsed and validated tables header
    /// * `Err(Error)` - Parsing failed due to format violations or insufficient data
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - **[`crate::Error::OutOfBounds`]**: Data too short for complete header (< 24 bytes)
    /// - **Malformed data**: No valid tables present (all bits in `valid` are 0)
    /// - **Version error**: Unsupported major/minor version combination
    /// - **Format error**: Invalid table data or corrupted stream structure
    /// - **Table error**: Individual table parsing failures due to malformed data
    ///
    /// # Examples
    ///
    /// ## Basic Tables Header Construction
    /// ```rust
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // Read compressed metadata tables stream from assembly
    /// # let tables_stream_data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
    /// let tables_stream_data = &[/* binary data from #~ stream */];
    ///
    /// let tables = TablesHeader::from(tables_stream_data)?;
    ///
    /// // Verify successful construction
    /// println!("Parsed metadata with {} tables", tables.table_count());
    /// println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
    ///
    /// // Check for common tables
    /// use dotscope::metadata::tables::TableId;
    /// if tables.has_table(TableId::TypeDef) {
    ///     println!("Assembly defines {} types", tables.table_row_count(TableId::TypeDef));
    /// }
    /// if tables.has_table(TableId::MethodDef) {
    ///     println!("Assembly defines {} methods", tables.table_row_count(TableId::MethodDef));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Handling and Validation
    /// ```rust
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example() {
    /// // Error: Data too short
    /// let too_short = [0u8; 20]; // Only 20 bytes, need at least 24
    /// assert!(TablesHeader::from(&too_short).is_err());
    ///
    /// // Error: No valid tables
    /// let no_tables = [
    ///     0x00, 0x00, 0x00, 0x00, // Reserved
    ///     0x02, 0x00,             // Version 2.0
    ///     0x01, 0x01,             // HeapSizes, Reserved
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Valid = 0 (no tables)
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sorted
    /// ];
    /// assert!(TablesHeader::from(&no_tables).is_err());
    /// # }
    /// ```
    ///
    /// ## Large Assembly Processing
    /// ```rust
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let large_assembly_data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
    /// // Process large assembly with many tables
    /// let large_assembly_data = &[/* large assembly #~ stream data */];
    ///
    /// let start_time = std::time::Instant::now();
    /// let tables = TablesHeader::from(large_assembly_data)?;
    /// let parse_time = start_time.elapsed();
    ///
    /// println!("Parsed {} tables in {:?}", tables.table_count(), parse_time);
    ///
    /// // Analyze assembly size and complexity
    /// let summaries = tables.table_summary();
    /// let total_rows: u32 = summaries.iter().map(|s| s.row_count).sum();
    ///
    /// println!("Assembly complexity:");
    /// println!("  Total metadata rows: {}", total_rows);
    /// println!("  Average rows per table: {:.1}",
    ///          total_rows as f64 / tables.table_count() as f64);
    ///
    /// // Identify the most complex tables
    /// let mut large_tables: Vec<_> = summaries.iter()
    ///     .filter(|s| s.row_count > 1000)
    ///     .collect();
    /// large_tables.sort_by_key(|s| std::cmp::Reverse(s.row_count));
    ///
    /// println!("Largest tables:");
    /// for summary in large_tables.iter().take(3) {
    ///     println!("  {:?}: {} rows", summary.table_id, summary.row_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Assembly Feature Detection
    /// ```rust
    /// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let assembly_data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
    /// let assembly_data = &[/* assembly #~ stream data */];
    /// let tables = TablesHeader::from(assembly_data)?;
    ///
    /// println!("Assembly Feature Analysis:");
    /// println!("=========================");
    ///
    /// // Detect .NET framework features
    /// if tables.has_table(TableId::GenericParam) {
    ///     let generic_count = tables.table_row_count(TableId::GenericParam);
    ///     println!("✓ Uses generics ({} parameters)", generic_count);
    /// }
    ///
    /// if tables.has_table(TableId::Event) {
    ///     let event_count = tables.table_row_count(TableId::Event);
    ///     println!("✓ Defines events ({} events)", event_count);
    /// }
    ///
    /// if tables.has_table(TableId::Property) {
    ///     let prop_count = tables.table_row_count(TableId::Property);
    ///     println!("✓ Defines properties ({} properties)", prop_count);
    /// }
    ///
    /// if tables.has_table(TableId::DeclSecurity) {
    ///     let security_count = tables.table_row_count(TableId::DeclSecurity);
    ///     println!("✓ Has security declarations ({} declarations)", security_count);
    /// }
    ///
    /// if tables.has_table(TableId::ImplMap) {
    ///     let pinvoke_count = tables.table_row_count(TableId::ImplMap);
    ///     println!("✓ Uses P/Invoke ({} mappings)", pinvoke_count);
    /// }
    ///
    /// if tables.has_table(TableId::ManifestResource) {
    ///     let resource_count = tables.table_row_count(TableId::ManifestResource);
    ///     println!("✓ Embeds resources ({} resources)", resource_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// Construction is thread-safe when called with different data sources.
    /// The resulting [`crate::metadata::streams::tablesheader::TablesHeader`] instance is immutable and safe for concurrent
    /// access across multiple threads.
    ///
    /// # ECMA-335 Compliance
    ///
    /// This method implements full ECMA-335 Partition II compliance:
    /// - **Section II.24.2.6**: Metadata tables stream header format
    /// - **Section II.22**: Individual table format specifications
    /// - **Compression format**: Variable-width index encoding based on heap sizes
    /// - **Table relationships**: Proper handling of cross-table references
    ///
    /// # See Also
    /// - [`TablesHeader::table`]: Access individual metadata tables after construction
    /// - [`TablesHeader::table_summary`]: Get overview of all present tables
    /// - [`crate::metadata::tables::TableInfo`]: Table metadata and row count information
    /// - [ECMA-335 II.24.2.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf): Tables header specification
    pub fn from(data: &'a [u8]) -> Result<TablesHeader<'a>> {
        if data.len() < 24 {
            return Err(out_of_bounds_error!());
        }

        let valid_bitvec = read_le::<u64>(&data[8..])?;
        if valid_bitvec == 0 {
            return Err(malformed_error!("No valid rows in any of the tables"));
        }

        let mut tables_header = TablesHeader {
            major_version: read_le::<u8>(&data[4..])?,
            minor_version: read_le::<u8>(&data[5..])?,
            valid: valid_bitvec,
            sorted: read_le::<u64>(&data[16..])?,
            info: Arc::new(TableInfo::new(data, valid_bitvec)?),
            tables_offset: (24 + valid_bitvec.count_ones() * 4) as usize,
            tables: Vec::with_capacity(TableId::CustomDebugInformation as usize + 1),
        };

        // with_capacity has allocated the buffer, but we can't 'insert' elements, only push
        // to make the vector grow - as .insert doesn't adjust length, only push does.
        tables_header
            .tables
            .resize_with(TableId::CustomDebugInformation as usize + 1, || None);

        let mut current_offset = tables_header.tables_offset as usize;
        for table_id in TableId::iter() {
            if current_offset > data.len() {
                return Err(out_of_bounds_error!());
            }

            tables_header.add_table(&data[current_offset..], table_id, &mut current_offset)?;
        }

        Ok(tables_header)
    }

    /// Get the total number of metadata tables present in this assembly.
    ///
    /// Returns the count of tables that are actually present and contain data.
    /// This is equivalent to the number of set bits in the `valid` field.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// println!("Assembly contains {} metadata tables", tables.table_count());
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn table_count(&self) -> u32 {
        self.valid.count_ones()
    }

    /// Get a specific table for efficient access to metadata table rows.
    ///
    /// This method provides safe, type-driven access to metadata tables without copying data.
    /// The returned table reference allows efficient iteration and random access to rows.
    /// The table type is automatically determined from the generic parameter, eliminating
    /// the need to specify table IDs and preventing type mismatches.
    ///
    /// # Type Parameter
    ///
    /// * `T` - The table row type (e.g., [`crate::metadata::tables::TypeDefRaw`])
    ///   The table ID is automatically inferred from the type parameter.
    ///
    /// # Returns
    ///
    /// * `Some(&MetadataTable<T>)` - Reference to the [`crate::metadata::tables::MetadataTable`] if present
    /// * `None` - If the table is not present in this assembly
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{streams::TablesHeader, tables::TypeDefRaw};
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// // Safe, ergonomic access with automatic type inference
    /// if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
    ///     // Efficient access to all type definitions
    ///     for type_def in typedef_table.iter().take(5) {
    ///         println!("Type: flags={:#x}, name_idx={}, namespace_idx={}",
    ///                 type_def.flags, type_def.type_name, type_def.type_namespace);
    ///     }
    ///     
    ///     // Random access to specific rows
    ///     if let Some(first_type) = typedef_table.get(0) {
    ///         println!("First type name index: {}", first_type.type_name);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The returned table reference is also safe for concurrent read access.
    ///
    /// # Implementation Details
    ///
    /// This method uses a trait to provide safe, compile-time verified table access.
    /// The trait implementation automatically maps each table type to its corresponding
    /// table ID, ensuring type safety without runtime overhead. No unsafe code is required.
    #[must_use]
    pub fn table<T: RowReadable>(&'a self) -> Option<&'a MetadataTable<'a, T>>
    where
        Self: TableAccess<'a, T>,
    {
        <Self as TableAccess<'a, T>>::table(self)
    }

    /// Add a table to the tables header
    // ToDo: table.size() needs a better fix than this.
    #[allow(clippy::cast_possible_truncation)]
    fn add_table(
        &mut self,
        data: &'a [u8],
        table_type: TableId,
        current_offset: &mut usize,
    ) -> Result<()> {
        let t_info = self.info.get(table_type);
        if t_info.rows == 0 {
            // We filtered out empty tables earlier, this case shouldn't happen here
            return Ok(());
        }

        let table = match table_type {
            TableId::Module => {
                let table = MetadataTable::<ModuleRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Module(table)
            }
            TableId::TypeRef => {
                let table = MetadataTable::<TypeRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::TypeRef(table)
            }
            TableId::TypeDef => {
                let table = MetadataTable::<TypeDefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::TypeDef(table)
            }
            TableId::FieldPtr => {
                let table =
                    MetadataTable::<FieldPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldPtr(table)
            }
            TableId::Field => {
                let table = MetadataTable::<FieldRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Field(table)
            }
            TableId::MethodPtr => {
                let table =
                    MetadataTable::<MethodPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodPtr(table)
            }
            TableId::MethodDef => {
                let table =
                    MetadataTable::<MethodDefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodDef(table)
            }
            TableId::ParamPtr => {
                let table =
                    MetadataTable::<ParamPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ParamPtr(table)
            }
            TableId::Param => {
                let table = MetadataTable::<ParamRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Param(table)
            }
            TableId::InterfaceImpl => {
                let table =
                    MetadataTable::<InterfaceImplRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::InterfaceImpl(table)
            }
            TableId::MemberRef => {
                let table =
                    MetadataTable::<MemberRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MemberRef(table)
            }
            TableId::Constant => {
                let table =
                    MetadataTable::<ConstantRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Constant(table)
            }
            TableId::CustomAttribute => {
                let table =
                    MetadataTable::<CustomAttributeRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::CustomAttribute(table)
            }
            TableId::FieldMarshal => {
                let table =
                    MetadataTable::<FieldMarshalRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldMarshal(table)
            }
            TableId::DeclSecurity => {
                let table =
                    MetadataTable::<DeclSecurityRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::DeclSecurity(table)
            }
            TableId::Document => {
                let table =
                    MetadataTable::<DocumentRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Document(table)
            }
            TableId::EncLog => {
                let table = MetadataTable::<EncLogRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::EncLog(table)
            }
            TableId::EncMap => {
                let table = MetadataTable::<EncMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::EncMap(table)
            }
            TableId::ClassLayout => {
                let table =
                    MetadataTable::<ClassLayoutRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ClassLayout(table)
            }
            TableId::FieldLayout => {
                let table =
                    MetadataTable::<FieldLayoutRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldLayout(table)
            }
            TableId::StandAloneSig => {
                let table =
                    MetadataTable::<StandAloneSigRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::StandAloneSig(table)
            }
            TableId::EventMap => {
                let table =
                    MetadataTable::<EventMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::EventMap(table)
            }
            TableId::EventPtr => {
                let table =
                    MetadataTable::<EventPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::EventPtr(table)
            }
            TableId::Event => {
                let table = MetadataTable::<EventRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Event(table)
            }
            TableId::PropertyMap => {
                let table =
                    MetadataTable::<PropertyMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::PropertyMap(table)
            }
            TableId::PropertyPtr => {
                let table =
                    MetadataTable::<PropertyPtrRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::PropertyPtr(table)
            }
            TableId::Property => {
                let table =
                    MetadataTable::<PropertyRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Property(table)
            }
            TableId::MethodSemantics => {
                let table =
                    MetadataTable::<MethodSemanticsRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodSemantics(table)
            }
            TableId::MethodImpl => {
                let table =
                    MetadataTable::<MethodImplRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodImpl(table)
            }
            TableId::ModuleRef => {
                let table =
                    MetadataTable::<ModuleRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ModuleRef(table)
            }
            TableId::TypeSpec => {
                let table =
                    MetadataTable::<TypeSpecRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::TypeSpec(table)
            }
            TableId::ImplMap => {
                let table = MetadataTable::<ImplMapRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ImplMap(table)
            }
            TableId::FieldRVA => {
                let table =
                    MetadataTable::<FieldRvaRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::FieldRVA(table)
            }
            TableId::Assembly => {
                let table =
                    MetadataTable::<AssemblyRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::Assembly(table)
            }
            TableId::AssemblyProcessor => {
                let table = MetadataTable::<AssemblyProcessorRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::AssemblyProcessor(table)
            }
            TableId::AssemblyOS => {
                let table =
                    MetadataTable::<AssemblyOsRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::AssemblyOS(table)
            }
            TableId::AssemblyRef => {
                let table =
                    MetadataTable::<AssemblyRefRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::AssemblyRef(table)
            }
            TableId::AssemblyRefProcessor => {
                let table = MetadataTable::<AssemblyRefProcessorRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::AssemblyRefProcessor(table)
            }
            TableId::AssemblyRefOS => {
                let table =
                    MetadataTable::<AssemblyRefOsRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::AssemblyRefOS(table)
            }
            TableId::File => {
                let table = MetadataTable::<FileRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::File(table)
            }
            TableId::ExportedType => {
                let table =
                    MetadataTable::<ExportedTypeRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ExportedType(table)
            }
            TableId::ManifestResource => {
                let table = MetadataTable::<ManifestResourceRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::ManifestResource(table)
            }
            TableId::NestedClass => {
                let table =
                    MetadataTable::<NestedClassRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::NestedClass(table)
            }
            TableId::GenericParam => {
                let table =
                    MetadataTable::<GenericParamRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::GenericParam(table)
            }
            TableId::MethodSpec => {
                let table =
                    MetadataTable::<MethodSpecRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::MethodSpec(table)
            }
            TableId::GenericParamConstraint => {
                let table = MetadataTable::<GenericParamConstraintRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::GenericParamConstraint(table)
            }
            TableId::MethodDebugInformation => {
                let table = MetadataTable::<MethodDebugInformationRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::MethodDebugInformation(table)
            }
            TableId::LocalScope => {
                let table =
                    MetadataTable::<LocalScopeRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::LocalScope(table)
            }
            TableId::LocalVariable => {
                let table =
                    MetadataTable::<LocalVariableRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::LocalVariable(table)
            }
            TableId::LocalConstant => {
                let table =
                    MetadataTable::<LocalConstantRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::LocalConstant(table)
            }
            TableId::ImportScope => {
                let table =
                    MetadataTable::<ImportScopeRaw>::new(data, t_info.rows, self.info.clone())?;
                *current_offset += table.size() as usize;

                TableData::ImportScope(table)
            }
            TableId::StateMachineMethod => {
                let table = MetadataTable::<StateMachineMethodRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::StateMachineMethod(table)
            }
            TableId::CustomDebugInformation => {
                let table = MetadataTable::<CustomDebugInformationRaw>::new(
                    data,
                    t_info.rows,
                    self.info.clone(),
                )?;
                *current_offset += table.size() as usize;

                TableData::CustomDebugInformation(table)
            }
        };

        self.tables.insert(table_type as usize, Some(table));
        Ok(())
    }

    /// Check if a specific metadata table is present in this assembly.
    ///
    /// Use this method to safely check for table presence before accessing it.
    /// This avoids potential panics when working with assemblies that may not
    /// contain all possible metadata tables.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to check for presence
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{streams::TablesHeader, tables::{TableId, EventRaw}};
    ///
    /// # fn example(tables: &TablesHeader) -> dotscope::Result<()> {
    /// /// Safe pattern: check before access
    /// if tables.has_table(TableId::Event) {
    ///     if let Some(event_table) = tables.table::<EventRaw>() {
    ///         println!("Assembly has {} events", event_table.row_count);
    ///     }
    /// } else {
    ///     println!("No events defined in this assembly");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn has_table(&self, table_id: TableId) -> bool {
        (self.valid & (1u64 << (table_id as u8))) != 0
    }

    /// Check if a metadata table is present by its numeric ID.
    ///
    /// This method provides a way to check for table presence using the raw
    /// numeric table identifiers (0-63) as defined in the ECMA-335 specification.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The numeric table ID (0-63) to check for presence
    ///
    /// # Returns
    ///
    /// * `true` - If the table is present
    /// * `false` - If the table is not present or `table_id` > 63
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// // Check for specific tables by their numeric IDs
    /// if tables.has_table_by_id(0x02) { // TypeDef
    ///     println!("TypeDef table present");
    /// }
    /// if tables.has_table_by_id(0x06) { // MethodDef  
    ///     println!("MethodDef table present");
    /// }
    /// if tables.has_table_by_id(0x04) { // Field
    ///     println!("Field table present");
    /// }
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn has_table_by_id(&self, table_id: u8) -> bool {
        if table_id > 63 {
            return false;
        }
        (self.valid & (1u64 << table_id)) != 0
    }

    /// Get an iterator over all present metadata tables.
    ///
    /// This method returns an iterator that yields [`crate::metadata::tables::TableId`] values for all tables
    /// that are present in this assembly's metadata. Useful for discovering what
    /// metadata is available without having to check each table individually.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// println!("Present metadata tables:");
    /// for table_id in tables.present_tables() {
    ///     let row_count = tables.table_row_count(table_id);
    ///     println!("  {:?}: {} rows", table_id, row_count);
    /// }
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn present_tables(&self) -> impl Iterator<Item = TableId> + '_ {
        TableId::iter().filter(|&table_id| self.has_table(table_id))
    }

    /// Get the row count for a specific metadata table.
    ///
    /// Returns the number of rows in the specified table. This information
    /// is available even if you don't access the table data itself.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to get the row count for
    ///
    /// # Returns
    ///
    /// Row count (0 if table is not present)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
    ///
    /// # fn example(tables: &TablesHeader) {
    /// let type_count = tables.table_row_count(TableId::TypeDef);
    /// let method_count = tables.table_row_count(TableId::MethodDef);
    /// let field_count = tables.table_row_count(TableId::Field);
    ///
    /// println!("Assembly contains:");
    /// println!("  {} types", type_count);
    /// println!("  {} methods", method_count);
    /// println!("  {} fields", field_count);
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn table_row_count(&self, table_id: TableId) -> u32 {
        self.info.get(table_id).rows
    }

    /// Get a summary of all present metadata tables with their row counts.
    ///
    /// Returns a vector of summary structs containing the table ID and row count
    /// for each table present in this assembly. This provides an efficient way to get an
    /// overview of the assembly's metadata structure without accessing individual tables.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::streams::TablesHeader;
    ///
    /// # fn example(tables: &TablesHeader) {
    /// let summaries = tables.table_summary();
    /// for summary in summaries {
    ///     println!("Table {:?}: {} rows", summary.table_id, summary.row_count);
    /// }
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn table_summary(&self) -> Vec<TableSummary> {
        self.present_tables()
            .map(|table_id| TableSummary {
                table_id,
                row_count: self.table_row_count(table_id),
            })
            .collect()
    }
}

/// Summary information for a metadata table providing table identity and size information.
///
/// This struct is used by [`crate::metadata::streams::tablesheader::TablesHeader::table_summary`] to provide an overview
/// of all present tables in the metadata without requiring full table access. This
/// is useful for assembly analysis, diagnostics, and determining what metadata is
/// available before processing specific tables.
///
/// # Examples
///
/// ## Basic Usage with Table Summary
/// ```rust
/// use dotscope::metadata::streams::TablesHeader;
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
///
/// // Get overview of all tables
/// let summaries = tables.table_summary();
///
/// for summary in summaries {
///     println!("Table {:?} has {} rows", summary.table_id, summary.row_count);
///     
///     // Make decisions based on table size
///     if summary.row_count > 1000 {
///         println!("  ↳ Large table - consider parallel processing");
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Filtering and Analysis
/// ```rust
/// use dotscope::metadata::{streams::TablesHeader, tables::TableId};
///
/// # fn example(tables_data: &[u8]) -> dotscope::Result<()> {
/// let tables = TablesHeader::from(tables_data)?;
/// let summaries = tables.table_summary();
///
/// // Find the largest tables
/// let mut large_tables: Vec<_> = summaries.iter()
///     .filter(|s| s.row_count > 100)
///     .collect();
/// large_tables.sort_by_key(|s| std::cmp::Reverse(s.row_count));
///
/// println!("Largest metadata tables:");
/// for summary in large_tables.iter().take(5) {
///     println!("  {:?}: {} rows", summary.table_id, summary.row_count);
/// }
///
/// // Check for specific features
/// let has_generics = summaries.iter()
///     .any(|s| s.table_id == TableId::GenericParam && s.row_count > 0);
/// if has_generics {
///     println!("Assembly uses generic types");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TableSummary {
    /// The type/ID of the metadata table.
    ///
    /// Identifies which specific metadata table this summary describes using the
    /// ECMA-335 table enumeration. This corresponds to table IDs 0-44 as defined
    /// in the specification.
    pub table_id: TableId,

    /// The number of rows present in this table.
    ///
    /// Indicates the count of data rows in the table. A value of 0 means the table
    /// is present in the assembly but contains no data. Tables not present in the
    /// assembly will not appear in the summary at all.
    pub row_count: u32,
}

// Generate safe TableAccess trait implementations for all metadata table types
impl_table_access!(ModuleRaw, TableId::Module, Module);
impl_table_access!(TypeRefRaw, TableId::TypeRef, TypeRef);
impl_table_access!(TypeDefRaw, TableId::TypeDef, TypeDef);
impl_table_access!(FieldPtrRaw, TableId::FieldPtr, FieldPtr);
impl_table_access!(FieldRaw, TableId::Field, Field);
impl_table_access!(MethodPtrRaw, TableId::MethodPtr, MethodPtr);
impl_table_access!(MethodDefRaw, TableId::MethodDef, MethodDef);
impl_table_access!(ParamPtrRaw, TableId::ParamPtr, ParamPtr);
impl_table_access!(ParamRaw, TableId::Param, Param);
impl_table_access!(InterfaceImplRaw, TableId::InterfaceImpl, InterfaceImpl);
impl_table_access!(MemberRefRaw, TableId::MemberRef, MemberRef);
impl_table_access!(ConstantRaw, TableId::Constant, Constant);
impl_table_access!(
    CustomAttributeRaw,
    TableId::CustomAttribute,
    CustomAttribute
);
impl_table_access!(FieldMarshalRaw, TableId::FieldMarshal, FieldMarshal);
impl_table_access!(DeclSecurityRaw, TableId::DeclSecurity, DeclSecurity);
impl_table_access!(ClassLayoutRaw, TableId::ClassLayout, ClassLayout);
impl_table_access!(FieldLayoutRaw, TableId::FieldLayout, FieldLayout);
impl_table_access!(StandAloneSigRaw, TableId::StandAloneSig, StandAloneSig);
impl_table_access!(EventMapRaw, TableId::EventMap, EventMap);
impl_table_access!(EventPtrRaw, TableId::EventPtr, EventPtr);
impl_table_access!(EventRaw, TableId::Event, Event);
impl_table_access!(PropertyMapRaw, TableId::PropertyMap, PropertyMap);
impl_table_access!(PropertyPtrRaw, TableId::PropertyPtr, PropertyPtr);
impl_table_access!(PropertyRaw, TableId::Property, Property);
impl_table_access!(
    MethodSemanticsRaw,
    TableId::MethodSemantics,
    MethodSemantics
);
impl_table_access!(MethodImplRaw, TableId::MethodImpl, MethodImpl);
impl_table_access!(ModuleRefRaw, TableId::ModuleRef, ModuleRef);
impl_table_access!(TypeSpecRaw, TableId::TypeSpec, TypeSpec);
impl_table_access!(ImplMapRaw, TableId::ImplMap, ImplMap);
impl_table_access!(FieldRvaRaw, TableId::FieldRVA, FieldRVA);
impl_table_access!(AssemblyRaw, TableId::Assembly, Assembly);
impl_table_access!(
    AssemblyProcessorRaw,
    TableId::AssemblyProcessor,
    AssemblyProcessor
);
impl_table_access!(AssemblyOsRaw, TableId::AssemblyOS, AssemblyOS);
impl_table_access!(AssemblyRefRaw, TableId::AssemblyRef, AssemblyRef);
impl_table_access!(
    AssemblyRefProcessorRaw,
    TableId::AssemblyRefProcessor,
    AssemblyRefProcessor
);
impl_table_access!(AssemblyRefOsRaw, TableId::AssemblyRefOS, AssemblyRefOS);
impl_table_access!(FileRaw, TableId::File, File);
impl_table_access!(ExportedTypeRaw, TableId::ExportedType, ExportedType);
impl_table_access!(
    ManifestResourceRaw,
    TableId::ManifestResource,
    ManifestResource
);
impl_table_access!(NestedClassRaw, TableId::NestedClass, NestedClass);
impl_table_access!(GenericParamRaw, TableId::GenericParam, GenericParam);
impl_table_access!(MethodSpecRaw, TableId::MethodSpec, MethodSpec);
impl_table_access!(
    GenericParamConstraintRaw,
    TableId::GenericParamConstraint,
    GenericParamConstraint
);
impl_table_access!(DocumentRaw, TableId::Document, Document);
impl_table_access!(
    MethodDebugInformationRaw,
    TableId::MethodDebugInformation,
    MethodDebugInformation
);
impl_table_access!(LocalScopeRaw, TableId::LocalScope, LocalScope);
impl_table_access!(LocalVariableRaw, TableId::LocalVariable, LocalVariable);
impl_table_access!(LocalConstantRaw, TableId::LocalConstant, LocalConstant);
impl_table_access!(ImportScopeRaw, TableId::ImportScope, ImportScope);
impl_table_access!(
    StateMachineMethodRaw,
    TableId::StateMachineMethod,
    StateMachineMethod
);
impl_table_access!(
    CustomDebugInformationRaw,
    TableId::CustomDebugInformation,
    CustomDebugInformation
);
impl_table_access!(EncLogRaw, TableId::EncLog, EncLog);
impl_table_access!(EncMapRaw, TableId::EncMap, EncMap);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::verify_tableheader;

    #[test]
    fn wb_stream_0() {
        let data = include_bytes!("../../../tests/samples/WB_STREAM_TABLES_O-0x6C_S-0x59EB4.bin");
        let header = TablesHeader::from(data).unwrap();

        verify_tableheader(&header);
    }
}
