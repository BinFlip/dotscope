//! # Metadata Tables Module
//!
//! This module provides comprehensive access to all .NET metadata tables as defined in the
//! ECMA-335 specification. It serves as the central access point for all table types, offering
//! both raw (unresolved) and owned (resolved) variants for each table.
//!
//! ## Overview
//!
//! The .NET metadata format organizes data into a series of tables, each containing specific
//! types of metadata information. This module provides Rust implementations for all standard
//! metadata tables, enabling complete inspection and manipulation of .NET assembly metadata.
//!
//! ## Table Categories
//!
//! The metadata tables are organized into several logical categories:
//!
//! ### **Assembly Information**
//! - [`crate::metadata::tables::Assembly`] - Assembly identity and configuration
//! - [`crate::metadata::tables::AssemblyOs`] - Operating system information  
//! - [`crate::metadata::tables::AssemblyProcessorRaw`] - Processor architecture information
//! - [`crate::metadata::tables::AssemblyRef`] - External assembly references
//! - [`crate::metadata::tables::AssemblyRefOs`] - OS info for external assemblies
//! - [`crate::metadata::tables::AssemblyRefProcessor`] - Processor info for external assemblies
//! - [`crate::metadata::tables::File`] - Files in the assembly manifest
//! - [`crate::metadata::tables::ManifestResource`] - Resources in the assembly manifest
//!
//! ### **Type System**
//! - [`crate::metadata::tables::TypeDefRaw`] - Type definitions within this assembly
//! - [`crate::metadata::tables::TypeRefRaw`] - References to external types
//! - [`crate::metadata::tables::TypeSpec`] - Constructed type specifications
//! - [`crate::metadata::tables::NestedClass`] - Nested type relationships
//! - [`crate::metadata::tables::InterfaceImpl`] - Interface implementation relationships
//!
//! ### **Methods and Fields**
//! - [`crate::metadata::tables::MethodDefRaw`] - Method definitions
//! - [`crate::metadata::tables::MethodImpl`] - Method implementation mappings
//! - [`crate::metadata::tables::MethodSemantics`] - Method semantic relationships (getters/setters)
//! - [`crate::metadata::tables::MethodSpec`] - Generic method instantiations
//! - [`crate::metadata::tables::Field`] - Field definitions
//! - [`crate::metadata::tables::FieldLayout`] - Field layout information
//! - [`crate::metadata::tables::FieldMarshal`] - Field marshalling information
//! - [`crate::metadata::tables::FieldRva`] - Field relative virtual addresses
//!
//! ### **Properties and Events**
//! - [`crate::metadata::tables::Property`] - Property definitions
//! - [`crate::metadata::tables::PropertyMap`] - Property to type mappings
//! - [`crate::metadata::tables::Event`] - Event definitions
//! - [`crate::metadata::tables::EventMap`] - Event to type mappings
//!
//! ### **Parameters and Variables**
//! - [`crate::metadata::tables::Param`] - Method parameter definitions
//! - [`crate::metadata::tables::GenericParam`] - Generic parameter definitions
//! - [`crate::metadata::tables::GenericParamConstraint`] - Generic parameter constraints
//!
//! ### **External References**
//! - [`crate::metadata::tables::MemberRef`] - External member references
//! - [`crate::metadata::tables::ModuleRef`] - External module references
//! - [`crate::metadata::tables::ImplMap`] - P/Invoke implementation mappings
//!
//! ### **Security and Attributes**
//! - [`crate::metadata::tables::CustomAttribute`] - Custom attribute applications
//! - [`crate::metadata::tables::DeclSecurity`] - Declarative security information
//!
//! ### **Layout and Constants**
//! - [`crate::metadata::tables::ClassLayout`] - Type layout information
//! - [`crate::metadata::tables::Constant`] - Constant value definitions
//! - [`crate::metadata::tables::StandAloneSig`] - Standalone signatures
//!
//! ### **Pointer Tables** (Optimization)
//! - [`crate::metadata::tables::FieldPtr`] - Field pointer indirection
//! - [`crate::metadata::tables::MethodPtr`] - Method pointer indirection  
//! - [`crate::metadata::tables::ParamPtr`] - Parameter pointer indirection
//! - [`crate::metadata::tables::EventPtr`] - Event pointer indirection
//! - [`crate::metadata::tables::PropertyPtr`] - Property pointer indirection
//!
//! ## Dual Representation Pattern
//!
//! Each table follows a consistent dual-representation pattern:
//!
//! - **Raw Variant** (`*Raw`): Contains unresolved indexes as they appear in the file format
//!   - Memory efficient for parsing and storage
//!   - Direct representation of binary format
//!   - Requires resolution for meaningful use
//!
//! - **Owned Variant**: Contains resolved references and owned data
//!   - Runtime efficient for metadata queries
//!   - Fully resolved cross-references
//!   - Ready for immediate use
//!
//! ## ECMA-335 Compliance
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22** - Metadata table definitions and structure
//! - **§II.23** - Metadata table schemas and relationships
//! - **§II.24** - Coding of indexes and signatures
//!
//! Each table module includes specific ECMA-335 references for detailed specifications.
//!
//! ## Error Handling
//!
//! Table operations may fail due to:
//! - Malformed metadata structures
//! - Invalid cross-references
//! - Missing required dependencies
//! - Corrupted data
//!
//! All operations return [`Result`](crate::Result) types for proper error handling.
//!
//! For detailed specifications, see [ECMA-335 6th Edition](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).

mod assembly;
mod assemblyos;
mod assemblyprocessor;
mod assemblyref;
mod assemblyrefos;
mod assemblyrefprocessor;
mod classlayout;
mod constant;
mod customattribute;
mod customdebuginformation;
mod declsecurity;
mod document;
mod enclog;
mod encmap;
mod event;
mod eventmap;
mod eventptr;
mod exportedtype;
mod field;
mod fieldlayout;
mod fieldmarshal;
mod fieldptr;
mod fieldrva;
mod file;
mod genericparam;
mod genericparamconstraint;
mod implmap;
mod importscope;
mod interfaceimpl;
mod localconstant;
mod localscope;
mod localvariable;
mod manifestresource;
mod memberref;
mod methoddebuginformation;
mod methoddef;
mod methodimpl;
mod methodptr;
mod methodsemantics;
mod methodspec;
mod module;
mod moduleref;
mod nestedclass;
mod param;
mod paramptr;
mod property;
mod propertymap;
mod propertyptr;
mod standalonesig;
mod statemachinemethod;
mod typedef;
mod typeref;
mod types;
mod typespec;

pub use assembly::*;
pub use assemblyos::*;
pub use assemblyprocessor::*;
pub use assemblyref::*;
pub use assemblyrefos::*;
pub use assemblyrefprocessor::*;
pub use classlayout::*;
pub use constant::*;
pub use customattribute::*;
pub use customdebuginformation::*;
pub use declsecurity::*;
pub use document::*;
pub use enclog::*;
pub use encmap::*;
pub use event::*;
pub use eventmap::*;
pub use eventptr::*;
pub use exportedtype::*;
pub use field::*;
pub use fieldlayout::*;
pub use fieldmarshal::*;
pub use fieldptr::*;
pub use fieldrva::*;
pub use file::*;
pub use genericparam::*;
pub use genericparamconstraint::*;
pub use implmap::*;
pub use importscope::*;
pub use interfaceimpl::*;
pub use localconstant::*;
pub use localscope::*;
pub use localvariable::*;
pub use manifestresource::*;
pub use memberref::*;
pub use methoddebuginformation::*;
pub use methoddef::*;
pub use methodimpl::*;
pub use methodptr::*;
pub use methodsemantics::*;
pub use methodspec::*;
pub use module::*;
pub use moduleref::*;
pub use nestedclass::*;
pub use param::*;
pub use paramptr::*;
pub use property::*;
pub use propertymap::*;
pub use propertyptr::*;
pub use standalonesig::*;
pub use statemachinemethod::*;
pub use typedef::*;
pub use typeref::*;
pub use types::*;
pub use typespec::*;
