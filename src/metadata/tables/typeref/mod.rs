//! `TypeRef` table support for .NET metadata.
//!
//! The `TypeRef` table contains references to types defined in other modules or assemblies.
//! Each row represents a type reference with its resolution scope (where the type is defined),
//! type name, and namespace.
//!
//! ## ECMA-335 Specification
//! From ECMA-335, Partition II, Section 22.38:
//! > The TypeRef table has the following columns:
//! > - ResolutionScope (an index into a Module, ModuleRef, AssemblyRef or TypeRef table)
//! > - TypeName (an index into the String heap)
//! > - TypeNamespace (an index into the String heap)

mod loader;
mod raw;

pub(crate) use loader::*;
pub use raw::*;
