//! # ECMA-335 Metadata Tables
//!
//! This module and its submodules provide parsing and representation for all ECMA-335 metadata tables.
//! Each submodule implements a specific table (e.g., Assembly, TypeDef, MethodDef) as defined in the .NET metadata specification.
//!
//! See each submodule for details and usage examples.
//
/// The implementations of various types necessary to parse and process this metadata
pub(crate) mod types;
//
/// The implementation of the '`Assembly`' table type
pub mod assembly;
/// The implementation of the '`AssemblyOS`' table type
pub mod assemblyos;
/// The implementation of the '`AssemblyProcessor`' table type
pub mod assemblyprocessor;
/// The implementation of the '`AssemblyRef`' table type
pub mod assemblyref;
/// The implementation of the '`AssemblyRefOS`' table type
pub mod assemblyrefos;
/// The implementation of the '`AssemblyRefProcessor`' table type
pub mod assemblyrefprocessor;
/// The implementation of the '`ClassLayout`' table type
pub mod classlayout;
/// The implementation of the '`Constant`' table type
pub mod constant;
/// The implementation of the '`CustomAttribute`' table type
pub mod customattribute;
/// The implementation of the '`DeclSecurity`' table type
pub mod declsecurity;
/// The implementation of the '`Event`' table type
pub mod event;
/// The implementation of the '`EventMap`' table type
pub mod eventmap;
/// The implementation of the '`ExportedType`' table type
pub mod exportedtype;
/// The implementation of the '`Field`' table type
pub mod field;
/// The implementation of the '`FieldLayout`' table type
pub mod fieldlayout;
/// The implementation of the '`FieldMarshal`' table type
pub mod fieldmarshal;
/// The implementation of the '`FieldPtr`' table type
pub mod fieldptr;
/// The implementation of the '`FieldRVA`' table type
pub mod fieldrva;
/// The implementation of the '`File`' table type
pub mod file;
/// The implementation of the '`GenericParam`' table type
pub mod genericparam;
/// The implementation of the '`GenericParamConstraint`' table type
pub mod genericparamconstraint;
/// The implementation of the '`ImplMap`' table type
pub mod implmap;
/// The implementation of the '`InterfaceImpl`' table type
pub mod interfaceimpl;
/// The implementation of the '`ManifestResource`' table type
pub mod manifestresource;
/// The implementation of the '`MemberRef`' table type
pub mod memberref;
/// The implementation of the '`MethodDef`' table type
pub mod methoddef;
/// The implementation of the '`MethodImpl`' table type
pub mod methodimpl;
/// The implementation of the '`MethodPtr`' table type
pub mod methodptr;
/// The implementation of the '`MethodScematics`' table type
pub mod methodsemantics;
/// The implementation of the '`MethodSpec`' table type
pub mod methodspec;
/// The implementation of the '`Module`' table type
pub mod module;
/// The implementation of the '`ModuleRef`' table type
pub mod moduleref;
/// The implementation of the '`NestedClass`' table type
pub mod nestedclass;
/// The implementation of the '`Param`' table type
pub mod param;
/// The implementation of the '`ParamPtr`' table type
pub mod paramptr;
/// The implementation of the '`Property`' table type
pub mod property;
/// The implementation of the '`PropertyMap`' table type
pub mod propertymap;
/// The implementation of the '`StandAloneSig`' table type
pub mod standalonesig;
/// The implementation of the '`TypeDef`' table type
pub mod typedef;
/// The implementation of the '`TypeRef`' table type
pub mod typeref;
/// The implementation of the '`TypeSpec`' table type
pub mod typespec;
