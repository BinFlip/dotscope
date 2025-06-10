//! `LoaderContext` - Centralized storage for all metadata table maps during loading.
//!
//! This module provides the `LoaderContext` structure that holds all table maps
//! during the metadata loading process. The context is created in `CilObjectData::from_file`,
//! passed to `execute_loaders_in_parallel`, and dropped after loading completes.

use std::sync::{Arc, OnceLock};

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        exports::Exports,
        imports::Imports,
        method::MethodMap,
        resources::Resources,
        root::Root,
        streams::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, AssemblyRefOsMap,
            AssemblyRefProcessorMap, Blob, ClassLayoutMap, ConstantMap, CustomAttributeMap,
            DeclSecurityMap, EventMap, EventMapEntryMap, FieldLayoutMap, FieldMap, FieldMarshalMap,
            FieldRVAMap, FileMap, GenericParamConstraintMap, GenericParamMap, Guid,
            InterfaceImplMap, MemberRefMap, MethodImplMap, MethodSemanticsMap, MethodSpecMap,
            ModuleRc, ModuleRefMap, NestedClassMap, ParamMap, PropertyMap, PropertyMapEntryMap,
            StandAloneSigMap, Strings, TablesHeader, TypeSpecMap, UserStrings,
        },
        typesystem::TypeRegistry,
    },
};

/// Context structure that holds maps for all metadata tables during the loading process.
///
/// This structure is created in `CilObjectData::from_file`, passed to all loaders during
/// `execute_loaders_in_parallel`, and dropped after loading completes. Each loader converts
/// raw table rows to owned structures using `to_owned()` and inserts them into these maps,
/// then calls `apply()` methods to build semantic relationships.
pub(crate) struct LoaderContext<'a> {
    pub input: Arc<File>,
    pub data: &'a [u8],
    pub header: &'a Cor20Header,
    pub header_root: &'a Root,
    pub meta: &'a Option<TablesHeader<'a>>,
    pub strings: &'a Option<Strings<'a>>,
    pub userstrings: &'a Option<UserStrings<'a>>,
    pub guids: &'a Option<Guid<'a>>,
    pub blobs: &'a Option<Blob<'a>>,

    pub assembly: &'a Arc<OnceLock<AssemblyRc>>,
    pub assembly_os: &'a Arc<OnceLock<AssemblyOsRc>>,
    pub assembly_processor: &'a Arc<OnceLock<AssemblyProcessorRc>>,
    pub assembly_ref: &'a AssemblyRefMap,
    pub assembly_ref_os: AssemblyRefOsMap,
    pub assembly_ref_processor: AssemblyRefProcessorMap,
    pub module: &'a Arc<OnceLock<ModuleRc>>,
    pub module_ref: &'a ModuleRefMap,
    pub type_spec: TypeSpecMap,
    pub method_def: &'a MethodMap,
    pub method_impl: MethodImplMap,
    pub method_semantics: MethodSemanticsMap,
    pub method_spec: MethodSpecMap,
    pub field: FieldMap,
    pub field_layout: FieldLayoutMap,
    pub field_marshal: FieldMarshalMap,
    pub field_rva: FieldRVAMap,
    pub param: ParamMap,
    pub generic_param: GenericParamMap,
    pub generic_param_constraint: GenericParamConstraintMap,
    pub property: PropertyMap,
    pub property_map: PropertyMapEntryMap,
    pub event: EventMap,
    pub event_map: EventMapEntryMap,
    pub member_ref: &'a MemberRefMap,
    pub class_layout: ClassLayoutMap,
    pub nested_class: NestedClassMap,
    pub interface_impl: InterfaceImplMap,
    pub constant: ConstantMap,
    pub custom_attribute: CustomAttributeMap,
    pub decl_security: DeclSecurityMap,
    //pub impl_map: ImplMapMap,
    pub file: &'a FileMap,
    pub exported_type: &'a Exports,
    //pub manifest_resource: ManifestResourceMap,
    pub standalone_sig: StandAloneSigMap,

    pub imports: &'a Imports,
    pub resources: &'a Resources,
    pub types: &'a Arc<TypeRegistry>,
}
