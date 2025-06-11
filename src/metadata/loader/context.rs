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
            AssemblyRefProcessorMap, Blob, ClassLayoutMap, CodedIndex, ConstantMap,
            CustomAttributeMap, DeclSecurityMap, EventMap, EventMapEntryMap, FieldLayoutMap,
            FieldMap, FieldMarshalMap, FieldRVAMap, FileMap, GenericParamConstraintMap,
            GenericParamMap, Guid, InterfaceImplMap, MemberRefMap, MethodImplMap,
            MethodSemanticsMap, MethodSpecMap, ModuleRc, ModuleRefMap, NestedClassMap, ParamMap,
            PropertyMap, PropertyMapEntryMap, StandAloneSigMap, Strings, TableId, TablesHeader,
            TypeSpecMap, UserStrings,
        },
        typesystem::{CilTypeReference, TypeRegistry},
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
    pub method_spec: &'a MethodSpecMap,
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

impl LoaderContext<'_> {
    /// Resolve a coded index to a `CilTypeReference`
    ///
    /// This method provides unified coded index resolution across all metadata tables.
    /// It uses the `CodedIndex`'s table ID (.tag) and token (.token) to look up the
    /// corresponding object in the appropriate map, then converts it to the correct
    /// `CilTypeReference` variant.
    ///
    /// # Arguments
    /// * `coded_index` - The coded index containing table ID and token to resolve
    ///
    /// # Returns
    /// Returns the corresponding `CilTypeReference` variant or `CilTypeReference::None`
    /// if the coded index cannot be resolved.
    ///
    /// # Examples
    /// ```rust, ignore
    /// // Resolve a TypeDef coded index
    /// let type_ref = context.get_ref(&some_coded_index);
    ///
    /// // The method automatically handles the table lookup based on coded_index.tag
    /// ```
    pub fn get_ref(&self, coded_index: &CodedIndex) -> CilTypeReference {
        match coded_index.tag {
            TableId::TypeDef => {
                if let Some(type_def) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeDef(type_def.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::TypeRef => {
                if let Some(type_ref) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeRef(type_ref.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::TypeSpec => {
                if let Some(type_spec) = self.types.get(&coded_index.token) {
                    CilTypeReference::TypeSpec(type_spec.into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MethodDef => {
                if let Some(method_def) = self.method_def.get(&coded_index.token) {
                    CilTypeReference::MethodDef(method_def.value().clone().into())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MemberRef => {
                if let Some(member_ref) = self.member_ref.get(&coded_index.token) {
                    CilTypeReference::MemberRef(member_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Field => {
                if let Some(field) = self.field.get(&coded_index.token) {
                    CilTypeReference::Field(field.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Param => {
                if let Some(param) = self.param.get(&coded_index.token) {
                    CilTypeReference::Param(param.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Property => {
                if let Some(property) = self.property.get(&coded_index.token) {
                    CilTypeReference::Property(property.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Event => {
                if let Some(event) = self.event.get(&coded_index.token) {
                    CilTypeReference::Event(event.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::InterfaceImpl => {
                if let Some(interface_impl) = self.interface_impl.get(&coded_index.token) {
                    CilTypeReference::InterfaceImpl(interface_impl.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Module => {
                if let Some(module) = self.module.get() {
                    CilTypeReference::Module(module.clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::ModuleRef => {
                if let Some(module_ref) = self.module_ref.get(&coded_index.token) {
                    CilTypeReference::ModuleRef(module_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::Assembly => {
                if let Some(assembly) = self.assembly.get() {
                    CilTypeReference::Assembly(assembly.clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::AssemblyRef => {
                if let Some(assembly_ref) = self.assembly_ref.get(&coded_index.token) {
                    CilTypeReference::AssemblyRef(assembly_ref.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::File => {
                if let Some(file) = self.file.get(&coded_index.token) {
                    CilTypeReference::File(file.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::ExportedType => {
                if let Some(exported_type) = self.exported_type.get(&coded_index.token) {
                    CilTypeReference::ExportedType(exported_type.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::GenericParam => {
                if let Some(generic_param) = self.generic_param.get(&coded_index.token) {
                    CilTypeReference::GenericParam(generic_param.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::GenericParamConstraint => {
                if let Some(constraint) = self.generic_param_constraint.get(&coded_index.token) {
                    CilTypeReference::GenericParamConstraint(constraint.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::MethodSpec => {
                if let Some(method_spec) = self.method_spec.get(&coded_index.token) {
                    CilTypeReference::MethodSpec(method_spec.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::DeclSecurity => {
                if let Some(decl_security) = self.decl_security.get(&coded_index.token) {
                    CilTypeReference::DeclSecurity(decl_security.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            TableId::StandAloneSig => {
                if let Some(standalone_sig) = self.standalone_sig.get(&coded_index.token) {
                    CilTypeReference::StandAloneSig(standalone_sig.value().clone())
                } else {
                    CilTypeReference::None
                }
            }
            _ => CilTypeReference::None,
        }
    }
}
