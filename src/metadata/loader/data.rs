//! `CilObjectData` - Core data structure for .NET assembly metadata.
//!
//! This module contains the main data holder for all parsed metadata from a .NET assembly.
//! It is used internally by the loader system and should not be exposed to external users.

use std::sync::{Arc, OnceLock};

use crossbeam_skiplist::SkipMap;

use crate::{
    file::File,
    metadata::{
        cor20header::Cor20Header,
        exports::Exports,
        imports::Imports,
        loader::{execute_loaders_in_parallel, LoaderContext},
        method::MethodMap,
        resources::Resources,
        root::Root,
        streams::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, Blob, FileMap, Guid,
            MemberRefMap, MethodSpecMap, ModuleRc, ModuleRefMap, Strings, TablesHeader,
            UserStrings,
        },
        typesystem::TypeRegistry,
    },
    Error::NotSupported,
    Result,
};

/// The holder of parsed data for a .NET assembly.
///
/// This struct contains all loaded metadata, headers, and parsed tables for a single assembly.
/// It is used internally by the loader system and should not be exposed to external users.
pub(crate) struct CilObjectData<'a> {
    pub file: Arc<File>,
    pub data: &'a [u8],
    pub header: Cor20Header,
    pub header_root: Root,
    pub meta: Option<TablesHeader<'a>>,
    pub strings: Option<Strings<'a>>,
    pub userstrings: Option<UserStrings<'a>>,
    pub guids: Option<Guid<'a>>,
    pub blobs: Option<Blob<'a>>,
    pub refs_assembly: AssemblyRefMap,
    pub refs_module: ModuleRefMap,
    pub refs_member: MemberRefMap,
    pub refs_file: FileMap,
    pub module: Arc<OnceLock<ModuleRc>>,
    pub assembly: Arc<OnceLock<AssemblyRc>>,
    pub assembly_os: Arc<OnceLock<AssemblyOsRc>>,
    pub assembly_processor: Arc<OnceLock<AssemblyProcessorRc>>,
    pub types: Arc<TypeRegistry>,
    pub imports: Imports,
    pub exports: Exports,
    pub methods: MethodMap,
    pub method_specs: MethodSpecMap,
    pub resources: Resources,
}

impl<'a> CilObjectData<'a> {
    /// Parse the CIL data from a `File`
    ///
    /// ## Arguments
    /// * 'file' - The file to parse
    /// * 'data' - A shared reference to the data of the file
    pub(crate) fn from_file(file: Arc<File>, data: &'a [u8]) -> Result<Self> {
        let (clr_rva, clr_size) = file.clr();
        let clr_slice = file.data_slice(file.rva_to_offset(clr_rva)?, clr_size)?;

        let header = Cor20Header::read(clr_slice)?;

        let meta_root_offset = file.rva_to_offset(header.meta_data_rva as usize)?;
        let meta_root_slice = file.data_slice(meta_root_offset, header.meta_data_size as usize)?;

        let header_root = Root::read(meta_root_slice)?;

        let mut cil_object = CilObjectData {
            file: file.clone(),
            data,
            header,
            header_root,
            meta: None,
            strings: None,
            userstrings: None,
            guids: None,
            blobs: None,
            refs_assembly: SkipMap::default(),
            refs_module: SkipMap::default(),
            refs_member: SkipMap::default(),
            refs_file: SkipMap::default(),
            module: Arc::new(OnceLock::new()),
            assembly: Arc::new(OnceLock::new()),
            assembly_os: Arc::new(OnceLock::new()),
            assembly_processor: Arc::new(OnceLock::new()),
            types: Arc::new(TypeRegistry::new()?),
            imports: Imports::new(),
            exports: Exports::new(),
            methods: SkipMap::default(),
            method_specs: SkipMap::default(),
            resources: Resources::new(file),
        };

        cil_object.load_streams(meta_root_offset)?;

        {
            let context = LoaderContext {
                input: cil_object.file.clone(),
                data,
                header: &cil_object.header,
                header_root: &cil_object.header_root,
                meta: &cil_object.meta,
                strings: &cil_object.strings,
                userstrings: &cil_object.userstrings,
                guids: &cil_object.guids,
                blobs: &cil_object.blobs,
                assembly: &cil_object.assembly,
                assembly_os: &cil_object.assembly_os,
                assembly_processor: &cil_object.assembly_processor,
                assembly_ref: &cil_object.refs_assembly,
                assembly_ref_os: SkipMap::default(),
                assembly_ref_processor: SkipMap::default(),
                module: &cil_object.module,
                module_ref: &cil_object.refs_module,
                type_spec: SkipMap::default(),
                method_def: &cil_object.methods,
                method_impl: SkipMap::default(),
                method_semantics: SkipMap::default(),
                method_spec: &cil_object.method_specs,
                field: SkipMap::default(),
                field_ptr: SkipMap::default(),
                field_layout: SkipMap::default(),
                field_marshal: SkipMap::default(),
                field_rva: SkipMap::default(),
                param: SkipMap::default(),
                generic_param: SkipMap::default(),
                generic_param_constraint: SkipMap::default(),
                property: SkipMap::default(),
                property_map: SkipMap::default(),
                event: SkipMap::default(),
                event_map: SkipMap::default(),
                member_ref: &cil_object.refs_member,
                class_layout: SkipMap::default(),
                nested_class: SkipMap::default(),
                interface_impl: SkipMap::default(),
                constant: SkipMap::default(),
                custom_attribute: SkipMap::default(),
                decl_security: SkipMap::default(),
                file: &cil_object.refs_file,
                exported_type: &cil_object.exports,
                standalone_sig: SkipMap::default(),
                imports: &cil_object.imports,
                resources: &cil_object.resources,
                types: &cil_object.types,
            };

            execute_loaders_in_parallel(&context)?;
        };

        Ok(cil_object)
    }

    /// Parses the various stream types
    ///
    /// ## Arguments
    /// * `meta_root_offset` - The offset of the metadata header to calculate the stream location
    fn load_streams(&mut self, meta_root_offset: usize) -> Result<()> {
        for stream in &self.header_root.stream_headers {
            let Some(start) = usize::checked_add(meta_root_offset, stream.offset as usize) else {
                return Err(malformed_error!(
                    "Loading streams failed! 'start' - Integer overflow = {} + {}",
                    meta_root_offset,
                    stream.offset
                ));
            };

            let Some(end) = start.checked_add(stream.size as usize) else {
                return Err(malformed_error!(
                    "Loading streams failed! 'end' - Integer overflow = {} + {}",
                    start,
                    stream.offset
                ));
            };

            if start >= self.data.len() || end >= self.data.len() {
                return Err(malformed_error!(
                    "Loading streams failed! 'start' and/or 'end' are too large - {} + {}",
                    start,
                    end
                ));
            }

            match stream.name.as_str() {
                "#~" => self.meta = Some(TablesHeader::from(&self.data[start..end])?),
                "#-" => {
                    // TODO: Handle uncompressed metadata tables stream properly
                    // Currently we parse #- streams the same as #~ streams, but this is incomplete.
                    // The #- stream may contain additional Ptr tables (FieldPtr, MethodPtr, ParamPtr,
                    // EventPtr, PropertyPtr) that require special indirection logic.
                    // See the comprehensive TODO in from_file() method above for full requirements.
                    self.meta = Some(TablesHeader::from(&self.data[start..end])?);
                }
                "#Strings" => self.strings = Some(Strings::from(&self.data[start..end])?),
                "#US" => self.userstrings = Some(UserStrings::from(&self.data[start..end])?),
                "#GUID" => self.guids = Some(Guid::from(&self.data[start..end])?),
                "#Blob" => self.blobs = Some(Blob::from(&self.data[start..end])?),
                _ => return Err(NotSupported),
            }
        }

        self.header_root
            .validate_stream_layout(meta_root_offset, self.header.meta_data_size)?;

        Ok(())
    }
}
