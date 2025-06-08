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
        loader::execute_loaders_in_parallel,
        method::MethodMap,
        resources::Resources,
        root::Root,
        streams::{
            AssemblyOsRc, AssemblyProcessorRc, AssemblyRc, AssemblyRefMap, Blob, EventMap,
            FieldMap, FileMap, GenericParamMap, Guid, MemberRefMap, ModuleRc, ModuleRefMap,
            ParamMap, PropertyMap, Strings, TablesHeader, UserStrings,
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
#[allow(missing_docs)]
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
    pub params: ParamMap,
    pub params_generic: GenericParamMap,
    pub fields: FieldMap,
    pub properties: PropertyMap,
    pub events: EventMap,
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
            params: SkipMap::default(),
            params_generic: SkipMap::default(),
            fields: SkipMap::default(),
            properties: SkipMap::default(),
            events: SkipMap::default(),
            resources: Resources::new(file),
        };

        cil_object.load_streams(meta_root_offset)?;

        /*
        ToDo:
            - Tables
                - CustomAttributes
                    - needs HasCustomAttributes for lookup, needs 'MethodDef' and 'MemberRef' for constructor
         */

        execute_loaders_in_parallel(&cil_object)?;

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
                "#Strings" => self.strings = Some(Strings::from(&self.data[start..end])?),
                "#US" => self.userstrings = Some(UserStrings::from(&self.data[start..end])?),
                "#GUID" => self.guids = Some(Guid::from(&self.data[start..end])?),
                "#Blob" => self.blobs = Some(Blob::from(&self.data[start..end])?),
                _ => return Err(NotSupported),
            }
        }

        Ok(())
    }
}
