mod windowsbase;
use std::sync::{atomic::AtomicU32, Arc, OnceLock};

pub use windowsbase::*;

use crate::metadata::{
    method::{
        Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
        MethodModifiers, MethodRc, MethodVtableFlags,
    },
    signatures::{SignatureMethod, SignatureParameter, TypeSignature},
    streams::{
        AssemblyRef, AssemblyRefHash, AssemblyRefRc, ExportedType, ExportedTypeRc, File, FileRc,
        ModuleRef, ModuleRefRc,
    },
    token::Token,
    typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeReference},
};

// Helper function to create a ModuleRef
pub fn create_module_ref(rid: u32, name: &str) -> ModuleRefRc {
    Arc::new(ModuleRef {
        rid,
        offset: rid as usize,
        token: Token::new(0x1A000000 + rid),
        name: name.to_string(),
    })
}

// Helper function to create an AssemblyRef
pub fn create_assembly_ref(rid: u32, name: &str) -> AssemblyRefRc {
    Arc::new(AssemblyRef {
        rid,
        token: Token::new(0x23000000 + rid),
        offset: rid as usize,
        name: name.to_string(),
        culture: None,
        major_version: 4,
        minor_version: 0,
        build_number: 0,
        revision_number: 0,
        flags: 0,
        identifier: None,
        hash: None,
        os_platform_id: AtomicU32::new(0),
        os_major_version: AtomicU32::new(0),
        os_minor_version: AtomicU32::new(0),
        processor: AtomicU32::new(0),
    })
}

// Helper function to create a File
pub fn create_file(rid: u32, name: &str) -> FileRc {
    Arc::new(File {
        rid,
        token: Token::new(0x26000000 + rid),
        offset: rid as usize,
        flags: 0,
        name: name.to_string(),
        hash_value: AssemblyRefHash::new(&[1, 2, 3, 4]).unwrap(),
    })
}

// Helper function to create a Method
pub fn create_method(name: &str) -> MethodRc {
    Arc::new(Method {
        rid: 1,
        token: Token::new(0x06000001),
        meta_offset: 0,
        impl_code_type: MethodImplCodeType::empty(),
        impl_management: MethodImplManagement::empty(),
        impl_options: MethodImplOptions::empty(),
        flags_access: MethodAccessFlags::empty(),
        flags_vtable: MethodVtableFlags::empty(),
        flags_modifiers: MethodModifiers::empty(),
        flags_pinvoke: AtomicU32::new(0),
        name: name.to_string(),
        params: Arc::new(boxcar::Vec::new()),
        varargs: Arc::new(boxcar::Vec::new()),
        generic_params: Arc::new(boxcar::Vec::new()),
        generic_args: Arc::new(boxcar::Vec::new()),
        signature: SignatureMethod {
            has_this: false,
            explicit_this: false,
            default: false,
            vararg: false,
            cdecl: true,
            stdcall: false,
            thiscall: false,
            fastcall: false,
            param_count_generic: 0,
            param_count: 0,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::Void,
            },
            params: Vec::new(),
            varargs: Vec::new(),
        },
        rva: Some(0x1000),
        body: OnceLock::new(),
        local_vars: Arc::new(boxcar::Vec::new()),
        overrides: OnceLock::new(),
        interface_impls: Arc::new(boxcar::Vec::new()),
        security: OnceLock::new(),
        blocks: OnceLock::new(),
    })
}

// Helper function to create a CilType
pub fn create_cil_type(
    token: Token,
    namespace: &str,
    name: &str,
    external: Option<CilTypeReference>,
) -> CilTypeRc {
    Arc::new(CilType::new(
        token,
        CilFlavor::Class,
        namespace.to_string(),
        name.to_string(),
        external,
        None,
        0,
        Arc::new(boxcar::Vec::new()),
        Arc::new(boxcar::Vec::new()),
    ))
}

/// Helper function to create an ExportedTypeRc
pub fn create_exportedtype(dummy_type: CilTypeRc) -> ExportedTypeRc {
    Arc::new(ExportedType {
        rid: 1,
        token: Token::new(0x27000001),
        offset: 0,
        flags: 0,
        type_def_id: dummy_type.token.0,
        name: "ExportedType".to_string(),
        namespace: Some("Test.Namespace".to_string()),
        implementation: CilTypeReference::File(create_file(1, "export_test")),
    })
}
