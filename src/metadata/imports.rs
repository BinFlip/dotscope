//! Analysis and representation of imported types and methods in .NET assemblies.
//!
//! This module provides types and logic for tracking all external dependencies (imports) of a .NET assembly,
//! including methods and types imported from other assemblies, modules, or native DLLs. Used for dependency analysis,
//! interop, and assembly resolution.
//!
//! # Key Types
//! - [`Import`] - Represents a method or type imported from another assembly or DLL
//! - [`ImportType`] - Enum for method or type import
//! - [`ImportSourceId`] - Enum for identifying the source of an import

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;

use crate::{
    metadata::{
        method::MethodRc,
        streams::{AssemblyRef, AssemblyRefRc, File, FileRc, Module, ModuleRef, ModuleRefRc},
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
    },
    Result,
};

/// A reference to an `Import`
pub type ImportRc = Arc<Import>;

/// What is being imported
///
/// Represents whether the import is a method or a type.
pub enum ImportType {
    /// Importing a Method
    Method(MethodRc),
    /// Importing a Type
    Type(CilTypeRc),
}

/// An import source identifier - internally used to track where imports come from
/// without creating reference cycles.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Debug)]
pub enum ImportSourceId {
    /// Import from a module (by token)
    Module(Token),
    /// Import from a module reference (by token)
    ModuleRef(Token),
    /// Import from an assembly reference (by token)
    AssemblyRef(Token),
    /// Import from a file (by token)
    File(Token),
    /// Import from a type reference (by token)
    TypeRef(Token),
    /// No source (internal use)
    None,
}

/// A `Method` or `Type` that is imported from another .NET Assembly or a native dll.
///
/// This struct contains all metadata about an import, including its name, namespace, type, and source.
/// Used for dependency analysis, interop, and assembly resolution.
pub struct Import {
    /// The token of this import
    pub token: Token,
    /// The name of the import (can be different from native export name)
    pub name: String,
    /// The namespace of the import (can be empty)
    pub namespace: String,
    /// The method or type being imported
    pub import: ImportType,
    /// From which source the import comes from (by ID rather than reference)
    pub source_id: ImportSourceId,
}

impl Import {
    /// Return the entity's full name (namespace.name)
    #[must_use]
    pub fn fullname(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.namespace, self.name)
        }
    }
}

/// Represents all externally imported `Method` or `CilType`
///
/// This struct provides efficient lookup and grouping of all imports in an assembly, supporting queries by name,
/// namespace, source, and more. Used for dependency analysis and interop.
pub struct Imports {
    // Primary storage - token to import mapping
    data: SkipMap<Token, ImportRc>,

    // Indices for efficient lookup
    by_name: DashMap<String, Vec<Token>>,
    by_fullname: DashMap<String, Vec<Token>>,
    by_namespace: DashMap<String, Vec<Token>>,

    // Group imports by their source
    by_source: DashMap<ImportSourceId, Vec<Token>>,

    modules: DashMap<Token, Arc<Module>>,
    module_refs: DashMap<Token, Arc<ModuleRef>>,
    assembly_refs: DashMap<Token, Arc<AssemblyRef>>,
    files: DashMap<Token, Arc<File>>,
}

impl Imports {
    /// Create a new instance of `Imports`
    #[must_use]
    pub fn new() -> Self {
        Imports {
            data: SkipMap::new(),
            by_name: DashMap::new(),
            by_fullname: DashMap::new(),
            by_namespace: DashMap::new(),
            by_source: DashMap::new(),
            modules: DashMap::new(),
            module_refs: DashMap::new(),
            assembly_refs: DashMap::new(),
            files: DashMap::new(),
        }
    }

    /// Register an entity that can own imports
    /// This creates a weak reference to avoid circular dependencies
    pub fn register_source(&self, source: &CilTypeReference) {
        match source {
            CilTypeReference::Module(module) => {
                let token = module.token;
                self.modules.insert(token, module.clone());
            }
            CilTypeReference::ModuleRef(module_ref) => {
                let token = module_ref.token;
                self.module_refs.insert(token, module_ref.clone());
            }
            CilTypeReference::AssemblyRef(assembly_ref) => {
                let token = assembly_ref.token;
                self.assembly_refs.insert(token, assembly_ref.clone());
            }
            CilTypeReference::File(file) => {
                let token = file.token;
                self.files.insert(token, file.clone());
            }
            _ => {}
        }
    }

    /// Insert a new `CilType` to be tracked as import
    ///
    /// ## Arguments
    /// * `cil_type` - The type to add as an import
    ///
    /// # Errors
    /// Returns an error if the external reference type is invalid or if source registration fails.
    pub fn add_type(&self, cil_type: &CilTypeRc) -> Result<()> {
        if let Some(external) = &cil_type.external {
            // Create the source ID from the external reference
            let source_id = match external {
                CilTypeReference::Module(module) => ImportSourceId::Module(module.token),
                CilTypeReference::ModuleRef(module_ref) => {
                    ImportSourceId::ModuleRef(module_ref.token)
                }
                CilTypeReference::AssemblyRef(assembly_ref) => {
                    ImportSourceId::AssemblyRef(assembly_ref.token)
                }
                CilTypeReference::File(file) => ImportSourceId::File(file.token),
                CilTypeReference::TypeRef(type_ref) => {
                    // For TypeRef, we just add the nested type and don't track it as an import
                    if let Some(nested_types) = type_ref.nested_types() {
                        nested_types.push(cil_type.clone().into());
                    }
                    return Ok(());
                }
                _ => return Err(malformed_error!("Invalid source id for Import")),
            };

            // Register the source entity for later reference
            self.register_source(external);

            // Create the import
            let import_rc = Arc::new(Import {
                token: cil_type.token,
                name: cil_type.name.clone(),
                namespace: cil_type.namespace.clone(),
                import: ImportType::Type(cil_type.clone()),
                source_id,
            });

            // Store the import with all appropriate indices
            self.add_import_entry(import_rc, source_id);

            Ok(())
        } else {
            Ok(())
        }
    }

    /// Insert a new `MethodDef` to be tracked as import
    ///
    /// ## Arguments
    /// * 'name'    - The name of the imported method
    /// * 'token'   - The token under which this method is imported
    /// * 'method'  - The method definition
    /// * 'module'  - The source module of the import
    ///
    /// # Errors
    /// This function currently does not return errors but is designed to be extensible
    /// for future validation requirements.
    pub fn add_method(
        &self,
        name: String,
        token: &Token,
        method: MethodRc,
        module: &ModuleRefRc,
    ) -> Result<()> {
        let source_id = ImportSourceId::ModuleRef(module.token);

        // Register the source module
        self.module_refs.insert(module.token, module.clone());

        // Create the import
        let import_rc = Arc::new(Import {
            token: *token,
            name,
            namespace: String::new(),
            import: ImportType::Method(method),
            source_id,
        });

        // Store the import with all appropriate indices
        self.add_import_entry(import_rc, source_id);

        Ok(())
    }

    /// Helper method to add an import entry to all indices
    fn add_import_entry(&self, import_rc: ImportRc, source_id: ImportSourceId) {
        // Add to lookup indices
        self.by_name
            .entry(import_rc.name.clone())
            .or_default()
            .push(import_rc.token);

        self.by_fullname
            .entry(import_rc.fullname())
            .or_default()
            .push(import_rc.token);

        if !import_rc.namespace.is_empty() {
            self.by_namespace
                .entry(import_rc.namespace.clone())
                .or_default()
                .push(import_rc.token);
        }

        // Add to source grouping
        self.by_source
            .entry(source_id)
            .or_default()
            .push(import_rc.token);

        // Add to primary storage
        self.data.insert(import_rc.token, import_rc);
    }

    /// Get the number of total imports
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no imports
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over all imports.
    ///
    /// Returns an iterator that yields tuples of (Token, `ImportRc`) for each import.
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<Token, ImportRc> {
        self.data.iter()
    }

    /// Get an `Import` by name
    ///
    /// ## Arguments
    /// * 'name' - The imported name to look for (method name or type name)
    pub fn by_name(&self, name: &str) -> Option<ImportRc> {
        if let Some(tokens) = self.by_name.get(name) {
            if !tokens.is_empty() {
                if let Some(token) = self.data.get(&tokens[0]) {
                    return Some(token.value().clone());
                }
            }
        }
        None
    }

    /// Get all `Import`s by name
    ///
    /// ## Arguments
    /// * 'name' - The imported name to look for (method name or type name)
    pub fn all_by_name(&self, name: &str) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_name.get(name) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Get an `Import` by full name (namespace.name)
    ///
    /// ## Arguments
    /// * 'name' - The imported name to look for
    pub fn by_fullname(&self, name: &str) -> Option<ImportRc> {
        if let Some(tokens) = self.by_fullname.get(name) {
            if !tokens.is_empty() {
                if let Some(token) = self.data.get(&tokens[0]) {
                    return Some(token.value().clone());
                }
            }
        }
        None
    }

    /// Get all `Import`s by full name (namespace.name)
    ///
    /// ## Arguments
    /// * 'name' - The imported name to look for
    pub fn all_by_fullname(&self, name: &str) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_fullname.get(name) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Get all `Import`s by namespace
    ///
    /// ## Arguments
    /// * 'namespace' - The namespace to look for
    pub fn by_namespace(&self, namespace: &str) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_namespace.get(namespace) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Get all `Import`s from a specific module
    ///
    /// ## Arguments
    /// * `module_ref` - The module reference to get imports from
    pub fn from_module_ref(&self, module_ref: &ModuleRefRc) -> Vec<ImportRc> {
        let source_id = ImportSourceId::ModuleRef(module_ref.token);
        self.imports_from_source(source_id)
    }

    /// Get all `Import`s from a specific assembly reference
    ///
    /// ## Arguments
    /// * `assembly_ref` - The assembly reference to get imports from
    pub fn from_assembly_ref(&self, assembly_ref: &AssemblyRefRc) -> Vec<ImportRc> {
        let source_id = ImportSourceId::AssemblyRef(assembly_ref.token);
        self.imports_from_source(source_id)
    }

    /// Get all `Import`s from a specific file
    ///
    /// ## Arguments
    /// * 'file' - The file to get imports from
    pub fn from_file(&self, file: &FileRc) -> Vec<ImportRc> {
        let source_id = ImportSourceId::File(file.token);
        self.imports_from_source(source_id)
    }

    /// Helper method to get all imports from a specific source ID
    fn imports_from_source(&self, source_id: ImportSourceId) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_source.get(&source_id) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }
}

impl Default for Imports {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> IntoIterator for &'a Imports {
    type Item = crossbeam_skiplist::map::Entry<'a, Token, ImportRc>;
    type IntoIter = crossbeam_skiplist::map::Iter<'a, Token, ImportRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Trait for types that can have imports
///
/// Implement this trait for any type that can own or aggregate imports.
pub trait ImportContainer {
    /// Get all imports from this container
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc>;
}

#[cfg(test)]
mod tests {
    use crate::test::{
        create_assembly_ref, create_cil_type, create_file, create_method, create_module_ref,
    };

    use super::*;

    #[test]
    fn test_add_method_import() {
        let imports = Imports::new();
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetProcessId");
        let token = Token::new(0x0A000001);

        imports
            .add_method(
                "GetProcessId".to_string(),
                &token,
                method.clone(),
                &module_ref,
            )
            .unwrap();

        assert_eq!(imports.len(), 1);

        // Test by_name lookup
        let found = imports.by_name("GetProcessId").unwrap();
        assert_eq!(found.token, token);
        assert_eq!(found.name, "GetProcessId");

        match &found.import {
            ImportType::Method(m) => {
                assert_eq!(m.name, "GetProcessId");
                assert_eq!(m.rva.unwrap(), 0x1000);
            }
            _ => panic!("Expected Method import type"),
        }

        // Test by_fullname lookup
        let found = imports.by_fullname("GetProcessId").unwrap();
        assert_eq!(found.token, token);

        // Test ImportContainer trait
        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 1);
        assert_eq!(module_imports[0].token, token);
        assert_eq!(module_imports[0].name, "GetProcessId");
    }

    #[test]
    fn test_add_type_import() {
        let imports = Imports::new();
        let assembly_ref = create_assembly_ref(1, "System.Core");
        let token = Token::new(0x01000001);

        let cil_type = create_cil_type(
            token,
            "System.Collections.Generic",
            "List",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        imports.add_type(&cil_type).unwrap();

        assert_eq!(imports.len(), 1);

        // Test by_name lookup
        let found = imports.by_name("List").unwrap();
        assert_eq!(found.token, token);
        assert_eq!(found.namespace, "System.Collections.Generic");

        // Test by_fullname lookup
        let found = imports
            .by_fullname("System.Collections.Generic.List")
            .unwrap();
        assert_eq!(found.token, token);

        // Test by_namespace lookup
        let found_by_ns = imports.by_namespace("System.Collections.Generic");
        assert_eq!(found_by_ns.len(), 1);
        assert_eq!(found_by_ns[0].token, token);

        // Test ImportContainer trait
        let assembly_imports = assembly_ref.get_imports(&imports);
        assert_eq!(assembly_imports.len(), 1);
        assert_eq!(assembly_imports[0].token, token);
    }

    #[test]
    fn test_multiple_imports_same_source() {
        let imports = Imports::new();
        let assembly_ref = create_assembly_ref(1, "System.Core");

        // Add multiple types from same assembly
        let token1 = Token::new(0x01000001);
        let token2 = Token::new(0x01000002);
        let token3 = Token::new(0x01000003);

        let type1 = create_cil_type(
            token1,
            "System.Collections.Generic",
            "List",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        let type2 = create_cil_type(
            token2,
            "System.Collections.Generic",
            "Dictionary",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        let type3 = create_cil_type(
            token3,
            "System.Linq",
            "Enumerable",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        imports.add_type(&type1).unwrap();
        imports.add_type(&type2).unwrap();
        imports.add_type(&type3).unwrap();

        assert_eq!(imports.len(), 3);

        // Test all_by_namespace
        let generic_types = imports.by_namespace("System.Collections.Generic");
        assert_eq!(generic_types.len(), 2);

        // Test ImportContainer trait
        let assembly_imports = assembly_ref.get_imports(&imports);
        assert_eq!(assembly_imports.len(), 3);
    }

    #[test]
    fn test_multiple_imports_different_sources() {
        let imports = Imports::new();

        let assembly_ref1 = create_assembly_ref(1, "System.Core");
        let assembly_ref2 = create_assembly_ref(2, "System.IO");
        let module_ref = create_module_ref(1, "kernel32.dll");
        let file_ref = create_file(1, "Resources.dll");

        // Types from different sources
        let token1 = Token::new(0x01000001);
        let token2 = Token::new(0x01000002);
        let token3 = Token::new(0x01000003);
        let token4 = Token::new(0x01000004);

        let type1 = create_cil_type(
            token1,
            "System.Collections",
            "ArrayList",
            Some(CilTypeReference::AssemblyRef(assembly_ref1.clone())),
        );

        let type2 = create_cil_type(
            token2,
            "System.IO",
            "Stream",
            Some(CilTypeReference::AssemblyRef(assembly_ref2.clone())),
        );

        let type3 = create_cil_type(
            token3,
            "NativeTypes",
            "ProcessInfo",
            Some(CilTypeReference::ModuleRef(module_ref.clone())),
        );

        let type4 = create_cil_type(
            token4,
            "Resources",
            "ImageData",
            Some(CilTypeReference::File(file_ref.clone())),
        );

        imports.add_type(&type1).unwrap();
        imports.add_type(&type2).unwrap();
        imports.add_type(&type3).unwrap();
        imports.add_type(&type4).unwrap();

        assert_eq!(imports.len(), 4);

        // Test imports by different sources
        let asm1_imports = assembly_ref1.get_imports(&imports);
        assert_eq!(asm1_imports.len(), 1);
        assert_eq!(asm1_imports[0].fullname(), "System.Collections.ArrayList");

        let asm2_imports = assembly_ref2.get_imports(&imports);
        assert_eq!(asm2_imports.len(), 1);
        assert_eq!(asm2_imports[0].fullname(), "System.IO.Stream");

        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 1);
        assert_eq!(module_imports[0].fullname(), "NativeTypes.ProcessInfo");

        let file_imports = file_ref.get_imports(&imports);
        assert_eq!(file_imports.len(), 1);
        assert_eq!(file_imports[0].fullname(), "Resources.ImageData");
    }

    #[test]
    fn test_name_collision() {
        let imports = Imports::new();

        let assembly_ref1 = create_assembly_ref(1, "System.Core");
        let assembly_ref2 = create_assembly_ref(2, "System.Drawing");

        // Two types with the same name but different namespaces
        let token1 = Token::new(0x01000001);
        let token2 = Token::new(0x01000002);

        let type1 = create_cil_type(
            token1,
            "System.Drawing",
            "Point",
            Some(CilTypeReference::AssemblyRef(assembly_ref1.clone())),
        );

        let type2 = create_cil_type(
            token2,
            "System.Windows",
            "Point",
            Some(CilTypeReference::AssemblyRef(assembly_ref2.clone())),
        );

        imports.add_type(&type1).unwrap();
        imports.add_type(&type2).unwrap();

        assert_eq!(imports.len(), 2);

        // Test all_by_name to get multiple matches
        let points = imports.all_by_name("Point");
        assert_eq!(points.len(), 2);

        // Make sure fullname lookups work correctly
        let drawing_point = imports.by_fullname("System.Drawing.Point").unwrap();
        assert_eq!(drawing_point.token, token1);

        let windows_point = imports.by_fullname("System.Windows.Point").unwrap();
        assert_eq!(windows_point.token, token2);
    }

    #[test]
    fn test_type_ref_handling() {
        let imports = Imports::new();

        // Create a TypeRef
        let type_ref_token = Token::new(0x01000001);
        let type_ref = create_cil_type(type_ref_token, "System", "Object", None);

        // Create a type that will be nested under the TypeRef
        let nested_token = Token::new(0x01000002);
        let nested_type = create_cil_type(
            nested_token,
            "System.Collections",
            "Nested",
            Some(CilTypeReference::TypeRef(type_ref.clone().into())),
        );

        // Adding a type with TypeRef external should add it to nested_types
        // but not track it as an import
        imports.add_type(&nested_type).unwrap();

        // Verify it wasn't added as an import
        assert_eq!(imports.len(), 0);

        // Verify it was added as a nested type
        assert_eq!(type_ref.nested_types.count(), 1);
        assert_eq!(type_ref.nested_types[0].token().unwrap(), nested_token);
    }

    #[test]
    fn test_module_method_imports() {
        let imports = Imports::new();
        let module_ref = create_module_ref(1, "kernel32.dll");

        // Add multiple methods from same module
        let method1 = create_method("GetProcessId");
        let method2 = create_method("GetCurrentProcess");
        let method3 = create_method("ExitProcess");

        let token1 = Token::new(0x0A000001);
        let token2 = Token::new(0x0A000002);
        let token3 = Token::new(0x0A000003);

        imports
            .add_method("GetProcessId".to_string(), &token1, method1, &module_ref)
            .unwrap();

        imports
            .add_method(
                "GetCurrentProcess".to_string(),
                &token2,
                method2,
                &module_ref,
            )
            .unwrap();

        imports
            .add_method("ExitProcess".to_string(), &token3, method3, &module_ref)
            .unwrap();

        assert_eq!(imports.len(), 3);

        // Test method imports via ImportContainer
        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 3);

        // Verify we can find all methods
        assert!(imports.by_name("GetProcessId").is_some());
        assert!(imports.by_name("GetCurrentProcess").is_some());
        assert!(imports.by_name("ExitProcess").is_some());
    }

    #[test]
    fn test_empty_lookups() {
        let imports = Imports::new();

        // Test various empty lookups
        assert!(imports.by_name("NonExistent").is_none());
        assert!(imports.by_fullname("NonExistent.Type").is_none());
        assert_eq!(imports.by_namespace("NonExistent").len(), 0);
        assert_eq!(imports.all_by_name("NonExistent").len(), 0);

        // Create a source but don't add any imports from it
        let module_ref = create_module_ref(1, "kernel32.dll");
        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 0);
    }

    #[test]
    fn test_iter_works() {
        let imports = Imports::new();
        let assembly_ref = create_assembly_ref(1, "System.Core");
        let module_ref = create_module_ref(1, "kernel32.dll");

        // Add a type import
        let type_token = Token::new(0x01000001);
        let cil_type = create_cil_type(
            type_token,
            "System.Collections.Generic",
            "List",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );
        imports.add_type(&cil_type).unwrap();

        // Add a method import
        let method_token = Token::new(0x0A000001);
        let method = create_method("GetProcessId");
        imports
            .add_method(
                "GetProcessId".to_string(),
                &method_token,
                method,
                &module_ref,
            )
            .unwrap();

        // Test that we can iterate over all imports
        let mut count = 0;
        let mut tokens = Vec::new();

        for entry in imports.iter() {
            count += 1;
            tokens.push(*entry.key());
        }

        assert_eq!(count, 2);
        assert!(tokens.contains(&type_token));
        assert!(tokens.contains(&method_token));

        // Verify we can access the imports through the iterator
        for entry in imports.iter() {
            let import = entry.value();
            match import.token {
                t if t == type_token => {
                    assert_eq!(import.name, "List");
                    assert_eq!(import.namespace, "System.Collections.Generic");
                    assert!(matches!(import.import, ImportType::Type(_)));
                }
                t if t == method_token => {
                    assert_eq!(import.name, "GetProcessId");
                    assert_eq!(import.namespace, "");
                    assert!(matches!(import.import, ImportType::Method(_)));
                }
                _ => panic!("Unexpected import token: {:?}", import.token),
            }
        }
    }
}
