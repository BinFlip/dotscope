use std::{
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;

use crate::{
    metadata::{
        streams::{AssemblyRefRc, FileRc, ModuleRc, ModuleRefRc},
        token::Token,
        typesystem::{
            CilFlavor, CilPrimitive, CilPrimitiveKind, CilType, CilTypeRc, CilTypeReference,
        },
    },
    Error::TypeNotFound,
    Result,
};

/// Represents the source of a type in the registry (module, assembly, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeSource {
    /// Type is defined in the current module
    CurrentModule,
    /// Type is defined in an external module
    Module(Token),
    /// Type is defined in an external module reference
    ModuleRef(Token),
    /// Type is defined in an external assembly reference
    AssemblyRef(Token),
    /// Type is defined in an external file
    File(Token),
    /// Type is a primitive defined by the CLR
    Primitive,
    /// Type source is not known
    Unknown,
}

/// Tracks sources of types to avoid strong circular references
struct SourceRegistry {
    modules: DashMap<Token, ModuleRc>,
    module_refs: DashMap<Token, ModuleRefRc>,
    assembly_refs: DashMap<Token, AssemblyRefRc>,
    files: DashMap<Token, FileRc>,
}

impl SourceRegistry {
    /// Create a new empty source registry
    fn new() -> Self {
        SourceRegistry {
            modules: DashMap::new(),
            module_refs: DashMap::new(),
            assembly_refs: DashMap::new(),
            files: DashMap::new(),
        }
    }

    /// Register a source with the registry
    ///
    /// ## Arguments
    /// * 'source' - A new source to register
    fn register_source(&self, source: &CilTypeReference) -> TypeSource {
        match source {
            CilTypeReference::Module(module) => {
                self.modules.insert(module.token, module.clone());
                TypeSource::Module(module.token)
            }
            CilTypeReference::ModuleRef(module_ref) => {
                self.module_refs
                    .insert(module_ref.token, module_ref.clone());
                TypeSource::ModuleRef(module_ref.token)
            }
            CilTypeReference::AssemblyRef(assembly_ref) => {
                self.assembly_refs
                    .insert(assembly_ref.token, assembly_ref.clone());
                TypeSource::AssemblyRef(assembly_ref.token)
            }
            CilTypeReference::File(file) => {
                self.files.insert(file.token, file.clone());
                TypeSource::File(file.token)
            }
            _ => TypeSource::Unknown,
        }
    }

    /// Get a `CilTypeReference` from a source
    ///
    /// ## Arguments
    /// * `source` - The source to lookup
    fn get_source(&self, source: TypeSource) -> Option<CilTypeReference> {
        match source {
            TypeSource::Module(token) => self
                .modules
                .get(&token)
                .map(|module| CilTypeReference::Module(module.clone())),
            TypeSource::ModuleRef(token) => self
                .module_refs
                .get(&token)
                .map(|moduleref| CilTypeReference::ModuleRef(moduleref.clone())),
            TypeSource::AssemblyRef(token) => self
                .assembly_refs
                .get(&token)
                .map(|assemblyref| CilTypeReference::AssemblyRef(assemblyref.clone())),
            TypeSource::File(token) => self
                .files
                .get(&token)
                .map(|file| CilTypeReference::File(file.clone())),
            TypeSource::Primitive | TypeSource::Unknown | TypeSource::CurrentModule => None,
        }
    }
}

/// A hash that represents a unique type
struct TypeSignatureHash {
    hash: u64,
}

impl TypeSignatureHash {
    /// Create a new signature hash builder
    fn new() -> Self {
        TypeSignatureHash { hash: 0 }
    }

    /// Add flavor to the hash
    ///
    /// ## Arguments
    /// * `flavor` - The `CilFlavor` to hash in
    fn add_flavor(&mut self, flavor: &CilFlavor) -> &mut Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        match flavor {
            CilFlavor::Void => 1u8.hash(&mut hasher),
            CilFlavor::Boolean => 2u8.hash(&mut hasher),
            CilFlavor::Char => 3u8.hash(&mut hasher),
            CilFlavor::I1 => 4u8.hash(&mut hasher),
            CilFlavor::U1 => 5u8.hash(&mut hasher),
            CilFlavor::I2 => 6u8.hash(&mut hasher),
            CilFlavor::U2 => 7u8.hash(&mut hasher),
            CilFlavor::I4 => 8u8.hash(&mut hasher),
            CilFlavor::U4 => 9u8.hash(&mut hasher),
            CilFlavor::I8 => 10u8.hash(&mut hasher),
            CilFlavor::U8 => 11u8.hash(&mut hasher),
            CilFlavor::R4 => 12u8.hash(&mut hasher),
            CilFlavor::R8 => 13u8.hash(&mut hasher),
            CilFlavor::I => 14u8.hash(&mut hasher),
            CilFlavor::U => 15u8.hash(&mut hasher),
            CilFlavor::Object => 16u8.hash(&mut hasher),
            CilFlavor::String => 17u8.hash(&mut hasher),
            CilFlavor::Array { rank, dimensions } => {
                18u8.hash(&mut hasher);
                rank.hash(&mut hasher);
                dimensions.len().hash(&mut hasher);
            }
            CilFlavor::Pointer => 19u8.hash(&mut hasher),
            CilFlavor::ByRef => 20u8.hash(&mut hasher),
            CilFlavor::GenericInstance => 21u8.hash(&mut hasher),
            CilFlavor::Pinned => 22u8.hash(&mut hasher),
            CilFlavor::FnPtr { signature: _ } => {
                // Function pointer signatures are complex, so we just use a simple marker
                // A full implementation would hash the entire signature
                23u8.hash(&mut hasher);
            }
            CilFlavor::GenericParameter { index, method } => {
                24u8.hash(&mut hasher);
                index.hash(&mut hasher);
                method.hash(&mut hasher);
            }
            CilFlavor::Class => 25u8.hash(&mut hasher),
            CilFlavor::ValueType => 26u8.hash(&mut hasher),
            CilFlavor::Interface => 27u8.hash(&mut hasher),
            CilFlavor::Unknown => 0u8.hash(&mut hasher),
        }

        self.hash ^= hasher.finish();
        self
    }

    /// Add namespace and name to the hash
    ///
    /// ## Arguments
    /// * 'namespace'   - The namespace of the type
    /// * 'name'        - The name of the type
    fn add_fullname(&mut self, namespace: &str, name: &str) -> &mut Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        namespace.hash(&mut hasher);
        name.hash(&mut hasher);
        self.hash ^= hasher.finish();
        self
    }

    /// Add a token to the hash
    ///
    /// ## Arguments
    /// * 'token' - The token of the type
    fn add_token(&mut self, token: Token) -> &mut Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        token.value().hash(&mut hasher);
        self.hash ^= hasher.finish();
        self
    }

    /// Add source information to the hash
    ///
    /// ## Arguments
    /// * 'source' - The source to hash in
    fn add_source(&mut self, source: TypeSource) -> &mut Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        match source {
            TypeSource::CurrentModule => {
                0u8.hash(&mut hasher);
            }
            TypeSource::Module(token) => {
                1u8.hash(&mut hasher);
                token.value().hash(&mut hasher);
            }
            TypeSource::ModuleRef(token) => {
                2u8.hash(&mut hasher);
                token.value().hash(&mut hasher);
            }
            TypeSource::AssemblyRef(token) => {
                3u8.hash(&mut hasher);
                token.value().hash(&mut hasher);
            }
            TypeSource::File(token) => {
                4u8.hash(&mut hasher);
                token.value().hash(&mut hasher);
            }
            TypeSource::Primitive => {
                5u8.hash(&mut hasher);
            }
            TypeSource::Unknown => {
                6u8.hash(&mut hasher);
            }
        }
        self.hash ^= hasher.finish();
        self
    }

    /// Finalize and get the hash value
    fn finalize(&self) -> u64 {
        self.hash
    }
}

/// Manages registration, lookup, and deduplication of types
pub struct TypeRegistry {
    /// Main storage for all types by their token
    types: SkipMap<Token, CilTypeRc>,
    /// Next available token for new types
    next_token: AtomicU32,
    /// Cache of type signature hashes to tokens
    signature_cache: DashMap<u64, Token>,
    /// Registry of external reference sources
    sources: SourceRegistry,
    /// Types by their source
    types_by_source: DashMap<TypeSource, Vec<Token>>,
    /// Types by name (qualified with namespace)
    types_by_fullname: DashMap<String, Vec<Token>>,
    /// Types by name only (may have duplicates across namespaces)
    types_by_name: DashMap<String, Vec<Token>>,
    /// Types by namespace
    types_by_namespace: DashMap<String, Vec<Token>>,
}

impl TypeRegistry {
    /// Create a new type registry with initialized primitive types
    ///
    /// # Errors
    /// Returns an error if primitive types cannot be initialized.
    pub fn new() -> Result<Self> {
        let registry = TypeRegistry {
            types: SkipMap::new(),
            next_token: AtomicU32::new(0xF000_0020), // Start after reserved primitives
            signature_cache: DashMap::new(),
            sources: SourceRegistry::new(),
            types_by_source: DashMap::new(),
            types_by_fullname: DashMap::new(),
            types_by_name: DashMap::new(),
            types_by_namespace: DashMap::new(),
        };

        registry.initialize_primitives()?;
        Ok(registry)
    }

    /// Get the next available token and increment the counter
    fn next_token(&self) -> Token {
        let next_token = self.next_token.fetch_add(1, Ordering::Relaxed);
        if next_token == 0xFFFF_FFFF {
            // We're out of tokens - this should never happen in practice
            debug_assert!(
                false,
                "We ran out of tokens and are going overwrite existing ones"
            );
            self.next_token.store(0xF100_0000, Ordering::Relaxed);
        }

        Token::new(next_token)
    }

    /// Initialize primitive types in the registry
    fn initialize_primitives(&self) -> Result<()> {
        for primitive in [
            CilPrimitive::new(CilPrimitiveKind::Void),
            CilPrimitive::new(CilPrimitiveKind::Boolean),
            CilPrimitive::new(CilPrimitiveKind::Char),
            CilPrimitive::new(CilPrimitiveKind::I1),
            CilPrimitive::new(CilPrimitiveKind::U1),
            CilPrimitive::new(CilPrimitiveKind::I2),
            CilPrimitive::new(CilPrimitiveKind::U2),
            CilPrimitive::new(CilPrimitiveKind::I4),
            CilPrimitive::new(CilPrimitiveKind::U4),
            CilPrimitive::new(CilPrimitiveKind::I8),
            CilPrimitive::new(CilPrimitiveKind::U8),
            CilPrimitive::new(CilPrimitiveKind::R4),
            CilPrimitive::new(CilPrimitiveKind::R8),
            CilPrimitive::new(CilPrimitiveKind::I),
            CilPrimitive::new(CilPrimitiveKind::U),
            CilPrimitive::new(CilPrimitiveKind::Object),
            CilPrimitive::new(CilPrimitiveKind::String),
            CilPrimitive::new(CilPrimitiveKind::TypedReference),
            CilPrimitive::new(CilPrimitiveKind::ValueType),
            CilPrimitive::new(CilPrimitiveKind::Var),
            CilPrimitive::new(CilPrimitiveKind::MVar),
            CilPrimitive::new(CilPrimitiveKind::Null),
        ] {
            let token = primitive.token();
            let flavor = primitive.to_flavor();

            let new_type = Arc::new(CilType::new(
                token,
                flavor,
                primitive.namespace().to_string(),
                primitive.name().to_string(),
                None,
                None,
                0,
                Arc::new(boxcar::Vec::new()),
                Arc::new(boxcar::Vec::new()),
            ));

            self.register_type_internal(new_type, TypeSource::Primitive);
        }

        // Set up base type relationships
        let object_token = CilPrimitive::new(CilPrimitiveKind::Object).token();
        let value_type_token = CilPrimitive::new(CilPrimitiveKind::ValueType).token();

        // All value types extend System.ValueType
        for primitive in [
            CilPrimitive::new(CilPrimitiveKind::Void),
            CilPrimitive::new(CilPrimitiveKind::Boolean),
            CilPrimitive::new(CilPrimitiveKind::Char),
            CilPrimitive::new(CilPrimitiveKind::I1),
            CilPrimitive::new(CilPrimitiveKind::U1),
            CilPrimitive::new(CilPrimitiveKind::I2),
            CilPrimitive::new(CilPrimitiveKind::U2),
            CilPrimitive::new(CilPrimitiveKind::I4),
            CilPrimitive::new(CilPrimitiveKind::U4),
            CilPrimitive::new(CilPrimitiveKind::I8),
            CilPrimitive::new(CilPrimitiveKind::U8),
            CilPrimitive::new(CilPrimitiveKind::R4),
            CilPrimitive::new(CilPrimitiveKind::R8),
            CilPrimitive::new(CilPrimitiveKind::I),
            CilPrimitive::new(CilPrimitiveKind::U),
        ] {
            let type_token = primitive.token();
            if let (Some(type_rc), Some(value_type_rc)) = (
                self.types.get(&type_token),
                self.types.get(&value_type_token),
            ) {
                type_rc
                    .value()
                    .base
                    .set(value_type_rc.value().clone().into())
                    .map_err(|_| malformed_error!("Type base already set"))?;
            }
        }

        // System.ValueType itself extends System.Object
        if let (Some(value_type_rc), Some(object_rc)) = (
            self.types.get(&value_type_token),
            self.types.get(&object_token),
        ) {
            value_type_rc
                .value()
                .base
                .set(object_rc.value().clone().into())
                .map_err(|_| malformed_error!("ValueType base already set"))?;
        }

        // System.String extends System.Object
        if let (Some(string_rc), Some(object_rc)) = (
            self.types
                .get(&CilPrimitive::new(CilPrimitiveKind::String).token()),
            self.types.get(&object_token),
        ) {
            string_rc
                .value()
                .base
                .set(object_rc.value().clone().into())
                .map_err(|_| malformed_error!("String base already set"))?;
        }

        Ok(())
    }

    /// Register a new type in all the lookup tables
    ///
    /// ## Arguments
    /// * `type_rc`     - The type instance
    /// * `source`      - The the source of the type
    fn register_type_internal(&self, type_rc: CilTypeRc, source: TypeSource) {
        self.types_by_source
            .entry(source)
            .or_default()
            .push(type_rc.token);

        if !type_rc.namespace.is_empty() {
            self.types_by_namespace
                .entry(type_rc.namespace.clone())
                .or_default()
                .push(type_rc.token);
        }

        self.types_by_name
            .entry(type_rc.name.clone())
            .or_default()
            .push(type_rc.token);

        self.types_by_fullname
            .entry(type_rc.fullname())
            .or_default()
            .push(type_rc.token);

        self.types.insert(type_rc.token, type_rc);
    }

    /// Insert a `CilType` into the registry
    ///
    /// ## Arguments
    /// * '`new_type`' - The type to register
    pub fn insert(&self, new_type: CilTypeRc) {
        let token = new_type.token;
        if self.types.contains_key(&token) {
            return;
        }

        let source = match &new_type.external {
            Some(external_source) => self.register_source(external_source),
            None => TypeSource::CurrentModule,
        };

        // ToDo: Improve hash calculation, generates collisions right now (during TypeDef and TypeRef ingestion)
        // let hash = TypeSignatureHash::new()
        //     .add_flavor(&new_type.borrow().flavor)
        //     .add_fullname(&new_type.borrow().namespace, &new_type.borrow().name)
        //     .add_source(source)
        //     .finalize();

        // if let Some(&existing_token) = self.signature_cache.get(&hash) {
        //     if let Some(existing_type) = self.types.get(&existing_token) {
        //         let name = &existing_type.borrow().name;
        //         let fullname = &existing_type.borrow().namespace;
        //         return;
        //     }
        // }
        //self.signature_cache.insert(hash, token);

        self.register_type_internal(new_type, source);
    }

    /// Create a new empty type with the next available token
    ///
    /// # Errors
    /// Returns an error if the type cannot be created or inserted into the registry.
    pub fn create_type_empty(&self) -> Result<CilTypeRc> {
        let token = self.next_token();

        let new_type = Arc::new(CilType::new(
            token,
            CilFlavor::Unknown,
            String::new(),
            String::new(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        ));

        self.types.insert(token, new_type.clone());
        Ok(new_type)
    }

    /// Create a new type with a specific flavor
    ///
    /// ## Arguments
    /// * 'flavor' - The flavor to set for the new type
    ///
    /// # Errors
    /// Returns an error if the type cannot be created or inserted into the registry.
    pub fn create_type_with_flavor(&self, flavor: CilFlavor) -> Result<CilTypeRc> {
        let new_type = self.create_type_empty()?;
        *write_lock!(new_type.flavor) = flavor;
        Ok(new_type)
    }

    /// Get a primitive type by its `CilPrimitive` enum value
    ///
    /// ## Arguments
    /// * 'primitive' - The kind of primitive to look up
    ///
    /// # Errors
    /// Returns an error if the primitive type is not found in the registry.
    pub fn get_primitive(&self, primitive: CilPrimitiveKind) -> Result<CilTypeRc> {
        match self.types.get(&primitive.token()) {
            Some(res) => Ok(res.value().clone()),
            None => Err(TypeNotFound(primitive.token())),
        }
    }

    /// Get a type by its token
    ///
    /// ## Arguments
    /// * 'token' - The token to look up
    pub fn get(&self, token: &Token) -> Option<CilTypeRc> {
        self.types.get(token).map(|entry| entry.value().clone())
    }

    /// Get a type by its source and name
    ///
    /// ## Arguments
    /// * 'source'      - The source of the type to look for
    /// * 'namespace'   - The namespace of the type to look for
    /// * 'name'        - The name of the type to look for
    pub fn get_by_source_and_name(
        &self,
        source: TypeSource,
        namespace: &str,
        name: &str,
    ) -> Option<CilTypeRc> {
        let fullname = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", namespace, name)
        };

        if let Some(tokens) = self.types_by_source.get(&source) {
            for &token in tokens.value() {
                if let Some(type_rc) = self.types.get(&token) {
                    if type_rc.value().namespace == namespace && type_rc.value().name == name {
                        return Some(type_rc.value().clone());
                    }
                }
            }
        }

        if let Some(tokens) = self.types_by_fullname.get(&fullname) {
            if let Some(&token) = tokens.first() {
                return self.types.get(&token).map(|res| res.value().clone());
            }
        }

        None
    }

    /// Get types by their namespace
    ///
    /// ## Arguments
    /// * 'namespace' - The namespace of the type to look for
    pub fn get_by_namespace(&self, namespace: &str) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_namespace.get(namespace) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get types by their name (may return multiple if they're in different namespaces)
    ///
    /// ## Arguments
    /// * 'name' - The name of the type to look for
    pub fn get_by_name(&self, name: &str) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_name.get(name) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get types by their fully qualified name (namespace.name)
    ///
    /// ## Arguments
    /// * 'fullname' - The fullname (namespace.name) of the type to look for
    pub fn get_by_fullname(&self, fullname: &str) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_fullname.get(fullname) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Register a source entity to enable resolving references to it
    ///
    /// ## Arguments
    /// * 'source' - The source of the type to register
    pub fn register_source(&self, source: &CilTypeReference) -> TypeSource {
        self.sources.register_source(source)
    }

    /// Get a source reference by its id
    ///
    /// ## Arguments
    /// * 'source' - The source of the type to look for
    pub fn get_source_reference(&self, source: TypeSource) -> Option<CilTypeReference> {
        self.sources.get_source(source)
    }

    /// Find or create a type with the given characteristics
    ///
    /// ## Arguments
    /// * 'token'       - The token to use for the new type (sometimes known, e.g. initial `TypeSpec`)
    /// * 'flavor'      - The flavor of the type to get or create
    /// * 'namespace'   - The namespace of the type to get or create
    /// * 'name'        - The name of the type to get or create
    /// * 'source'      - The source of the type to get or create
    ///
    /// # Errors
    /// Returns an error if the type cannot be created or if there are conflicts
    /// in the type registry during type creation.
    pub fn get_or_create_type(
        &self,
        token_init: &mut Option<Token>,
        flavor: CilFlavor,
        namespace: &str,
        name: &str,
        source: TypeSource,
    ) -> Result<CilTypeRc> {
        // ToDo: Improve hash calculation, generates collisions right now (during TypeDef, TypeRef and TypeSpec ingestion)
        // let hash = TypeSignatureHash::new()
        //     .add_flavor(&flavor)
        //     .add_fullname(namespace, name)
        //     .add_source(source)
        //     .finalize();

        // if let Some(&existing_token) = self.signature_cache.get(&hash) {
        //     if let Some(existing_type) = self.types.get(&existing_token) {
        //         return Ok(existing_type.clone());
        //     }
        // }

        let token = if let Some(init_token) = token_init.take() {
            init_token
        } else {
            self.next_token()
        };

        if let Some(existing) = self.types.get(&token) {
            return Ok(existing.value().clone());
        }

        let new_type = Arc::new(CilType::new(
            token,
            flavor,
            namespace.to_string(),
            name.to_string(),
            self.get_source_reference(source),
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        ));

        self.register_type_internal(new_type.clone(), source);
        //self.signature_cache.insert(hash, token);

        Ok(new_type)
    }

    /// Count of types in the registry
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Returns an iterator over all types in the registry
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<Token, CilTypeRc> {
        self.types.iter()
    }

    /// Get all types in the registry
    pub fn all_types(&self) -> Vec<CilTypeRc> {
        self.types
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get types from a specific source
    ///
    /// ## Arguments
    /// * 'source' - The source of the types to look for
    pub fn types_from_source(&self, source: TypeSource) -> Vec<CilTypeRc> {
        if let Some(tokens) = self.types_by_source.get(&source) {
            tokens
                .iter()
                .filter_map(|token| self.types.get(token).map(|entry| entry.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl<'a> IntoIterator for &'a TypeRegistry {
    type Item = crossbeam_skiplist::map::Entry<'a, Token, CilTypeRc>;
    type IntoIter = crossbeam_skiplist::map::Iter<'a, Token, CilTypeRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use uguid::guid;

    use super::*;
    use crate::metadata::streams::{AssemblyRef, AssemblyRefHash, File, Module, ModuleRef};

    #[test]
    fn test_registry_primitives() {
        let registry = TypeRegistry::new().unwrap();

        let bool_type = registry.get_primitive(CilPrimitiveKind::Boolean).unwrap();
        assert_eq!(bool_type.name, "Boolean");
        assert_eq!(bool_type.namespace, "System");

        let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
        assert_eq!(int_type.name, "Int32");
        assert_eq!(int_type.namespace, "System");

        let object_type = registry.get_primitive(CilPrimitiveKind::Object).unwrap();
        let string_type = registry.get_primitive(CilPrimitiveKind::String).unwrap();

        assert_eq!(
            string_type.base.get().unwrap().token().unwrap(),
            object_type.token
        );

        let value_type = registry.get_primitive(CilPrimitiveKind::ValueType).unwrap();
        assert_eq!(
            value_type.base.get().unwrap().token().unwrap(),
            object_type.token
        );

        assert_eq!(
            int_type.base.get().unwrap().token().unwrap(),
            value_type.token
        );

        let all_primitives = [
            CilPrimitiveKind::Void,
            CilPrimitiveKind::Boolean,
            CilPrimitiveKind::Char,
            CilPrimitiveKind::I1,
            CilPrimitiveKind::U1,
            CilPrimitiveKind::I2,
            CilPrimitiveKind::U2,
            CilPrimitiveKind::I4,
            CilPrimitiveKind::U4,
            CilPrimitiveKind::I8,
            CilPrimitiveKind::U8,
            CilPrimitiveKind::R4,
            CilPrimitiveKind::R8,
            CilPrimitiveKind::I,
            CilPrimitiveKind::U,
            CilPrimitiveKind::Object,
            CilPrimitiveKind::String,
            CilPrimitiveKind::TypedReference,
            CilPrimitiveKind::ValueType,
            CilPrimitiveKind::Var,
            CilPrimitiveKind::MVar,
            CilPrimitiveKind::Null,
        ];

        for primitive in all_primitives.iter() {
            let prim_type = registry.get_primitive(*primitive);
            assert!(
                prim_type.is_ok(),
                "Failed to get primitive: {:?}",
                primitive
            );
        }
    }

    #[test]
    fn test_create_and_lookup() {
        let registry = TypeRegistry::new().unwrap();

        let list_type = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "System.Collections.Generic",
                "List`1",
                TypeSource::CurrentModule,
            )
            .unwrap();

        assert_eq!(list_type.name, "List`1");
        assert_eq!(list_type.namespace, "System.Collections.Generic");

        let found = registry.get_by_name("List`1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, list_type.token);

        let found = registry.get_by_namespace("System.Collections.Generic");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, list_type.token);

        let found = registry.get_by_fullname("System.Collections.Generic.List`1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, list_type.token);

        let found = registry.get(&list_type.token);
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, list_type.token);

        let found = registry.get_by_source_and_name(
            TypeSource::CurrentModule,
            "System.Collections.Generic",
            "List`1",
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, list_type.token);
    }

    #[test]
    fn test_multiple_types_with_same_name() {
        let registry = TypeRegistry::new().unwrap();

        let point1 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::ValueType,
                "System.Drawing",
                "Point",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let point2 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::ValueType,
                "System.Windows",
                "Point",
                TypeSource::CurrentModule,
            )
            .unwrap();

        assert_ne!(point1.token, point2.token);

        let found = registry.get_by_name("Point");
        assert_eq!(found.len(), 2);

        let found = registry.get_by_fullname("System.Drawing.Point");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, point1.token);

        let found = registry.get_by_fullname("System.Windows.Point");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].token, point2.token);
    }

    #[test]
    fn test_create_type_empty() {
        let registry = TypeRegistry::new().unwrap();

        let empty_type = registry.create_type_empty().unwrap();

        assert_eq!(empty_type.namespace, "");
        assert_eq!(empty_type.name, "");
        assert!(matches!(*read_lock!(empty_type.flavor), CilFlavor::Unknown));
    }

    #[test]
    fn test_create_type_with_flavor() {
        let registry = TypeRegistry::new().unwrap();

        let class_type = registry.create_type_with_flavor(CilFlavor::Class).unwrap();

        assert_eq!(class_type.namespace, "");
        assert_eq!(class_type.name, "");
        assert!(matches!(*read_lock!(class_type.flavor), CilFlavor::Class));
    }

    #[test]
    fn test_insert() {
        let registry = TypeRegistry::new().unwrap();

        let token = Token::new(0x01000123);
        let new_type = Arc::new(CilType::new(
            token,
            CilFlavor::Class,
            "MyNamespace".to_string(),
            "MyClass".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        ));

        registry.insert(new_type.clone());

        let found = registry.get(&token);
        assert!(found.is_some());
        assert_eq!(found.unwrap().token, token);

        registry.insert(new_type.clone());

        let user_types = registry.types_from_source(TypeSource::CurrentModule);
        assert_eq!(user_types.len(), 1);
    }

    #[test]
    fn test_source_registry() {
        let registry = TypeRegistry::new().unwrap();

        let module = Arc::new(Module {
            token: Token::new(0x00000001),
            name: "MainModule".to_string(),
            mvid: guid!("01234567-89ab-cdef-0123-456789abcdef"),
            encid: None,
            rid: 1,
            offset: 1,
            generation: 0,
            encbaseid: None,
            imports: Vec::new(),
        });

        let module_ref = Arc::new(ModuleRef {
            token: Token::new(0x1A000001),
            name: "ReferenceModule".to_string(),
            rid: 0,
            offset: 0,
        });

        let assembly_ref = Arc::new(AssemblyRef {
            token: Token::new(0x23000001),
            flags: 0,
            name: "ReferenceAssembly".to_string(),
            culture: Some("".to_string()),
            rid: 0,
            offset: 0,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 1,
            identifier: None,
            hash: None,
            os_platform_id: AtomicU32::new(0),
            os_major_version: AtomicU32::new(0),
            os_minor_version: AtomicU32::new(0),
            processor: AtomicU32::new(0),
        });

        let file = Arc::new(File {
            token: Token::new(0x26000001),
            flags: 0,
            name: "ExternalFile.dll".to_string(),
            rid: 0,
            offset: 0,
            hash_value: AssemblyRefHash::new(&[0xCC, 0xCC]).unwrap(),
        });

        let module_source = registry.register_source(&CilTypeReference::Module(module.clone()));
        let module_ref_source =
            registry.register_source(&CilTypeReference::ModuleRef(module_ref.clone()));
        let assembly_ref_source =
            registry.register_source(&CilTypeReference::AssemblyRef(assembly_ref.clone()));
        let file_source = registry.register_source(&CilTypeReference::File(file.clone()));

        assert!(matches!(module_source, TypeSource::Module(_)));
        assert!(matches!(module_ref_source, TypeSource::ModuleRef(_)));
        assert!(matches!(assembly_ref_source, TypeSource::AssemblyRef(_)));
        assert!(matches!(file_source, TypeSource::File(_)));

        if let TypeSource::Module(token) = module_source {
            if let CilTypeReference::Module(ref m) =
                registry.get_source_reference(module_source).unwrap()
            {
                assert_eq!(m.token, token);
            } else {
                panic!("Expected Module reference");
            }
        }

        if let TypeSource::ModuleRef(token) = module_ref_source {
            if let CilTypeReference::ModuleRef(ref m) =
                registry.get_source_reference(module_ref_source).unwrap()
            {
                assert_eq!(m.token, token);
            } else {
                panic!("Expected ModuleRef reference");
            }
        }

        if let TypeSource::AssemblyRef(token) = assembly_ref_source {
            if let CilTypeReference::AssemblyRef(ref a) =
                registry.get_source_reference(assembly_ref_source).unwrap()
            {
                assert_eq!(a.token, token);
            } else {
                panic!("Expected AssemblyRef reference");
            }
        }

        if let TypeSource::File(token) = file_source {
            if let CilTypeReference::File(ref f) =
                registry.get_source_reference(file_source).unwrap()
            {
                assert_eq!(f.token, token);
            } else {
                panic!("Expected File reference");
            }
        }

        let type1 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "System.Collections",
                "ArrayList",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let type2 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "System.Collections",
                "ArrayList",
                module_ref_source,
            )
            .unwrap();

        let type3 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "System.Collections",
                "ArrayList",
                assembly_ref_source,
            )
            .unwrap();

        assert_ne!(type1.token, type2.token);
        assert_ne!(type1.token, type3.token);
        assert_ne!(type2.token, type3.token);

        let types_from_module_ref = registry.types_from_source(module_ref_source);
        assert_eq!(types_from_module_ref.len(), 1);
        assert_eq!(types_from_module_ref[0].token, type2.token);

        let types_from_assembly_ref = registry.types_from_source(assembly_ref_source);
        assert_eq!(types_from_assembly_ref.len(), 1);
        assert_eq!(types_from_assembly_ref[0].token, type3.token);
    }

    #[test]
    fn test_registry_count_and_all_types() {
        let registry = TypeRegistry::new().unwrap();

        let initial_count = registry.len();

        let _ = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "MyNamespace",
                "MyClass1",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let _ = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "MyNamespace",
                "MyClass2",
                TypeSource::CurrentModule,
            )
            .unwrap();

        assert_eq!(registry.len(), initial_count + 2);

        let all_types = registry.all_types();
        assert!(all_types.len() >= initial_count + 2);

        let class1_count = all_types
            .iter()
            .filter(|t| t.name == "MyClass1" && t.namespace == "MyNamespace")
            .count();

        let class2_count = all_types
            .iter()
            .filter(|t| t.name == "MyClass2" && t.namespace == "MyNamespace")
            .count();

        assert_eq!(class1_count, 1);
        assert_eq!(class2_count, 1);
    }

    #[test]
    fn test_type_signature_hash() {
        let registry = TypeRegistry::new().unwrap();

        let source1 = TypeSource::CurrentModule;
        let source2 = TypeSource::AssemblyRef(Token::new(0x23000001));

        let type1 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "System.Collections",
                "ArrayList",
                source1,
            )
            .unwrap();

        let type2 = registry
            .get_or_create_type(
                &mut None,
                CilFlavor::Class,
                "System.Collections",
                "ArrayList",
                source2,
            )
            .unwrap();

        assert_ne!(type1.token, type2.token);
    }

    #[test]
    fn test_token_generation() {
        let registry = TypeRegistry::new().unwrap();

        let token1 = registry.create_type_empty().unwrap().token;
        let token2 = registry.create_type_empty().unwrap().token;
        let token3 = registry.create_type_empty().unwrap().token;

        assert_eq!(token2.value(), token1.value() + 1);
        assert_eq!(token3.value(), token2.value() + 1);
    }

    #[test]
    fn test_get_and_lookup_methods() {
        let registry = TypeRegistry::new().unwrap();

        let bad_token = Token::new(0x01999999);
        assert!(registry.get(&bad_token).is_none());

        let bad_name = registry.get_by_name("DoesNotExist");
        assert!(bad_name.is_empty());

        let bad_namespace = registry.get_by_namespace("NonExistent.Namespace");
        assert!(bad_namespace.is_empty());

        let bad_fullname = registry.get_by_fullname("NonExistent.Namespace.Type");
        assert!(bad_fullname.is_empty());

        let bad_source_name = registry.get_by_source_and_name(
            TypeSource::CurrentModule,
            "NonExistent.Namespace",
            "Type",
        );
        assert!(bad_source_name.is_none());
    }
}
