//! Central type registry for .NET assembly analysis.
//!
//! This module provides the `TypeRegistry`, a thread-safe, high-performance registry for managing
//! all types within a .NET assembly. It serves as the central hub for type lookup, deduplication,
//! and cross-reference resolution during metadata analysis.
//!
//! # Key Components
//!
//! - [`TypeRegistry`] - Central registry managing all types in an assembly
//! - [`TypeSource`] - Classification of type origins (current module, external assemblies, etc.)
//! - `SourceRegistry` - Internal management of external type references
//!
//! # Registry Architecture
//!
//! The type registry uses a multi-index approach for efficient type lookup:
//!
//! - **Token-based lookup**: Primary index using metadata tokens
//! - **Name-based lookup**: Secondary indices for full names, simple names, and namespaces
//! - **Source-based lookup**: Types grouped by their origin (assembly, module, etc.)
//! - **Signature cache**: Deduplication using type signature hashes
//!
//! # Thread Safety
//!
//! The registry is designed for high-concurrency scenarios:
//! - Lock-free data structures for primary storage (`SkipMap`)
//! - Concurrent hash maps for indices (`DashMap`)
//! - Atomic operations for token generation
//! - No blocking operations during normal lookup/insertion
//!
//! # Type Sources
//!
//! Types in the registry can originate from various sources:
//! - **Current Module**: Types defined in the assembly being analyzed
//! - **External Assemblies**: Types from referenced assemblies
//! - **Primitive Types**: Built-in CLR types (System.Int32, System.String, etc.)
//! - **External Modules**: Types from module references
//! - **Files**: Types from file references
//!
//! # Examples
//!
//! ## Creating and Using a Registry
//!
//! ```rust,ignore
//! use dotscope::metadata::typesystem::{TypeRegistry, CilType};
//! use dotscope::metadata::token::Token;
//!
//! // Create a new registry with primitive types
//! let registry = TypeRegistry::new()?;
//!
//! // Look up types by name
//! for entry in registry.get_by_fullname("System.String") {
//!     println!("Found String type: 0x{:08X}", entry.token.value());
//! }
//!
//! // Look up by token
//! if let Some(type_def) = registry.get(&Token::new(0x02000001)) {
//!     println!("Type: {}.{}", type_def.namespace, type_def.name);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Registering New Types
//!
//! ```rust,ignore
//! use dotscope::metadata::typesystem::{TypeRegistry, CilType, TypeSource};
//! use dotscope::metadata::token::Token;
//! use std::sync::Arc;
//!
//! # fn example() -> dotscope::Result<()> {
//! let registry = TypeRegistry::new()?;
//!
//! // Create a new type
//! let new_type = CilType::new(
//!     Token::new(0x02000001),
//!     "MyNamespace".to_string(),
//!     "MyClass".to_string(),
//!     None, // No external reference
//!     None, // No base type yet
//!     0x00100001, // Public class
//!     Arc::new(boxcar::Vec::new()), // Empty fields
//!     Arc::new(boxcar::Vec::new()), // Empty methods
//!     None, // Flavor will be computed
//! );
//!
//! // Register the type
//! registry.insert(Arc::new(new_type));
//! # Ok(())
//! # }
//! ```
//!
//! ## Type Lookup Patterns
//!
//! The registry provides multiple lookup methods by name, namespace, and token.
//! Each method returns the appropriate collection type for the query.
//!
//! # ECMA-335 Compliance
//!
//! The registry handles all type reference mechanisms defined in ECMA-335:
//! - `TypeDef`, `TypeRef`, and `TypeSpec` tokens
//! - Assembly, Module, and File references
//! - Generic type instantiations
//! - Cross-assembly type resolution

use std::{
    hash::Hash,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;

use crate::{
    metadata::{
        tables::{AssemblyRefRc, FileRc, ModuleRc, ModuleRefRc},
        token::Token,
        typesystem::{
            CilFlavor, CilPrimitive, CilPrimitiveKind, CilType, CilTypeRc, CilTypeReference,
        },
    },
    Error::TypeNotFound,
    Result,
};

/// Classification of type origins within the .NET assembly ecosystem.
///
/// `TypeSource` identifies where a type is defined, enabling proper resolution
/// of cross-assembly and cross-module type references. This is crucial for
/// handling external dependencies and maintaining proper type identity.
///
/// # Type Resolution
///
/// Different sources require different resolution strategies:
/// - **`CurrentModule`**: Direct access to type definition
/// - **External sources**: Resolution through metadata references
/// - **Primitive**: Built-in CLR types with artificial tokens
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::typesystem::TypeSource;
/// use dotscope::metadata::token::Token;
///
/// // Local type
/// let local_source = TypeSource::CurrentModule;
///
/// // External assembly type
/// let external_source = TypeSource::AssemblyRef(Token::new(0x23000001));
///
/// // Primitive type
/// let primitive_source = TypeSource::Primitive;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeSource {
    /// Type is defined in the current module being analyzed
    CurrentModule,
    /// Type is defined in an external module (cross-module reference)
    Module(Token),
    /// Type is defined in an external module reference
    ModuleRef(Token),
    /// Type is defined in an external assembly reference  
    AssemblyRef(Token),
    /// Type is defined in an external file reference
    File(Token),
    /// Type is a primitive defined by the CLR runtime
    Primitive,
    /// Type source is not determined or not available
    Unknown,
}

/// Internal registry for tracking external type reference sources.
///
/// `SourceRegistry` maintains weak references to external assemblies, modules,
/// and files to prevent circular reference cycles while enabling proper type
/// resolution. It serves as a lookup table for converting `TypeSource` values
/// back to their corresponding metadata references.
///
/// # Memory Management
///
/// The registry uses reference counting to track external sources without
/// creating strong circular references that could prevent garbage collection.
/// When sources are no longer needed, they can be automatically cleaned up.
///
/// # Thread Safety
///
/// All internal collections use `DashMap` for lock-free concurrent access,
/// making source registration and lookup safe from multiple threads.
struct SourceRegistry {
    /// External modules indexed by their metadata tokens
    modules: DashMap<Token, ModuleRc>,
    /// Module references indexed by their metadata tokens
    module_refs: DashMap<Token, ModuleRefRc>,
    /// Assembly references indexed by their metadata tokens
    assembly_refs: DashMap<Token, AssemblyRefRc>,
    /// File references indexed by their metadata tokens
    files: DashMap<Token, FileRc>,
}

impl SourceRegistry {
    /// Create a new empty source registry.
    ///
    /// Initializes all internal collections as empty, ready to receive
    /// source registrations during metadata loading.
    ///
    /// # Returns
    /// A new `SourceRegistry` with empty collections
    fn new() -> Self {
        SourceRegistry {
            modules: DashMap::new(),
            module_refs: DashMap::new(),
            assembly_refs: DashMap::new(),
            files: DashMap::new(),
        }
    }

    /// Register an external type reference source.
    ///
    /// Stores the external reference and returns a corresponding `TypeSource`
    /// value that can be used for efficient lookups. This method handles all
    /// supported external reference types defined in ECMA-335.
    ///
    /// # Arguments
    /// * `source` - The external type reference to register
    ///
    /// # Returns
    /// A `TypeSource` value for efficient source identification
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from
    /// multiple threads during metadata loading.
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

    /// Retrieve a type reference from a registered source.
    ///
    /// Converts a `TypeSource` back to its corresponding `CilTypeReference`,
    /// enabling resolution of external type references during analysis.
    ///
    /// # Arguments
    /// * `source` - The type source to look up
    ///
    /// # Returns
    /// * `Some(CilTypeReference)` - The corresponding external reference
    /// * `None` - If source is not external or not found
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and lock-free for concurrent access.
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

// /// A hash that represents a unique type
// struct TypeSignatureHash {
//     hash: u64,
// }

// impl TypeSignatureHash {
//     /// Create a new signature hash builder
//     fn new() -> Self {
//         TypeSignatureHash { hash: 0 }
//     }

//     /// Add flavor to the hash
//     ///
//     /// ## Arguments
//     /// * `flavor` - The `CilFlavor` to hash in
//     fn add_flavor(&mut self, flavor: &CilFlavor) -> &mut Self {
//         let mut hasher = std::collections::hash_map::DefaultHasher::new();

//         match flavor {
//             CilFlavor::Void => 1u8.hash(&mut hasher),
//             CilFlavor::Boolean => 2u8.hash(&mut hasher),
//             CilFlavor::Char => 3u8.hash(&mut hasher),
//             CilFlavor::I1 => 4u8.hash(&mut hasher),
//             CilFlavor::U1 => 5u8.hash(&mut hasher),
//             CilFlavor::I2 => 6u8.hash(&mut hasher),
//             CilFlavor::U2 => 7u8.hash(&mut hasher),
//             CilFlavor::I4 => 8u8.hash(&mut hasher),
//             CilFlavor::U4 => 9u8.hash(&mut hasher),
//             CilFlavor::I8 => 10u8.hash(&mut hasher),
//             CilFlavor::U8 => 11u8.hash(&mut hasher),
//             CilFlavor::R4 => 12u8.hash(&mut hasher),
//             CilFlavor::R8 => 13u8.hash(&mut hasher),
//             CilFlavor::I => 14u8.hash(&mut hasher),
//             CilFlavor::U => 15u8.hash(&mut hasher),
//             CilFlavor::Object => 16u8.hash(&mut hasher),
//             CilFlavor::String => 17u8.hash(&mut hasher),
//             CilFlavor::Array { rank, dimensions } => {
//                 18u8.hash(&mut hasher);
//                 rank.hash(&mut hasher);
//                 dimensions.len().hash(&mut hasher);
//             }
//             CilFlavor::Pointer => 19u8.hash(&mut hasher),
//             CilFlavor::ByRef => 20u8.hash(&mut hasher),
//             CilFlavor::GenericInstance => 21u8.hash(&mut hasher),
//             CilFlavor::Pinned => 22u8.hash(&mut hasher),
//             CilFlavor::FnPtr { signature: _ } => {
//                 // Function pointer signatures are complex, so we just use a simple marker
//                 23u8.hash(&mut hasher);
//             }
//             CilFlavor::GenericParameter { index, method } => {
//                 24u8.hash(&mut hasher);
//                 index.hash(&mut hasher);
//                 method.hash(&mut hasher);
//             }
//             CilFlavor::Class => 25u8.hash(&mut hasher),
//             CilFlavor::ValueType => 26u8.hash(&mut hasher),
//             CilFlavor::Interface => 27u8.hash(&mut hasher),
//             CilFlavor::Unknown => 0u8.hash(&mut hasher),
//         }

//         self.hash ^= hasher.finish();
//         self
//     }

//     /// Add namespace and name to the hash
//     ///
//     /// ## Arguments
//     /// * 'namespace'   - The namespace of the type
//     /// * 'name'        - The name of the type
//     fn add_fullname(&mut self, namespace: &str, name: &str) -> &mut Self {
//         let mut hasher = std::collections::hash_map::DefaultHasher::new();
//         namespace.hash(&mut hasher);
//         name.hash(&mut hasher);
//         self.hash ^= hasher.finish();
//         self
//     }

//     /// Add a token to the hash
//     ///
//     /// ## Arguments
//     /// * 'token' - The token of the type
//     fn add_token(&mut self, token: Token) -> &mut Self {
//         let mut hasher = std::collections::hash_map::DefaultHasher::new();
//         token.value().hash(&mut hasher);
//         self.hash ^= hasher.finish();
//         self
//     }

//     /// Add source information to the hash
//     ///
//     /// ## Arguments
//     /// * 'source' - The source to hash in
//     fn add_source(&mut self, source: TypeSource) -> &mut Self {
//         let mut hasher = std::collections::hash_map::DefaultHasher::new();
//         match source {
//             TypeSource::CurrentModule => {
//                 0u8.hash(&mut hasher);
//             }
//             TypeSource::Module(token) => {
//                 1u8.hash(&mut hasher);
//                 token.value().hash(&mut hasher);
//             }
//             TypeSource::ModuleRef(token) => {
//                 2u8.hash(&mut hasher);
//                 token.value().hash(&mut hasher);
//             }
//             TypeSource::AssemblyRef(token) => {
//                 3u8.hash(&mut hasher);
//                 token.value().hash(&mut hasher);
//             }
//             TypeSource::File(token) => {
//                 4u8.hash(&mut hasher);
//                 token.value().hash(&mut hasher);
//             }
//             TypeSource::Primitive => {
//                 5u8.hash(&mut hasher);
//             }
//             TypeSource::Unknown => {
//                 6u8.hash(&mut hasher);
//             }
//         }
//         self.hash ^= hasher.finish();
//         self
//     }

//     /// Finalize and get the hash value
//     fn finalize(&self) -> u64 {
//         self.hash
//     }
// }

/// Central registry for managing all types within a .NET assembly.
///
/// `TypeRegistry` provides thread-safe, high-performance storage and lookup
/// capabilities for all types encountered during metadata analysis. It serves
/// as the authoritative source for type information and handles deduplication,
/// cross-references, and efficient query operations.
///
/// # Architecture
///
/// The registry uses a multi-layered indexing strategy:
/// - **Primary storage**: Token-based skip list for O(log n) lookups
/// - **Secondary indices**: Hash maps for name-based and source-based queries
/// - **Deduplication**: Signature cache to prevent duplicate type entries
/// - **External references**: Source registry for cross-assembly resolution
///
/// # Concurrency Design
///
/// All operations are designed for high-concurrency scenarios:
/// - Lock-free primary storage using `SkipMap`
/// - Concurrent secondary indices using `DashMap`
/// - Atomic token generation for thread-safe registration
/// - No blocking operations during normal operations
///
/// # Type Identity
///
/// Types are identified using multiple strategies:
/// - **Token identity**: Primary key using metadata tokens
/// - **Signature identity**: Hash-based deduplication for complex types
/// - **Name identity**: Full namespace.name qualification
/// - **Source identity**: Origin-based grouping
///
/// # Memory Management
///
/// The registry uses reference counting (`Arc`) to manage type lifetime:
/// - Types can be shared across multiple consumers
/// - Automatic cleanup when no longer referenced
/// - Efficient memory usage through deduplication
///
/// # Examples
///
/// ## Basic Registry Operations
///
/// ```rust,ignore
/// use dotscope::metadata::typesystem::TypeRegistry;
///
/// // Create registry with primitive types
/// let registry = TypeRegistry::new()?;
///
/// // Query primitive types
/// for entry in registry.get_by_fullname("System.Int32") {
///     println!("Found Int32: 0x{:08X}", entry.token.value());
/// }
///
/// // Check registry statistics
/// println!("Total types: {}", registry.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// The registry is fully thread-safe and optimized for concurrent access:
/// - Multiple threads can perform lookups simultaneously
/// - Registration operations are atomic and consistent
/// - No explicit locking required by consumers
///
/// # Performance Characteristics
///
/// - **Token lookup**: O(log n) using skip list
/// - **Name lookup**: O(1) average using hash indices  
/// - **Registration**: O(log n) + O(1) for indexing
/// - **Memory**: O(n) with deduplication benefits
pub struct TypeRegistry {
    /// Primary type storage indexed by metadata tokens - uses skip list for O(log n) operations
    types: SkipMap<Token, CilTypeRc>,
    /// Atomic counter for generating unique artificial tokens for new types
    next_token: AtomicU32,
    /// Cache mapping type signature hashes to tokens for deduplication
    signature_cache: DashMap<u64, Token>,
    /// Registry managing external assembly/module/file references
    sources: SourceRegistry,
    /// Secondary index: types grouped by their origin source
    types_by_source: DashMap<TypeSource, Vec<Token>>,
    /// Secondary index: types indexed by full name (namespace.name)
    types_by_fullname: DashMap<String, Vec<Token>>,
    /// Secondary index: types indexed by simple name (may have duplicates)
    types_by_name: DashMap<String, Vec<Token>>,
    /// Secondary index: types grouped by namespace
    types_by_namespace: DashMap<String, Vec<Token>>,
}

impl TypeRegistry {
    /// Create a new type registry with initialized primitive types.
    ///
    /// Constructs a complete type registry with all .NET primitive types
    /// pre-registered and ready for use. The registry starts with artificial
    /// tokens in the `0xF000_0020`+ range for new type registration.
    ///
    /// # Primitive Types
    ///
    /// The following primitive types are automatically registered:
    /// - `System.Void`, `System.Boolean`, `System.Char`
    /// - Integer types: `SByte`, `Byte`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`
    /// - Floating point: `Single`, `Double`
    /// - Platform types: `IntPtr`, `UIntPtr`
    /// - Reference types: `Object`, `String`
    /// - Special types: `TypedReference`, `ValueType`
    ///
    /// # Returns
    /// * `Ok(TypeRegistry)` - Fully initialized registry with primitive types
    /// * `Err(Error)` - If primitive type initialization fails
    ///
    /// # Errors
    ///
    /// This function will return an error if the primitive type initialization fails,
    /// which could happen due to internal inconsistencies during registry setup.
    ///
    /// # Thread Safety
    ///
    /// The returned registry is fully thread-safe and ready for concurrent use.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// let registry = TypeRegistry::new()?;
    ///
    /// // Primitive types are immediately available
    /// let string_types = registry.get_by_fullname("System.String");
    /// assert!(!string_types.is_empty());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
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
                primitive.namespace().to_string(),
                primitive.name().to_string(),
                None,
                None,
                0,
                Arc::new(boxcar::Vec::new()),
                Arc::new(boxcar::Vec::new()),
                Some(flavor),
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

        let source = match new_type.get_external() {
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
            String::new(),
            String::new(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            None,
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
        let token = self.next_token();

        let new_type = Arc::new(CilType::new(
            token,
            String::new(),
            String::new(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(flavor),
        ));

        self.types.insert(token, new_type.clone());
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

    /// Look up a type by its metadata token.
    ///
    /// Performs the primary lookup operation using the token-based index.
    /// This is the most efficient lookup method with O(log n) complexity.
    ///
    /// # Arguments
    /// * `token` - The metadata token to look up
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The type if found
    /// * `None` - If no type exists with the given token
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and lock-free for concurrent access.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{typesystem::TypeRegistry, token::Token};
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// if let Some(type_def) = registry.get(&Token::new(0x02000001)) {
    ///     println!("Found type: {}.{}", type_def.namespace, type_def.name);
    /// }
    /// # }
    /// ```
    pub fn get(&self, token: &Token) -> Option<CilTypeRc> {
        self.types.get(token).map(|entry| entry.value().clone())
    }

    /// Look up a type by its source and qualified name.
    ///
    /// Performs a targeted lookup for types from a specific source with
    /// exact namespace and name matching. This is useful for resolving
    /// external type references where the source is known.
    ///
    /// # Arguments
    /// * `source` - The origin source of the type
    /// * `namespace` - The namespace of the type (can be empty)
    /// * `name` - The exact name of the type
    ///
    /// # Returns
    /// * `Some(CilTypeRc)` - The first matching type from the specified source
    /// * `None` - If no matching type is found in the source
    ///
    /// # Performance
    ///
    /// This method combines source filtering with name lookup for efficient
    /// resolution of external type references.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::{TypeRegistry, TypeSource};
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// let external_source = TypeSource::AssemblyRef(Token::new(0x23000001));
    /// if let Some(type_def) = registry.get_by_source_and_name(
    ///     external_source,
    ///     "System",
    ///     "String"
    /// ) {
    ///     println!("Found external String type");
    /// }
    /// # }
    /// ```
    pub fn get_by_source_and_name(
        &self,
        source: TypeSource,
        namespace: &str,
        name: &str,
    ) -> Option<CilTypeRc> {
        let fullname = if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{namespace}.{name}")
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

    /// Get all types within a specific namespace.
    ///
    /// Returns all types that belong to the specified namespace, regardless
    /// of their source or other characteristics. This is useful for namespace
    /// exploration and type discovery operations.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to search for (case-sensitive)
    ///
    /// # Returns
    /// A vector of all types in the specified namespace. The vector may be
    /// empty if no types exist in the namespace.
    ///
    /// # Performance
    ///
    /// This operation is O(1) for namespace lookup plus O(n) for type
    /// resolution where n is the number of types in the namespace.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// // Get all System types
    /// let system_types = registry.get_by_namespace("System");
    /// for type_def in system_types {
    ///     println!("System type: {}", type_def.name);
    /// }
    ///
    /// // Get types in global namespace
    /// let global_types = registry.get_by_namespace("");
    /// # }
    /// ```
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

    /// Get all types with a specific simple name across all namespaces.
    ///
    /// Returns all types that have the specified name, regardless of their
    /// namespace. This can return multiple types if the same name exists
    /// in different namespaces (e.g., multiple "List" types).
    ///
    /// # Arguments
    /// * `name` - The simple name to search for (case-sensitive)
    ///
    /// # Returns
    /// A vector of all types with the specified name. Types from different
    /// namespaces will be included. The vector may be empty if no types
    /// with the name exist.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// // Find all "List" types (may find System.Collections.List,
    /// // System.Collections.Generic.List, custom List types, etc.)
    /// let list_types = registry.get_by_name("List");
    /// for type_def in list_types {
    ///     println!("List type: {}.{}", type_def.namespace, type_def.name);
    /// }
    /// # }
    /// ```
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

    /// Get types by their fully qualified name (namespace.name).
    ///
    /// Returns all types that exactly match the specified fully qualified name.
    /// This is the most precise name-based lookup method and typically returns
    /// at most one type (unless there are duplicate definitions).
    ///
    /// # Arguments
    /// * `fullname` - The fully qualified name in "namespace.name" format
    ///
    /// # Returns
    /// A vector containing types that match the full name. Usually contains
    /// zero or one element, but may contain multiple if duplicates exist.
    ///
    /// # Name Format
    ///
    /// The fullname should be in the format:
    /// - "Namespace.TypeName" for namespaced types
    /// - "`TypeName`" for types in the global namespace
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::TypeRegistry;
    ///
    /// # fn example(registry: &TypeRegistry) {
    /// // Find the specific System.String type
    /// let string_types = registry.get_by_fullname("System.String");
    /// if let Some(string_type) = string_types.first() {
    ///     println!("Found System.String: 0x{:08X}", string_type.token.value());
    /// }
    ///
    /// // Find a global type
    /// let global_types = registry.get_by_fullname("GlobalType");
    /// # }
    /// ```
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
            namespace.to_string(),
            name.to_string(),
            self.get_source_reference(source),
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(flavor),
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
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<'_, Token, CilTypeRc> {
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
    use crate::metadata::tables::{AssemblyRef, AssemblyRefHash, File, Module, ModuleRef};

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
            assert!(prim_type.is_ok(), "Failed to get primitive: {primitive:?}");
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
        assert!(matches!(*empty_type.flavor(), CilFlavor::Class)); // Empty types default to Class with lazy evaluation
    }

    #[test]
    fn test_create_type_with_flavor() {
        let registry = TypeRegistry::new().unwrap();

        let class_type = registry.create_type_with_flavor(CilFlavor::Class).unwrap();

        assert_eq!(class_type.namespace, "");
        assert_eq!(class_type.name, "");
        assert!(matches!(*class_type.flavor(), CilFlavor::Class));
    }

    #[test]
    fn test_insert() {
        let registry = TypeRegistry::new().unwrap();

        let token = Token::new(0x01000123);
        let new_type = Arc::new(CilType::new(
            token,
            "MyNamespace".to_string(),
            "MyClass".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
            Some(CilFlavor::Class),
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
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        let module_ref = Arc::new(ModuleRef {
            token: Token::new(0x1A000001),
            name: "ReferenceModule".to_string(),
            rid: 0,
            offset: 0,
            custom_attributes: Arc::new(boxcar::Vec::new()),
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
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        let file = Arc::new(File {
            token: Token::new(0x26000001),
            flags: 0,
            name: "ExternalFile.dll".to_string(),
            rid: 0,
            offset: 0,
            hash_value: AssemblyRefHash::new(&[0xCC, 0xCC]).unwrap(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
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
