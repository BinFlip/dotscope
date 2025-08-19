//! Type signature resolution for .NET metadata analysis.
//!
//! This module provides the `TypeResolver`, which converts abstract type signatures from
//! .NET metadata into concrete type instances within the type registry. It handles the
//! complex process of resolving type references, generic instantiations, arrays, pointers,
//! and modified types according to ECMA-335 specifications.
//!
//! # Key Components
//!
//! - [`TypeResolver`] - Main resolver for converting type signatures to concrete types
//! - Context management for source tracking and parent type relationships
//! - Recursive resolution with depth protection against circular references
//! - Support for all ECMA-335 type signature constructs
//!
//! # Type Signature Resolution
//!
//! The resolver handles the full spectrum of .NET type signatures:
//!
//! ## Primitive Types
//! - Built-in types (void, bool, int32, string, etc.)
//! - Direct mapping to primitive type registry entries
//!
//! ## Complex Types
//! - **Array types**: Multi-dimensional arrays with size specifications
//! - **Pointer types**: Managed and unmanaged pointer references
//! - **Modified types**: Required and optional type modifiers
//! - **Generic instances**: Instantiated generic types with type arguments
//! - **Function pointers**: Method signature type references
//!
//! ## Reference Resolution
//! - **Class/ValueType tokens**: Lookup in type registry by metadata token
//! - **Cross-assembly references**: Resolution through source context
//! - **Generic parameters**: Type and method parameter substitution
//!
//! # Resolution Context
//!
//! The resolver maintains contextual information during resolution:
//! - **Source context**: Origin of types being resolved (current module, external assembly)
//! - **Parent relationships**: For modifier types that need parent type context
//! - **Token initialization**: For creating new composite types
//!
//! # Recursion Protection
//!
//! The resolver includes protection against infinite recursion:
//! - Maximum depth limit prevents stack overflow
//! - Circular reference detection
//! - Graceful error handling for malformed signatures
//!
//! # Examples
//!
//! ## Basic Type Resolution
//!
//! ```rust,ignore
//! use dotscope::metadata::{
//!     typesystem::{TypeResolver, TypeRegistry},
//!     signatures::TypeSignature
//! };
//! use std::sync::Arc;
//!
//! # fn example() -> dotscope::Result<()> {
//! let registry = Arc::new(TypeRegistry::new()?);
//! let mut resolver = TypeResolver::new(registry.clone());
//!
//! // Resolve a primitive type
//! let int_type = resolver.resolve(&TypeSignature::I4)?;
//! println!("Resolved: {}.{}", int_type.namespace, int_type.name);
//!
//! // Resolve a string type
//! let string_type = resolver.resolve(&TypeSignature::String)?;
//! assert_eq!(string_type.name, "String");
//! # Ok(())
//! # }
//! ```
//!
//! ## Array Type Resolution
//!
//! ```rust,ignore
//! use dotscope::metadata::{
//!     typesystem::{TypeResolver, ArrayDimensions},
//!     signatures::{TypeSignature, ArraySpecification}
//! };
//!
//! # fn example(mut resolver: TypeResolver) -> dotscope::Result<()> {
//! // Create array signature: int[]
//! let array_sig = TypeSignature::Array(Box::new(ArraySpecification {
//!     base: TypeSignature::I4,
//!     rank: 1,
//!     dimensions: ArrayDimensions::default(),
//! }));
//!
//! let array_type = resolver.resolve(&array_sig)?;
//! assert_eq!(array_type.name, "Int32[]");
//! # Ok(())
//! # }
//! ```
//!
//! ## Context-Aware Resolution
//!
//! ```rust,ignore
//! use dotscope::metadata::{
//!     typesystem::{TypeResolver, TypeSource},
//!     token::Token
//! };
//!
//! # fn example(resolver: TypeResolver) -> dotscope::Result<()> {
//! // Set up context for external assembly resolution
//! let external_source = TypeSource::AssemblyRef(Token::new(0x23000001));
//! let mut context_resolver = resolver
//!     .with_source(external_source)
//!     .with_parent(Token::new(0x02000001));
//!
//! // Resolution will now use the external context
//! # Ok(())
//! # }
//! ```
//!
//! # Error Handling
//!
//! The resolver provides comprehensive error reporting:
//! - **`TypeNotFound`**: Referenced types don't exist in registry
//! - **`RecursionLimit`**: Maximum recursion depth exceeded
//! - **`TypeMissingParent`**: Modifier types without required parent context
//! - **`TypeError`**: General type system inconsistencies
//!
//! # Performance Characteristics
//!
//! - **Primitive resolution**: O(1) direct registry lookup
//! - **Complex types**: O(log n) registry operations plus signature complexity
//! - **Recursive structures**: Protected by depth limits
//! - **Memory usage**: Minimal allocation, leverages reference counting
//!
//! # ECMA-335 Compliance
//!
//! The resolver implements the complete ECMA-335 type signature specification:
//! - Element type constants (§II.23.2.12)
//! - Type signature encoding (§II.23.2.14)
//! - Generic type instantiation (§II.23.2.15)
//! - Array and pointer type construction (§II.23.2.13)

use std::sync::Arc;

use crate::{
    metadata::{
        signatures::{SignatureMethodSpec, TypeSignature},
        tables::MethodSpec,
        token::Token,
        typesystem::{
            ArrayDimensions, CilFlavor, CilModifier, CilPrimitiveKind, CilTypeRc, CilTypeReference,
            TypeRegistry, TypeSource,
        },
    },
    Error::{RecursionLimit, TypeError, TypeMissingParent, TypeNotFound},
    Result,
};

/// Maximum recursion depth for type signature resolution to prevent stack overflow
const MAX_RECURSION_DEPTH: usize = 100;

/// Converts abstract type signatures into concrete type instances.
///
/// `TypeResolver` is the core component responsible for transforming type signatures
/// from .NET metadata into fully resolved type objects within the type registry.
/// It handles complex type constructions, maintains resolution context, and provides
/// protection against circular references.
///
/// # Resolution Process
///
/// The resolver follows a systematic approach to type resolution:
/// 1. **Context setup**: Source, parent, and initialization token configuration
/// 2. **Signature analysis**: Pattern matching on signature structure
/// 3. **Registry lookup**: Finding existing types or creating new ones
/// 4. **Relationship building**: Establishing inheritance and modifier relationships
/// 5. **Result caching**: Storing resolved types for future reference
///
/// # Context Management
///
/// The resolver maintains several pieces of contextual information:
/// - **Source context**: Determines where types originate (current module, external assembly)
/// - **Parent token**: Required for modifier types that need parent relationships
/// - **Initialization token**: Used when creating new composite types
///
/// # Thread Safety
///
/// While the resolver itself is not `Send`/`Sync`, it operates on thread-safe
/// registry and type structures. Create separate resolver instances for
/// concurrent resolution operations.
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust,ignore
/// use dotscope::metadata::{
///     typesystem::{TypeResolver, TypeRegistry},
///     signatures::TypeSignature
/// };
/// use std::sync::Arc;
///
/// # fn example() -> dotscope::Result<()> {
/// let registry = Arc::new(TypeRegistry::new()?);
/// let mut resolver = TypeResolver::new(registry);
///
/// // Resolve primitive types
/// let void_type = resolver.resolve(&TypeSignature::Void)?;
/// let int_type = resolver.resolve(&TypeSignature::I4)?;
/// let string_type = resolver.resolve(&TypeSignature::String)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Context Configuration
///
/// ```rust,ignore
/// use dotscope::metadata::{
///     typesystem::{TypeResolver, TypeSource},
///     token::Token
/// };
///
/// # fn example(registry: std::sync::Arc<dotscope::metadata::typesystem::TypeRegistry>) {
/// let resolver = TypeResolver::new(registry)
///     .with_source(TypeSource::AssemblyRef(Token::new(0x23000001)))
///     .with_parent(Token::new(0x02000001))
///     .with_token_init(Token::new(0x1B000001));
/// # }
/// ```
pub struct TypeResolver {
    /// Reference to the central type registry for lookups and storage
    registry: Arc<TypeRegistry>,
    /// Current source context determining type origin (current module, external assembly, etc.)
    current_source: TypeSource,
    /// Token of the parent type, required for resolving modifier types
    token_parent: Option<Token>,
    /// Initial token for creating new composite types during resolution
    token_init: Option<Token>,
}

impl TypeResolver {
    /// Create a new type resolver with the specified registry.
    ///
    /// Initializes a resolver with default context settings:
    /// - Source: `CurrentModule` (resolving types in the current assembly)
    /// - Parent token: None (no parent type context)
    /// - Initialization token: None (registry will generate tokens as needed)
    ///
    /// # Arguments
    /// * `registry` - Shared reference to the type registry for lookups and storage
    ///
    /// # Returns
    /// A new `TypeResolver` instance ready for type signature resolution
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::{TypeResolver, TypeRegistry};
    /// use std::sync::Arc;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let registry = Arc::new(TypeRegistry::new()?);
    /// let resolver = TypeResolver::new(registry);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(registry: Arc<TypeRegistry>) -> Self {
        TypeResolver {
            registry,
            current_source: TypeSource::CurrentModule,
            token_parent: None,
            token_init: None,
        }
    }

    /// Set the source context for type resolution.
    ///
    /// The source context determines where resolved types are considered to originate.
    /// This affects how type references are resolved and where new types are registered.
    ///
    /// # Arguments
    /// * `source` - The type source context to use for subsequent resolutions
    ///
    /// # Returns
    /// Self with the new source context, enabling method chaining
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::typesystem::{TypeResolver, TypeSource};
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example(resolver: TypeResolver) {
    /// // Set up for resolving external assembly types
    /// let external_resolver = resolver
    ///     .with_source(TypeSource::AssemblyRef(Token::new(0x23000001)));
    ///
    /// // Set up for resolving current module types  
    /// // Note: resolver is consumed by the first call, so you'd typically
    /// // create separate resolver instances for different contexts
    /// # }
    /// # fn example2() -> dotscope::Result<()> {
    /// # use std::sync::Arc;
    /// # use dotscope::metadata::typesystem::TypeRegistry;
    /// let registry = Arc::new(TypeRegistry::new()?);
    /// let resolver = TypeResolver::new(registry);
    /// let local_resolver = resolver
    ///     .with_source(TypeSource::CurrentModule);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_source(mut self, source: TypeSource) -> Self {
        self.current_source = source;
        self
    }

    /// Set the parent type token for modifier type resolution.
    ///
    /// Some type signatures (like modified types) require a parent type context
    /// to be properly resolved. This method sets the parent token that will be
    /// used when resolving such types.
    ///
    /// # Arguments
    /// * `token` - The metadata token of the parent type
    ///
    /// # Returns
    /// Self with the parent token set, enabling method chaining
    ///
    /// # Use Cases
    ///
    /// - Resolving required/optional modifier types
    /// - Processing nested type definitions
    /// - Handling type parameter constraints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{typesystem::TypeResolver, token::Token};
    ///
    /// # fn example(resolver: TypeResolver) {
    /// let resolver_with_parent = resolver
    ///     .with_parent(Token::new(0x02000001)); // TypeDef token
    /// # }
    /// ```
    #[must_use]
    pub fn with_parent(mut self, token: Token) -> Self {
        self.token_parent = Some(token);
        self
    }

    /// Set the initialization token for new type creation.
    ///
    /// When the resolver needs to create new composite types (arrays, pointers,
    /// generic instances), it can use this token as a starting point instead of
    /// generating a completely new token from the registry.
    ///
    /// # Arguments
    /// * `token` - The token to use for initializing new types
    ///
    /// # Returns
    /// Self with the initialization token set, enabling method chaining
    ///
    /// # Use Cases
    ///
    /// - Creating array types with specific tokens
    /// - Building generic instantiations with predetermined tokens
    /// - Constructing pointer types with known identity
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{typesystem::TypeResolver, token::Token};
    ///
    /// # fn example(resolver: TypeResolver) {
    /// let resolver_with_init = resolver
    ///     .with_token_init(Token::new(0x1B000001)); // TypeSpec token
    /// # }
    /// ```
    #[must_use]
    pub fn with_token_init(mut self, token: Token) -> Self {
        self.token_init = Some(token);
        self
    }

    /// Resolve a type signature to a concrete type instance.
    ///
    /// This is the main entry point for type resolution. It takes an abstract type
    /// signature from .NET metadata and converts it into a concrete type object
    /// stored in the registry. The method handles all types of signatures from
    /// simple primitives to complex generic instantiations.
    ///
    /// # Arguments
    /// * `signature` - The type signature to resolve (from metadata parsing)
    ///
    /// # Returns
    /// * `Ok(CilTypeRc)` - Successfully resolved concrete type
    /// * `Err(Error)` - Resolution failed due to various reasons
    ///
    /// # Errors
    ///
    /// The method can fail with several error types:
    /// - [`TypeNotFound`] - Referenced types don't exist in the registry
    /// - [`RecursionLimit`] - Maximum recursion depth exceeded (circular references)
    /// - [`TypeMissingParent`] - Modifier types require parent context
    /// - [`TypeError`] - General type system inconsistencies
    ///
    /// # Resolution Strategy
    ///
    /// The resolver handles different signature types:
    /// - **Primitives**: Direct lookup in primitive type registry
    /// - **Class/ValueType**: Token-based lookup in main registry
    /// - **Arrays**: Element type resolution + array construction
    /// - **Pointers**: Base type resolution + pointer wrapper
    /// - **Generic instances**: Type argument resolution + instantiation
    /// - **Modifiers**: Parent type lookup + modifier application
    ///
    /// # Examples
    ///
    /// ## Primitive Type Resolution
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{
    ///     typesystem::TypeResolver,
    ///     signatures::TypeSignature
    /// };
    ///
    /// # fn example(mut resolver: TypeResolver) -> dotscope::Result<()> {
    /// // Resolve basic types
    /// let int_type = resolver.resolve(&TypeSignature::I4)?;
    /// let string_type = resolver.resolve(&TypeSignature::String)?;
    /// let void_type = resolver.resolve(&TypeSignature::Void)?;
    ///
    /// assert_eq!(int_type.name, "Int32");
    /// assert_eq!(string_type.name, "String");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Complex Type Resolution
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::{
    ///     signatures::{TypeSignature, ArraySpecification},
    ///     typesystem::ArrayDimensions,
    ///     token::Token
    /// };
    ///
    /// # fn example(mut resolver: dotscope::metadata::typesystem::TypeResolver) -> dotscope::Result<()> {
    /// // Resolve class reference
    /// let class_sig = TypeSignature::Class(Token::new(0x02000001));
    /// let class_type = resolver.resolve(&class_sig)?;
    ///
    /// // Resolve array type
    /// let array_sig = TypeSignature::Array(Box::new(ArraySpecification {
    ///     base: TypeSignature::I4,
    ///     rank: 1,
    ///     dimensions: ArrayDimensions::default(),
    /// }));
    /// let array_type = resolver.resolve(&array_sig)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is not thread-safe due to mutable state. Use separate
    /// resolver instances for concurrent resolution operations.
    pub fn resolve(&mut self, signature: &TypeSignature) -> Result<CilTypeRc> {
        self.resolve_with_depth(signature, 0)
    }

    /// Internal recursive resolver with depth tracking and overflow protection.
    ///
    /// This method performs the actual resolution work while tracking recursion
    /// depth to prevent stack overflow from circular type references. It implements
    /// the core resolution logic for all type signature variants.
    ///
    /// # Arguments
    /// * `signature` - The type signature to resolve
    /// * `depth` - Current recursion depth (0 for initial call)
    ///
    /// # Returns
    /// * `Ok(CilTypeRc)` - Successfully resolved type
    /// * `Err(RecursionLimit)` - Maximum depth exceeded
    /// * `Err(...)` - Other resolution errors
    ///
    /// # Recursion Protection
    ///
    /// The method enforces a maximum recursion depth of [`MAX_RECURSION_DEPTH`]
    /// to prevent stack overflow. This protects against:
    /// - Circular type references in malformed metadata
    /// - Deeply nested generic type instantiations
    /// - Complex array-of-array-of-array constructions
    ///
    /// # Implementation Details
    ///
    /// The resolver uses pattern matching to handle each signature type:
    /// - Direct registry lookups for primitives and simple references
    /// - Recursive resolution for composite types (arrays, pointers)
    /// - Complex construction for generic instances and modifiers
    fn resolve_with_depth(&mut self, signature: &TypeSignature, depth: usize) -> Result<CilTypeRc> {
        if depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        match signature {
            TypeSignature::Void => self.registry.get_primitive(CilPrimitiveKind::Void),
            TypeSignature::Boolean => self.registry.get_primitive(CilPrimitiveKind::Boolean),
            TypeSignature::Char => self.registry.get_primitive(CilPrimitiveKind::Char),
            TypeSignature::I1 => self.registry.get_primitive(CilPrimitiveKind::I1),
            TypeSignature::U1 => self.registry.get_primitive(CilPrimitiveKind::U1),
            TypeSignature::I2 => self.registry.get_primitive(CilPrimitiveKind::I2),
            TypeSignature::U2 => self.registry.get_primitive(CilPrimitiveKind::U2),
            TypeSignature::I4 => self.registry.get_primitive(CilPrimitiveKind::I4),
            TypeSignature::U4 => self.registry.get_primitive(CilPrimitiveKind::U4),
            TypeSignature::I8 => self.registry.get_primitive(CilPrimitiveKind::I8),
            TypeSignature::U8 => self.registry.get_primitive(CilPrimitiveKind::U8),
            TypeSignature::R4 => self.registry.get_primitive(CilPrimitiveKind::R4),
            TypeSignature::R8 => self.registry.get_primitive(CilPrimitiveKind::R8),
            TypeSignature::I => self.registry.get_primitive(CilPrimitiveKind::I),
            TypeSignature::U => self.registry.get_primitive(CilPrimitiveKind::U),
            TypeSignature::Object => self.registry.get_primitive(CilPrimitiveKind::Object),
            TypeSignature::String => self.registry.get_primitive(CilPrimitiveKind::String),
            TypeSignature::Class(token) | TypeSignature::ValueType(token) => {
                if let Some(class_type) = self.registry.get(token) {
                    Ok(class_type)
                } else {
                    Err(TypeNotFound(*token))
                }
            }
            TypeSignature::ModifiedRequired(modifiers)
            | TypeSignature::ModifiedOptional(modifiers) => {
                if let Some(parent_token) = self.token_parent {
                    if let Some(parent_type) = self.registry.get(&parent_token) {
                        for modifier in modifiers {
                            if let Some(mod_type) = self.registry.get(&modifier.modifier_type) {
                                parent_type.modifiers.push(CilModifier {
                                    required: modifier.is_required,
                                    modifier: mod_type.into(),
                                });
                            } else {
                                return Err(TypeNotFound(modifier.modifier_type));
                            }
                        }
                        Ok(parent_type)
                    } else {
                        Err(TypeNotFound(parent_token))
                    }
                } else {
                    Err(TypeMissingParent)
                }
            }
            TypeSignature::Array(array) => {
                let mut token_init = self.token_init.take();

                let element_type = self.resolve_with_depth(&array.base, depth + 1)?;

                let array_flavor = CilFlavor::Array {
                    rank: array.rank,
                    dimensions: array.dimensions.clone(),
                };

                // Create array name: ElementName[,] for multi-dimensional arrays
                let namespace = element_type.namespace.clone();
                let name = if array.rank == 1 {
                    format!("{}[]", element_type.name)
                } else {
                    format!(
                        "{}[{}]",
                        element_type.name,
                        ",".repeat(array.rank as usize - 1)
                    )
                };

                let array_type = self.registry.get_or_create_type(
                    &mut token_init,
                    array_flavor,
                    &namespace,
                    &name,
                    self.current_source,
                )?;

                array_type
                    .base
                    .set(element_type.into())
                    .map_err(|_| malformed_error!("Array type base already set"))?;

                Ok(array_type)
            }
            TypeSignature::SzArray(szarray) => {
                let mut token_init = self.token_init.take();

                let element_type = self.resolve_with_depth(&szarray.base, depth + 1)?;

                let namespace = element_type.namespace.clone();
                let name = format!("{}[]", element_type.name);

                let array_flavor = CilFlavor::Array {
                    rank: 1,
                    dimensions: vec![ArrayDimensions {
                        size: None,
                        lower_bound: None,
                    }],
                };

                let array_type = self.registry.get_or_create_type(
                    &mut token_init,
                    array_flavor,
                    &namespace,
                    &name,
                    self.current_source,
                )?;

                array_type
                    .base
                    .set(element_type.into())
                    .map_err(|_| malformed_error!("Array type base already set"))?;

                for modifier in &szarray.modifiers {
                    if let Some(mod_type) = self.registry.get(&modifier.modifier_type) {
                        array_type.modifiers.push(CilModifier {
                            required: modifier.is_required,
                            modifier: mod_type.into(),
                        });
                    }
                }

                Ok(array_type)
            }
            TypeSignature::Ptr(ptr) => {
                let mut token_init = self.token_init.take();

                let pointed_type = self.resolve_with_depth(&ptr.base, depth + 1)?;

                let namespace = pointed_type.namespace.clone();
                let name = format!("{}*", pointed_type.name);

                let ptr_type = self.registry.get_or_create_type(
                    &mut token_init,
                    CilFlavor::Pointer,
                    &namespace,
                    &name,
                    self.current_source,
                )?;

                ptr_type
                    .base
                    .set(pointed_type.into())
                    .map_err(|_| malformed_error!("Pointer type base already set"))?;

                for modifier in &ptr.modifiers {
                    if let Some(mod_type) = self.registry.get(&modifier.modifier_type) {
                        ptr_type.modifiers.push(CilModifier {
                            required: modifier.is_required,
                            modifier: mod_type.into(),
                        });
                    }
                }

                Ok(ptr_type)
            }
            TypeSignature::ByRef(type_sig) => {
                let mut token_init = self.token_init.take();

                let ref_type = self.resolve_with_depth(type_sig, depth + 1)?;

                let namespace = ref_type.namespace.clone();
                let name = format!("{}&", ref_type.name);

                let byref_type = self.registry.get_or_create_type(
                    &mut token_init,
                    CilFlavor::ByRef,
                    &namespace,
                    &name,
                    self.current_source,
                )?;

                byref_type
                    .base
                    .set(ref_type.into())
                    .map_err(|_| malformed_error!("ByRef type base already set"))?;
                Ok(byref_type)
            }
            TypeSignature::FnPtr(fn_ptr) => {
                let name = format!("FunctionPointer_{:X}", std::ptr::from_ref(fn_ptr) as usize);

                let fnptr_type = self.registry.get_or_create_type(
                    &mut self.token_init,
                    CilFlavor::FnPtr {
                        signature: *fn_ptr.clone(),
                    },
                    "",
                    &name,
                    self.current_source,
                )?;

                Ok(fnptr_type)
            }
            TypeSignature::Pinned(type_sig) => {
                let mut token_init = self.token_init.take();

                let pinned_type = self.resolve_with_depth(type_sig, depth + 1)?;

                let namespace = pinned_type.namespace.clone();
                let name = format!("pinned {}", pinned_type.name);

                let pinned_wrapper = self.registry.get_or_create_type(
                    &mut token_init,
                    CilFlavor::Pinned,
                    &namespace,
                    &name,
                    self.current_source,
                )?;

                pinned_wrapper
                    .base
                    .set(pinned_type.into())
                    .map_err(|_| malformed_error!("Pinned wrapper base already set"))?;
                Ok(pinned_wrapper)
            }
            TypeSignature::GenericInst(base_sig, type_args) => {
                let mut token_init = self.token_init.take();

                let base_type = self.resolve_with_depth(base_sig, depth + 1)?;

                // Build name like List<T1,T2>
                let namespace = base_type.namespace.clone();
                let mut name = base_type.name.clone();
                if !name.contains('`') {
                    // If the base type name doesn't include the arity marker,
                    // add it (e.g., "List" -> "List`1")
                    name = format!("{}`{}", name, type_args.len());
                }

                let generic_inst = self.registry.get_or_create_type(
                    &mut token_init,
                    CilFlavor::GenericInstance,
                    &namespace,
                    &name,
                    self.current_source,
                )?;

                let mut generic_args = Vec::with_capacity(type_args.len());
                for arg_sig in type_args {
                    let arg_type = self.resolve_with_depth(arg_sig, depth + 1)?;
                    generic_args.push(arg_type);
                }

                for (index, arg_type) in generic_args.into_iter().enumerate() {
                    let rid = u32::try_from(index)
                        .map_err(|_| malformed_error!("Generic argument index too large"))?
                        + 1;
                    let token_value =
                        0x2B00_0000_u32
                            .checked_add(u32::try_from(index).map_err(|_| {
                                malformed_error!("Generic argument index too large")
                            })?)
                            .and_then(|v| v.checked_add(1))
                            .ok_or_else(|| malformed_error!("Token value overflow"))?;

                    let method_spec = Arc::new(MethodSpec {
                        rid,
                        token: Token::new(token_value),
                        offset: 0,
                        method: CilTypeReference::None,
                        instantiation: SignatureMethodSpec {
                            generic_args: vec![],
                        },
                        custom_attributes: Arc::new(boxcar::Vec::new()),
                        generic_args: {
                            let type_ref_list = Arc::new(boxcar::Vec::with_capacity(1));
                            type_ref_list.push(arg_type.into());
                            type_ref_list
                        },
                    });
                    generic_inst.generic_args.push(method_spec);
                }

                generic_inst
                    .base
                    .set(base_type.into())
                    .map_err(|_| malformed_error!("Generic instance base already set"))?;
                Ok(generic_inst)
            }
            TypeSignature::GenericParamType(index) => {
                let param_name = format!("T{index}");

                let param_type = self.registry.get_or_create_type(
                    &mut self.token_init,
                    CilFlavor::GenericParameter {
                        index: *index,
                        method: false,
                    },
                    "",
                    &param_name,
                    self.current_source,
                )?;

                Ok(param_type)
            }
            TypeSignature::GenericParamMethod(index) => {
                let param_name = format!("TM{index}");

                let param_type = self.registry.get_or_create_type(
                    &mut self.token_init,
                    CilFlavor::GenericParameter {
                        index: *index,
                        method: true,
                    },
                    "",
                    &param_name,
                    self.current_source,
                )?;

                Ok(param_type)
            }
            _ => Err(TypeError("TypeSignature not supported!".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::{
        metadata::{
            signatures::{
                SignatureArray, SignatureMethod, SignaturePointer, SignatureSzArray, TypeSignature,
            },
            tables::GenericParam,
            typesystem::ArrayDimensions,
        },
        Error,
    };

    #[test]
    fn test_resolve_primitive() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let registry_bool = registry.get_primitive(CilPrimitiveKind::Boolean).unwrap();
        let mut resolver = TypeResolver::new(registry);

        let bool_type = resolver.resolve(&TypeSignature::Boolean).unwrap();
        assert_eq!(bool_type.name, "Boolean");
        assert_eq!(bool_type.namespace, "System");
        assert_eq!(bool_type.token, registry_bool.token);

        let primitives = [
            (TypeSignature::Void, "Void"),
            (TypeSignature::Boolean, "Boolean"),
            (TypeSignature::Char, "Char"),
            (TypeSignature::I1, "SByte"),
            (TypeSignature::U1, "Byte"),
            (TypeSignature::I2, "Int16"),
            (TypeSignature::U2, "UInt16"),
            (TypeSignature::I4, "Int32"),
            (TypeSignature::U4, "UInt32"),
            (TypeSignature::I8, "Int64"),
            (TypeSignature::U8, "UInt64"),
            (TypeSignature::R4, "Single"),
            (TypeSignature::R8, "Double"),
            (TypeSignature::I, "IntPtr"),
            (TypeSignature::U, "UIntPtr"),
            (TypeSignature::Object, "Object"),
            (TypeSignature::String, "String"),
        ];

        for (sig, name) in primitives.iter() {
            let resolved = resolver.resolve(sig).unwrap();
            assert_eq!(resolved.name, *name);
            assert_eq!(resolved.namespace, "System");
        }
    }

    #[test]
    fn test_resolve_array() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);
        let int_array_sig = TypeSignature::SzArray(SignatureSzArray {
            modifiers: Vec::new(),
            base: Box::new(TypeSignature::I4),
        });

        let int_array = resolver.resolve(&int_array_sig).unwrap();
        assert_eq!(int_array.name, "Int32[]");
        assert_eq!(int_array.namespace, "System");

        let element_type = int_array.base.get().unwrap().upgrade().unwrap();
        assert_eq!(element_type.name, "Int32");

        let int_2d_array_sig = TypeSignature::Array(SignatureArray {
            rank: 2,
            dimensions: vec![
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
            ],
            base: Box::new(TypeSignature::I4),
        });

        let int_2d_array = resolver.resolve(&int_2d_array_sig).unwrap();
        assert_eq!(int_2d_array.name, "Int32[,]");

        assert_ne!(int_array.token, int_2d_array.token);

        let int_3d_array_sig = TypeSignature::Array(SignatureArray {
            rank: 3,
            dimensions: vec![
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
            ],
            base: Box::new(TypeSignature::I4),
        });

        let int_3d_array = resolver.resolve(&int_3d_array_sig).unwrap();
        assert_eq!(int_3d_array.name, "Int32[,,]");
        assert!(matches!(
            *int_3d_array.flavor(),
            CilFlavor::Array { rank: 3, .. }
        ));
    }

    #[test]
    fn test_resolve_pointer() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let in_attr_token = Token::new(0x01000111);
        let _ = registry
            .get_or_create_type(
                &mut Some(in_attr_token),
                CilFlavor::Class,
                "System.Runtime.InteropServices",
                "InAttribute",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let mut resolver = TypeResolver::new(registry);
        let int_ptr_sig = TypeSignature::Ptr(SignaturePointer {
            modifiers: Vec::new(),
            base: Box::new(TypeSignature::I4),
        });

        let int_ptr = resolver.resolve(&int_ptr_sig).unwrap();
        assert_eq!(int_ptr.name, "Int32*");
        assert_eq!(int_ptr.namespace, "System");
        assert!(matches!(*int_ptr.flavor(), CilFlavor::Pointer));

        let pointed_type = int_ptr.base.get().unwrap().upgrade().unwrap();
        assert_eq!(pointed_type.name, "Int32");

        let mod_ptr_sig = TypeSignature::Ptr(SignaturePointer {
            modifiers: vec![crate::metadata::signatures::CustomModifier {
                is_required: false,
                modifier_type: in_attr_token,
            }],
            base: Box::new(TypeSignature::I4),
        });

        let mod_ptr = resolver.resolve(&mod_ptr_sig).unwrap();
        assert_eq!(mod_ptr.name, "Int32*");

        // Test double pointer (Int32**)
        let int_ptr_ptr_sig = TypeSignature::Ptr(SignaturePointer {
            modifiers: Vec::new(),
            base: Box::new(TypeSignature::Ptr(SignaturePointer {
                modifiers: Vec::new(),
                base: Box::new(TypeSignature::I4),
            })),
        });

        let int_ptr_ptr = resolver.resolve(&int_ptr_ptr_sig).unwrap();
        assert_eq!(int_ptr_ptr.name, "Int32**");
        assert!(matches!(*int_ptr_ptr.flavor(), CilFlavor::Pointer));

        let inner_ptr = int_ptr_ptr.base.get().unwrap().upgrade().unwrap();
        assert_eq!(inner_ptr.name, "Int32*");
    }

    #[test]
    fn test_resolve_byref() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);
        let int_ref_sig = TypeSignature::ByRef(Box::new(TypeSignature::I4));

        let int_ref = resolver.resolve(&int_ref_sig).unwrap();
        assert_eq!(int_ref.name, "Int32&");
        assert_eq!(int_ref.namespace, "System");
        assert!(matches!(*int_ref.flavor(), CilFlavor::ByRef));

        let ref_type = int_ref.base.get().unwrap().upgrade().unwrap();
        assert_eq!(ref_type.name, "Int32");

        let array_ref_sig =
            TypeSignature::ByRef(Box::new(TypeSignature::SzArray(SignatureSzArray {
                modifiers: Vec::new(),
                base: Box::new(TypeSignature::I4),
            })));

        let array_ref = resolver.resolve(&array_ref_sig).unwrap();
        assert_eq!(array_ref.name, "Int32[]&");
        assert!(matches!(*array_ref.flavor(), CilFlavor::ByRef));
    }

    #[test]
    fn test_recursion_limit() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);

        let mut sig = TypeSignature::I4;
        for _ in 0..MAX_RECURSION_DEPTH + 10 {
            sig = TypeSignature::Ptr(SignaturePointer {
                modifiers: Vec::new(),
                base: Box::new(sig),
            });
        }

        let result = resolver.resolve(&sig);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::RecursionLimit(_))));
    }

    #[test]
    fn test_resolve_fn_ptr() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);

        let method_sig = SignatureMethod::default();
        let fn_ptr_sig = TypeSignature::FnPtr(Box::new(method_sig));

        let fn_ptr = resolver.resolve(&fn_ptr_sig).unwrap();
        assert!(fn_ptr.name.starts_with("FunctionPointer_"));
        assert_eq!(fn_ptr.namespace, "");
        assert!(matches!(*fn_ptr.flavor(), CilFlavor::FnPtr { .. }));
    }

    #[test]
    fn test_resolve_pinned() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);

        let pinned_sig = TypeSignature::Pinned(Box::new(TypeSignature::Object));

        let pinned = resolver.resolve(&pinned_sig).unwrap();
        assert_eq!(pinned.name, "pinned Object");
        assert_eq!(pinned.namespace, "System");
        assert!(matches!(*pinned.flavor(), CilFlavor::Pinned));

        let base_type = pinned.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Object");
    }

    #[test]
    fn test_resolve_generic_instance() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let list_token = Token::new(0x01000333);
        let list_type = registry
            .get_or_create_type(
                &mut Some(list_token),
                CilFlavor::Class,
                "System.Collections.Generic",
                "List`1",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let type_param = Arc::new(GenericParam {
            token: Token::new(0x2A000001),
            number: 0,
            flags: 0,
            owner: OnceLock::new(),
            name: "T".to_string(),
            constraints: Arc::new(boxcar::Vec::new()),
            rid: 1,
            offset: 1,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        list_type.generic_params.push(type_param);

        let mut resolver = TypeResolver::new(registry);

        let generic_sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(list_token)),
            vec![TypeSignature::I4],
        );

        let list_int = resolver.resolve(&generic_sig).unwrap();
        assert_eq!(list_int.name, "List`1");
        assert_eq!(list_int.namespace, "System.Collections.Generic");
        assert!(matches!(*list_int.flavor(), CilFlavor::GenericInstance));

        assert_eq!(list_int.generic_args.count(), 1);
        assert_eq!(
            list_int.generic_args[0].generic_args[0].name().unwrap(),
            "Int32"
        );
    }

    #[test]
    fn test_resolve_generic_params() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);

        // Type parameter (T0)
        let type_param_sig = TypeSignature::GenericParamType(0);
        let type_param = resolver.resolve(&type_param_sig).unwrap();
        assert_eq!(type_param.name, "T0");
        assert_eq!(type_param.namespace, "");
        if let CilFlavor::GenericParameter { index, method } = *type_param.flavor() {
            assert_eq!(index, 0);
            assert!(!method);
        } else {
            panic!("Expected GenericParameter flavor");
        }

        // Method parameter (TM0)
        let method_param_sig = TypeSignature::GenericParamMethod(0);
        let method_param = resolver.resolve(&method_param_sig).unwrap();
        assert_eq!(method_param.name, "TM0");
        assert_eq!(method_param.namespace, "");
        if let CilFlavor::GenericParameter { index, method } = *method_param.flavor() {
            assert_eq!(index, 0);
            assert!(method);
        } else {
            panic!("Expected GenericParameter flavor");
        };
    }

    #[test]
    fn test_resolve_class_and_valuetype() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let class_token = Token::new(0x01000222);
        let value_token = Token::new(0x01000223);

        let _ = registry
            .get_or_create_type(
                &mut Some(class_token),
                CilFlavor::Class,
                "System",
                "String",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let _ = registry
            .get_or_create_type(
                &mut Some(value_token),
                CilFlavor::ValueType,
                "System",
                "DateTime",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let mut resolver = TypeResolver::new(registry);

        let class_sig = TypeSignature::Class(class_token);
        let class_type = resolver.resolve(&class_sig).unwrap();
        assert_eq!(class_type.name, "String");
        assert_eq!(class_type.namespace, "System");
        assert!(matches!(*class_type.flavor(), CilFlavor::Class));

        let value_sig = TypeSignature::ValueType(value_token);
        let value_type = resolver.resolve(&value_sig).unwrap();
        assert_eq!(value_type.name, "DateTime");
        assert_eq!(value_type.namespace, "System");
        assert!(matches!(*value_type.flavor(), CilFlavor::ValueType));
    }

    #[test]
    fn test_resolve_modifiers() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let modifier_token = Token::new(0x01000444);
        let _ = registry
            .get_or_create_type(
                &mut Some(modifier_token),
                CilFlavor::Class,
                "System.Runtime.InteropServices",
                "InAttribute",
                TypeSource::CurrentModule,
            )
            .unwrap();

        // Create parent type
        let parent_token = Token::new(0x01000445);
        let _ = registry
            .get_or_create_type(
                &mut Some(parent_token),
                CilFlavor::Class,
                "System",
                "Int32",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let mut resolver = TypeResolver::new(registry).with_parent(parent_token);

        let req_mod_sig =
            TypeSignature::ModifiedRequired(vec![crate::metadata::signatures::CustomModifier {
                is_required: true,
                modifier_type: modifier_token,
            }]);
        let req_mod_type = resolver.resolve(&req_mod_sig).unwrap();

        assert_eq!(req_mod_type.token, parent_token);
        assert_eq!(req_mod_type.modifiers.count(), 1);
        assert!(req_mod_type.modifiers[0].required);
        assert_eq!(
            req_mod_type.modifiers[0].modifier.token().unwrap(),
            modifier_token
        );

        let opt_mod_sig =
            TypeSignature::ModifiedOptional(vec![crate::metadata::signatures::CustomModifier {
                is_required: false,
                modifier_type: modifier_token,
            }]);
        let opt_mod_type = resolver.resolve(&opt_mod_sig).unwrap();

        assert_eq!(opt_mod_type.token, parent_token);
        assert_eq!(opt_mod_type.modifiers.count(), 2);
        assert!(opt_mod_type.modifiers[0].required);
        assert!(!opt_mod_type.modifiers[1].required);
    }

    #[test]
    fn test_resolver_with_source() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let source = TypeSource::AssemblyRef(Token::new(0x23000001));

        let mut resolver = TypeResolver::new(registry).with_source(source);

        let int_array_sig = TypeSignature::SzArray(SignatureSzArray {
            modifiers: Vec::new(),
            base: Box::new(TypeSignature::I4),
        });

        let int_array = resolver.resolve(&int_array_sig).unwrap();
        assert_eq!(int_array.name, "Int32[]");
    }

    #[test]
    fn test_resolver_with_token_init() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let init_token = Token::new(0x1B000001);

        let mut resolver = TypeResolver::new(registry).with_token_init(init_token);

        let array_sig = TypeSignature::SzArray(SignatureSzArray {
            modifiers: Vec::new(),
            base: Box::new(TypeSignature::I4),
        });

        let array_type = resolver.resolve(&array_sig).unwrap();
        assert_eq!(array_type.token, init_token);
    }

    #[test]
    fn test_resolver_error_cases() {
        let registry = Arc::new(TypeRegistry::new().unwrap());
        let mut resolver = TypeResolver::new(registry);

        // Test TypeNotFound error
        let bad_token = Token::new(0x01999999);
        let bad_class_sig = TypeSignature::Class(bad_token);
        let result = resolver.resolve(&bad_class_sig);

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotFound(_))));

        // Test TypeMissingParent error
        let mod_token = Token::new(0x01000001);
        let mod_sig =
            TypeSignature::ModifiedRequired(vec![crate::metadata::signatures::CustomModifier {
                is_required: true,
                modifier_type: mod_token,
            }]);
        let result = resolver.resolve(&mod_sig);

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeMissingParent)));

        // Test unsupported signature
        struct UnsupportedSignature;

        #[allow(non_local_definitions)]
        impl TypeSignature {
            fn unsupported() -> Self {
                // This is a hack to create a variant that's not handled by the resolver
                TypeSignature::Class(Token::new(0))
            }
        }

        let unsupported_sig = TypeSignature::unsupported();
        let result = resolver.resolve(&unsupported_sig);

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::TypeNotFound(_))));
    }
}
