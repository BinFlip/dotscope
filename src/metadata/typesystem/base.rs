//! # Type System Base Types
//!
//! This module provides the foundational types and abstractions for the .NET CIL (Common
//! Intermediate Language) type system. It defines the core building blocks used throughout
//! the dotscope library for representing, manipulating, and reasoning about .NET types.
//!
//! ## Core Components
//!
//! ### Type References
//!
//! - [`CilTypeRef`] - Smart weak reference to prevent circular dependencies
//! - [`CilTypeRefList`] - Collection of type references
//! - [`CilTypeReference`] - Unified reference to any metadata table entry
//!
//! ### Type Flavors
//!
//! - [`CilFlavor`] - Categorizes types (primitives, arrays, classes, etc.)
//! - [`CilModifier`] - Required/optional type modifiers
//! - [`ArrayDimensions`] - Array dimension information
//!
//! ### Element Type Constants
//!
//! - [`ELEMENT_TYPE`] - Standard .NET metadata element type constants
//!
//! ## Type System Design
//!
//! The type system is designed to handle the complexity of .NET's type model:
//!
//! - **Primitive Types**: Built-in types like `int`, `string`, `bool`
//! - **Constructed Types**: Arrays, pointers, generic instantiations
//! - **Reference Types**: Classes, interfaces, delegates
//! - **Value Types**: Structs, enums, primitive values
//! - **Generic Types**: Generic parameters and instantiated generics
//!
//! ## Memory Management
//!
//! To handle circular references common in type systems (e.g., nested types, generic
//! constraints), this module uses weak references through [`CilTypeRef`]. This prevents
//! memory leaks while maintaining a clean API for type operations.
//!
//! ## Type Compatibility
//!
//! The type system implements .NET's type compatibility rules:
//!
//! - **Exact matching** for identity
//! - **Widening conversions** for primitive types
//! - **Reference type compatibility** through inheritance
//! - **Constant assignment rules** for compile-time values
//!
//! ## Usage Example
//!
//! ```rust
//! use dotscope::metadata::typesystem::{CilFlavor, ArrayDimensions};
//!
//! // Create a 2D array type
//! let array_type = CilFlavor::Array {
//!     rank: 2,
//!     dimensions: vec![
//!         ArrayDimensions { size: Some(10), lower_bound: Some(0) },
//!         ArrayDimensions { size: Some(5), lower_bound: Some(0) },
//!     ],
//! };
//!
//! assert!(array_type.is_reference_type());
//! assert!(!array_type.is_primitive());
//!
//! // Check type compatibility
//! let int_type = CilFlavor::I4;
//! let long_type = CilFlavor::I8;
//! assert!(int_type.is_compatible_with(&long_type)); // int can widen to long
//! ```
//!
//! ## Thread Safety
//!
//! All types in this module are designed to be `Send + Sync` where appropriate.
//! [`CilTypeRef`] uses weak references which are thread-safe for concurrent access.
//!
//! ## References
//!
//! - [ECMA-335 §I.8 - Common Type System](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [ECMA-335 §II.23.1.16 - Element types](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - [`crate::metadata::typesystem`] - Higher-level type system operations

use std::{sync::Arc, sync::Weak};

use crate::{
    metadata::{
        method::MethodRef,
        signatures::SignatureMethod,
        tables::{
            AssemblyRc, AssemblyRefRc, DeclSecurityRc, EventRc, ExportedTypeRc, FieldRc, FileRc,
            GenericParamConstraintRc, GenericParamRc, InterfaceImplRc, MemberRefRc, MethodSpecList,
            MethodSpecRc, ModuleRc, ModuleRefRc, ParamRc, PropertyRc, StandAloneSigRc,
        },
        typesystem::{CilPrimitive, CilPrimitiveKind, CilType, CilTypeRc},
    },
    prelude::{GenericParamList, Token},
};

/// A vector that holds [`CilTypeRef`] instances (weak references).
///
/// This type alias provides a convenient way to work with collections of type references
/// while maintaining the memory safety benefits of weak references. The use of `boxcar::Vec`
/// provides thread-safe, lock-free vector operations suitable for concurrent access patterns
/// common in metadata processing.
///
/// ## Usage
///
/// ```rust
/// use dotscope::metadata::typesystem::{CilTypeRefList, CilTypeRef};
/// use std::sync::Arc;
///
/// # fn example() {
/// let type_list: CilTypeRefList = Arc::new(boxcar::Vec::new());
/// // Add type references to the collection
/// # }
/// ```
pub type CilTypeRefList = Arc<boxcar::Vec<CilTypeRef>>;

/// A smart reference to a [`CilType`] that uses weak references to prevent circular dependencies.
///
/// This type provides a safe way to reference [`CilType`] instances without creating
/// circular reference chains that could lead to memory leaks. It's particularly important
/// in type systems where types often reference each other (e.g., nested types, generic
/// constraints, inheritance hierarchies).
///
/// ## Design Rationale
///
/// The .NET type system has many scenarios where types reference each other:
/// - Nested types reference their enclosing types
/// - Generic types reference their type parameters
/// - Base types and derived types form hierarchies
/// - Interface implementations create bidirectional references
///
/// Using weak references breaks these cycles while still providing convenient access
/// to referenced types when they're needed.
///
/// ## Memory Safety
///
/// The weak reference will become invalid if the referenced [`CilType`] is dropped.
/// All methods that access the referenced type handle this gracefully by returning
/// [`Option`] types or providing panic-safe alternatives.
///
/// ## Usage Example
///
/// ```rust
/// use dotscope::metadata::typesystem::CilTypeRef;
/// use std::sync::Arc;
///
/// # fn example() {
/// # use dotscope::metadata::typesystem::CilType;
/// # let some_type: Arc<CilType> = unimplemented!();
/// // Create a weak reference to a type
/// let type_ref = CilTypeRef::new(&some_type);
///
/// // Access the type safely
/// if let Some(strong_ref) = type_ref.upgrade() {
///     println!("Type name: {}", strong_ref.name);
/// }
///
/// // Check if the reference is still valid
/// if type_ref.is_valid() {
///     // Safe to use expect() here
///     let strong_ref = type_ref.expect("Type should be valid");
/// }
/// # }
/// ```
///
/// ## Thread Safety
///
/// [`CilTypeRef`] is `Send + Sync` as it only contains a [`Weak`] pointer, which
/// is safe to share between threads.
#[derive(Clone, Debug)]
pub struct CilTypeRef {
    /// The weak reference to the actual type instance
    weak_ref: Weak<CilType>,
}

impl CilTypeRef {
    /// Creates a new weak reference from a strong reference to a [`CilType`].
    ///
    /// This method creates a [`CilTypeRef`] that holds a weak reference to the provided
    /// type. The weak reference will not prevent the type from being dropped when all
    /// strong references are released.
    ///
    /// ## Arguments
    ///
    /// * `strong_ref` - A strong reference to the type to create a weak reference to
    ///
    /// ## Returns
    ///
    /// A new [`CilTypeRef`] containing a weak reference to the provided type.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    /// assert!(type_ref.is_valid());
    /// # }
    /// ```
    pub fn new(strong_ref: &CilTypeRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Attempts to upgrade the weak reference to a strong reference.
    ///
    /// This method tries to convert the weak reference back to a strong reference.
    /// If the referenced type has been dropped, this will return [`None`].
    ///
    /// ## Returns
    ///
    /// - [`Some(CilTypeRc)`] if the referenced type is still alive
    /// - [`None`] if the referenced type has been dropped
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    ///
    /// match type_ref.upgrade() {
    ///     Some(strong_ref) => {
    ///         // Use the strong reference
    ///         println!("Type: {}", strong_ref.name);
    ///     }
    ///     None => {
    ///         println!("Type has been dropped");
    ///     }
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn upgrade(&self) -> Option<CilTypeRc> {
        self.weak_ref.upgrade()
    }

    /// Gets a strong reference to the type, panicking if the type has been dropped.
    ///
    /// This method is similar to [`upgrade`](Self::upgrade) but will panic if the
    /// referenced type is no longer available. Use this when you're certain the
    /// type should still exist and want to avoid handling the [`Option`].
    ///
    /// ## Arguments
    ///
    /// * `msg` - The panic message to use if the type has been dropped
    ///
    /// ## Returns
    ///
    /// A strong reference to the type.
    ///
    /// ## Panics
    ///
    /// Panics if the referenced type has been dropped and the weak reference
    /// cannot be upgraded to a strong reference.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    ///
    /// // This will panic if my_type has been dropped
    /// let strong_ref = type_ref.expect("Type should still be alive");
    /// println!("Type: {}", strong_ref.name);
    /// # }
    /// ```
    #[must_use]
    pub fn expect(&self, msg: &str) -> CilTypeRc {
        self.weak_ref.upgrade().expect(msg)
    }

    /// Checks if the referenced type is still alive.
    ///
    /// This method returns `true` if there are still strong references to the
    /// type, meaning [`upgrade()`](Self::upgrade) would succeed. Returns `false`
    /// if the type has been dropped.
    ///
    /// ## Returns
    ///
    /// `true` if the referenced type is still alive, `false` otherwise.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let my_type: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&my_type);
    ///
    /// if type_ref.is_valid() {
    ///     // Safe to call expect() or upgrade().unwrap()
    ///     let strong_ref = type_ref.upgrade().unwrap();
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.weak_ref.strong_count() > 0
    }

    // ToDo: These accessors are inefficient, creating copies in exchange for a clean API.
    /// Gets the token of the referenced type if it's still alive.
    ///
    /// This is a convenience method that upgrades the weak reference and extracts
    /// the token. Returns [`None`] if the type has been dropped.
    ///
    /// ## Performance Note
    ///
    /// This method creates a temporary strong reference and copies the token value.
    /// For better performance when accessing multiple fields, consider using
    /// [`upgrade()`](Self::upgrade) once and accessing fields directly.
    ///
    /// ## Returns
    ///
    /// The token of the referenced type, or [`None`] if the type is no longer alive.
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        self.upgrade().map(|t| t.token)
    }

    /// Gets the name of the referenced type if it's still alive.
    ///
    /// This is a convenience method that upgrades the weak reference and clones
    /// the name. Returns [`None`] if the type has been dropped.
    ///
    /// ## Performance Note
    ///
    /// This method creates a temporary strong reference and clones the name string.
    /// For better performance when accessing multiple fields, consider using
    /// [`upgrade()`](Self::upgrade) once and accessing fields directly.
    ///
    /// ## Returns
    ///
    /// A clone of the name of the referenced type, or [`None`] if the type is no longer alive.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.upgrade().map(|t| t.name.clone())
    }

    /// Gets the namespace of the referenced type if it's still alive.
    ///
    /// This is a convenience method that upgrades the weak reference and clones
    /// the namespace. Returns [`None`] if the type has been dropped.
    ///
    /// ## Performance Note
    ///
    /// This method creates a temporary strong reference and clones the namespace string.
    /// For better performance when accessing multiple fields, consider using
    /// [`upgrade()`](Self::upgrade) once and accessing fields directly.
    ///
    /// ## Returns
    ///
    /// A clone of the namespace of the referenced type, or [`None`] if the type is no longer alive.
    #[must_use]
    pub fn namespace(&self) -> Option<String> {
        self.upgrade().map(|t| t.namespace.clone())
    }

    /// Gets the nested types collection of the referenced type if it's still alive.
    ///
    /// This is a convenience method that upgrades the weak reference and clones
    /// the nested types collection. Returns [`None`] if the type has been dropped.
    ///
    /// ## Performance Note
    ///
    /// This method creates a temporary strong reference and clones the collection.
    /// For better performance when accessing multiple fields, consider using
    /// [`upgrade()`](Self::upgrade) once and accessing fields directly.
    ///
    /// ## Returns
    ///
    /// A clone of the nested types collection, or [`None`] if the type is no longer alive.
    #[must_use]
    pub fn nested_types(&self) -> Option<CilTypeRefList> {
        self.upgrade().map(|t| t.nested_types.clone())
    }

    /// Gets the generic parameters collection of the referenced type if it's still alive.
    ///
    /// This is a convenience method that upgrades the weak reference and clones
    /// the generic parameters collection. Returns [`None`] if the type has been dropped.
    ///
    /// ## Performance Note
    ///
    /// This method creates a temporary strong reference and clones the collection.
    /// For better performance when accessing multiple fields, consider using
    /// [`upgrade()`](Self::upgrade) once and accessing fields directly.
    ///
    /// ## Returns
    ///
    /// A clone of the generic parameters collection, or [`None`] if the type is no longer alive.
    #[must_use]
    pub fn generic_params(&self) -> Option<GenericParamList> {
        self.upgrade().map(|t| t.generic_params.clone())
    }

    /// Gets the generic arguments collection of the referenced type if it's still alive.
    ///
    /// This is a convenience method that upgrades the weak reference and clones
    /// the generic arguments collection. Returns [`None`] if the type has been dropped.
    ///
    /// ## Performance Note
    ///
    /// This method creates a temporary strong reference and clones the collection.
    /// For better performance when accessing multiple fields, consider using
    /// [`upgrade()`](Self::upgrade) once and accessing fields directly.
    ///
    /// ## Returns
    ///
    /// A clone of the generic arguments collection, or [`None`] if the type is no longer alive.
    #[must_use]
    pub fn generic_args(&self) -> Option<MethodSpecList> {
        self.upgrade().map(|t| t.generic_args.clone())
    }

    /// Checks if this type reference is compatible with another type.
    ///
    /// This method upgrades the weak reference and delegates to the type's
    /// compatibility checking logic. Returns `false` if the referenced type
    /// has been dropped.
    ///
    /// ## Arguments
    ///
    /// * `other` - The other type to check compatibility against
    ///
    /// ## Returns
    ///
    /// `true` if this type is compatible with the other type, `false` if
    /// incompatible or if the reference is invalid.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::CilType;
    /// # use std::sync::Arc;
    /// # let type1: Arc<CilType> = unimplemented!();
    /// # let type2: Arc<CilType> = unimplemented!();
    /// let type_ref = CilTypeRef::new(&type1);
    ///
    /// if type_ref.is_compatible_with(&type2) {
    ///     println!("Types are compatible");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn is_compatible_with(&self, other: &CilType) -> bool {
        if let Some(this_type) = self.upgrade() {
            this_type.is_compatible_with(other)
        } else {
            false
        }
    }

    /// Checks if this type reference can accept a constant value.
    ///
    /// This method upgrades the weak reference and delegates to the type's
    /// constant acceptance logic. Returns `false` if the referenced type
    /// has been dropped.
    ///
    /// ## Arguments
    ///
    /// * `constant` - The constant value to check
    ///
    /// ## Returns
    ///
    /// `true` if this type can accept the constant, `false` if not or if
    /// the reference is invalid.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilTypeRef;
    /// # fn example() {
    /// # use dotscope::metadata::typesystem::{CilType, CilPrimitive};
    /// # use std::sync::Arc;
    /// # let type_ref: CilTypeRef = unimplemented!();
    /// # let constant: CilPrimitive = unimplemented!();
    /// if type_ref.accepts_constant(&constant) {
    ///     println!("Type can accept this constant");
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn accepts_constant(&self, constant: &CilPrimitive) -> bool {
        if let Some(this_type) = self.upgrade() {
            this_type.accepts_constant(constant)
        } else {
            false
        }
    }
}

impl From<CilTypeRc> for CilTypeRef {
    fn from(strong_ref: CilTypeRc) -> Self {
        Self::new(&strong_ref)
    }
}

/// Represents a single dimension of a multi-dimensional array with optional size and bounds.
///
/// In .NET, arrays can have multiple dimensions with configurable lower bounds and sizes.
/// This structure captures the metadata for a single dimension of such an array.
///
/// ## Fields
///
/// - `size`: The number of elements in this dimension (if known at compile time)
/// - `lower_bound`: The lowest valid index for this dimension (typically 0)
///
/// ## Examples
///
/// ```rust
/// use dotscope::metadata::typesystem::ArrayDimensions;
///
/// // A dimension with 10 elements starting at index 0
/// let dim = ArrayDimensions {
///     size: Some(10),
///     lower_bound: Some(0),
/// };
///
/// // An unbounded dimension (size determined at runtime)
/// let unbounded = ArrayDimensions {
///     size: None,
///     lower_bound: Some(1), // 1-based indexing
/// };
/// ```
///
/// ## References
///
/// - [ECMA-335 §II.23.2.13 - Array shapes](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ArrayDimensions {
    /// The size of this dimension (number of elements).
    ///
    /// `None` indicates the size is not fixed at compile time and will be
    /// determined at runtime when the array is allocated.
    pub size: Option<u32>,

    /// The lower bound of this dimension (lowest index that can be used to access an element).
    ///
    /// Most .NET arrays use 0-based indexing, but the runtime supports arbitrary lower bounds.
    /// `None` typically means the lower bound is 0.
    pub lower_bound: Option<u32>,
}

/// Represents a unified reference to various metadata table entries in the .NET runtime.
///
/// This enum provides a type-safe way to reference different kinds of metadata entries
/// that can appear in various contexts throughout the .NET type system. It's similar
/// to a `CodedIndex` but contains fully resolved references rather than raw indices.
///
/// ## Design
///
/// Unlike raw coded indices which are just numbers that need to be decoded, this enum
/// holds strong references to the actual metadata objects, making it easier and safer
/// to work with resolved metadata.
///
/// ## Variants
///
/// The enum covers all major metadata table types that can be referenced:
///
/// - **Type References**: [`crate::metadata::tables::TypeRefRaw`], [`crate::metadata::tables::TypeDefRaw`], [`crate::metadata::tables::TypeSpec`] - Different ways types can be referenced
/// - **Members**: [`crate::metadata::tables::Field`], [`crate::metadata::tables::Property`], [`crate::metadata::tables::MethodDefRaw`], [`crate::metadata::tables::MemberRef`] - Type members
/// - **Parameters**: [`crate::metadata::tables::Param`] - Method and property parameters
/// - **Modules**: [`crate::metadata::tables::Module`], [`crate::metadata::tables::ModuleRef`] - Assembly modules
/// - **Security**: [`crate::metadata::tables::DeclSecurity`] - Security declarations
/// - **Events**: [`crate::metadata::tables::Event`] - Event declarations
/// - **Signatures**: [`crate::metadata::tables::StandAloneSig`] - Standalone signatures
/// - **Assemblies**: [`crate::metadata::tables::Assembly`], [`crate::metadata::tables::AssemblyRef`] - Assembly references
/// - **Files**: [`crate::metadata::tables::File`], [`crate::metadata::tables::ExportedType`] - File and exported type references
/// - **Generics**: [`crate::metadata::tables::GenericParam`], [`crate::metadata::tables::GenericParamConstraint`], [`crate::metadata::tables::MethodSpec`] - Generic type system
/// - **Interfaces**: [`crate::metadata::tables::InterfaceImpl`] - Interface implementations
/// - **None**: Used when no reference is present
///
/// ## Usage Example
///
/// ```rust
/// use dotscope::metadata::typesystem::CilTypeReference;
///
/// # fn example(reference: CilTypeReference) {
/// match reference {
///     CilTypeReference::TypeDef(type_ref) => {
///         if let Some(type_obj) = type_ref.upgrade() {
///             println!("Found type: {}", type_obj.name);
///         }
///     }
///     CilTypeReference::Field(field) => {
///         println!("Found field: {}", field.name);
///     }
///     CilTypeReference::None => {
///         println!("No reference");
///     }
///     _ => {
///         println!("Other reference type");
///     }
/// }
/// # }
/// ```
///
/// ## Memory Management
///
/// Type references ([`crate::metadata::tables::TypeRefRaw`], [`crate::metadata::tables::TypeDefRaw`], [`crate::metadata::tables::TypeSpec`]) use [`CilTypeRef`] which
/// contains weak references to prevent circular dependencies. Other variants hold
/// strong references to their respective metadata objects.
///
/// ## Thread Safety
///
/// All contained references are designed to be thread-safe for concurrent access.
#[derive(Clone)]
pub enum CilTypeReference {
    /// Reference to a type defined in another module or assembly
    TypeRef(CilTypeRef),
    /// Reference to a type defined in the current module
    TypeDef(CilTypeRef),
    /// Reference to a type specification (constructed type)
    TypeSpec(CilTypeRef),
    /// Reference to a field
    Field(FieldRc),
    /// Reference to a parameter
    Param(ParamRc),
    /// Reference to a property
    Property(PropertyRc),
    /// Reference to a method definition
    MethodDef(MethodRef),
    /// Reference to an interface implementation
    InterfaceImpl(InterfaceImplRc),
    /// Reference to a member (field, method, etc.)
    MemberRef(MemberRefRc),
    /// Reference to a module
    Module(ModuleRc),
    /// Reference to a security declaration
    DeclSecurity(DeclSecurityRc),
    /// Reference to an event
    Event(EventRc),
    /// Reference to a standalone signature
    StandAloneSig(StandAloneSigRc),
    /// Reference to an external module
    ModuleRef(ModuleRefRc),
    /// Reference to an assembly
    Assembly(AssemblyRc),
    /// Reference to an external assembly
    AssemblyRef(AssemblyRefRc),
    /// Reference to a file
    File(FileRc),
    /// Reference to an exported type
    ExportedType(ExportedTypeRc),
    /// Reference to a generic parameter
    GenericParam(GenericParamRc),
    /// Reference to a generic parameter constraint
    GenericParamConstraint(GenericParamConstraintRc),
    /// Reference to a method specialization
    MethodSpec(MethodSpecRc),
    /// No reference (null/empty)
    None,
}

/// Constants representing .NET metadata element types as defined in ECMA-335.
///
/// These constants correspond to the element type values used in .NET metadata
/// signatures to identify different types. They are used throughout the runtime
/// for type identification, signature parsing, and type system operations.
///
/// ## Organization
///
/// The constants are organized into several categories:
///
/// ### Primitive Types (0x01-0x0e, 0x18-0x19, 0x1c)
/// Basic types built into the runtime like integers, floats, booleans, etc.
///
/// ### Constructed Types (0x0f-0x17, 0x1d-0x1e)
/// Types built from other types like arrays, pointers, generics.
///
/// ### Modifiers (0x1f-0x20, 0x40-0x45)
/// Type modifiers for optional/required constraints, variance, etc.
///
/// ## Usage
///
/// These constants are primarily used when parsing metadata signatures and
/// when generating type information for the runtime.
///
/// ```rust
/// use dotscope::metadata::typesystem::ELEMENT_TYPE;
///
/// # fn parse_signature_element(element: u8) {
/// match element {
///     ELEMENT_TYPE::I4 => println!("32-bit integer"),
///     ELEMENT_TYPE::STRING => println!("String type"),
///     ELEMENT_TYPE::SZARRAY => println!("Single-dimension array"),
///     _ => println!("Other element type"),
/// }
/// # }
/// ```
///
/// ## References
///
/// - [ECMA-335 §II.23.1.16 - Element types](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - [CoreCLR Type System](https://github.com/dotnet/coreclr/blob/master/src/inc/corinfo.h)
#[allow(non_snake_case, dead_code)]
pub mod ELEMENT_TYPE {
    /// Marks the end of a list in signatures
    pub const END: u8 = 0x00;
    /// Void type (no return value)
    pub const VOID: u8 = 0x01;
    /// Boolean type (true/false)
    pub const BOOLEAN: u8 = 0x02;
    /// 16-bit Unicode character
    pub const CHAR: u8 = 0x03;
    /// Signed 8-bit integer
    pub const I1: u8 = 0x04;
    /// Unsigned 8-bit integer  
    pub const U1: u8 = 0x05;
    /// Signed 16-bit integer
    pub const I2: u8 = 0x06;
    /// Unsigned 16-bit integer
    pub const U2: u8 = 0x07;
    /// Signed 32-bit integer
    pub const I4: u8 = 0x08;
    /// Unsigned 32-bit integer
    pub const U4: u8 = 0x09;
    /// Signed 64-bit integer
    pub const I8: u8 = 0x0a;
    /// Unsigned 64-bit integer
    pub const U8: u8 = 0x0b;
    /// 32-bit floating point
    pub const R4: u8 = 0x0c;
    /// 64-bit floating point
    pub const R8: u8 = 0x0d;
    /// String type
    pub const STRING: u8 = 0x0e;
    /// Unmanaged pointer (followed by type)
    pub const PTR: u8 = 0x0f;
    /// Managed reference (followed by type)
    pub const BYREF: u8 = 0x10;
    /// Value type (followed by `TypeDef` or `TypeRef` token)
    pub const VALUETYPE: u8 = 0x11;
    /// Reference type/class (followed by `TypeDef` or `TypeRef` token)
    pub const CLASS: u8 = 0x12;
    /// Generic parameter in a generic type definition (represented as number)
    pub const VAR: u8 = 0x13;
    /// Multi-dimensional array (type rank boundsCount bound1 … loCount lo1 …)
    pub const ARRAY: u8 = 0x14;
    /// Generic type instantiation (followed by type type-arg-count type-1 ... type-n)
    pub const GENERICINST: u8 = 0x15;
    /// Typed reference type
    pub const TYPEDBYREF: u8 = 0x16;
    /// Native integer type (System.IntPtr)
    pub const I: u8 = 0x18;
    /// Native unsigned integer type (System.UIntPtr)
    pub const U: u8 = 0x19;
    /// Function pointer (followed by full method signature)
    pub const FNPTR: u8 = 0x1b;
    /// Object type (System.Object)
    pub const OBJECT: u8 = 0x1c;
    /// Single-dimension array with 0 lower bound
    pub const SZARRAY: u8 = 0x1d;
    /// Generic parameter in a generic method definition (represented as number)
    pub const MVAR: u8 = 0x1e;
    /// Required modifier (followed by a `TypeDef` or `TypeRef` token)
    pub const CMOD_REQD: u8 = 0x1f;
    /// Optional modifier (followed by a `TypeDef` or `TypeRef` token)
    pub const CMOD_OPT: u8 = 0x20;
    /// Implemented within the CLI
    pub const INTERNAL: u8 = 0x21;
    /// Modifier flag (OR'd with following element types)
    pub const MODIFIER: u8 = 0x40;
    /// Sentinel for vararg method signature
    pub const SENTINEL: u8 = 0x41;
    /// Denotes a local variable that points at a pinned object
    pub const PINNED: u8 = 0x45;
}

/// Represents a type modifier that can be applied to .NET types.
///
/// In the .NET type system, types can have modifiers that constrain or extend their behavior.
/// These modifiers can be either required (must be understood by the runtime) or optional
/// (can be ignored if not understood).
///
/// ## Modifier Types
///
/// - **Required modifiers** (`CMOD_REQD`): Must be processed by the runtime. If the runtime
///   doesn't understand a required modifier, it should reject the type.
/// - **Optional modifiers** (`CMOD_OPT`): Can be safely ignored by runtimes that don't
///   understand them.
///
/// ## Common Use Cases
///
/// - **const/volatile semantics**: Indicating memory access patterns
/// - **Platform-specific constraints**: Hardware or ABI-specific requirements  
/// - **Language-specific features**: Language extensions that map to runtime behavior
/// - **Interop constraints**: Requirements for native code interaction
///
/// ## Example
///
/// ```rust
/// use dotscope::metadata::typesystem::{CilModifier, CilTypeRef};
///
/// # fn example(const_modifier_type: CilTypeRef) {
/// // A required const modifier
/// let const_modifier = CilModifier {
///     required: true,
///     modifier: const_modifier_type,
/// };
///
/// assert!(const_modifier.required);
/// # }
/// ```
///
/// ## References
///
/// - [ECMA-335 §II.23.2.7 - Type](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - [ECMA-335 §II.7.1.1 - modreq and modopt](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
pub struct CilModifier {
    /// Whether this modifier is required (`true`) or optional (`false`).
    ///
    /// Required modifiers must be understood and processed by the runtime.
    /// Optional modifiers can be safely ignored if not recognized.
    pub required: bool,

    /// The type reference that defines the modifier behavior.
    ///
    /// This typically points to a type that encodes the specific semantics
    /// of the modifier (e.g., a const modifier type, volatile modifier type, etc.).
    pub modifier: CilTypeRef,
}

/// Represents the different categories and flavors of types in the .NET type system.
///
/// This enum categorizes all possible types that can exist in .NET metadata, from simple
/// primitive types to complex constructed types like generics and arrays. It provides
/// a unified way to represent type information and perform type-related operations.
///
/// ## Type Categories
///
/// ### Primitive Types
/// Basic built-in types that have direct runtime support:
/// - **Integer types**: `I1`, `U1`, `I2`, `U2`, `I4`, `U4`, `I8`, `U8`
/// - **Floating point**: `R4` (float), `R8` (double)
/// - **Character types**: `Char` (16-bit Unicode)
/// - **Boolean**: `Boolean` (true/false)
/// - **Native integers**: `I` (`IntPtr`), `U` (`UIntPtr`)
/// - **Special types**: `Void`, `Object`, `String`
///
/// ### Constructed Types
/// Types built from other types:
/// - **Arrays**: Multi-dimensional (`Array`) and single-dimensional (`SZARRAY` via single-dimension arrays)
/// - **Pointers**: Unmanaged pointers (`Pointer`) and managed references (`ByRef`)
/// - **Function pointers**: `FnPtr` with method signatures
/// - **Generic instances**: `GenericInstance` with type arguments
/// - **Generic parameters**: `GenericParameter` from type or method definitions
///
/// ### Reference Categories
/// High-level categorizations:
/// - **Classes**: Reference types (`Class`)
/// - **Value types**: Stack-allocated types (`ValueType`)
/// - **Interfaces**: Contract definitions (`Interface`)
///
/// ## Usage Examples
///
/// ```rust
/// use dotscope::metadata::typesystem::{CilFlavor, ArrayDimensions};
///
/// // Primitive type
/// let int_type = CilFlavor::I4;
/// assert!(int_type.is_primitive());
/// assert!(int_type.is_value_type());
///
/// // Array type
/// let array_type = CilFlavor::Array {
///     rank: 2,
///     dimensions: vec![
///         ArrayDimensions { size: Some(10), lower_bound: Some(0) },
///         ArrayDimensions { size: Some(5), lower_bound: Some(0) },
///     ],
/// };
/// assert!(array_type.is_reference_type());
///
/// // Generic parameter
/// let generic_param = CilFlavor::GenericParameter {
///     index: 0,
///     method: false, // Type parameter, not method parameter
/// };
/// ```
///
/// ## Type Compatibility
///
/// The enum provides methods for checking type compatibility and primitive conversions:
///
/// ```rust
/// # use dotscope::metadata::typesystem::CilFlavor;
/// let byte_type = CilFlavor::U1;
/// let int_type = CilFlavor::I4;
///
/// // Byte can be widened to int
/// assert!(byte_type.is_compatible_with(&int_type));
///
/// // But int cannot be assigned to byte
/// assert!(!int_type.is_compatible_with(&byte_type));
/// ```
///
/// ## Thread Safety
///
/// All variants are `Clone + Send + Sync` and safe for concurrent access.
///
/// ## References
///
/// - [ECMA-335 §I.8 - Common Type System](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
/// - [ECMA-335 §II.23.1.16 - Element types](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
#[derive(Debug, Clone, PartialEq)]
pub enum CilFlavor {
    // Base primitive types
    /// Void type (no value, used for methods that don't return anything)
    Void,
    /// Boolean type (true or false)
    Boolean,
    /// 16-bit Unicode character
    Char,
    /// Signed 8-bit integer (-128 to 127)
    I1,
    /// Unsigned 8-bit integer (0 to 255)
    U1,
    /// Signed 16-bit integer (-32,768 to 32,767)
    I2,
    /// Unsigned 16-bit integer (0 to 65,535)
    U2,
    /// Signed 32-bit integer (-2,147,483,648 to 2,147,483,647)
    I4,
    /// Unsigned 32-bit integer (0 to 4,294,967,295)
    U4,
    /// Signed 64-bit integer
    I8,
    /// Unsigned 64-bit integer
    U8,
    /// 32-bit floating point number (IEEE 754 single precision)
    R4,
    /// 64-bit floating point number (IEEE 754 double precision)
    R8,
    /// Native signed integer (pointer-sized, `IntPtr`)
    I,
    /// Native unsigned integer (pointer-sized, `UIntPtr`)
    U,
    /// Base object type (System.Object)
    Object,
    /// String type (System.String)
    String,

    // Complex types
    /// Multi-dimensional array type with configurable dimensions and bounds
    Array {
        /// The rank (number of dimensions) of the array
        rank: u32,
        /// Details about each dimension including size and lower bounds
        dimensions: Vec<ArrayDimensions>,
    },
    /// Unmanaged pointer type (unsafe, points to unmanaged memory)
    Pointer,
    /// Managed reference type (safe, tracked by garbage collector)
    ByRef,
    /// Generic type instantiation (e.g., `List<int>`, `Dictionary<string, object>`)
    GenericInstance,
    /// Pinned type (prevents garbage collector from moving the object)
    Pinned,
    /// Function pointer type with a specific method signature
    FnPtr {
        /// The method signature this function pointer must match
        signature: SignatureMethod,
    },
    /// Generic parameter from a type or method definition
    GenericParameter {
        /// Index in the generic parameters list (0-based)
        index: u32,
        /// Whether this is a method parameter (`true`) or type parameter (`false`)
        method: bool,
    },

    // Type categories
    /// Reference type / class (allocated on managed heap)
    Class,
    /// Value type (allocated on stack or inline in objects)
    ValueType,
    /// Interface type (contract definition)
    Interface,

    // Fallback
    /// Unknown or unsupported type
    Unknown,
}

impl CilFlavor {
    /// Checks if this type flavor is a primitive type with direct runtime support.
    ///
    /// Primitive types are built into the .NET runtime and have optimized handling.
    /// This includes all basic value types, the object and string reference types.
    ///
    /// ## Returns
    ///
    /// `true` if this is a primitive type, `false` otherwise.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// assert!(CilFlavor::I4.is_primitive());
    /// assert!(CilFlavor::String.is_primitive());
    /// assert!(!CilFlavor::Class.is_primitive());
    /// ```
    #[must_use]
    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            CilFlavor::Void
                | CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::I8
                | CilFlavor::U8
                | CilFlavor::R4
                | CilFlavor::R8
                | CilFlavor::I
                | CilFlavor::U
                | CilFlavor::Object
                | CilFlavor::String
        )
    }

    /// Checks if this type flavor represents a value type.
    ///
    /// Value types are typically allocated on the stack (for locals) or inline within
    /// objects and have value semantics (copying creates a new instance).
    ///
    /// ## Returns
    ///
    /// `true` if this is a value type, `false` otherwise.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// assert!(CilFlavor::I4.is_value_type());
    /// assert!(CilFlavor::Boolean.is_value_type());
    /// assert!(!CilFlavor::String.is_value_type()); // String is a reference type
    /// assert!(!CilFlavor::Class.is_value_type());
    /// ```
    #[must_use]
    pub fn is_value_type(&self) -> bool {
        matches!(
            self,
            CilFlavor::Boolean
                | CilFlavor::Char
                | CilFlavor::I1
                | CilFlavor::U1
                | CilFlavor::I2
                | CilFlavor::U2
                | CilFlavor::I4
                | CilFlavor::U4
                | CilFlavor::I8
                | CilFlavor::U8
                | CilFlavor::R4
                | CilFlavor::R8
                | CilFlavor::I
                | CilFlavor::U
                | CilFlavor::ValueType
        )
    }

    /// Checks if this type flavor represents a reference type.
    ///
    /// Reference types are allocated on the managed heap and have reference semantics
    /// (copying creates a new reference to the same object). The garbage collector
    /// manages their memory.
    ///
    /// ## Returns
    ///
    /// `true` if this is a reference type, `false` otherwise.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use dotscope::metadata::typesystem::{CilFlavor, ArrayDimensions};
    ///
    /// assert!(CilFlavor::String.is_reference_type());
    /// assert!(CilFlavor::Object.is_reference_type());
    /// assert!(CilFlavor::Class.is_reference_type());
    ///
    /// let array_type = CilFlavor::Array {
    ///     rank: 1,
    ///     dimensions: vec![ArrayDimensions::default()],
    /// };
    /// assert!(array_type.is_reference_type());
    ///
    /// assert!(!CilFlavor::I4.is_reference_type()); // int is a value type
    /// ```
    #[must_use]
    pub fn is_reference_type(&self) -> bool {
        matches!(
            self,
            CilFlavor::Object | CilFlavor::String | CilFlavor::Class | CilFlavor::Array { .. }
        )
    }

    /// Try to convert to a `CilPrimitive` if this is a primitive type
    #[must_use]
    pub fn to_primitive_kind(&self) -> Option<CilPrimitiveKind> {
        match self {
            CilFlavor::Void => Some(CilPrimitiveKind::Void),
            CilFlavor::Boolean => Some(CilPrimitiveKind::Boolean),
            CilFlavor::Char => Some(CilPrimitiveKind::Char),
            CilFlavor::I1 => Some(CilPrimitiveKind::I1),
            CilFlavor::U1 => Some(CilPrimitiveKind::U1),
            CilFlavor::I2 => Some(CilPrimitiveKind::I2),
            CilFlavor::U2 => Some(CilPrimitiveKind::U2),
            CilFlavor::I4 => Some(CilPrimitiveKind::I4),
            CilFlavor::U4 => Some(CilPrimitiveKind::U4),
            CilFlavor::I8 => Some(CilPrimitiveKind::I8),
            CilFlavor::U8 => Some(CilPrimitiveKind::U8),
            CilFlavor::R4 => Some(CilPrimitiveKind::R4),
            CilFlavor::R8 => Some(CilPrimitiveKind::R8),
            CilFlavor::I => Some(CilPrimitiveKind::I),
            CilFlavor::U => Some(CilPrimitiveKind::U),
            CilFlavor::Object => Some(CilPrimitiveKind::Object),
            CilFlavor::String => Some(CilPrimitiveKind::String),
            CilFlavor::ValueType => Some(CilPrimitiveKind::ValueType),
            CilFlavor::GenericParameter { method, .. } => {
                if *method {
                    Some(CilPrimitiveKind::MVar)
                } else {
                    Some(CilPrimitiveKind::Var)
                }
            }
            _ => None,
        }
    }

    /// Check if this flavor is compatible with (assignable to) the target flavor
    ///
    /// Implements .NET primitive type compatibility rules including:
    /// - Exact type matching
    /// - Primitive widening conversions (byte -> int -> long, etc.)
    /// - Reference type compatibility
    ///
    /// # Arguments
    /// * `target` - The target flavor to check compatibility against
    ///
    /// # Returns
    /// `true` if this flavor can be assigned to the target flavor
    #[must_use]
    pub fn is_compatible_with(&self, target: &CilFlavor) -> bool {
        // Exact match
        if self == target {
            return true;
        }

        // Primitive widening rules
        #[allow(clippy::match_same_arms)]
        match (self, target) {
            // Integer widening: smaller -> larger
            (CilFlavor::I1 | CilFlavor::U1, CilFlavor::I2 | CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I2, CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I4, CilFlavor::I8) => true,

            // Unsigned integer widening
            (CilFlavor::U1, CilFlavor::U2 | CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U2, CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U4, CilFlavor::U8) => true,

            // Float widening: float -> double
            (CilFlavor::R4, CilFlavor::R8) => true,

            // Integer to float (with potential precision loss)
            (
                CilFlavor::I1 | CilFlavor::U1 | CilFlavor::I2 | CilFlavor::U2 | CilFlavor::I4,
                CilFlavor::R4 | CilFlavor::R8,
            ) => true,
            (CilFlavor::I8 | CilFlavor::U4 | CilFlavor::U8, CilFlavor::R8) => true,

            // Any reference type to Object
            (source, CilFlavor::Object) if source.is_reference_type() => true,

            // All value types are compatible with ValueType
            (source, CilFlavor::ValueType) if source.is_value_type() => true,

            _ => false,
        }
    }

    /// Check if this flavor can accept a constant of the given flavor
    ///
    /// This is more restrictive than general compatibility as constants
    /// require exact matches or safe widening conversions only.
    ///
    /// # Arguments
    /// * `constant_flavor` - The flavor of the constant value
    ///
    /// # Returns  
    /// `true` if a constant of the given flavor can be assigned to this type
    #[must_use]
    pub fn accepts_constant(&self, constant_flavor: &CilFlavor) -> bool {
        // Exact match is always allowed
        if self == constant_flavor {
            return true;
        }

        // For constants, we're more restrictive - only safe widening
        #[allow(clippy::match_same_arms)]
        match (constant_flavor, self) {
            // Integer literal widening (safe)
            (CilFlavor::I1, CilFlavor::I2 | CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I2, CilFlavor::I4 | CilFlavor::I8) => true,
            (CilFlavor::I4, CilFlavor::I8) => true,

            // Unsigned integer literal widening
            (CilFlavor::U1, CilFlavor::U2 | CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U2, CilFlavor::U4 | CilFlavor::U8) => true,
            (CilFlavor::U4, CilFlavor::U8) => true,

            // Float literal widening
            (CilFlavor::R4, CilFlavor::R8) => true,

            // String constants to Object
            (CilFlavor::String, CilFlavor::Object) => true,

            // Null constant to any reference type
            // Note: This would need special handling for null literals
            _ => false,
        }
    }
}
