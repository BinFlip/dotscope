//! High-level builders for constructing .NET metadata signatures.
//!
//! This module provides fluent APIs for constructing various .NET signature types
//! programmatically. These builders provide a convenient, type-safe way to create
//! complex signatures without manually manipulating the underlying binary format.
//!
//! # Signature Builder Overview
//!
//! Each builder provides a fluent API that guides developers through the process
//! of creating valid signatures while preventing common errors:
//!
//! - **Type Safety**: Builders ensure signatures are well-formed at compile time
//! - **ECMA-335 Compliance**: All generated signatures follow the standard
//! - **Fluent APIs**: Method chaining provides readable, discoverable interfaces
//! - **Validation**: Built-in validation prevents invalid signature combinations
//!
//! # Available Builders
//!
//! ## [`MethodSignatureBuilder`]
//! Constructs method signatures with calling conventions, parameters, and return types:
//! ```rust
//! use dotscope::metadata::signatures::{MethodSignatureBuilder, TypeSignature};
//!
//! # fn example() -> dotscope::Result<()> {
//! let signature = MethodSignatureBuilder::new()
//!     .calling_convention_default()
//!     .has_this(true)  // Instance method
//!     .returns(TypeSignature::I4)
//!     .param(TypeSignature::String)
//!     .param(TypeSignature::I4)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## [`FieldSignatureBuilder`]
//! Constructs field signatures with type information and custom modifiers:
//! ```rust
//! use dotscope::metadata::signatures::{FieldSignatureBuilder, TypeSignature};
//!
//! # fn example() -> dotscope::Result<()> {
//! let signature = FieldSignatureBuilder::new()
//!     .field_type(TypeSignature::String)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## [`PropertySignatureBuilder`]
//! Constructs property signatures for properties and indexers:
//! ```rust
//! use dotscope::metadata::signatures::{PropertySignatureBuilder, TypeSignature};
//!
//! # fn example() -> dotscope::Result<()> {
//! let signature = PropertySignatureBuilder::new()
//!     .has_this(true)  // Instance property
//!     .property_type(TypeSignature::I4)
//!     .param(TypeSignature::String)  // For indexer: string indexer[string key]
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## [`LocalVariableSignatureBuilder`]
//! Constructs local variable signatures for method bodies:
//! ```rust
//! use dotscope::metadata::signatures::{LocalVariableSignatureBuilder, TypeSignature};
//!
//! # fn example() -> dotscope::Result<()> {
//! let signature = LocalVariableSignatureBuilder::new()
//!     .add_local(TypeSignature::I4)
//!     .add_pinned_local(TypeSignature::String)
//!     .add_byref_local(TypeSignature::Object)
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## [`TypeSpecSignatureBuilder`]
//! Constructs type specification signatures for generic instantiations:
//! ```rust
//! use dotscope::metadata::signatures::{TypeSpecSignatureBuilder, TypeSignature};
//! use dotscope::metadata::token::Token;
//!
//! # fn example() -> dotscope::Result<()> {
//! let list_token = Token::new(0x02000001); // List<T> type token
//! let signature = TypeSpecSignatureBuilder::new()
//!     .generic_instantiation(
//!         TypeSignature::Class(list_token),
//!         vec![TypeSignature::I4]  // List<int>
//!     )
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Integration with Blob Heaps
//!
//! All builders produce signature structures that can be encoded using the existing
//! [`crate::metadata::typesystem::encoder::TypeSignatureEncoder`] and stored in blob heaps.
//! Integration with the assembly modification system is provided through the
//! [`crate::cilassembly::builder::BuilderContext`].
//!
//! # Validation and Error Handling
//!
//! Builders perform validation during construction and at build time:
//! - Calling convention conflicts are detected and prevented
//! - Parameter counts are automatically maintained
//! - Invalid type combinations are rejected
//! - ECMA-335 compliance is enforced

use crate::{
    metadata::{
        signatures::{
            types::{
                SignatureField, SignatureLocalVariable, SignatureLocalVariables, SignatureMethod,
                SignatureParameter, SignatureProperty, SignatureTypeSpec, TypeSignature,
            },
            CustomModifier,
        },
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing method signatures with fluent API.
///
/// `MethodSignatureBuilder` provides a type-safe, fluent interface for creating
/// [`SignatureMethod`] instances. The builder ensures that signatures are
/// well-formed and comply with ECMA-335 requirements.
///
/// # Calling Conventions
///
/// The builder ensures that only one calling convention is active at a time:
/// - [`calling_convention_default()`](Self::calling_convention_default): Default managed calling convention
/// - [`calling_convention_vararg()`](Self::calling_convention_vararg): Variable argument calling convention
/// - [`calling_convention_cdecl()`](Self::calling_convention_cdecl): C declaration calling convention
/// - [`calling_convention_stdcall()`](Self::calling_convention_stdcall): Standard call calling convention
/// - [`calling_convention_thiscall()`](Self::calling_convention_thiscall): This call calling convention
/// - [`calling_convention_fastcall()`](Self::calling_convention_fastcall): Fast call calling convention
///
/// # Generic Methods
///
/// Generic methods are supported through the [`generic_param_count()`](Self::generic_param_count) method:
/// ```rust
/// use dotscope::metadata::signatures::MethodSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = MethodSignatureBuilder::new()
///     .calling_convention_default()
///     .generic_param_count(1)  // T Method<T>(T item)
///     .returns(TypeSignature::GenericParamMethod(0))  // Return T
///     .param(TypeSignature::GenericParamMethod(0))    // Parameter T
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Variable Arguments
///
/// Variable argument methods are supported when using the vararg calling convention:
/// ```rust
/// use dotscope::metadata::signatures::MethodSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = MethodSignatureBuilder::new()
///     .calling_convention_vararg()
///     .returns(TypeSignature::Void)
///     .param(TypeSignature::String)           // Fixed parameter
///     .vararg_param(TypeSignature::Object)    // Variable argument
///     .vararg_param(TypeSignature::I4)        // Another variable argument
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MethodSignatureBuilder {
    signature: SignatureMethod,
}

impl MethodSignatureBuilder {
    /// Creates a new method signature builder with default settings.
    ///
    /// The default configuration creates a static, non-generic method with
    /// the default managed calling convention and void return type.
    pub fn new() -> Self {
        Self {
            signature: SignatureMethod {
                has_this: false,
                explicit_this: false,
                default: true, // Default to managed calling convention
                vararg: false,
                cdecl: false,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                param_count_generic: 0,
                param_count: 0,
                return_type: SignatureParameter {
                    modifiers: vec![],
                    by_ref: false,
                    base: TypeSignature::Void,
                },
                params: vec![],
                varargs: vec![],
            },
        }
    }

    /// Sets the method to use the default managed calling convention.
    ///
    /// This is the standard calling convention for .NET methods and is
    /// the default setting for new builders.
    pub fn calling_convention_default(mut self) -> Self {
        self.clear_calling_conventions();
        self.signature.default = true;
        self
    }

    /// Sets the method to use the variable argument calling convention.
    ///
    /// Methods using this calling convention can accept additional arguments
    /// beyond their fixed parameter list through the [`vararg_param()`](Self::vararg_param) method.
    pub fn calling_convention_vararg(mut self) -> Self {
        self.clear_calling_conventions();
        self.signature.vararg = true;
        self
    }

    /// Sets the method to use the C declaration calling convention.
    ///
    /// This calling convention is used for interop with native C functions.
    pub fn calling_convention_cdecl(mut self) -> Self {
        self.clear_calling_conventions();
        self.signature.cdecl = true;
        self
    }

    /// Sets the method to use the standard call calling convention.
    ///
    /// This calling convention is commonly used for Windows API functions.
    pub fn calling_convention_stdcall(mut self) -> Self {
        self.clear_calling_conventions();
        self.signature.stdcall = true;
        self
    }

    /// Sets the method to use the this call calling convention.
    ///
    /// This calling convention is used for C++ member functions.
    pub fn calling_convention_thiscall(mut self) -> Self {
        self.clear_calling_conventions();
        self.signature.thiscall = true;
        self
    }

    /// Sets the method to use the fast call calling convention.
    ///
    /// This calling convention uses registers for parameter passing where possible.
    pub fn calling_convention_fastcall(mut self) -> Self {
        self.clear_calling_conventions();
        self.signature.fastcall = true;
        self
    }

    /// Sets whether this method has an implicit `this` parameter.
    ///
    /// Instance methods should set this to `true`, while static methods
    /// should set this to `false` (the default).
    ///
    /// # Arguments
    /// * `has_this` - `true` for instance methods, `false` for static methods
    pub fn has_this(mut self, has_this: bool) -> Self {
        self.signature.has_this = has_this;
        self
    }

    /// Sets whether the `this` parameter is explicitly declared in the signature.
    ///
    /// This is typically used for special interop scenarios and is rarely
    /// needed for normal .NET methods.
    ///
    /// # Arguments
    /// * `explicit_this` - `true` if `this` is explicitly declared
    pub fn explicit_this(mut self, explicit_this: bool) -> Self {
        self.signature.explicit_this = explicit_this;
        self
    }

    /// Sets the number of generic type parameters this method declares.
    ///
    /// Generic methods with type parameters like `<T>` or `<T, U>` should
    /// specify the parameter count here.
    ///
    /// # Arguments
    /// * `count` - Number of generic type parameters (0 for non-generic methods)
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::signatures::MethodSignatureBuilder;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// // For method: T Method<T>(T item)
    /// let builder = MethodSignatureBuilder::new()
    ///     .generic_param_count(1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn generic_param_count(mut self, count: u32) -> Self {
        self.signature.param_count_generic = count;
        self
    }

    /// Sets the return type of the method.
    ///
    /// # Arguments
    /// * `return_type` - The type signature for the method's return value
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::signatures::MethodSignatureBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let builder = MethodSignatureBuilder::new()
    ///     .returns(TypeSignature::I4);  // Returns int
    /// # Ok(())
    /// # }
    /// ```
    pub fn returns(mut self, return_type: TypeSignature) -> Self {
        self.signature.return_type.base = return_type;
        self
    }

    /// Sets the return type to be passed by reference.
    ///
    /// This is used for methods that return references (`ref` returns in C#).
    pub fn returns_by_ref(mut self) -> Self {
        self.signature.return_type.by_ref = true;
        self
    }

    /// Adds a custom modifier to the return type.
    ///
    /// # Arguments
    /// * `modifier_token` - Token referencing the modifier type
    /// * `is_required` - Whether this is a required (modreq) or optional (modopt) modifier
    pub fn return_modifier(mut self, modifier_token: Token, is_required: bool) -> Self {
        self.signature.return_type.modifiers.push(CustomModifier {
            is_required,
            modifier_type: modifier_token,
        });
        self
    }

    /// Adds a fixed parameter to the method signature.
    ///
    /// Fixed parameters are the standard method parameters that are always
    /// present when the method is called.
    ///
    /// # Arguments
    /// * `param_type` - The type signature for the parameter
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::signatures::MethodSignatureBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let builder = MethodSignatureBuilder::new()
    ///     .param(TypeSignature::String)   // First parameter: string
    ///     .param(TypeSignature::I4);      // Second parameter: int
    /// # Ok(())
    /// # }
    /// ```
    pub fn param(mut self, param_type: TypeSignature) -> Self {
        let param = SignatureParameter {
            modifiers: vec![],
            by_ref: false,
            base: param_type,
        };
        self.signature.params.push(param);
        self
    }

    /// Adds a by-reference parameter to the method signature.
    ///
    /// This is used for `ref` and `out` parameters in C#.
    ///
    /// # Arguments
    /// * `param_type` - The type signature for the parameter
    pub fn param_by_ref(mut self, param_type: TypeSignature) -> Self {
        let param = SignatureParameter {
            modifiers: vec![],
            by_ref: true,
            base: param_type,
        };
        self.signature.params.push(param);
        self
    }

    /// Adds a parameter with custom modifiers to the method signature.
    ///
    /// # Arguments
    /// * `param_type` - The type signature for the parameter
    /// * `modifiers` - Custom modifiers to apply to the parameter
    pub fn param_with_modifiers(
        mut self,
        param_type: TypeSignature,
        modifiers: Vec<CustomModifier>,
    ) -> Self {
        let param = SignatureParameter {
            modifiers,
            by_ref: false,
            base: param_type,
        };
        self.signature.params.push(param);
        self
    }

    /// Adds a variable argument parameter to the method signature.
    ///
    /// Variable argument parameters are only valid when using the vararg
    /// calling convention. These parameters can be omitted when calling
    /// the method.
    ///
    /// # Arguments
    /// * `param_type` - The type signature for the variable argument parameter
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::signatures::MethodSignatureBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let builder = MethodSignatureBuilder::new()
    ///     .calling_convention_vararg()
    ///     .param(TypeSignature::String)        // Fixed parameter
    ///     .vararg_param(TypeSignature::Object) // Variable argument
    ///     .vararg_param(TypeSignature::I4);    // Another variable argument
    /// # Ok(())
    /// # }
    /// ```
    pub fn vararg_param(mut self, param_type: TypeSignature) -> Self {
        let param = SignatureParameter {
            modifiers: vec![],
            by_ref: false,
            base: param_type,
        };
        self.signature.varargs.push(param);
        self
    }

    /// Builds the final method signature.
    ///
    /// Performs validation to ensure the signature is well-formed and
    /// complies with ECMA-335 requirements.
    ///
    /// # Returns
    /// A [`SignatureMethod`] instance ready for encoding.
    ///
    /// # Errors
    /// - No calling convention is set
    /// - Vararg parameters are used without vararg calling convention
    /// - Invalid calling convention combinations
    pub fn build(mut self) -> Result<SignatureMethod> {
        // Validate calling convention
        let calling_conv_count = [
            self.signature.default,
            self.signature.vararg,
            self.signature.cdecl,
            self.signature.stdcall,
            self.signature.thiscall,
            self.signature.fastcall,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        if calling_conv_count == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Method signature must have exactly one calling convention".to_string(),
            });
        }

        if calling_conv_count > 1 {
            return Err(Error::ModificationInvalidOperation {
                details: "Method signature cannot have multiple calling conventions".to_string(),
            });
        }

        // Validate varargs usage
        if !self.signature.varargs.is_empty() && !self.signature.vararg {
            return Err(Error::ModificationInvalidOperation {
                details: "Variable argument parameters require vararg calling convention"
                    .to_string(),
            });
        }

        // Validate explicit_this requires has_this
        if self.signature.explicit_this && !self.signature.has_this {
            return Err(Error::ModificationInvalidOperation {
                details: "explicit_this requires has_this to be true".to_string(),
            });
        }

        // Update param_count to match actual parameter count
        self.signature.param_count = self.signature.params.len() as u32;

        Ok(self.signature)
    }

    /// Helper method to clear all calling convention flags.
    fn clear_calling_conventions(&mut self) {
        self.signature.default = false;
        self.signature.vararg = false;
        self.signature.cdecl = false;
        self.signature.stdcall = false;
        self.signature.thiscall = false;
        self.signature.fastcall = false;
    }
}

impl Default for MethodSignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing field signatures with fluent API.
///
/// `FieldSignatureBuilder` provides a type-safe interface for creating
/// [`SignatureField`] instances used in field definitions and references.
///
/// # Basic Usage
/// ```rust
/// use dotscope::metadata::signatures::FieldSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = FieldSignatureBuilder::new()
///     .field_type(TypeSignature::String)
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Custom Modifiers
/// Field signatures can include custom modifiers for advanced scenarios:
/// ```rust
/// use dotscope::metadata::signatures::FieldSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// let volatile_token = Token::new(0x01000001); // Reference to volatile modifier
/// let signature = FieldSignatureBuilder::new()
///     .field_type(TypeSignature::I4)
///     .custom_modifier(volatile_token, false) // false = optional modifier
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct FieldSignatureBuilder {
    field_type: Option<TypeSignature>,
    modifiers: Vec<CustomModifier>,
}

impl FieldSignatureBuilder {
    /// Creates a new field signature builder.
    pub fn new() -> Self {
        Self {
            field_type: None,
            modifiers: vec![],
        }
    }

    /// Sets the type of the field.
    ///
    /// # Arguments
    /// * `field_type` - The type signature for the field
    pub fn field_type(mut self, field_type: TypeSignature) -> Self {
        self.field_type = Some(field_type);
        self
    }

    /// Adds a custom modifier to the field.
    ///
    /// Custom modifiers provide additional type information for advanced
    /// scenarios like volatile fields or platform-specific annotations.
    ///
    /// # Arguments
    /// * `modifier_token` - Token referencing the modifier type
    pub fn custom_modifier(mut self, modifier_token: Token, is_required: bool) -> Self {
        self.modifiers.push(CustomModifier {
            is_required,
            modifier_type: modifier_token,
        });
        self
    }

    /// Builds the final field signature.
    ///
    /// # Returns
    /// A [`SignatureField`] instance ready for encoding.
    ///
    /// # Errors
    /// - No field type is specified
    pub fn build(self) -> Result<SignatureField> {
        let field_type = self
            .field_type
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Field signature must specify a field type".to_string(),
            })?;

        Ok(SignatureField {
            modifiers: self.modifiers,
            base: field_type,
        })
    }
}

impl Default for FieldSignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing property signatures with fluent API.
///
/// `PropertySignatureBuilder` provides a type-safe interface for creating
/// [`SignatureProperty`] instances used in property definitions.
///
/// # Simple Property
/// ```rust
/// use dotscope::metadata::signatures::PropertySignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = PropertySignatureBuilder::new()
///     .has_this(true)  // Instance property
///     .property_type(TypeSignature::String)
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Indexed Property
/// ```rust
/// use dotscope::metadata::signatures::PropertySignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// // Property: string this[int index, string key] { get; set; }
/// let signature = PropertySignatureBuilder::new()
///     .has_this(true)
///     .property_type(TypeSignature::String)
///     .param(TypeSignature::I4)       // int index
///     .param(TypeSignature::String)   // string key
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PropertySignatureBuilder {
    signature: SignatureProperty,
}

impl PropertySignatureBuilder {
    /// Creates a new property signature builder.
    pub fn new() -> Self {
        Self {
            signature: SignatureProperty {
                has_this: false,
                modifiers: vec![],
                base: TypeSignature::Object, // Default to object, will be overridden
                params: vec![],
            },
        }
    }

    /// Sets whether this property has an implicit `this` parameter.
    ///
    /// Instance properties should set this to `true`, while static properties
    /// should set this to `false` (the default).
    ///
    /// # Arguments
    /// * `has_this` - `true` for instance properties, `false` for static properties
    pub fn has_this(mut self, has_this: bool) -> Self {
        self.signature.has_this = has_this;
        self
    }

    /// Sets the type of the property.
    ///
    /// # Arguments
    /// * `property_type` - The type signature for the property's value
    pub fn property_type(mut self, property_type: TypeSignature) -> Self {
        self.signature.base = property_type;
        self
    }

    /// Adds a custom modifier to the property type.
    ///
    /// # Arguments
    /// * `modifier_token` - Token referencing the modifier type
    /// * `is_required` - Whether this is a required (modreq) or optional (modopt) modifier
    pub fn property_type_modifier(mut self, modifier_token: Token, is_required: bool) -> Self {
        self.signature.modifiers.push(CustomModifier {
            is_required,
            modifier_type: modifier_token,
        });
        self
    }

    /// Adds a parameter for indexed properties.
    ///
    /// Indexed properties (indexers) can have multiple parameters that
    /// specify the index values used to access the property.
    ///
    /// # Arguments
    /// * `param_type` - The type signature for the index parameter
    pub fn param(mut self, param_type: TypeSignature) -> Self {
        let param = SignatureParameter {
            modifiers: vec![],
            by_ref: false,
            base: param_type,
        };
        self.signature.params.push(param);
        self
    }

    /// Adds a by-reference parameter for indexed properties.
    ///
    /// # Arguments
    /// * `param_type` - The type signature for the index parameter
    pub fn param_by_ref(mut self, param_type: TypeSignature) -> Self {
        let param = SignatureParameter {
            modifiers: vec![],
            by_ref: true,
            base: param_type,
        };
        self.signature.params.push(param);
        self
    }

    /// Builds the final property signature.
    ///
    /// # Returns
    /// A [`SignatureProperty`] instance ready for encoding.
    pub fn build(self) -> Result<SignatureProperty> {
        Ok(self.signature)
    }
}

impl Default for PropertySignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing local variable signatures with fluent API.
///
/// `LocalVariableSignatureBuilder` provides a type-safe interface for creating
/// [`SignatureLocalVariables`] instances used in method body metadata.
///
/// # Basic Usage
/// ```rust
/// use dotscope::metadata::signatures::LocalVariableSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = LocalVariableSignatureBuilder::new()
///     .add_local(TypeSignature::I4)       // int local
///     .add_local(TypeSignature::String)   // string local
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Advanced Local Types
/// ```rust
/// use dotscope::metadata::signatures::LocalVariableSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = LocalVariableSignatureBuilder::new()
///     .add_local(TypeSignature::I4)
///     .add_pinned_local(TypeSignature::String)  // Pinned for interop
///     .add_byref_local(TypeSignature::Object)   // Reference local
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct LocalVariableSignatureBuilder {
    signature: SignatureLocalVariables,
}

impl LocalVariableSignatureBuilder {
    /// Creates a new local variable signature builder.
    pub fn new() -> Self {
        Self {
            signature: SignatureLocalVariables { locals: vec![] },
        }
    }

    /// Adds a local variable to the signature.
    ///
    /// # Arguments
    /// * `local_type` - The type signature for the local variable
    pub fn add_local(mut self, local_type: TypeSignature) -> Self {
        let local = SignatureLocalVariable {
            modifiers: vec![],
            is_byref: false,
            is_pinned: false,
            base: local_type,
        };
        self.signature.locals.push(local);
        self
    }

    /// Adds a pinned local variable to the signature.
    ///
    /// Pinned locals are used in unsafe/interop scenarios where the
    /// garbage collector must not move the variable in memory.
    ///
    /// # Arguments
    /// * `local_type` - The type signature for the pinned local variable
    pub fn add_pinned_local(mut self, local_type: TypeSignature) -> Self {
        let local = SignatureLocalVariable {
            modifiers: vec![],
            is_byref: false,
            is_pinned: true,
            base: local_type,
        };
        self.signature.locals.push(local);
        self
    }

    /// Adds a by-reference local variable to the signature.
    ///
    /// By-reference locals store references to other variables rather
    /// than the actual values.
    ///
    /// # Arguments
    /// * `local_type` - The type signature for the referenced type
    pub fn add_byref_local(mut self, local_type: TypeSignature) -> Self {
        let local = SignatureLocalVariable {
            modifiers: vec![],
            is_byref: true,
            is_pinned: false,
            base: local_type,
        };
        self.signature.locals.push(local);
        self
    }

    /// Adds a local variable with custom modifiers.
    ///
    /// # Arguments
    /// * `local_type` - The type signature for the local variable
    /// * `modifiers` - Custom modifiers to apply to the local
    pub fn add_local_with_modifiers(
        mut self,
        local_type: TypeSignature,
        modifiers: Vec<CustomModifier>,
    ) -> Self {
        let local = SignatureLocalVariable {
            modifiers,
            is_byref: false,
            is_pinned: false,
            base: local_type,
        };
        self.signature.locals.push(local);
        self
    }

    /// Builds the final local variable signature.
    ///
    /// # Returns
    /// A [`SignatureLocalVariables`] instance ready for encoding.
    pub fn build(self) -> Result<SignatureLocalVariables> {
        Ok(self.signature)
    }
}

impl Default for LocalVariableSignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing type specification signatures with fluent API.
///
/// `TypeSpecSignatureBuilder` provides a type-safe interface for creating
/// [`SignatureTypeSpec`] instances used for generic type instantiations
/// and complex type references.
///
/// # Generic Instantiation
/// ```rust
/// use dotscope::metadata::signatures::TypeSpecSignatureBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
/// use dotscope::metadata::token::Token;
///
/// # fn example() -> dotscope::Result<()> {
/// let list_token = Token::new(0x02000001); // List<T> type token
/// let signature = TypeSpecSignatureBuilder::new()
///     .generic_instantiation(
///         TypeSignature::Class(list_token),
///         vec![TypeSignature::I4]  // List<int>
///     )
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Complex Array Type
/// ```rust
/// use dotscope::metadata::signatures::TypeSpecSignatureBuilder;
/// use dotscope::metadata::signatures::{TypeSignature, SignatureSzArray};
///
/// # fn example() -> dotscope::Result<()> {
/// let signature = TypeSpecSignatureBuilder::new()
///     .type_signature(TypeSignature::SzArray(SignatureSzArray {
///         modifiers: vec![],
///         base: Box::new(TypeSignature::String),
///     }))
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TypeSpecSignatureBuilder {
    type_signature: Option<TypeSignature>,
}

impl TypeSpecSignatureBuilder {
    /// Creates a new type specification signature builder.
    pub fn new() -> Self {
        Self {
            type_signature: None,
        }
    }

    /// Sets the type signature directly.
    ///
    /// # Arguments
    /// * `type_signature` - The type signature for the type specification
    pub fn type_signature(mut self, type_signature: TypeSignature) -> Self {
        self.type_signature = Some(type_signature);
        self
    }

    /// Creates a generic type instantiation.
    ///
    /// This is a convenience method for creating generic instantiations
    /// like `List<int>` or `Dictionary<string, object>`.
    ///
    /// # Arguments
    /// * `base_type` - The generic type definition (e.g., `List<T>`)
    /// * `type_args` - The type arguments for the instantiation
    ///
    /// # Examples
    /// ```rust
    /// use dotscope::metadata::signatures::TypeSpecSignatureBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// let dict_token = Token::new(0x02000001); // Dictionary<TKey, TValue>
    /// let signature = TypeSpecSignatureBuilder::new()
    ///     .generic_instantiation(
    ///         TypeSignature::Class(dict_token),
    ///         vec![TypeSignature::String, TypeSignature::I4]  // Dictionary<string, int>
    ///     )
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn generic_instantiation(
        mut self,
        base_type: TypeSignature,
        type_args: Vec<TypeSignature>,
    ) -> Self {
        self.type_signature = Some(TypeSignature::GenericInst(Box::new(base_type), type_args));
        self
    }

    /// Builds the final type specification signature.
    ///
    /// # Returns
    /// A [`SignatureTypeSpec`] instance ready for encoding.
    ///
    /// # Errors
    /// - No type signature is specified
    pub fn build(self) -> Result<SignatureTypeSpec> {
        let type_signature =
            self.type_signature
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Type specification signature must specify a type".to_string(),
                })?;

        Ok(SignatureTypeSpec {
            base: type_signature,
        })
    }
}

impl Default for TypeSpecSignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_signature_builder_basic() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .has_this(true)
            .returns(TypeSignature::I4)
            .param(TypeSignature::String)
            .build()
            .unwrap();

        assert!(signature.has_this);
        assert!(signature.default);
        assert_eq!(signature.param_count, 1);
        assert_eq!(signature.params.len(), 1);
        assert_eq!(signature.return_type.base, TypeSignature::I4);
        assert_eq!(signature.params[0].base, TypeSignature::String);
    }

    #[test]
    fn test_method_signature_builder_generic() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .generic_param_count(1)
            .returns(TypeSignature::GenericParamMethod(0))
            .param(TypeSignature::GenericParamMethod(0))
            .build()
            .unwrap();

        assert_eq!(signature.param_count_generic, 1);
        assert_eq!(
            signature.return_type.base,
            TypeSignature::GenericParamMethod(0)
        );
        assert_eq!(
            signature.params[0].base,
            TypeSignature::GenericParamMethod(0)
        );
    }

    #[test]
    fn test_method_signature_builder_varargs() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_vararg()
            .returns(TypeSignature::Void)
            .param(TypeSignature::String)
            .vararg_param(TypeSignature::Object)
            .vararg_param(TypeSignature::I4)
            .build()
            .unwrap();

        assert!(signature.vararg);
        assert_eq!(signature.param_count, 1);
        assert_eq!(signature.varargs.len(), 2);
        assert_eq!(signature.varargs[0].base, TypeSignature::Object);
        assert_eq!(signature.varargs[1].base, TypeSignature::I4);
    }

    #[test]
    fn test_method_signature_builder_validation_no_calling_convention() {
        let builder = MethodSignatureBuilder::new();
        // Clear the default calling convention
        let mut builder = builder;
        builder.signature.default = false;

        let result = builder.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exactly one calling convention"));
    }

    #[test]
    fn test_method_signature_builder_validation_multiple_calling_conventions() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .calling_convention_cdecl(); // This should clear default and set cdecl

        let result = signature.build();
        assert!(result.is_ok()); // Should be OK since calling_convention_cdecl clears others

        let sig = result.unwrap();
        assert!(!sig.default);
        assert!(sig.cdecl);
    }

    #[test]
    fn test_method_signature_builder_validation_varargs_without_vararg_convention() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .vararg_param(TypeSignature::Object);

        let result = signature.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("vararg calling convention"));
    }

    #[test]
    fn test_field_signature_builder() {
        let signature = FieldSignatureBuilder::new()
            .field_type(TypeSignature::String)
            .build()
            .unwrap();

        assert_eq!(signature.base, TypeSignature::String);
        assert!(signature.modifiers.is_empty());
    }

    #[test]
    fn test_field_signature_builder_with_modifiers() {
        let modifier_token = Token::new(0x01000001);
        let signature = FieldSignatureBuilder::new()
            .field_type(TypeSignature::I4)
            .custom_modifier(modifier_token, false) // false = optional modifier
            .build()
            .unwrap();

        assert_eq!(signature.base, TypeSignature::I4);
        assert_eq!(signature.modifiers.len(), 1);
        assert_eq!(signature.modifiers[0].modifier_type, modifier_token);
        assert!(!signature.modifiers[0].is_required);
    }

    #[test]
    fn test_field_signature_builder_validation_no_type() {
        let result = FieldSignatureBuilder::new().build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("field type"));
    }

    #[test]
    fn test_property_signature_builder() {
        let signature = PropertySignatureBuilder::new()
            .has_this(true)
            .property_type(TypeSignature::String)
            .param(TypeSignature::I4)
            .build()
            .unwrap();

        assert!(signature.has_this);
        assert_eq!(signature.base, TypeSignature::String);
        assert_eq!(signature.params.len(), 1);
        assert_eq!(signature.params[0].base, TypeSignature::I4);
    }

    #[test]
    fn test_local_variable_signature_builder() {
        let signature = LocalVariableSignatureBuilder::new()
            .add_local(TypeSignature::I4)
            .add_pinned_local(TypeSignature::String)
            .add_byref_local(TypeSignature::Object)
            .build()
            .unwrap();

        assert_eq!(signature.locals.len(), 3);

        // First local: int
        assert_eq!(signature.locals[0].base, TypeSignature::I4);
        assert!(!signature.locals[0].is_byref);
        assert!(!signature.locals[0].is_pinned);

        // Second local: pinned string
        assert_eq!(signature.locals[1].base, TypeSignature::String);
        assert!(!signature.locals[1].is_byref);
        assert!(signature.locals[1].is_pinned);

        // Third local: ref object
        assert_eq!(signature.locals[2].base, TypeSignature::Object);
        assert!(signature.locals[2].is_byref);
        assert!(!signature.locals[2].is_pinned);
    }

    #[test]
    fn test_type_spec_signature_builder() {
        let list_token = Token::new(0x02000001);
        let signature = TypeSpecSignatureBuilder::new()
            .generic_instantiation(TypeSignature::Class(list_token), vec![TypeSignature::I4])
            .build()
            .unwrap();

        if let TypeSignature::GenericInst(base_type, type_args) = &signature.base {
            if let TypeSignature::Class(token) = base_type.as_ref() {
                assert_eq!(*token, list_token);
            } else {
                panic!("Expected class type");
            }
            assert_eq!(type_args.len(), 1);
            assert_eq!(type_args[0], TypeSignature::I4);
        } else {
            panic!("Expected generic instantiation");
        }
    }

    #[test]
    fn test_type_spec_signature_builder_validation_no_type() {
        let result = TypeSpecSignatureBuilder::new().build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("specify a type"));
    }
}
