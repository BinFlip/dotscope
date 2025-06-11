//! Builder for .NET type specifications.
//!
//! This module provides the [`TypeBuilder`] struct, which offers a fluent API for constructing complex .NET type specifications, including primitives, classes, value types, interfaces, pointers, arrays, and generics. It is used internally by the type system and metadata loader to create and register types in the [`TypeRegistry`].
//!
//! # Example
//!
//! ```rust
//! use dotscope::metadata::typesystem::{TypeBuilder, TypeRegistry, CilPrimitiveKind};
//! use std::sync::Arc;
//!
//! let registry = Arc::new(TypeRegistry::new()?);
//! let builder = TypeBuilder::new(registry.clone())
//!     .primitive(CilPrimitiveKind::I4)?
//!     .pointer()
//!     .unwrap()
//!     .array();
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::sync::Arc;

use crate::{
    metadata::{
        signatures::SignatureMethod,
        token::Token,
        typesystem::{
            CilFlavor, CilModifier, CilPrimitiveKind, CilTypeRc, TypeRegistry, TypeSource,
        },
    },
    Error::TypeError,
    Result,
};

/// Provides a fluent API for building type specifications
pub struct TypeBuilder {
    /// Type registry for storing the types
    registry: Arc<TypeRegistry>,
    /// Current source context
    source: TypeSource,
    /// Current type being built
    current_type: Option<CilTypeRc>,
    /// Token for the initial type (if applicable)
    token_init: Option<Token>,
}

impl TypeBuilder {
    /// Create a new builder with the given registry
    ///
    /// ## Arguments
    /// * 'registry' - The type registry to use
    pub fn new(registry: Arc<TypeRegistry>) -> Self {
        TypeBuilder {
            registry,
            source: TypeSource::CurrentModule,
            current_type: None,
            token_init: None,
        }
    }

    /// Set the source context for the builder
    ///
    /// ## Arguments
    /// * 'source' - Set the source to use
    #[must_use]
    pub fn with_source(mut self, source: TypeSource) -> Self {
        self.source = source;
        self
    }

    /// Set the initial token
    ///
    /// ## Arguments
    /// * 'token' - Set the initial token to use
    #[must_use]
    pub fn with_token_init(mut self, token: Token) -> Self {
        self.token_init = Some(token);
        self
    }

    /// Start building a primitive type
    ///
    /// # Arguments
    /// * `primitive` - Get the `PrimitiveKind` base type
    ///
    /// # Errors
    /// Returns an error if the primitive type cannot be retrieved from the registry.
    pub fn primitive(mut self, primitive: CilPrimitiveKind) -> Result<Self> {
        self.current_type = Some(self.registry.get_primitive(primitive)?);
        Ok(self)
    }

    /// Start building a class with the given name
    ///
    /// ## Arguments
    /// * 'namespace' - Namespace for a class type
    /// * 'name'      - Name for a class type
    ///
    /// # Errors
    /// Returns an error if the class type cannot be created or retrieved from the registry.
    pub fn class(mut self, namespace: &str, name: &str) -> Result<Self> {
        self.current_type = Some(self.registry.get_or_create_type(
            &mut self.token_init,
            CilFlavor::Class,
            namespace,
            name,
            self.source,
        )?);
        Ok(self)
    }

    /// Start building a value type with the given name
    ///
    /// ## Arguments
    /// * 'namespace' - Namespace for a value type
    /// * 'name'      - Name for a value type
    ///
    /// # Errors
    /// Returns an error if the value type cannot be created or retrieved from the registry.
    pub fn value_type(mut self, namespace: &str, name: &str) -> Result<Self> {
        self.current_type = Some(self.registry.get_or_create_type(
            &mut self.token_init,
            CilFlavor::ValueType,
            namespace,
            name,
            self.source,
        )?);
        Ok(self)
    }

    /// Start building an interface with the given name
    ///
    /// ## Arguments
    /// * 'namespace' - Namespace for a interface type
    /// * 'name'      - Name for a interface type
    ///
    /// # Errors
    /// Returns an error if the interface type cannot be created or retrieved from the registry.
    pub fn interface(mut self, namespace: &str, name: &str) -> Result<Self> {
        self.current_type = Some(self.registry.get_or_create_type(
            &mut self.token_init,
            CilFlavor::Interface,
            namespace,
            name,
            self.source,
        )?);
        Ok(self)
    }

    /// Create a pointer to the current type
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the pointer type cannot be created.
    pub fn pointer(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("{}*", base_type.name);
            let namespace = base_type.namespace.clone();

            let ptr_type = self.registry.get_or_create_type(
                &mut self.token_init,
                CilFlavor::Pointer,
                &namespace,
                &name,
                self.source,
            )?;

            // Use weak reference to prevent cycles
            ptr_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Pointer type base already set"))?;
            self.current_type = Some(ptr_type);
        }
        Ok(self)
    }

    /// Create a by-reference version of the current type
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the by-reference type cannot be created.
    pub fn by_ref(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("{}&", base_type.name);
            let namespace = base_type.namespace.clone();

            let ref_type = self.registry.get_or_create_type(
                &mut self.token_init,
                CilFlavor::ByRef,
                &namespace,
                &name,
                self.source,
            )?;

            ref_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("ByRef type base already set"))?;
            self.current_type = Some(ref_type);
        }
        Ok(self)
    }

    /// Create a pinned version of the current type
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the pinned type cannot be created.
    pub fn pinned(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("pinned {}", base_type.name);
            let namespace = base_type.namespace.clone();

            let pinned_type = self.registry.get_or_create_type(
                &mut self.token_init,
                CilFlavor::Pinned,
                &namespace,
                &name,
                self.source,
            )?;

            pinned_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Pinned type base already set"))?;
            self.current_type = Some(pinned_type);
        }
        Ok(self)
    }

    /// Create a 1D array of the current type
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the array type cannot be created.
    pub fn array(mut self) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let name = format!("{}[]", base_type.name);
            let namespace = base_type.namespace.clone();

            let array_type = self.registry.get_or_create_type(
                &mut self.token_init,
                CilFlavor::Array {
                    rank: 1,
                    dimensions: vec![],
                },
                &namespace,
                &name,
                self.source,
            )?;

            array_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Array type base already set"))?;
            self.current_type = Some(array_type);
        }
        Ok(self)
    }

    /// Create a multi-dimensional array of the current type
    ///
    /// ## Arguments
    /// * 'rank' - The dimensions for the array
    ///
    /// # Errors
    /// Returns an error if no current type is set or if the multi-dimensional array type cannot be created.
    pub fn multi_dimensional_array(mut self, rank: u32) -> Result<Self> {
        if let Some(base_type) = self.current_type.take() {
            let dimension_part = if rank <= 1 {
                "[]".to_string()
            } else {
                format!("[{}]", ",".repeat(rank as usize - 1))
            };

            let name = format!("{}{}", base_type.name, dimension_part);
            let namespace = base_type.namespace.clone();

            let array_type = self.registry.get_or_create_type(
                &mut self.token_init,
                CilFlavor::Array {
                    rank,
                    dimensions: vec![],
                },
                &namespace,
                &name,
                self.source,
            )?;

            array_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Multi-dimensional array type base already set"))?;
            self.current_type = Some(array_type);
        }
        Ok(self)
    }

    /// Create or set a function pointer type
    ///
    /// ## Arguments
    /// * 'signature' - Set the signature for the function pointer
    ///
    /// # Errors
    /// Returns an error if the function pointer type cannot be created.
    pub fn function_pointer(mut self, signature: SignatureMethod) -> Result<Self> {
        let name = format!("FunctionPointer_{:X}", &raw const signature as usize);

        let fn_ptr_type = self.registry.get_or_create_type(
            &mut self.token_init,
            CilFlavor::FnPtr { signature },
            "",
            &name,
            self.source,
        )?;

        self.current_type = Some(fn_ptr_type);
        Ok(self)
    }

    /// Add required modifier to the current type
    ///
    /// ## Arguments
    /// * `modifer_token` - Set the modifier token
    ///
    /// # Errors
    /// Returns an error if the modifier cannot be applied (currently always succeeds).
    pub fn required_modifier(self, modifier_token: Token) -> Result<Self> {
        if let Some(current) = &self.current_type {
            if let Some(modifier_type) = self.registry.get(&modifier_token) {
                current.modifiers.push(CilModifier {
                    required: true,
                    modifier: modifier_type.into(),
                });
            }
        }
        Ok(self)
    }

    /// Add optional modifier to the current type
    ///
    /// ## Arguments
    /// * `modifer_token` - Set the modifier token
    ///
    /// # Errors
    /// Returns an error if the modifier cannot be applied (currently always succeeds).
    pub fn optional_modifier(self, modifier_token: Token) -> Result<Self> {
        if let Some(current) = &self.current_type {
            if let Some(modifier_type) = self.registry.get(&modifier_token) {
                current.modifiers.push(CilModifier {
                    required: false,
                    modifier: modifier_type.into(),
                });
            }
        }
        Ok(self)
    }

    /// Specify a base type for the current type
    ///
    /// ## Arguments
    /// * `base_token` - Set the base of the type
    ///
    /// # Errors
    /// Returns an error if the base type is already set or if the base token cannot be resolved.
    pub fn extends(self, base_token: Token) -> Result<Self> {
        if let Some(current) = &self.current_type {
            // Get the base type
            if let Some(base_type) = self.registry.get(&base_token) {
                current
                    .base
                    .set(base_type.into())
                    .map_err(|_| malformed_error!("Base type already set"))?;
            }
        }
        Ok(self)
    }

    /// Create a generic instance of the current type
    ///
    /// ## Arguments
    /// * `arg_count`   - Argument count for the generic instance
    /// * `arg_builder` - Builder function for the arguments
    ///
    /// # Errors
    /// Returns an error if no current type is set, if the argument builder fails,
    /// or if the generic instance type cannot be created.
    pub fn generic_instance<F>(mut self, arg_count: usize, arg_builder: F) -> Result<Self>
    where
        F: FnOnce(Arc<TypeRegistry>) -> Result<Vec<CilTypeRc>>,
    {
        if let Some(base_type) = self.current_type.take() {
            // Extract or create a name with arity
            let mut name = base_type.name.clone();
            if !name.contains('`') {
                name = format!("{}`{}", name, arg_count);
            }

            let namespace = base_type.namespace.clone();
            let generic_type = self.registry.get_or_create_type(
                &mut self.token_init,
                CilFlavor::GenericInstance,
                &namespace,
                &name,
                self.source,
            )?;

            let args = arg_builder(self.registry.clone())?;
            if !args.is_empty() {
                // For type-level generic instances, create MethodSpec instances that wrap the resolved types
                for (index, arg) in args.iter().enumerate() {
                    // Create a dummy method specification for the type argument
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

                    let method_spec = Arc::new(crate::metadata::streams::MethodSpec {
                        rid,
                        token: Token::new(token_value),
                        offset: 0,
                        method: crate::metadata::typesystem::CilTypeReference::None,
                        instantiation: crate::metadata::signatures::SignatureMethodSpec {
                            generic_args: vec![],
                        },
                        custom_attributes: Arc::new(boxcar::Vec::new()),
                        generic_args: {
                            let type_ref_list = Arc::new(boxcar::Vec::with_capacity(1));
                            type_ref_list.push(arg.clone().into());
                            type_ref_list
                        },
                    });
                    generic_type.generic_args.push(method_spec);
                }
            }

            generic_type
                .base
                .set(base_type.into())
                .map_err(|_| malformed_error!("Generic type base already set"))?;
            self.current_type = Some(generic_type);
        }
        Ok(self)
    }

    /// Finalize and return the built type
    ///
    /// # Errors
    /// Returns an error if no type has been built or if the type construction failed.
    pub fn build(self) -> Result<CilTypeRc> {
        match self.current_type {
            Some(t) => Ok(t),
            None => Err(TypeError("Failed to build requested Type".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::{
        metadata::{
            signatures::{SignatureMethod, SignatureParameter, TypeSignature},
            streams::GenericParam,
            token::Token,
            typesystem::{CilFlavor, CilPrimitiveKind, TypeRegistry, TypeSource},
        },
        Error,
    };

    #[test]
    fn test_build_primitive() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let int_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_type.name, "Int32");
        assert_eq!(int_type.namespace, "System");
        assert!(matches!(*int_type.flavor(), CilFlavor::I4));
    }

    #[test]
    fn test_build_pointer() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let int_ptr = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .pointer()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_ptr.name, "Int32*");
        assert!(matches!(*int_ptr.flavor(), CilFlavor::Pointer));

        let base_type = int_ptr.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Int32");
    }

    #[test]
    fn test_build_array() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let string_array = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::String)
            .unwrap()
            .array()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(string_array.name, "String[]");
        assert!(matches!(*string_array.flavor(), CilFlavor::Array { .. }));

        let base_type = string_array.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "String");
    }

    #[test]
    fn test_build_multidimensional_array() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let int_2d_array = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .multi_dimensional_array(2)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_2d_array.name, "Int32[,]");

        if let CilFlavor::Array { rank, .. } = *int_2d_array.flavor() {
            assert_eq!(rank, 2);
        } else {
            panic!("Expected Array flavor");
        };
    }

    #[test]
    fn test_build_class() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let list_type = TypeBuilder::new(registry.clone())
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(list_type.name, "List`1");
        assert_eq!(list_type.namespace, "System.Collections.Generic");
        assert!(matches!(*list_type.flavor(), CilFlavor::Class));
    }

    #[test]
    fn test_build_value_type() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let struct_type = TypeBuilder::new(registry.clone())
            .value_type("System", "DateTime")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(struct_type.name, "DateTime");
        assert_eq!(struct_type.namespace, "System");
        assert!(matches!(*struct_type.flavor(), CilFlavor::ValueType));
    }

    #[test]
    fn test_build_interface() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let interface_type = TypeBuilder::new(registry.clone())
            .interface("System.Collections.Generic", "IList`1")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(interface_type.name, "IList`1");
        assert_eq!(interface_type.namespace, "System.Collections.Generic");
        assert!(matches!(*interface_type.flavor(), CilFlavor::Interface));
    }

    #[test]
    fn test_build_generic_instance() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let list_type = TypeBuilder::new(registry.clone())
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .build()
            .unwrap();

        let generic_param = Arc::new(GenericParam {
            token: Token::new(0x2A000001),
            number: 0,
            flags: 0,
            owner: OnceLock::new(),
            name: "T".to_string(),
            constraints: Arc::new(boxcar::Vec::new()),
            rid: 0,
            offset: 0,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        list_type.generic_params.push(generic_param);

        let list_int_instance = TypeBuilder::new(registry.clone())
            .with_source(TypeSource::CurrentModule)
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .generic_instance(1, |registry| {
                // Get int type
                let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
                Ok(vec![int_type])
            })
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(list_int_instance.name, "List`1");
        assert!(matches!(
            *list_int_instance.flavor(),
            CilFlavor::GenericInstance
        ));

        assert_eq!(list_int_instance.generic_args.count(), 1);
        assert_eq!(
            list_int_instance.generic_args[0].generic_args[0]
                .name()
                .unwrap(),
            "Int32"
        );
    }

    #[test]
    fn test_build_byref() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let byref_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .by_ref()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(byref_type.name, "Int32&");
        assert!(matches!(*byref_type.flavor(), CilFlavor::ByRef));

        let base_type = byref_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Int32");
    }

    #[test]
    fn test_build_pinned() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let pinned_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::Object)
            .unwrap()
            .pinned()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(pinned_type.name, "pinned Object");
        assert!(matches!(*pinned_type.flavor(), CilFlavor::Pinned));

        let base_type = pinned_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(base_type.name, "Object");
    }

    #[test]
    fn test_build_function_pointer() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let signature = SignatureMethod {
            has_this: false,
            explicit_this: false,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                base: TypeSignature::Void,
                by_ref: false,
            },
            params: Vec::new(),
            default: false,
            vararg: false,
            cdecl: false,
            stdcall: true,
            thiscall: false,
            fastcall: false,
            param_count_generic: 0,
            param_count: 0,
            varargs: Vec::new(),
        };

        let fn_ptr = TypeBuilder::new(registry.clone())
            .function_pointer(signature)
            .unwrap()
            .build()
            .unwrap();

        assert!(fn_ptr.name.starts_with("FunctionPointer_"));
        if let CilFlavor::FnPtr { signature: sig } = &*fn_ptr.flavor() {
            assert!(!sig.has_this);
            assert_eq!(sig.params.len(), 0);
        } else {
            panic!("Expected FnPtr flavor");
        };
    }

    #[test]
    fn test_with_source() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let source = TypeSource::AssemblyRef(Token::new(0x23000001));
        let int_type = TypeBuilder::new(registry.clone())
            .with_source(source)
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_type.name, "Int32");
    }

    #[test]
    fn test_with_token_init() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let token: Token = Token::new(0x01000999);
        let list_type = TypeBuilder::new(registry.clone())
            .with_token_init(token)
            .class("System.Collections.Generic", "List`1")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(list_type.name, "List`1");
        assert_eq!(list_type.namespace, "System.Collections.Generic");
        assert_eq!(list_type.token, token);
        assert!(matches!(*list_type.flavor(), CilFlavor::Class));
    }

    #[test]
    fn test_modifiers() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let in_attr_token = Token::new(0x01000888);
        let _ = registry
            .get_or_create_type(
                &mut Some(in_attr_token),
                CilFlavor::Class,
                "System.Runtime.InteropServices",
                "InAttribute",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let int_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::I4)
            .unwrap()
            .required_modifier(in_attr_token)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(int_type.modifiers.count(), 1);
        assert!(int_type.modifiers[0].required);
        assert_eq!(
            int_type.modifiers[0].modifier.name().unwrap(),
            "InAttribute"
        );

        let string_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::String)
            .unwrap()
            .optional_modifier(in_attr_token)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(string_type.modifiers.count(), 1);
        assert!(!string_type.modifiers[0].required);
    }

    #[test]
    fn test_extends() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let base_token = Token::new(0x01000777);
        let _ = registry
            .get_or_create_type(
                &mut Some(base_token),
                CilFlavor::Class,
                "System",
                "Exception",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let derived_type = TypeBuilder::new(registry.clone())
            .class("System.IO", "IOException")
            .unwrap()
            .extends(base_token)
            .unwrap()
            .build()
            .unwrap();

        let base_type = derived_type.base.get().unwrap().upgrade();
        assert!(base_type.is_some());
        let base_type = base_type.unwrap();
        assert_eq!(base_type.token, base_token);
        assert_eq!(base_type.name, "Exception");
    }

    #[test]
    fn test_build_failure() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        let result = TypeBuilder::new(registry.clone()).build();
        assert!(result.is_err());
        match result {
            Err(Error::TypeError(_)) => (), // Expected error
            _ => panic!("Expected TypeError"),
        }
    }

    #[test]
    fn test_build_complex_chain() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        // Build a complex type chain: string[][]*&
        let complex_type = TypeBuilder::new(registry.clone())
            .primitive(CilPrimitiveKind::String)
            .unwrap()
            .array()
            .unwrap() // string[]
            .array()
            .unwrap() // string[][]
            .pointer()
            .unwrap() // string[][]*
            .by_ref()
            .unwrap() // string[][]*&
            .build()
            .unwrap();

        assert_eq!(complex_type.name, "String[][]*&");
        assert!(matches!(*complex_type.flavor(), CilFlavor::ByRef));

        let pointer_type = complex_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(pointer_type.name, "String[][]*");
        assert!(matches!(*pointer_type.flavor(), CilFlavor::Pointer));

        let array2d_type = pointer_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(array2d_type.name, "String[][]");

        let array_type = array2d_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(array_type.name, "String[]");

        let string_type = array_type.base.get().unwrap().upgrade().unwrap();
        assert_eq!(string_type.name, "String");
    }

    #[test]
    fn test_generic_instance_with_multiple_args() {
        let registry = Arc::new(TypeRegistry::new().unwrap());

        // Create Dictionary<TKey, TValue> type
        let dict_token = Token::new(0x01000555);
        let dict_type = registry
            .get_or_create_type(
                &mut Some(dict_token),
                CilFlavor::Class,
                "System.Collections.Generic",
                "Dictionary`2",
                TypeSource::CurrentModule,
            )
            .unwrap();

        let key_param = Arc::new(GenericParam {
            token: Token::new(0x2A000002),
            number: 0,
            flags: 0,
            owner: OnceLock::new(),
            name: "TKey".to_string(),
            constraints: Arc::new(boxcar::Vec::new()),
            rid: 0,
            offset: 0,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        let value_param = Arc::new(GenericParam {
            token: Token::new(0x2A000003),
            number: 1,
            flags: 0,
            owner: OnceLock::new(),
            name: "TValue".to_string(),
            constraints: Arc::new(boxcar::Vec::new()),
            rid: 1,
            offset: 1,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        dict_type.generic_params.push(key_param);
        dict_type.generic_params.push(value_param);

        // Create a Dictionary<string, int> instance
        let dict_instance = TypeBuilder::new(registry.clone())
            .with_source(TypeSource::CurrentModule)
            .with_token_init(dict_token)
            .class("System.Collections.Generic", "Dictionary`2")
            .unwrap()
            .generic_instance(2, |registry| {
                let string_type = registry.get_primitive(CilPrimitiveKind::String).unwrap();
                let int_type = registry.get_primitive(CilPrimitiveKind::I4).unwrap();
                Ok(vec![string_type, int_type])
            })
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(dict_instance.name, "Dictionary`2");
        assert!(matches!(
            *dict_instance.flavor(),
            CilFlavor::GenericInstance
        ));

        assert_eq!(dict_instance.generic_args.count(), 2);
        assert_eq!(
            dict_instance.generic_args[0].generic_args[0]
                .name()
                .unwrap(),
            "String"
        );
        assert_eq!(
            dict_instance.generic_args[1].generic_args[0]
                .name()
                .unwrap(),
            "Int32"
        );

        // With the simplified approach, we only store the resolved types
        // The order corresponds to the generic parameter order (0=TKey, 1=TValue)
        assert_eq!(
            dict_instance.generic_args[0].generic_args[0]
                .name()
                .unwrap(),
            "String"
        ); // TKey -> String
        assert_eq!(
            dict_instance.generic_args[1].generic_args[0]
                .name()
                .unwrap(),
            "Int32"
        ); // TValue -> Int32
    }
}
