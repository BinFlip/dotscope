use std::sync::Arc;

use crate::{
    metadata::{
        signatures::{SignatureMethodSpec, TypeSignature},
        streams::MethodSpec,
        token::Token,
        typesystem::{
            ArrayDimensions, CilFlavor, CilModifier, CilPrimitiveKind, CilTypeRc, CilTypeReference,
            TypeRegistry, TypeSource,
        },
    },
    Error::{RecursionLimit, TypeError, TypeMissingParent, TypeNotFound},
    Result,
};

/// Maximum recursion depth for type signature resolution
const MAX_RECURSION_DEPTH: usize = 100;

/// Resolves type signatures to concrete types in the registry
pub struct TypeResolver {
    /// Reference to the type registry
    registry: Arc<TypeRegistry>,
    /// Current source context
    current_source: TypeSource,
    /// Token of the parent type (if applicable)
    token_parent: Option<Token>,
    /// Token for the initial type (if applicable)
    token_init: Option<Token>,
}

impl TypeResolver {
    /// Create a new resolver with the given registry
    ///
    /// ## Arguments
    /// * 'registry' - The type registry to use
    pub fn new(registry: Arc<TypeRegistry>) -> Self {
        TypeResolver {
            registry,
            current_source: TypeSource::CurrentModule,
            token_parent: None,
            token_init: None,
        }
    }

    /// Set the current source context
    ///
    /// ## Arguments
    /// * 'source' - The source to set for the current context
    #[must_use]
    pub fn with_source(mut self, source: TypeSource) -> Self {
        self.current_source = source;
        self
    }

    /// Set the parent token
    ///
    /// ## Arguments
    /// * 'token' - The token of the parent
    #[must_use]
    pub fn with_parent(mut self, token: Token) -> Self {
        self.token_parent = Some(token);
        self
    }

    /// Set the initial token
    ///
    /// ## Arguments
    /// * 'token' - The token for the first type
    #[must_use]
    pub fn with_token_init(mut self, token: Token) -> Self {
        self.token_init = Some(token);
        self
    }

    /// Resolve a type signature to a concrete type
    ///
    /// ## Arguments
    /// * 'signature' - The signature to resolve
    ///
    /// # Errors
    /// Returns an error if:
    /// - Type references cannot be found in the registry
    /// - Recursion depth exceeds the maximum limit
    /// - Required parent types are missing for modifier types
    /// - Type creation or modification fails
    pub fn resolve(&mut self, signature: &TypeSignature) -> Result<CilTypeRc> {
        self.resolve_with_depth(signature, 0)
    }

    /// Internal recursive resolver with depth tracking
    ///
    /// ## Arguments
    /// * 'signature'   - The signature to resolve
    /// * 'depth'       - Indicator of recursion level
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
            TypeSignature::Class(token) => {
                if let Some(class_type) = self.registry.get(token) {
                    Ok(class_type)
                } else {
                    Err(TypeNotFound(*token))
                }
            }
            TypeSignature::ValueType(token) => {
                if let Some(value_type) = self.registry.get(token) {
                    Ok(value_type)
                } else {
                    Err(TypeNotFound(*token))
                }
            }
            TypeSignature::ModifiedRequired(tokens) => {
                if let Some(parent_token) = self.token_parent {
                    if let Some(parent_type) = self.registry.get(&parent_token) {
                        for &token in tokens {
                            if let Some(mod_type) = self.registry.get(&token) {
                                parent_type.modifiers.push(CilModifier {
                                    required: true,
                                    modifier: mod_type.into(),
                                });
                            } else {
                                return Err(TypeNotFound(token));
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
            TypeSignature::ModifiedOptional(tokens) => {
                if let Some(parent_token) = self.token_parent {
                    if let Some(parent_type) = self.registry.get(&parent_token) {
                        for &token in tokens {
                            if let Some(mod_type) = self.registry.get(&token) {
                                parent_type.modifiers.push(CilModifier {
                                    required: false,
                                    modifier: mod_type.into(),
                                });
                            } else {
                                return Err(TypeNotFound(token));
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

                for &token in &szarray.modifiers {
                    if let Some(mod_type) = self.registry.get(&token) {
                        array_type.modifiers.push(CilModifier {
                            required: true,
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

                for &token in &ptr.modifiers {
                    if let Some(mod_type) = self.registry.get(&token) {
                        ptr_type.modifiers.push(CilModifier {
                            required: true,
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
                let param_name = format!("T{}", index);

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
                let param_name = format!("TM{}", index);

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
            streams::GenericParam,
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
            modifiers: vec![in_attr_token],
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

        let req_mod_sig = TypeSignature::ModifiedRequired(vec![modifier_token]);
        let req_mod_type = resolver.resolve(&req_mod_sig).unwrap();

        assert_eq!(req_mod_type.token, parent_token);
        assert_eq!(req_mod_type.modifiers.count(), 1);
        assert!(req_mod_type.modifiers[0].required);
        assert_eq!(
            req_mod_type.modifiers[0].modifier.token().unwrap(),
            modifier_token
        );

        let opt_mod_sig = TypeSignature::ModifiedOptional(vec![modifier_token]);
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
        let mod_sig = TypeSignature::ModifiedRequired(vec![mod_token]);
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
