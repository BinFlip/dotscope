//! Custom attribute parsing and representation for .NET metadata.
//!
//! This module provides parsing of .NET custom attributes according to the ECMA-335 standard.
//! Custom attributes encode metadata annotations in a compact binary format that includes
//! constructor arguments and named field/property values.
//!
//! # Custom Attribute Format
//!
//! Custom attributes use a binary encoding with the following structure:
//! - **Prolog** - Standard 0x0001 marker indicating valid custom attribute blob
//! - **Fixed Arguments** - Constructor parameter values in declaration order
//! - **Named Arguments** - Field and property values with name/value pairs
//!
//! # Parsing Approach
//!
//! The parsing implementation follows ECMA-335 II.23.3 specification strictly:
//!
//! - **Type-Aware Parsing** - Uses resolved constructor method parameters for precise parsing
//! - **Standard Compliance** - Only accepts well-formed custom attribute blobs with proper type information
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::{parse_custom_attribute_data, CustomAttributeValue};
//! use dotscope::metadata::method::MethodRc;
//!
//! // Parse a custom attribute blob with constructor method information
//! let blob_data = &[0x01, 0x00, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F]; // Example blob
//! # fn get_constructor_method() -> MethodRc { todo!() }
//! let constructor_method = get_constructor_method();
//! let result = parse_custom_attribute_data(blob_data, &constructor_method.params)?;
//!
//! match result {
//!     CustomAttributeValue { fixed_args, named_args } => {
//!         println!("Found {} fixed arguments and {} named arguments",
//!                  fixed_args.len(), named_args.len());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Implementation Notes
//!
//! - All parsing follows ECMA-335 II.23.3 specification for custom attribute encoding
//! - Constructor method information is required for accurate type-aware parsing
//! - Named arguments support both field and property assignments according to the specification
//!
//! # References
//!
//! - ECMA-335 6th Edition, Partition II, Section 23.3 - Custom Attributes

mod parser;
mod types;

pub use parser::{parse_custom_attribute_blob, parse_custom_attribute_data};
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplManagement, MethodImplOptions,
            MethodModifiers, MethodRc, MethodVtableFlags,
        },
        signatures::SignatureMethod,
        streams::{Param, ParamRc},
        token::Token,
        typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeRef, TypeBuilder, TypeRegistry},
    };
    use std::sync::{
        atomic::AtomicU32,
        {Arc, OnceLock},
    };

    // Helper function to extract params Arc from method for the new API
    fn get_params_from_method(method: &MethodRc) -> &Arc<boxcar::Vec<ParamRc>> {
        &method.params
    }

    // Helper function to create a mock method for testing
    fn create_mock_method() -> MethodRc {
        Arc::new(Method {
            rid: 1,
            token: Token::new(0x06000001),
            meta_offset: 0,
            name: "TestConstructor".to_string(),
            impl_code_type: MethodImplCodeType::empty(),
            impl_management: MethodImplManagement::empty(),
            impl_options: MethodImplOptions::empty(),
            flags_access: MethodAccessFlags::empty(),
            flags_vtable: MethodVtableFlags::empty(),
            flags_modifiers: MethodModifiers::empty(),
            flags_pinvoke: AtomicU32::new(0),
            params: Arc::new(boxcar::Vec::new()),
            varargs: Arc::new(boxcar::Vec::new()),
            generic_params: Arc::new(boxcar::Vec::new()),
            generic_args: Arc::new(boxcar::Vec::new()),
            signature: SignatureMethod::default(),
            rva: None,
            body: OnceLock::new(),
            local_vars: Arc::new(boxcar::Vec::new()),
            overrides: OnceLock::new(),
            interface_impls: Arc::new(boxcar::Vec::new()),
            security: OnceLock::new(),
            blocks: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        })
    }

    // Helper function to create a method with specific parameter types
    fn create_method_with_params(param_types: Vec<CilFlavor>) -> MethodRc {
        let method = create_mock_method();
        let type_registry = Arc::new(TypeRegistry::new().unwrap());

        for (i, flavor) in param_types.into_iter().enumerate() {
            // Use the TypeRegistry to get or create types with proper lifetime management
            let param_type = match flavor {
                CilFlavor::Boolean => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::Boolean)
                    .unwrap(),
                CilFlavor::Char => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::Char)
                    .unwrap(),
                CilFlavor::I1 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::I1)
                    .unwrap(),
                CilFlavor::U1 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::U1)
                    .unwrap(),
                CilFlavor::I2 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::I2)
                    .unwrap(),
                CilFlavor::U2 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::U2)
                    .unwrap(),
                CilFlavor::I4 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::I4)
                    .unwrap(),
                CilFlavor::U4 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::U4)
                    .unwrap(),
                CilFlavor::I8 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::I8)
                    .unwrap(),
                CilFlavor::U8 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::U8)
                    .unwrap(),
                CilFlavor::R4 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::R4)
                    .unwrap(),
                CilFlavor::R8 => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::R8)
                    .unwrap(),
                CilFlavor::I => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::I)
                    .unwrap(),
                CilFlavor::U => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::U)
                    .unwrap(),
                CilFlavor::String => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::String)
                    .unwrap(),
                CilFlavor::Object => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::Object)
                    .unwrap(),
                CilFlavor::Void => type_registry
                    .get_primitive(crate::metadata::typesystem::CilPrimitiveKind::Void)
                    .unwrap(),
                other_flavor => {
                    // For complex types, create them properly in the registry
                    type_registry
                        .get_or_create_type(
                            &mut None,
                            other_flavor,
                            "System",
                            "TestType",
                            crate::metadata::typesystem::TypeSource::CurrentModule,
                        )
                        .unwrap()
                }
            };

            let param = Arc::new(Param {
                rid: (i + 1) as u32,
                token: Token::new(0x08000001 + i as u32),
                offset: 0,
                flags: 0,
                sequence: (i + 1) as u32,
                name: Some(format!("param{}", i)),
                default: OnceLock::new(),
                marshal: OnceLock::new(),
                modifiers: std::sync::RwLock::new(Vec::new()),
                base: OnceLock::new(),
                is_by_ref: std::sync::atomic::AtomicBool::new(false),
                custom_attributes: Arc::new(boxcar::Vec::new()),
            });

            param.base.set(CilTypeRef::from(param_type)).ok();
            method.params.push(param);
        }

        // Store the type registry in a static location to keep types alive
        // This is a test-only workaround - use thread-safe unique keys
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Mutex;
        static TYPE_REGISTRIES: std::sync::OnceLock<Mutex<HashMap<u64, Arc<TypeRegistry>>>> =
            std::sync::OnceLock::new();
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        let registries = TYPE_REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut registries_lock = registries.lock().unwrap();
        let key = COUNTER.fetch_add(1, Ordering::SeqCst);
        registries_lock.insert(key, type_registry);

        method
    }

    // Helper function to create a type with specific flavor
    fn create_type_with_flavor(flavor: CilFlavor) -> CilTypeRc {
        Arc::new(CilType::new(
            Token::new(0x01000001),
            flavor,
            "System".to_string(),
            "TestType".to_string(),
            None,
            None,
            0,
            Arc::new(boxcar::Vec::new()),
            Arc::new(boxcar::Vec::new()),
        ))
    }

    #[test]
    fn test_parse_empty_blob_with_method() {
        let method = create_mock_method();
        let result =
            parse_custom_attribute_data(&[0x01, 0x00], get_params_from_method(&method)).unwrap();
        assert!(result.fixed_args.is_empty());
        assert!(result.named_args.is_empty());
    }

    #[test]
    fn test_parse_invalid_prolog_with_method() {
        let method = create_mock_method();
        let result = parse_custom_attribute_data(&[0x00, 0x01], get_params_from_method(&method));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid custom attribute prolog"));
    }

    #[test]
    fn test_parse_simple_blob_with_method() {
        let method = create_mock_method();

        // Test case 1: Just prolog
        let blob_data = &[0x01, 0x00];
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 0);
        assert_eq!(result.named_args.len(), 0);

        // Test case 2: Valid prolog with no fixed arguments and no named arguments
        let blob_data = &[
            0x01, 0x00, // Prolog (0x0001)
            0x00, 0x00, // NumNamed = 0
        ];
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        // Without resolved parameter types, fixed args should be empty
        assert_eq!(result.fixed_args.len(), 0);
        assert_eq!(result.named_args.len(), 0);
    }

    #[test]
    fn test_parse_boolean_argument() {
        let method = create_method_with_params(vec![CilFlavor::Boolean]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, // Boolean true
            0x00, 0x00, // NumNamed = 0
        ];

        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Bool(val) => assert!(*val),
            _ => panic!("Expected Boolean argument"),
        }
    }

    #[test]
    fn test_parse_char_argument() {
        let method = create_method_with_params(vec![CilFlavor::Char]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x41, 0x00, // Char 'A' (UTF-16 LE)
            0x00, 0x00, // NumNamed = 0
        ];

        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Char(val) => assert_eq!(*val, 'A'),
            _ => panic!("Expected Char argument"),
        }
    }

    #[test]
    fn test_parse_integer_arguments() {
        let method = create_method_with_params(vec![
            CilFlavor::I1,
            CilFlavor::U1,
            CilFlavor::I2,
            CilFlavor::U2,
            CilFlavor::I4,
            CilFlavor::U4,
            CilFlavor::I8,
            CilFlavor::U8,
        ]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0xFF, // I1: -1
            0x42, // U1: 66
            0x00, 0x80, // I2: -32768 (LE)
            0xFF, 0xFF, // U2: 65535 (LE)
            0x00, 0x00, 0x00, 0x80, // I4: -2147483648 (LE)
            0xFF, 0xFF, 0xFF, 0xFF, // U4: 4294967295 (LE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // I8: -9223372036854775808 (LE)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // U8: 18446744073709551615 (LE)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 8);

        match &result.fixed_args[0] {
            CustomAttributeArgument::I1(val) => assert_eq!(*val, -1i8),
            _ => panic!("Expected I1 argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::U1(val) => assert_eq!(*val, 66u8),
            _ => panic!("Expected U1 argument"),
        }
        match &result.fixed_args[2] {
            CustomAttributeArgument::I2(val) => assert_eq!(*val, -32768i16),
            _ => panic!("Expected I2 argument"),
        }
        match &result.fixed_args[3] {
            CustomAttributeArgument::U2(val) => assert_eq!(*val, 65535u16),
            _ => panic!("Expected U2 argument"),
        }
        match &result.fixed_args[4] {
            CustomAttributeArgument::I4(val) => assert_eq!(*val, -2147483648i32),
            _ => panic!("Expected I4 argument"),
        }
        match &result.fixed_args[5] {
            CustomAttributeArgument::U4(val) => assert_eq!(*val, 4294967295u32),
            _ => panic!("Expected U4 argument"),
        }
        match &result.fixed_args[6] {
            CustomAttributeArgument::I8(val) => assert_eq!(*val, -9223372036854775808i64),
            _ => panic!("Expected I8 argument"),
        }
        match &result.fixed_args[7] {
            CustomAttributeArgument::U8(val) => assert_eq!(*val, 18446744073709551615u64),
            _ => panic!("Expected U8 argument"),
        }
    }

    #[test]
    fn test_parse_floating_point_arguments() {
        let method = create_method_with_params(vec![CilFlavor::R4, CilFlavor::R8]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, 0x20, 0x41, // R4: 10.0 (LE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x40, // R8: 10.0 (LE)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 2);

        match &result.fixed_args[0] {
            CustomAttributeArgument::R4(val) => assert_eq!(*val, 10.0f32),
            _ => panic!("Expected R4 argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::R8(val) => assert_eq!(*val, 10.0f64),
            _ => panic!("Expected R8 argument"),
        }
    }

    #[test]
    fn test_parse_native_integer_arguments() {
        let method = create_method_with_params(vec![CilFlavor::I, CilFlavor::U]);

        #[cfg(target_pointer_width = "64")]
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, // I: -9223372036854775808 (LE, 64-bit)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, // U: 18446744073709551615 (LE, 64-bit)
            0x00, 0x00, // NumNamed = 0
        ];

        #[cfg(target_pointer_width = "32")]
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, 0x00, 0x80, // I: -2147483648 (LE, 32-bit)
            0xFF, 0xFF, 0xFF, 0xFF, // U: 4294967295 (LE, 32-bit)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 2);

        match &result.fixed_args[0] {
            CustomAttributeArgument::I(_) => (), // Value depends on platform
            _ => panic!("Expected I argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::U(_) => (), // Value depends on platform
            _ => panic!("Expected U argument"),
        }
    }

    #[test]
    fn test_parse_string_argument() {
        let method = create_method_with_params(vec![CilFlavor::String]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x05, // String length (compressed)
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::String(val) => assert_eq!(val, "Hello"),
            _ => panic!("Expected String argument"),
        }
    }

    #[test]
    fn test_parse_class_as_type_argument() {
        let method = create_method_with_params(vec![CilFlavor::Class]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x0C, // Type name length (compressed) - 12 bytes for "System.Int32"
            0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x2E, 0x49, 0x6E, 0x74, 0x33,
            0x32, // "System.Int32"
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Type(val) => assert_eq!(val, "System.Int32"),
            _ => panic!("Expected Type argument"),
        }
    }

    #[test]
    fn test_parse_valuetype_enum_argument() {
        let method = create_method_with_params(vec![CilFlavor::ValueType]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, 0x00, 0x00, // Enum value as I4 (1)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Enum(type_name, boxed_val) => {
                assert_eq!(type_name, "Unknown");
                match boxed_val.as_ref() {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 1),
                    _ => panic!("Expected I4 in enum"),
                }
            }
            _ => panic!("Expected Enum argument"),
        }
    }

    #[test]
    fn test_parse_void_argument() {
        let method = create_method_with_params(vec![CilFlavor::Void]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Void => (),
            _ => panic!("Expected Void argument"),
        }
    }

    #[test]
    fn test_parse_array_argument_error() {
        let method = create_method_with_params(vec![CilFlavor::Array {
            rank: 1,
            dimensions: vec![],
        }]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x03, 0x00, 0x00, 0x00, // Array element count (I4) = 3
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Array type has no base element type information"));
    }

    #[test]
    fn test_parse_simple_array_argument() {
        // Create an array type with I4 elements using TypeBuilder
        let type_registry = Arc::new(TypeRegistry::new().unwrap());

        // Create the array type using TypeBuilder to properly set the base type
        let array_type = TypeBuilder::new(type_registry.clone())
            .primitive(crate::metadata::typesystem::CilPrimitiveKind::I4)
            .unwrap()
            .array()
            .unwrap()
            .build()
            .unwrap();

        // Create method with the array parameter
        let method = create_mock_method();
        let param = Arc::new(Param {
            rid: 1,
            token: Token::new(0x08000001),
            offset: 0,
            flags: 0,
            sequence: 1,
            name: Some("arrayParam".to_string()),
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: std::sync::RwLock::new(Vec::new()),
            base: OnceLock::new(),
            is_by_ref: std::sync::atomic::AtomicBool::new(false),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });
        param.base.set(CilTypeRef::from(array_type)).ok();
        method.params.push(param);

        // Test blob data: array with 3 I4 elements
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x03, 0x00, 0x00, 0x00, // Array element count (I4) = 3
            0x01, 0x00, 0x00, 0x00, // First I4: 1
            0x02, 0x00, 0x00, 0x00, // Second I4: 2
            0x03, 0x00, 0x00, 0x00, // Third I4: 3
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);

        match &result.fixed_args[0] {
            CustomAttributeArgument::Array(elements) => {
                assert_eq!(elements.len(), 3);
                match &elements[0] {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 1),
                    _ => panic!("Expected I4 element"),
                }
                match &elements[1] {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 2),
                    _ => panic!("Expected I4 element"),
                }
                match &elements[2] {
                    CustomAttributeArgument::I4(val) => assert_eq!(*val, 3),
                    _ => panic!("Expected I4 element"),
                }
            }
            _ => panic!("Expected Array argument"),
        }

        // Keep the type registry alive for the duration of the test
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Mutex;
        static TYPE_REGISTRIES: std::sync::OnceLock<Mutex<HashMap<u64, Arc<TypeRegistry>>>> =
            std::sync::OnceLock::new();
        static COUNTER: AtomicU64 = AtomicU64::new(1);

        let registries = TYPE_REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut registries_lock = registries.lock().unwrap();
        let key = COUNTER.fetch_add(1, Ordering::SeqCst);
        registries_lock.insert(key, type_registry);
    }

    #[test]
    fn test_parse_multidimensional_array_error() {
        let method = create_method_with_params(vec![CilFlavor::Array {
            rank: 2,
            dimensions: vec![],
        }]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Multi-dimensional arrays not supported"));
    }

    #[test]
    fn test_parse_named_arguments() {
        let method = create_mock_method();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x02, 0x00, // NumNamed = 2
            // First named argument (field)
            0x53, // Field indicator
            0x08, // I4 type
            0x05, // Name length
            0x56, 0x61, 0x6C, 0x75, 0x65, // "Value"
            0x2A, 0x00, 0x00, 0x00, // I4 value: 42
            // Second named argument (property)
            0x54, // Property indicator
            0x0E, // String type
            0x04, // Name length
            0x4E, 0x61, 0x6D, 0x65, // "Name"
            0x04, // String value length
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 0);
        assert_eq!(result.named_args.len(), 2);

        // Check first named argument (field)
        let field_arg = &result.named_args[0];
        assert!(field_arg.is_field);
        assert_eq!(field_arg.name, "Value");
        assert_eq!(field_arg.arg_type, "I4");
        match &field_arg.value {
            CustomAttributeArgument::I4(val) => assert_eq!(*val, 42),
            _ => panic!("Expected I4 value"),
        }

        // Check second named argument (property)
        let prop_arg = &result.named_args[1];
        assert!(!prop_arg.is_field);
        assert_eq!(prop_arg.name, "Name");
        assert_eq!(prop_arg.arg_type, "String");
        match &prop_arg.value {
            CustomAttributeArgument::String(val) => assert_eq!(val, "Test"),
            _ => panic!("Expected String value"),
        }
    }

    #[test]
    fn test_parse_named_argument_char_type() {
        let method = create_mock_method();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, // NumNamed = 1
            0x53, // Field indicator
            0x03, // Char type
            0x06, // Name length
            0x4C, 0x65, 0x74, 0x74, 0x65, 0x72, // "Letter"
            0x5A, 0x00, // Char value: 'Z' (UTF-16 LE)
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.named_args.len(), 1);

        let named_arg = &result.named_args[0];
        assert_eq!(named_arg.arg_type, "Char");
        match &named_arg.value {
            CustomAttributeArgument::Char(val) => assert_eq!(*val, 'Z'),
            _ => panic!("Expected Char value"),
        }
    }

    #[test]
    fn test_parse_invalid_named_argument_type() {
        let method = create_mock_method();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, // NumNamed = 1
            0x99, // Invalid field/property indicator (should be 0x53 or 0x54)
            0x08, // Valid type indicator (I4)
            0x04, // Name length
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method));
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid field/property indicator"));
        }
    }

    #[test]
    fn test_parse_malformed_data_errors() {
        let method = create_method_with_params(vec![CilFlavor::I4]);

        // Test insufficient data for fixed argument
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // Not enough data for I4
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not enough data for I4 argument"));

        // Test string with invalid length
        let method_string = create_method_with_params(vec![CilFlavor::String]);
        let blob_data = &[
            0x01, 0x00, // Prolog
            0xFF, 0xFF, 0xFF, 0xFF, 0x0F, // Invalid compressed length (too large)
        ];

        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method_string));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mixed_fixed_and_named_arguments() {
        let method = create_method_with_params(vec![CilFlavor::I4, CilFlavor::String]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            // Fixed arguments
            0x2A, 0x00, 0x00, 0x00, // I4: 42
            0x05, // String length
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
            // Named arguments
            0x01, 0x00, // NumNamed = 1
            0x54, // Property indicator
            0x02, // Boolean type
            0x07, // Name length
            0x45, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x64, // "Enabled"
            0x01, // Boolean true
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 2);
        assert_eq!(result.named_args.len(), 1);

        // Check fixed arguments
        match &result.fixed_args[0] {
            CustomAttributeArgument::I4(val) => assert_eq!(*val, 42),
            _ => panic!("Expected I4 argument"),
        }
        match &result.fixed_args[1] {
            CustomAttributeArgument::String(val) => assert_eq!(val, "Hello"),
            _ => panic!("Expected String argument"),
        }

        // Check named argument
        let named_arg = &result.named_args[0];
        assert!(!named_arg.is_field);
        assert_eq!(named_arg.name, "Enabled");
        assert_eq!(named_arg.arg_type, "Boolean");
        match &named_arg.value {
            CustomAttributeArgument::Bool(val) => assert!(*val),
            _ => panic!("Expected Boolean value"),
        }
    }

    #[test]
    fn test_parse_utf16_edge_cases() {
        let method = create_method_with_params(vec![CilFlavor::Char]);

        // Test invalid UTF-16 value (should be replaced with replacement character)
        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0xD8, // Invalid UTF-16 surrogate (0xD800)
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::Char(val) => assert_eq!(*val, '\u{FFFD}'), // Replacement character
            _ => panic!("Expected Char argument"),
        }
    }

    #[test]
    fn test_unsupported_type_flavor_error() {
        let method = create_method_with_params(vec![CilFlavor::Pointer]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported type flavor in custom attribute"));
    }

    #[test]
    fn test_empty_string_argument() {
        let method = create_method_with_params(vec![CilFlavor::String]);

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x00, // String length = 0
            0x00, 0x00, // NumNamed = 0
        ];

        // Using direct API
        let result =
            parse_custom_attribute_data(blob_data, get_params_from_method(&method)).unwrap();
        assert_eq!(result.fixed_args.len(), 1);
        match &result.fixed_args[0] {
            CustomAttributeArgument::String(val) => assert_eq!(val, ""),
            _ => panic!("Expected String argument"),
        }
    }

    #[test]
    fn test_parse_unsupported_named_argument_type() {
        let method = create_mock_method();

        let blob_data = &[
            0x01, 0x00, // Prolog
            0x01, 0x00, // NumNamed = 1
            0x53, // Valid field indicator
            0xFF, // Unsupported type indicator
            0x04, // Name length
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        // Using direct API
        let result = parse_custom_attribute_data(blob_data, get_params_from_method(&method));
        // Strict parsing should fail on unsupported types
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e
                .to_string()
                .contains("Unsupported named argument type: 0xFF"));
        }
    }
}
