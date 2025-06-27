//! .NET Code Access Security (CAS) implementation.
//!
//! This module provides comprehensive support for parsing and representing .NET Code Access Security
//! permissions and permission sets from assembly metadata. Code Access Security was a fundamental
//! security model in early .NET Framework versions that allowed fine-grained control over code
//! execution permissions based on evidence about the code's origin and trustworthiness.
//!
//! # Architecture
//!
//! The security module is organized around the core CAS concepts defined in ECMA-335:
//!
//! - **Permission Sets**: Collections of individual permissions that define what operations code can perform
//! - **Security Actions**: Timing and enforcement mechanisms for permission checks (Demand, LinkDemand, etc.)
//! - **Named Arguments**: Flexible parameter systems for custom security attributes
//! - **Permission Types**: Specific classes of permissions (FileIOPermission, SecurityPermission, etc.)
//!
//! The module follows a layered design where high-level permission sets are built from individual
//! permissions, which in turn are composed of named arguments and type specifications.
//!
//! # Key Components
//!
//! - [`crate::metadata::security::PermissionSet`] - Container for collections of security permissions with action types
//! - [`crate::metadata::security::Permission`] - Individual security permission with type information and arguments
//! - [`crate::metadata::security::NamedArgument`] - Key-value parameter pairs for permission configuration
//! - [`crate::metadata::security::SecurityAction`] - Enumeration of CAS enforcement timing and behavior
//! - [`crate::metadata::security::SecurityPermissionFlags`] - Bitfield flags for common security permission types
//!
//! # Usage Examples
//!
//! ## Basic Permission Set Analysis
//!
//! ```rust,ignore
//! use dotscope::{CilObject, metadata::security::PermissionSet};
//!
//! let assembly = CilObject::from_file("legacy_app.dll".as_ref())?;
//!
//! // Analyze security permissions on types
//! for entry in assembly.types().iter() {
//!     let (token, type_def) = (entry.key(), entry.value());
//!     if let Some(security) = type_def.security.get() {
//!         println!("Type {} has security declaration", type_def.name);
//!         println!("  Action: {:?}", security.action);
//!         println!("  Permissions: {}", security.permission_set.permissions().len());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Detailed Permission Analysis
//!
//! ```rust,ignore
//! use dotscope::metadata::security::{PermissionSet, Permission, SecurityAction};
//!
//! # let permission_set_data = &[0u8; 100]; // placeholder
//! let permission_set = PermissionSet::new(permission_set_data)?;
//!
//! // Check for dangerous permissions
//! if permission_set.has_file_io() {
//!     println!("WARNING: File system access permissions detected");
//!     let write_paths = permission_set.get_all_file_write_paths();
//!     if !write_paths.is_empty() {
//!         println!("  Write access to: {:?}", write_paths);
//!     }
//! }
//!
//! // Enumerate individual permissions
//! for permission in permission_set.permissions() {
//!     println!("Permission type: {}", permission.class_name);
//!     for arg in &permission.named_arguments {
//!         println!("  {}: {:?}", arg.name, arg.value);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This module defines security-specific error handling for CAS parsing:
//! - **Malformed Security Data**: When permission set binary data is corrupted or invalid
//! - **Unknown Permission Types**: When encountering permission types not defined in the specification
//! - **Invalid Security Actions**: When security action codes are outside valid ranges
//! - **Missing Required Arguments**: When mandatory permission arguments are absent
//!
//! All parsing operations return [`crate::Result<T>`] and follow consistent error patterns
//! defined in the main error module.
//!
//! # Integration
//!
//! Security metadata integrates with several other dotscope modules:
//! - **Tables Module**: Security information is stored in the DeclSecurity metadata table
//! - **Signatures Module**: Permission types may reference type signatures for custom permissions
//! - **Streams Module**: Binary permission data is stored in the blob heap
//! - **Custom Attributes**: Some security specifications use custom attribute syntax
//!
//! # Legacy Status
//!
//! **Important**: Code Access Security was deprecated starting with .NET Framework 4.0
//! and is not supported in .NET Core/.NET 5+. This implementation is primarily useful
//! for analyzing older .NET Framework assemblies and understanding historical security models.
//! Modern .NET applications should use alternative security mechanisms.
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement `Send + Sync`:
//! - Permission sets and permissions are immutable after parsing
//! - No internal mutability or shared state is used
//! - Parsing operations are stateless and can be performed concurrently
//!
//! # References
//!
//! - [ECMA-335 6th Edition, Partition II, Section 22.11 - DeclSecurity Table](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - [ECMA-335 6th Edition, Partition II, Section 23.1.3 - Security Actions](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
//! - Microsoft .NET Framework Security Documentation (archived)

pub mod builders;
mod encoder;
mod namedargument;
mod permission;
mod permissionset;
mod types;

pub use builders::*;
pub use encoder::*;
pub use namedargument::NamedArgument;
pub use permission::Permission;
pub use permissionset::PermissionSet;
pub use types::*;

#[cfg(test)]
mod tests {
    use crate::{
        metadata::security::{
            encode_permission_set, ArgumentType, ArgumentValue, NamedArgument, Permission,
            PermissionSet, PermissionSetBuilder, PermissionSetFormat,
        },
        Result,
    };

    /// Test complete round-trip for SecurityPermission with Unrestricted flag.
    #[test]
    fn test_round_trip_security_permission_unrestricted() -> Result<()> {
        // Step 1: Create permission set with SecurityPermission
        let original_permissions = vec![Permission {
            class_name: "System.Security.Permissions.SecurityPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Unrestricted".to_string(),
                arg_type: ArgumentType::Boolean,
                value: ArgumentValue::Boolean(true),
            }],
        }];

        // Step 2: Encode to binary format
        let permission_blob =
            encode_permission_set(&original_permissions, PermissionSetFormat::BinaryLegacy)?;

        // Step 3: Parse back and verify
        let parsed_set = PermissionSet::new(&permission_blob)?;
        assert_eq!(parsed_set.permissions().len(), 1);
        assert!(parsed_set.is_unrestricted());
        assert!(parsed_set.is_full_trust());

        // Verify the specific permission details
        let permission = &parsed_set.permissions()[0];
        assert_eq!(
            permission.class_name,
            "System.Security.Permissions.SecurityPermission"
        );
        assert_eq!(permission.named_arguments.len(), 1);
        assert_eq!(permission.named_arguments[0].name, "Unrestricted");

        if let ArgumentValue::Boolean(value) = &permission.named_arguments[0].value {
            assert!(value);
        } else {
            panic!("Expected boolean value for Unrestricted");
        }

        Ok(())
    }

    /// Test round-trip for FileIOPermission with multiple paths.
    #[test]
    fn test_round_trip_file_io_permission() -> Result<()> {
        let original_permissions = vec![Permission {
            class_name: "System.Security.Permissions.FileIOPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![
                NamedArgument {
                    name: "Read".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\Data;C:\\Config".to_string()),
                },
                NamedArgument {
                    name: "Write".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\Logs;C:\\Output".to_string()),
                },
            ],
        }];

        let permission_blob =
            encode_permission_set(&original_permissions, PermissionSetFormat::BinaryLegacy)?;
        let parsed_set = PermissionSet::new(&permission_blob)?;

        assert_eq!(parsed_set.permissions().len(), 1);
        assert!(parsed_set.has_file_io());
        assert!(!parsed_set.is_full_trust());

        // Check file paths
        let read_paths = parsed_set.get_all_file_read_paths();
        let write_paths = parsed_set.get_all_file_write_paths();

        assert_eq!(read_paths.len(), 1);
        assert_eq!(read_paths[0], "C:\\Data;C:\\Config");
        assert_eq!(write_paths.len(), 1);
        assert_eq!(write_paths[0], "C:\\Logs;C:\\Output");

        Ok(())
    }

    /// Test round-trip for multiple permissions in a single set.
    #[test]
    fn test_round_trip_multiple_permissions() -> Result<()> {
        let original_permissions = vec![
            Permission {
                class_name: "System.Security.Permissions.SecurityPermission".to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Flags".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("Execution, SkipVerification".to_string()),
                }],
            },
            Permission {
                class_name: "System.Security.Permissions.FileIOPermission".to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Read".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\temp".to_string()),
                }],
            },
            Permission {
                class_name: "System.Security.Permissions.RegistryPermission".to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Read".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("HKEY_LOCAL_MACHINE\\SOFTWARE".to_string()),
                }],
            },
        ];

        let permission_blob =
            encode_permission_set(&original_permissions, PermissionSetFormat::BinaryLegacy)?;
        let parsed_set = PermissionSet::new(&permission_blob)?;

        assert_eq!(parsed_set.permissions().len(), 3);
        assert!(parsed_set.has_file_io());
        assert!(parsed_set.has_registry());
        assert!(!parsed_set.has_reflection());

        // Verify each permission is correctly parsed
        let security_perm =
            parsed_set.get_permission("System.Security.Permissions.SecurityPermission");
        assert!(security_perm.is_some());

        let fileio_perm = parsed_set.get_permission("System.Security.Permissions.FileIOPermission");
        assert!(fileio_perm.is_some());

        let registry_perm =
            parsed_set.get_permission("System.Security.Permissions.RegistryPermission");
        assert!(registry_perm.is_some());

        Ok(())
    }

    /// Test round-trip using the fluent builder API.
    #[test]
    fn test_round_trip_builder_api() -> Result<()> {
        let permission_blob = PermissionSetBuilder::new()
            .add_security_permission()
            .flags("Execution, Assertion")
            .build()
            .add_file_io_permission()
            .read_paths(&["C:\\Data", "C:\\Config"])
            .write_paths(&["C:\\Logs"])
            .unrestricted(false)
            .build()
            .encode(PermissionSetFormat::BinaryLegacy)?;

        let parsed_set = PermissionSet::new(&permission_blob)?;

        assert_eq!(parsed_set.permissions().len(), 2);
        assert!(parsed_set.has_file_io());
        assert!(!parsed_set.is_full_trust());

        // Verify SecurityPermission flags
        let security_perm = parsed_set
            .get_permission("System.Security.Permissions.SecurityPermission")
            .unwrap();
        assert_eq!(security_perm.named_arguments.len(), 1);
        assert_eq!(security_perm.named_arguments[0].name, "Flags");

        // Verify FileIOPermission paths
        let fileio_perm = parsed_set
            .get_permission("System.Security.Permissions.FileIOPermission")
            .unwrap();
        assert_eq!(fileio_perm.named_arguments.len(), 3); // Read, Write, Unrestricted

        Ok(())
    }

    /// Test XML format round-trip.
    #[test]
    fn test_round_trip_xml_format() -> Result<()> {
        let original_permissions = vec![Permission {
            class_name: "System.Security.Permissions.SecurityPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![
                NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                },
                NamedArgument {
                    name: "Flags".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("AllFlags".to_string()),
                },
            ],
        }];

        let xml_blob = encode_permission_set(&original_permissions, PermissionSetFormat::Xml)?;
        let xml_str = String::from_utf8(xml_blob.clone()).expect("Valid UTF-8");

        // Verify XML structure
        assert!(xml_str.contains("<PermissionSet"));
        assert!(xml_str.contains("System.Security.Permissions.SecurityPermission"));
        assert!(xml_str.contains("Unrestricted=\"true\""));
        assert!(xml_str.contains("Flags=\"AllFlags\""));
        assert!(xml_str.contains("</PermissionSet>"));

        // Parse back from XML
        let parsed_set = PermissionSet::new(&xml_blob)?;
        assert_eq!(parsed_set.permissions().len(), 1);

        let permission = &parsed_set.permissions()[0];
        assert_eq!(
            permission.class_name,
            "System.Security.Permissions.SecurityPermission"
        );
        assert_eq!(permission.named_arguments.len(), 2);

        Ok(())
    }

    /// Test empty permission set round-trip.
    #[test]
    fn test_round_trip_empty_permission_set() -> Result<()> {
        let empty_permissions = vec![];

        let permission_blob =
            encode_permission_set(&empty_permissions, PermissionSetFormat::BinaryLegacy)?;
        let parsed_set = PermissionSet::new(&permission_blob)?;

        assert_eq!(parsed_set.permissions().len(), 0);
        assert!(!parsed_set.has_file_io());
        assert!(!parsed_set.has_registry());
        assert!(!parsed_set.is_full_trust());

        Ok(())
    }

    /// Test permission set with integer arguments.
    #[test]
    fn test_round_trip_integer_arguments() -> Result<()> {
        let original_permissions = vec![Permission {
            class_name: "System.Security.Permissions.SecurityPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![
                NamedArgument {
                    name: "Flags".to_string(),
                    arg_type: ArgumentType::Int32,
                    value: ArgumentValue::Int32(7), // Multiple flags combined
                },
                NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(false),
                },
            ],
        }];

        let permission_blob =
            encode_permission_set(&original_permissions, PermissionSetFormat::BinaryLegacy)?;
        let parsed_set = PermissionSet::new(&permission_blob)?;

        assert_eq!(parsed_set.permissions().len(), 1);
        let permission = &parsed_set.permissions()[0];
        assert_eq!(permission.named_arguments.len(), 2);

        // Find and verify the integer flags argument
        let flags_arg = permission
            .named_arguments
            .iter()
            .find(|arg| arg.name == "Flags")
            .expect("Should have Flags argument");

        if let ArgumentValue::Int32(value) = &flags_arg.value {
            assert_eq!(*value, 7);
        } else {
            panic!("Expected Int32 value for Flags");
        }

        Ok(())
    }

    /// Test permission set with special characters in string values.
    #[test]
    fn test_round_trip_special_characters() -> Result<()> {
        let original_permissions = vec![Permission {
            class_name: "System.Security.Permissions.FileIOPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Read".to_string(),
                arg_type: ArgumentType::String,
                value: ArgumentValue::String("C:\\Program Files\\My App\\data.xml".to_string()),
            }],
        }];

        let permission_blob =
            encode_permission_set(&original_permissions, PermissionSetFormat::BinaryLegacy)?;
        let parsed_set = PermissionSet::new(&permission_blob)?;

        assert_eq!(parsed_set.permissions().len(), 1);
        let permission = &parsed_set.permissions()[0];
        assert_eq!(permission.named_arguments.len(), 1);

        if let ArgumentValue::String(path) = &permission.named_arguments[0].value {
            assert_eq!(path, "C:\\Program Files\\My App\\data.xml");
        } else {
            panic!("Expected string value for Read path");
        }

        Ok(())
    }

    /// Test security action conversion works correctly.
    #[test]
    fn test_security_actions() {
        use crate::metadata::security::SecurityAction;

        let actions = vec![
            SecurityAction::Demand,
            SecurityAction::Assert,
            SecurityAction::Deny,
            SecurityAction::PermitOnly,
            SecurityAction::LinkDemand,
            SecurityAction::InheritanceDemand,
            SecurityAction::RequestMinimum,
            SecurityAction::RequestOptional,
            SecurityAction::RequestRefuse,
            SecurityAction::PrejitGrant,
            SecurityAction::PrejitDeny,
            SecurityAction::NonCasDemand,
            SecurityAction::NonCasLinkDemand,
            SecurityAction::NonCasInheritance,
        ];

        for action in actions {
            // Verify we can create and convert SecurityAction values
            let action_value: u16 = action.into();
            let converted_back = SecurityAction::from(action_value);
            assert_eq!(converted_back, action);
        }
    }

    /// Test comprehensive permission analysis methods.
    #[test]
    fn test_permission_analysis() -> Result<()> {
        // Create a complex permission set for analysis
        let permission_blob = PermissionSetBuilder::new()
            .add_security_permission()
            .flags("SkipVerification, ControlPolicy, ControlEvidence")
            .build()
            .add_file_io_permission()
            .read_paths(&["C:\\Data"])
            .write_paths(&["C:\\Logs"])
            .build()
            .encode(PermissionSetFormat::BinaryLegacy)?;

        let parsed_set = PermissionSet::new(&permission_blob)?;

        // Test analysis methods
        assert!(parsed_set.has_file_io());
        assert!(!parsed_set.has_registry());
        assert!(!parsed_set.has_reflection());
        assert!(!parsed_set.has_environment());

        // This combination of security flags should indicate full trust
        assert!(parsed_set.is_full_trust());

        // Test path extraction
        let read_paths = parsed_set.get_all_file_read_paths();
        let write_paths = parsed_set.get_all_file_write_paths();
        assert_eq!(read_paths, vec!["C:\\Data"]);
        assert_eq!(write_paths, vec!["C:\\Logs"]);

        Ok(())
    }
}
