//! Individual security permissions in .NET Code Access Security.
//!
//! This module provides the [`Permission`] type, which represents individual security permissions
//! within .NET permission sets. Each permission corresponds to a specific .NET Framework security
//! class that defines access controls for system resources such as files, network, registry,
//! reflection capabilities, and other protected operations.
//!
//! # Architecture
//!
//! The .NET Code Access Security model uses strongly-typed permission classes to grant or restrict
//! access to system resources. The architecture follows a hierarchical structure:
//!
//! ```text
//! Permission Set
//! ├── Permission 1 (e.g., FileIOPermission)
//! │   ├── Class Name: System.Security.Permissions.FileIOPermission
//! │   ├── Assembly: mscorlib
//! │   └── Named Arguments: [Read="path", Write="path"]
//! ├── Permission 2 (e.g., SecurityPermission)
//! │   ├── Class Name: System.Security.Permissions.SecurityPermission
//! │   ├── Assembly: mscorlib
//! │   └── Named Arguments: [Flags=0x0002]
//! └── ...
//! ```
//!
//! Each permission encapsulates:
//! - **Class Identity**: Fully qualified type name and assembly
//! - **Configuration**: Named arguments defining specific access rules
//! - **Type Safety**: Strongly typed argument validation
//!
//! # Key Components
//!
//! ## Permission Classes
//! The .NET Framework provides numerous permission classes, each controlling specific resource access:
//!
//! ### File System Permissions
//! - **`FileIOPermission`**: Controls file system access (read, write, append, path discovery)
//! - **`IsolatedStoragePermission`**: Controls isolated storage access
//!
//! ### System Access Permissions
//! - **`SecurityPermission`**: Controls security-sensitive operations (unmanaged code, reflection)
//! - **`RegistryPermission`**: Controls Windows registry access
//! - **`EnvironmentPermission`**: Controls environment variable access
//!
//! ### Network and Communication
//! - **`SocketPermission`**: Controls network socket operations
//! - **`WebPermission`**: Controls HTTP web access
//! - **`DnsPermission`**: Controls DNS resolution
//!
//! ### Code Access Permissions
//! - **`ReflectionPermission`**: Controls reflection and code analysis capabilities
//! - **`FileDialogPermission`**: Controls file dialog operations
//! - **`UIPermission`**: Controls user interface operations
//!
//! ## Named Arguments Structure
//! Each permission can have multiple named arguments that configure its behavior:
//! - **Name**: Property or field identifier
//! - **Type**: Argument data type ([`crate::metadata::security::ArgumentType`])
//! - **Value**: Typed value ([`crate::metadata::security::ArgumentValue`])
//!
//! # Usage Examples
//!
//! ## File IO Permission Configuration
//!
//! ```rust
//! use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
//!
//! // Represents: [FileIOPermission(Read = "C:\\Data", Write = "C:\\Logs")]
//! let file_permission = Permission::new(
//!     "System.Security.Permissions.FileIOPermission".to_string(),
//!     "mscorlib".to_string(),
//!     vec![
//!         NamedArgument::new(
//!             "Read".to_string(),
//!             ArgumentType::String,
//!             ArgumentValue::String("C:\\Data".to_string())
//!         ),
//!         NamedArgument::new(
//!             "Write".to_string(),
//!             ArgumentType::String,
//!             ArgumentValue::String("C:\\Logs".to_string())
//!         ),
//!     ]
//! );
//!
//! assert!(file_permission.is_file_io());
//! println!("Permission: {}", file_permission);
//! ```
//!
//! ## Security Permission with Flags
//!
//! ```rust
//! use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
//!
//! // Represents: [SecurityPermission(UnmanagedCode = true)]
//! let security_permission = Permission::new(
//!     "System.Security.Permissions.SecurityPermission".to_string(),
//!     "mscorlib".to_string(),
//!     vec![
//!         NamedArgument::new(
//!             "Flags".to_string(),
//!             ArgumentType::Int32,
//!             ArgumentValue::Int32(0x0002) // UnmanagedCode flag
//!         ),
//!     ]
//! );
//!
//! assert!(security_permission.is_security());
//! ```
//!
//! ## Permission Analysis and Introspection
//!
//! ```rust
//! use dotscope::metadata::security::Permission;
//!
//! # fn get_permission() -> Permission {
//! #     Permission::new(
//! #         "System.Security.Permissions.FileIOPermission".to_string(),
//! #         "mscorlib".to_string(),
//! #         vec![]
//! #     )
//! # }
//! let permission = get_permission();
//!
//! // Check permission type
//! if permission.is_file_io() {
//!     println!("This permission controls file access");
//!     
//!     // Check for specific arguments
//!     if let Some(read_arg) = permission.get_argument("Read") {
//!         println!("Read access granted to: {:?}", read_arg.value());
//!     }
//! }
//!
//! // Display full permission details
//! println!("Permission class: {}", permission.class_name);
//! println!("From assembly: {}", permission.assembly_name);
//! println!("Argument count: {}", permission.named_arguments.len());
//! ```
//!
//! ## Extracting File Paths from `FileIOPermission`
//!
//! ```rust,ignore
//! use dotscope::metadata::security::Permission;
//!
//! # fn get_file_permission() -> Permission {
//! #     Permission::new(
//! #         "System.Security.Permissions.FileIOPermission".to_string(),
//! #         "mscorlib".to_string(),
//! #         vec![]
//! #     )
//! # }
//! let permission = get_file_permission();
//!
//! if permission.is_file_io() {
//!     // Extract specific file access paths
//!     let read_paths = permission.get_file_read_paths();
//!     let write_paths = permission.get_file_write_paths();
//!     let discovery_paths = permission.get_file_path_discovery();
//!     
//!     println!("Read access: {:?}", read_paths);
//!     println!("Write access: {:?}", write_paths);
//!     println!("Path discovery: {:?}", discovery_paths);
//! }
//! ```
//!
//! # Integration
//!
//! Permissions integrate with the broader .NET security infrastructure:
//!
//! ## With Permission Sets
//! - Individual permissions are grouped into [`crate::metadata::security::PermissionSet`]
//! - Each permission set can contain multiple permissions of different types
//! - Permission sets define complete security policies for assemblies, types, or methods
//!
//! ## With Security Attributes
//! - Permissions are created from declarative security attributes in .NET metadata
//! - Custom attribute blobs are parsed to extract permission configurations
//! - Support both property and field-based argument specification
//!
//! ## With Assembly Analysis
//! - Used for security policy analysis and compliance checking
//! - Enable detection of privileged operations in .NET assemblies
//! - Support both static analysis and runtime security enforcement
//!
//! ## With Security Actions
//! - Permissions work with security actions like Demand, Assert, Deny, `PermitOnly`
//! - Each action modifies how the permission is enforced at runtime
//! - Actions determine whether permissions grant or restrict access
//!
//! # Binary Format
//!
//! Permissions are stored in `DeclSecurity` metadata using a custom binary format:
//! ```text
//! - Permission class name (string)
//! - Assembly name (string)  
//! - Named argument count (compressed integer)
//! - Named arguments array (see NamedArgument format)
//! ```
//!
//! The format is defined by the .NET Framework security infrastructure and follows
//! the custom attribute serialization specification.
//!
//! # Error Handling
//!
//! The module handles various error conditions related to permission processing:
//! - **Invalid Class Names**: Malformed or unrecognized permission class names
//! - **Assembly Resolution**: Missing or incorrect assembly references
//! - **Argument Validation**: Type mismatches or invalid argument configurations
//! - **Serialization Errors**: Corrupted binary data in security metadata
//!
//! Common error scenarios include:
//! - Permissions referencing custom assemblies not available during analysis
//! - Malformed argument blobs due to metadata corruption
//! - Version mismatches between permission classes and runtime expectations
//!
//! # Legacy Support
//!
//! Code Access Security was deprecated in .NET Framework 4.0 and removed in .NET Core.
//! This implementation primarily supports analysis of legacy .NET Framework assemblies
//! that use declarative security attributes.
//!
//! # Thread Safety
//!
//! [`Permission`] instances are immutable after creation and safe to share across threads.

use crate::metadata::security::{
    security_classes, ArgumentValue, NamedArgument, SecurityPermissionFlags,
};
use std::fmt;

/// Represents a .NET security permission within a permission set.
///
/// A Permission represents a single security permission in the .NET Code Access Security (CAS) system.
/// Each permission corresponds to a specific .NET Framework security class that defines access
/// controls for system resources (like file I/O, network access, reflection capabilities, etc.).
///
/// # Structure
///
/// Each permission contains:
/// - **Class Name**: The fully qualified .NET type name (e.g., "System.Security.Permissions.FileIOPermission")
/// - **Assembly Name**: The assembly containing the permission class (typically "mscorlib" or "System")
/// - **Named Arguments**: Collection of property/field configurations specific to the permission type
///
/// # Examples
///
/// ## Creating a File I/O Permission
///
/// ```rust
/// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
///
/// let permission = Permission::new(
///     "System.Security.Permissions.FileIOPermission".to_string(),
///     "mscorlib".to_string(),
///     vec![
///         NamedArgument::new(
///             "Read".to_string(),
///             ArgumentType::String,
///             ArgumentValue::String("C:\\Data".to_string())
///         ),
///     ]
/// );
///
/// assert!(permission.is_file_io());
/// ```
///
/// ## Analyzing Permission Properties
///
/// ```rust
/// # use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
/// # let permission = Permission::new(
/// #     "System.Security.Permissions.FileIOPermission".to_string(),
/// #     "mscorlib".to_string(),
/// #     vec![NamedArgument::new("Read".to_string(), ArgumentType::String, ArgumentValue::String("C:\\Data".to_string()))]
/// # );
/// // Check permission type
/// if permission.is_file_io() {
///     if let Some(paths) = permission.get_file_read_paths() {
///         println!("Read access to: {:?}", paths);
///     }
/// }
///
/// // Get specific arguments
/// if let Some(arg) = permission.get_argument("Read") {
///     println!("Read argument: {}", arg);
/// }
/// ```
///
/// # Binary Format Support
///
/// Permissions are parsed from `DeclSecurity` metadata using the binary format defined
/// in ECMA-335. The format includes the permission class name, assembly name, and
/// a variable number of named arguments with their types and values.
///
/// # Thread Safety
///
/// [`Permission`] instances are immutable after creation and safe to share across threads.
/// All accessor methods are read-only and do not modify the internal state.
///
/// * `class_name` - The full name of the permission class (e.g., "System.Security.Permissions.FileIOPermission")
/// * `assembly_name` - The assembly containing the permission class (e.g., "mscorlib")
/// * `named_arguments` - Collection of named property or field settings for this permission
///
/// # Notes
///
/// In older .NET Framework versions, these permissions were extensively used to control security.
/// While less common in modern .NET, they may still be encountered in legacy assemblies.
#[derive(Debug, Clone)]
pub struct Permission {
    /// The fully qualified .NET type name of the permission class.
    ///
    /// Examples include:
    /// - `"System.Security.Permissions.FileIOPermission"`
    /// - `"System.Security.Permissions.SecurityPermission"`
    /// - `"System.Security.Permissions.ReflectionPermission"`
    /// - `"System.Security.Permissions.RegistryPermission"`
    pub class_name: String,

    /// The assembly containing the permission class.
    ///
    /// Typically "mscorlib" for core .NET Framework permissions, but may be
    /// "System" or other assemblies for specialized permission types.
    pub assembly_name: String,

    /// Collection of named property/field arguments that configure this permission.
    ///
    /// Each named argument represents a property or field setting on the permission
    /// instance, such as file paths for `FileIOPermission` or flags for `SecurityPermission`.
    /// The collection may be empty for permissions that grant unrestricted access.
    pub named_arguments: Vec<NamedArgument>,
}

impl Permission {
    /// Creates a new permission instance.
    ///
    /// # Arguments
    ///
    /// * `class_name` - The fully qualified .NET type name of the permission class
    /// * `assembly_name` - The assembly containing the permission class
    /// * `named_arguments` - Collection of named property/field settings for this permission
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let permission = Permission::new(
    ///     "System.Security.Permissions.FileIOPermission".to_string(),
    ///     "mscorlib".to_string(),
    ///     vec![
    ///         NamedArgument::new(
    ///             "Read".to_string(),
    ///             ArgumentType::String,
    ///             ArgumentValue::String("C:\\Data".to_string())
    ///         ),
    ///     ]
    /// );
    /// ```
    #[must_use]
    pub fn new(
        class_name: String,
        assembly_name: String,
        named_arguments: Vec<NamedArgument>,
    ) -> Self {
        Permission {
            class_name,
            assembly_name,
            named_arguments,
        }
    }

    /// Checks if this is a `FileIOPermission`.
    ///
    /// `FileIOPermissions` control access to file system resources including read, write,
    /// append, and path discovery operations.
    ///
    /// # Returns
    ///
    /// `true` if this permission's class name matches the `FileIOPermission` type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::Permission;
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.FileIOPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![]
    /// # );
    /// if permission.is_file_io() {
    ///     println!("This permission controls file system access");
    /// }
    /// ```
    #[must_use]
    pub fn is_file_io(&self) -> bool {
        self.class_name == security_classes::FILE_IO_PERMISSION
    }

    /// Checks if this is a `SecurityPermission`.
    ///
    /// `SecurityPermissions` control access to security-sensitive operations such as
    /// executing unmanaged code, skipping verification, controlling threads, and
    /// other runtime security features.
    ///
    /// # Returns
    ///
    /// `true` if this permission's class name matches the `SecurityPermission` type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::Permission;
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.SecurityPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![]
    /// # );
    /// if permission.is_security() {
    ///     if let Some(flags) = permission.get_security_flags() {
    ///         println!("Security flags: {:?}", flags);
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn is_security(&self) -> bool {
        self.class_name == security_classes::SECURITY_PERMISSION
    }

    /// Checks if this is a `ReflectionPermission`.
    ///
    /// `ReflectionPermissions` control access to reflection capabilities such as
    /// emitting IL code, invoking non-public members, and accessing type information.
    ///
    /// # Returns
    ///
    /// `true` if this permission's class name matches the `ReflectionPermission` type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::Permission;
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.ReflectionPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![]
    /// # );
    /// if permission.is_reflection() {
    ///     println!("This permission controls reflection operations");
    /// }
    /// ```
    #[must_use]
    pub fn is_reflection(&self) -> bool {
        self.class_name == security_classes::REFLECTION_PERMISSION
    }

    /// Checks if this is a `RegistryPermission`.
    ///
    /// `RegistryPermissions` control access to Windows registry operations including
    /// reading and writing registry keys and values.
    ///
    /// # Returns
    ///
    /// `true` if this permission's class name matches the `RegistryPermission` type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::Permission;
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.RegistryPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![]
    /// # );
    /// if permission.is_registry() {
    ///     println!("This permission controls registry access");
    /// }
    /// ```
    #[must_use]
    pub fn is_registry(&self) -> bool {
        self.class_name == security_classes::REGISTRY_PERMISSION
    }

    /// Checks if this is a `UIPermission`.
    ///
    /// `UIPermissions` control access to user interface operations such as
    /// clipboard access, safe printing, and window manipulation.
    ///
    /// # Returns
    ///
    /// `true` if this permission's class name matches the `UIPermission` type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::Permission;
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.UIPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![]
    /// # );
    /// if permission.is_ui() {
    ///     println!("This permission controls UI operations");
    /// }
    /// ```
    #[must_use]
    pub fn is_ui(&self) -> bool {
        self.class_name == security_classes::UI_PERMISSION
    }

    /// Checks if this is an `EnvironmentPermission`.
    ///
    /// `EnvironmentPermissions` control access to environment variable operations
    /// including reading and writing system and user environment variables.
    ///
    /// # Returns
    ///
    /// `true` if this permission's class name matches the `EnvironmentPermission` type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::Permission;
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.EnvironmentPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![]
    /// # );
    /// if permission.is_environment() {
    ///     println!("This permission controls environment variable access");
    /// }
    /// ```
    #[must_use]
    pub fn is_environment(&self) -> bool {
        self.class_name == security_classes::ENVIRONMENT_PERMISSION
    }

    /// Retrieves a named argument by name.
    ///
    /// Named arguments represent property or field assignments on the permission instance.
    /// Common argument names include "Read", "Write", "Unrestricted", "Flags", etc.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the argument to search for (case-sensitive)
    ///
    /// # Returns
    ///
    /// `Some(&NamedArgument)` if an argument with the specified name exists,
    /// `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.FileIOPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![NamedArgument::new("Read".to_string(), ArgumentType::String, ArgumentValue::String("C:\\Data".to_string()))]
    /// # );
    /// if let Some(read_arg) = permission.get_argument("Read") {
    ///     println!("Read argument: {}", read_arg);
    /// }
    ///
    /// assert!(permission.get_argument("NonExistent").is_none());
    /// ```
    #[must_use]
    pub fn get_argument(&self, name: &str) -> Option<&NamedArgument> {
        self.named_arguments.iter().find(|arg| arg.name == name)
    }

    /// Extracts file paths granted read access from a `FileIOPermission`.
    ///
    /// This method specifically looks for the "Read" argument in `FileIOPermissions`
    /// and extracts the file paths specified for read access. The paths can be
    /// specified as a single string or an array of strings.
    ///
    /// # Returns
    ///
    /// - `Some(Vec<String>)` containing the read paths if this is a `FileIOPermission` with a "Read" argument
    /// - `None` if this is not a `FileIOPermission` or has no "Read" argument
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// # let permission = Permission::new(
    /// #     "System.Security.Permissions.FileIOPermission".to_string(),
    /// #     "mscorlib".to_string(),
    /// #     vec![NamedArgument::new("Read".to_string(), ArgumentType::String, ArgumentValue::String("C:\\Data".to_string()))]
    /// # );
    /// if let Some(paths) = permission.get_file_read_paths() {
    ///     for path in paths {
    ///         println!("Read access to: {}", path);
    ///     }
    /// }
    /// ```
    ///
    /// # Path Format
    ///
    /// The returned paths are exactly as specified in the permission metadata,
    /// which may include wildcards, UNC paths, or relative paths depending on
    /// how the permission was originally configured.
    #[must_use]
    pub fn get_file_read_paths(&self) -> Option<Vec<String>> {
        if !self.is_file_io() {
            return None;
        }

        if let Some(arg) = self.get_argument("Read") {
            match &arg.value {
                ArgumentValue::String(s) => Some(vec![s.clone()]),
                ArgumentValue::Array(arr) => {
                    let mut paths = Vec::new();
                    for value in arr {
                        if let ArgumentValue::String(s) = value {
                            paths.push(s.clone());
                        }
                    }
                    Some(paths)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Extracts file paths granted write access from a `FileIOPermission`.
    ///
    /// This method specifically looks for the "Write" argument in `FileIOPermissions`
    /// and extracts the file paths specified for write access. The paths can be
    /// specified as a single string or an array of strings.
    ///
    /// # Returns
    ///
    /// - `Some(Vec<String>)` containing the write paths if this is a `FileIOPermission` with a "Write" argument
    /// - `None` if this is not a `FileIOPermission` or has no "Write" argument
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let permission = Permission::new(
    ///     "System.Security.Permissions.FileIOPermission".to_string(),
    ///     "mscorlib".to_string(),
    ///     vec![NamedArgument::new(
    ///         "Write".to_string(),
    ///         ArgumentType::String,
    ///         ArgumentValue::String("C:\\Logs".to_string())
    ///     )]
    /// );
    ///
    /// if let Some(paths) = permission.get_file_write_paths() {
    ///     for path in paths {
    ///         println!("Write access to: {}", path);
    ///     }
    /// }
    /// ```
    ///
    /// # Security Implications
    ///
    /// Write permissions are more sensitive than read permissions as they allow
    /// modification of the file system. The paths should be carefully validated
    /// in security-sensitive contexts.
    #[must_use]
    pub fn get_file_write_paths(&self) -> Option<Vec<String>> {
        if !self.is_file_io() {
            return None;
        }

        if let Some(arg) = self.get_argument("Write") {
            match &arg.value {
                ArgumentValue::String(s) => Some(vec![s.clone()]),
                ArgumentValue::Array(arr) => {
                    let mut paths = Vec::new();
                    for value in arr {
                        if let ArgumentValue::String(s) = value {
                            paths.push(s.clone());
                        }
                    }
                    Some(paths)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Extracts file paths granted path discovery access from a `FileIOPermission`.
    ///
    /// Path discovery permission allows code to determine if a file or directory exists
    /// and to retrieve path information, but not to read the actual contents.
    /// This method looks for the "`PathDiscovery`" argument in `FileIOPermissions`.
    ///
    /// # Returns
    ///
    /// - `Some(Vec<String>)` containing the path discovery paths if this is a `FileIOPermission` with a "`PathDiscovery`" argument
    /// - `None` if this is not a `FileIOPermission` or has no "`PathDiscovery`" argument
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let permission = Permission::new(
    ///     "System.Security.Permissions.FileIOPermission".to_string(),
    ///     "mscorlib".to_string(),
    ///     vec![NamedArgument::new(
    ///         "PathDiscovery".to_string(),
    ///         ArgumentType::String,
    ///         ArgumentValue::String("C:\\Program Files".to_string())
    ///     )]
    /// );
    ///
    /// if let Some(paths) = permission.get_file_path_discovery() {
    ///     for path in paths {
    ///         println!("Path discovery access to: {}", path);
    ///     }
    /// }
    /// ```
    ///
    /// # Use Cases
    ///
    /// Path discovery is often used by applications that need to check for the
    /// existence of files or directories without actually reading their contents,
    /// such as installers or configuration utilities.
    #[must_use]
    pub fn get_file_path_discovery(&self) -> Option<Vec<String>> {
        if !self.is_file_io() {
            return None;
        }

        if let Some(arg) = self.get_argument("PathDiscovery") {
            match &arg.value {
                ArgumentValue::String(s) => Some(vec![s.clone()]),
                ArgumentValue::Array(arr) => {
                    let mut paths = Vec::new();
                    for value in arr {
                        if let ArgumentValue::String(s) = value {
                            paths.push(s.clone());
                        }
                    }
                    Some(paths)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Determines if this permission grants unrestricted access.
    ///
    /// Many .NET permission classes support an "Unrestricted" property that, when set to `true`,
    /// grants full access to the protected resource without any limitations. This effectively
    /// bypasses all specific permission checks for that resource type.
    ///
    /// # Returns
    ///
    /// `true` if the permission has an "Unrestricted" argument set to `true`, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let unrestricted_permission = Permission::new(
    ///     "System.Security.Permissions.FileIOPermission".to_string(),
    ///     "mscorlib".to_string(),
    ///     vec![NamedArgument::new(
    ///         "Unrestricted".to_string(),
    ///         ArgumentType::Boolean,
    ///         ArgumentValue::Boolean(true)
    ///     )]
    /// );
    ///
    /// if unrestricted_permission.is_unrestricted() {
    ///     println!("This permission grants unrestricted access");
    /// }
    /// ```
    ///
    /// # Security Implications
    ///
    /// Unrestricted permissions are very powerful and should be carefully monitored
    /// in security audits, as they effectively disable all access controls for
    /// the associated resource type.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        if let Some(arg) = self.get_argument("Unrestricted") {
            if let ArgumentValue::Boolean(b) = &arg.value {
                return *b;
            }
        }
        false
    }

    /// Extracts security permission flags from a `SecurityPermission`.
    ///
    /// `SecurityPermissions` use a flags enumeration to specify which security-sensitive
    /// operations are allowed. This method parses the "Flags" argument and returns
    /// the corresponding [`crate::metadata::security::SecurityPermissionFlags`].
    ///
    /// # Returns
    ///
    /// - `Some(SecurityPermissionFlags)` if this is a `SecurityPermission` with valid flags
    /// - `None` if this is not a `SecurityPermission` or has no flags argument
    ///
    /// # Supported Flag Formats
    ///
    /// The method supports multiple flag formats commonly found in .NET metadata:
    /// - **Integer values**: Direct bitwise flag values
    /// - **Enum values**: Typed enum representations
    /// - **String values**: Comma-separated flag names (e.g., "Execution,UnmanagedCode")
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{Permission, NamedArgument, ArgumentType, ArgumentValue, SecurityPermissionFlags};
    ///
    /// let permission = Permission::new(
    ///     "System.Security.Permissions.SecurityPermission".to_string(),
    ///     "mscorlib".to_string(),
    ///     vec![NamedArgument::new(
    ///         "Flags".to_string(),
    ///         ArgumentType::Int32,
    ///         ArgumentValue::Int32(0x0002) // UnmanagedCode flag
    ///     )]
    /// );
    ///
    /// if let Some(flags) = permission.get_security_flags() {
    ///     if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_UNSAFE_CODE) {
    ///         println!("This permission allows unsafe code execution");
    ///     }
    /// }
    /// ```
    ///
    /// # Common Security Flags
    ///
    /// - **Execution**: Allows code execution
    /// - **`UnmanagedCode`**: Allows calling unmanaged code
    /// - **`SkipVerification`**: Allows skipping IL verification
    /// - **Assertion**: Allows asserting permissions
    /// - **`ControlThread`**: Allows thread manipulation
    /// - **`ControlPolicy`**: Allows security policy control
    #[must_use]
    pub fn get_security_flags(&self) -> Option<SecurityPermissionFlags> {
        if !self.is_security() {
            return None;
        }

        if let Some(arg) = self.get_argument("Flags") {
            if let ArgumentValue::Int32(flags) = &arg.value {
                return Some(SecurityPermissionFlags::from_bits_truncate(*flags));
            } else if let ArgumentValue::Enum(_, flags) = &arg.value {
                return Some(SecurityPermissionFlags::from_bits_truncate(*flags));
            } else if let ArgumentValue::String(flags_str) = &arg.value {
                // Handle string representations of security flags
                return Some(Self::parse_flags_from_string(flags_str));
            }
        }
        None
    }

    /// Parses security permission flags from a string representation.
    ///
    /// This internal method handles the conversion of string-based flag specifications
    /// to the corresponding [`crate::metadata::security::SecurityPermissionFlags`] bitfield.
    /// It supports both individual flag names and the special "`AllFlags`" value.
    ///
    /// # Arguments
    ///
    /// * `flags_str` - A string containing comma-separated flag names or "`AllFlags`"
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::security::SecurityPermissionFlags`] value representing the parsed flags.
    ///
    /// # Supported Flag Names
    ///
    /// - `"Execution"` - Basic code execution rights
    /// - `"SkipVerification"` - Ability to skip IL verification
    /// - `"Assertion"` - Permission assertion capabilities
    /// - `"UnmanagedCode"` - Unmanaged code execution (maps to multiple internal flags)
    /// - `"UnsafeCode"` - Direct unsafe code execution
    /// - `"ControlAppDomains"` - Application domain control
    /// - `"ControlPolicy"` - Security policy manipulation
    /// - `"Serialization"` - Object serialization rights
    /// - `"ControlThread"` - Thread lifecycle control
    /// - `"ControlEvidence"` - Evidence manipulation
    /// - `"ControlPrincipal"` - Principal object control
    /// - `"Infrastructure"` - Infrastructure services access
    /// - `"Binding"` - Assembly binding control
    /// - `"Remoting"` - Remoting infrastructure access
    /// - `"ControlDomain"` - Domain-level control
    /// - `"Reflection"` - Reflection capabilities
    /// - `"AllFlags"` - All available permissions
    ///
    /// # Format Examples
    ///
    /// - `"Execution"` - Single flag
    /// - `"Execution,UnmanagedCode"` - Multiple flags
    /// - `"AllFlags"` - All permissions
    ///
    /// Unknown flag names are silently ignored to maintain compatibility with
    /// future .NET Framework versions that may introduce new flags.
    fn parse_flags_from_string(flags_str: &str) -> SecurityPermissionFlags {
        let mut flags = SecurityPermissionFlags::empty();

        if flags_str == "AllFlags" {
            return SecurityPermissionFlags::all();
        }

        // Parse comma-separated flag names
        for flag_name in flags_str.split(',').map(str::trim) {
            match flag_name {
                "Execution" => flags |= SecurityPermissionFlags::SECURITY_FLAG_EXECUTION,
                "SkipVerification" => {
                    flags |= SecurityPermissionFlags::SECURITY_FLAG_SKIP_VERIFICATION;
                }
                "Assertion" => flags |= SecurityPermissionFlags::SECURITY_FLAG_ASSERTION,
                "UnmanagedCode" => {
                    // UnmanagedCode is typically a combination of several flags in older .NET
                    flags |= SecurityPermissionFlags::SECURITY_FLAG_UNSAFE_CODE;
                    flags |= SecurityPermissionFlags::SECURITY_FLAG_SKIP_VERIFICATION;
                }
                "UnsafeCode" => flags |= SecurityPermissionFlags::SECURITY_FLAG_UNSAFE_CODE,
                "ControlAppDomains" => {
                    flags |= SecurityPermissionFlags::SECURITY_FLAG_CONTROL_APPDOMAINS;
                }
                "ControlPolicy" => flags |= SecurityPermissionFlags::SECURITY_FLAG_CONTROL_POLICY,
                "Serialization" => flags |= SecurityPermissionFlags::SECURITY_FLAG_SERIALIZATION,
                "ControlThread" => flags |= SecurityPermissionFlags::SECURITY_FLAG_CONTROL_THREAD,
                "ControlEvidence" => {
                    flags |= SecurityPermissionFlags::SECURITY_FLAG_CONTROL_EVIDENCE;
                }
                "ControlPrincipal" => {
                    flags |= SecurityPermissionFlags::SECURITY_FLAG_CONTROL_PRINCIPAL;
                }
                "Infrastructure" => flags |= SecurityPermissionFlags::SECURITY_FLAG_INFRASTRUCTURE,
                "Binding" => flags |= SecurityPermissionFlags::SECURITY_FLAG_BINDING,
                "Remoting" => flags |= SecurityPermissionFlags::SECURITY_FLAG_REMOTING,
                "ControlDomain" => flags |= SecurityPermissionFlags::SECURITY_FLAG_CONTROL_DOMAIN,
                "Reflection" => flags |= SecurityPermissionFlags::SECURITY_FLAG_REFLECTION,
                _ => {} // Ignore unknown flags
            }
        }

        flags
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.class_name)?;

        for (i, arg) in self.named_arguments.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{arg}")?;
        }

        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::security::{ArgumentType, ArgumentValue};

    fn create_test_permission() -> Permission {
        let named_args = vec![
            NamedArgument::new(
                "Read".to_string(),
                ArgumentType::String,
                ArgumentValue::String("C:\\Data".to_string()),
            ),
            NamedArgument::new(
                "Unrestricted".to_string(),
                ArgumentType::Boolean,
                ArgumentValue::Boolean(false),
            ),
        ];

        Permission::new(
            security_classes::FILE_IO_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        )
    }

    #[test]
    fn test_permission_new() {
        let permission = create_test_permission();
        assert_eq!(permission.class_name, security_classes::FILE_IO_PERMISSION);
        assert_eq!(permission.assembly_name, "mscorlib");
        assert_eq!(permission.named_arguments.len(), 2);
    }

    #[test]
    fn test_is_file_io() {
        let file_io_perm = create_test_permission();
        assert!(file_io_perm.is_file_io());

        let security_perm = Permission::new(
            security_classes::SECURITY_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );
        assert!(!security_perm.is_file_io());
    }

    #[test]
    fn test_is_security() {
        let security_perm = Permission::new(
            security_classes::SECURITY_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );
        assert!(security_perm.is_security());

        let file_io_perm = create_test_permission();
        assert!(!file_io_perm.is_security());
    }

    #[test]
    fn test_is_reflection() {
        let reflection_perm = Permission::new(
            security_classes::REFLECTION_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );
        assert!(reflection_perm.is_reflection());

        let file_io_perm = create_test_permission();
        assert!(!file_io_perm.is_reflection());
    }

    #[test]
    fn test_is_registry() {
        let registry_perm = Permission::new(
            security_classes::REGISTRY_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );
        assert!(registry_perm.is_registry());

        let file_io_perm = create_test_permission();
        assert!(!file_io_perm.is_registry());
    }

    #[test]
    fn test_is_ui() {
        let ui_perm = Permission::new(
            security_classes::UI_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );
        assert!(ui_perm.is_ui());

        let file_io_perm = create_test_permission();
        assert!(!file_io_perm.is_ui());
    }

    #[test]
    fn test_is_environment() {
        let env_perm = Permission::new(
            security_classes::ENVIRONMENT_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );
        assert!(env_perm.is_environment());

        let file_io_perm = create_test_permission();
        assert!(!file_io_perm.is_environment());
    }

    #[test]
    fn test_get_argument() {
        let permission = create_test_permission();

        let read_arg = permission.get_argument("Read");
        assert!(read_arg.is_some());
        assert_eq!(read_arg.unwrap().name, "Read");

        let nonexistent = permission.get_argument("NonExistent");
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_get_file_read_paths_string() {
        let permission = create_test_permission();
        let paths = permission.get_file_read_paths();
        assert!(paths.is_some());

        let paths = paths.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "C:\\Data");
    }

    #[test]
    fn test_get_file_read_paths_array() {
        let named_args = vec![NamedArgument::new(
            "Read".to_string(),
            ArgumentType::Array(Box::new(ArgumentType::String)),
            ArgumentValue::Array(vec![
                ArgumentValue::String("C:\\Data1".to_string()),
                ArgumentValue::String("C:\\Data2".to_string()),
            ]),
        )];

        let permission = Permission::new(
            security_classes::FILE_IO_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        );

        let paths = permission.get_file_read_paths();
        assert!(paths.is_some());

        let paths = paths.unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], "C:\\Data1");
        assert_eq!(paths[1], "C:\\Data2");
    }

    #[test]
    fn test_get_file_read_paths_non_file_io() {
        let security_perm = Permission::new(
            security_classes::SECURITY_PERMISSION.to_string(),
            "mscorlib".to_string(),
            vec![],
        );

        let paths = security_perm.get_file_read_paths();
        assert!(paths.is_none());
    }

    #[test]
    fn test_get_file_write_paths() {
        let named_args = vec![NamedArgument::new(
            "Write".to_string(),
            ArgumentType::String,
            ArgumentValue::String("C:\\Logs".to_string()),
        )];

        let permission = Permission::new(
            security_classes::FILE_IO_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        );

        let paths = permission.get_file_write_paths();
        assert!(paths.is_some());

        let paths = paths.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "C:\\Logs");
    }

    #[test]
    fn test_get_file_path_discovery() {
        let named_args = vec![NamedArgument::new(
            "PathDiscovery".to_string(),
            ArgumentType::String,
            ArgumentValue::String("C:\\Discovery".to_string()),
        )];

        let permission = Permission::new(
            security_classes::FILE_IO_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        );

        let paths = permission.get_file_path_discovery();
        assert!(paths.is_some());

        let paths = paths.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "C:\\Discovery");
    }

    #[test]
    fn test_is_unrestricted_true() {
        let named_args = vec![NamedArgument::new(
            "Unrestricted".to_string(),
            ArgumentType::Boolean,
            ArgumentValue::Boolean(true),
        )];

        let permission = Permission::new(
            security_classes::FILE_IO_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        );

        assert!(permission.is_unrestricted());
    }

    #[test]
    fn test_is_unrestricted_false() {
        let permission = create_test_permission();
        assert!(!permission.is_unrestricted());
    }

    #[test]
    fn test_get_security_flags() {
        let named_args = vec![NamedArgument::new(
            "Flags".to_string(),
            ArgumentType::Int32,
            ArgumentValue::Int32(0x1), // ASSERTION flag
        )];

        let permission = Permission::new(
            security_classes::SECURITY_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        );

        let flags = permission.get_security_flags();
        assert!(flags.is_some());

        let flags = flags.unwrap();
        assert!(flags.contains(SecurityPermissionFlags::SECURITY_FLAG_ASSERTION));
    }

    #[test]
    fn test_get_security_flags_enum() {
        let named_args = vec![NamedArgument::new(
            "Flags".to_string(),
            ArgumentType::Enum("SecurityPermissionFlag".to_string()),
            ArgumentValue::Enum("SecurityPermissionFlag".to_string(), 0x20), // UNSAFE_CODE
        )];

        let permission = Permission::new(
            security_classes::SECURITY_PERMISSION.to_string(),
            "mscorlib".to_string(),
            named_args,
        );

        let flags = permission.get_security_flags();
        assert!(flags.is_some());

        let flags = flags.unwrap();
        assert!(flags.contains(SecurityPermissionFlags::SECURITY_FLAG_UNSAFE_CODE));
    }

    #[test]
    fn test_get_security_flags_non_security() {
        let permission = create_test_permission();
        let flags = permission.get_security_flags();
        assert!(flags.is_none());
    }

    #[test]
    fn test_display_formatting() {
        let permission = create_test_permission();
        let formatted = format!("{permission}");

        assert!(formatted.starts_with(security_classes::FILE_IO_PERMISSION));
        assert!(formatted.contains("Read = \"C:\\Data\""));
        assert!(formatted.contains("Unrestricted = false"));
        assert!(formatted.contains("("));
        assert!(formatted.contains(")"));
    }

    #[test]
    fn test_display_formatting_empty_args() {
        let permission =
            Permission::new("TestPermission".to_string(), "mscorlib".to_string(), vec![]);

        let formatted = format!("{permission}");
        assert_eq!(formatted, "TestPermission()");
    }

    #[test]
    fn test_clone() {
        let original = create_test_permission();
        let cloned = original.clone();

        assert_eq!(cloned.class_name, original.class_name);
        assert_eq!(cloned.assembly_name, original.assembly_name);
        assert_eq!(cloned.named_arguments.len(), original.named_arguments.len());
    }

    #[test]
    fn test_debug_formatting() {
        let permission = create_test_permission();
        let debug_str = format!("{permission:?}");

        assert!(debug_str.contains("Permission"));
        assert!(debug_str.contains(security_classes::FILE_IO_PERMISSION));
    }
}
