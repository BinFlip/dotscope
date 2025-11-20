//! Fluent builder APIs for creating .NET security permission sets.
//!
//! This module provides ergonomic builder patterns for constructing complex permission sets
//! programmatically with type-safe operations and validation. The builders follow fluent API
//! design principles to enable readable and maintainable security permission creation for
//! .NET Code Access Security (CAS) scenarios.
//!
//! # Architecture
//!
//! The builder system is designed around the core CAS permission hierarchy:
//!
//! - **Permission Set Builder**: Top-level builder for creating collections of permissions
//! - **Permission Builders**: Specialized builders for each permission type (Security, FileIO, etc.)
//! - **Fluent Composition**: Builders return themselves for method chaining
//! - **Type Safety**: Each builder validates its specific permission constraints
//! - **Encoding Integration**: Direct integration with [`crate::metadata::security::encode_permission_set`]
//!
//! The builder pattern abstracts the complex manual construction of [`crate::metadata::security::Permission`]
//! and [`crate::metadata::security::NamedArgument`] structures while ensuring proper type relationships
//! and argument validation.
//!
//! # Key Components
//!
//! - [`crate::metadata::security::builders::PermissionSetBuilder`] - Primary builder for creating permission sets
//! - [`crate::metadata::security::builders::SecurityPermissionBuilder`] - Builder for SecurityPermission instances
//! - [`crate::metadata::security::builders::FileIOPermissionBuilder`] - Builder for FileIOPermission instances
//!
//! # Usage Examples
//!
//! ## Basic Permission Set Creation
//!
//! ```rust,ignore
//! use dotscope::metadata::security::{PermissionSetBuilder, PermissionSetFormat};
//!
//! let permission_bytes = PermissionSetBuilder::new()
//!     .add_security_permission()
//!         .unrestricted(true)
//!         .build()
//!     .encode(PermissionSetFormat::BinaryLegacy)?;
//!
//! // Result: Binary permission set with unrestricted security permissions
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Complex Multi-Permission Sets
//!
//! ```rust,ignore
//! use dotscope::metadata::security::{PermissionSetBuilder, PermissionSetFormat};
//!
//! let permission_bytes = PermissionSetBuilder::new()
//!     .add_security_permission()
//!         .flags("Execution, SkipVerification")
//!         .build()
//!     .add_file_io_permission()
//!         .read_paths(&["C:\\Data", "C:\\Config"])
//!         .write_paths(&["C:\\Logs"])
//!         .unrestricted(false)
//!         .build()
//!     .encode(PermissionSetFormat::BinaryLegacy)?;
//!
//! // Result: Permission set with specific security and file I/O permissions
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Custom Permission Addition
//!
//! ```rust,ignore
//! use dotscope::metadata::security::{
//!     PermissionSetBuilder, Permission, NamedArgument, ArgumentType, ArgumentValue
//! };
//!
//! let custom_permission = Permission {
//!     class_name: "CustomNamespace.CustomPermission".to_string(),
//!     assembly_name: "CustomAssembly".to_string(),
//!     named_arguments: vec![
//!         NamedArgument {
//!             name: "CustomProperty".to_string(),
//!             arg_type: ArgumentType::String,
//!             value: ArgumentValue::String("CustomValue".to_string()),
//!         }
//!     ],
//! };
//!
//! let permission_set = PermissionSetBuilder::new()
//!     .add_permission(custom_permission)
//!     .permissions();
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All builder types in this module are not [`Send`] or [`Sync`] as they contain
//! mutable state and are designed for single-threaded construction scenarios.
//! Once a permission set is built and encoded, the resulting data is thread-safe.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::security::encode_permission_set`] - For encoding built permission sets to binary/XML formats
//! - [`crate::metadata::security::PermissionSet`] - For validation and parsing of encoded permissions
//! - [`crate::metadata::security::Permission`] - For core permission type definitions

use crate::{
    metadata::security::{
        encode_permission_set, ArgumentType, ArgumentValue, NamedArgument, Permission,
        PermissionSetFormat,
    },
    Result,
};

/// Builder for creating permission sets with fluent API.
///
/// The [`crate::metadata::security::builders::PermissionSetBuilder`] provides a convenient way to build permission sets
/// programmatically with type-safe operations and validation. It follows the builder pattern
/// to enable readable and maintainable permission set construction for .NET Code Access Security.
///
/// # Design Benefits
///
/// - **Fluent Interface**: Method chaining for readable permission construction
/// - **Type Safety**: Each permission builder validates its specific constraints
/// - **Composition**: Easily combine multiple permission types in a single set
/// - **Encoding Integration**: Direct encoding to binary or XML formats
/// - **Extensibility**: Support for custom permissions alongside built-in types
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::security::{PermissionSetBuilder, PermissionSetFormat};
///
/// // Create a simple unrestricted permission set
/// let permission_bytes = PermissionSetBuilder::new()
///     .add_security_permission()
///         .unrestricted(true)
///         .build()
///     .encode(PermissionSetFormat::BinaryLegacy)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] because it contains mutable state for
/// building permissions. Use within a single thread and encode the result for
/// cross-thread sharing.
pub struct PermissionSetBuilder {
    /// Collection of permissions being built
    permissions: Vec<Permission>,
}

impl PermissionSetBuilder {
    /// Creates a new permission set builder.
    ///
    /// Initializes an empty permission set builder ready to accept permission configurations.
    /// The builder starts with no permissions and can be populated using the various
    /// `add_*` methods or by directly adding [`crate::metadata::security::Permission`] instances.
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::security::builders::PermissionSetBuilder`] instance ready for permission addition.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// let builder = PermissionSetBuilder::new();
    /// assert_eq!(builder.permissions().len(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        PermissionSetBuilder {
            permissions: Vec::new(),
        }
    }

    /// Adds a custom permission to the set.
    ///
    /// Directly adds a pre-constructed [`crate::metadata::security::Permission`] to the permission set.
    /// This method is useful for adding custom permission types that don't have dedicated
    /// builder methods, or when you need full control over permission construction.
    ///
    /// # Arguments
    ///
    /// * `permission` - A fully constructed [`crate::metadata::security::Permission`] instance to add
    ///
    /// # Returns
    ///
    /// Returns the builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::{
    ///     PermissionSetBuilder, Permission, NamedArgument, ArgumentType, ArgumentValue
    /// };
    ///
    /// let custom_permission = Permission {
    ///     class_name: "CustomNamespace.CustomPermission".to_string(),
    ///     assembly_name: "CustomAssembly".to_string(),
    ///     named_arguments: vec![
    ///         NamedArgument {
    ///             name: "Level".to_string(),
    ///             arg_type: ArgumentType::Int32,
    ///             value: ArgumentValue::Int32(5),
    ///         }
    ///     ],
    /// };
    ///
    /// let builder = PermissionSetBuilder::new()
    ///     .add_permission(custom_permission);
    /// ```
    #[must_use]
    pub fn add_permission(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Starts building a SecurityPermission.
    ///
    /// Creates a new [`crate::metadata::security::builders::SecurityPermissionBuilder`] for configuring a
    /// `System.Security.Permissions.SecurityPermission` instance. This permission type
    /// controls fundamental security operations like skipping verification, controlling
    /// policy, and managing evidence.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::security::builders::SecurityPermissionBuilder`] for configuring security permissions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// let builder = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .flags("Execution, SkipVerification")
    ///         .build();
    /// ```
    #[must_use]
    pub fn add_security_permission(self) -> SecurityPermissionBuilder {
        SecurityPermissionBuilder::new(self)
    }

    /// Starts building a FileIOPermission.
    ///
    /// Creates a new [`crate::metadata::security::builders::FileIOPermissionBuilder`] for configuring a
    /// `System.Security.Permissions.FileIOPermission` instance. This permission type
    /// controls file system access including read, write, and append operations on
    /// specific paths or with unrestricted access.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::security::builders::FileIOPermissionBuilder`] for configuring file I/O permissions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .read_paths(&["C:\\Data"])
    ///         .write_paths(&["C:\\Logs"])
    ///         .build();
    /// ```
    #[must_use]
    pub fn add_file_io_permission(self) -> FileIOPermissionBuilder {
        FileIOPermissionBuilder::new(self)
    }

    /// Encodes the permission set to the specified format.
    ///
    /// Converts the built permission set to binary representation using the specified format.
    /// This method consumes the builder and delegates to [`crate::metadata::security::encode_permission_set`]
    /// for the actual encoding process.
    ///
    /// # Arguments
    ///
    /// * `format` - The target [`crate::metadata::security::PermissionSetFormat`] for encoding
    ///
    /// # Returns
    ///
    /// Returns the encoded permission set as a byte vector, or an error if encoding fails.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - [`crate::Error::Malformed`] - When permission data contains unsupported types
    /// - [`crate::Error::Malformed`] - When the target format is [`crate::metadata::security::PermissionSetFormat::Unknown`]
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::{PermissionSetBuilder, PermissionSetFormat};
    ///
    /// let binary_data = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .unrestricted(true)
    ///         .build()
    ///     .encode(PermissionSetFormat::BinaryLegacy)?;
    ///
    /// let xml_data = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .unrestricted(true)
    ///         .build()
    ///     .encode(PermissionSetFormat::Xml)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode(self, format: PermissionSetFormat) -> Result<Vec<u8>> {
        encode_permission_set(&self.permissions, format)
    }

    /// Gets the built permissions.
    ///
    /// Consumes the builder and returns the constructed permission collection.
    /// This method is useful when you need access to the permission structures
    /// without encoding them, such as for further processing or validation.
    ///
    /// # Returns
    ///
    /// Returns a vector of [`crate::metadata::security::Permission`] instances that were built.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// let permissions = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .unrestricted(true)
    ///         .build()
    ///     .permissions();
    ///
    /// assert_eq!(permissions.len(), 1);
    /// assert_eq!(permissions[0].class_name, "System.Security.Permissions.SecurityPermission");
    /// ```
    #[must_use]
    pub fn permissions(self) -> Vec<Permission> {
        self.permissions
    }
}

impl Default for PermissionSetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for SecurityPermission instances.
///
/// The [`crate::metadata::security::builders::SecurityPermissionBuilder`] provides a fluent interface for creating
/// `System.Security.Permissions.SecurityPermission` instances with proper argument
/// validation and type safety. SecurityPermissions control fundamental runtime
/// security operations in the .NET Code Access Security model.
///
/// # SecurityPermission Flags
///
/// Common security permission flags include:
/// - **Execution**: Permission to execute code
/// - **SkipVerification**: Permission to skip verification
/// - **UnmanagedCode**: Permission to call unmanaged code
/// - **ControlThread**: Permission to control threads
/// - **ControlEvidence**: Permission to control evidence
/// - **ControlPolicy**: Permission to control security policy
/// - **SerializationFormatter**: Permission to use serialization formatters
/// - **ControlDomainPolicy**: Permission to control application domain policy
/// - **ControlPrincipal**: Permission to control the principal
/// - **ControlAppDomain**: Permission to control application domains
/// - **RemotingConfiguration**: Permission to configure remoting
/// - **Infrastructure**: Infrastructure permission
/// - **BindingRedirects**: Permission to redirect assemblies
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::security::PermissionSetBuilder;
///
/// // Unrestricted security permission
/// let builder = PermissionSetBuilder::new()
///     .add_security_permission()
///         .unrestricted(true)
///         .build();
///
/// // Specific security flags
/// let builder = PermissionSetBuilder::new()
///     .add_security_permission()
///         .flags("Execution, SkipVerification")
///         .build();
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] because it maintains mutable state during
/// the building process and is designed for single-threaded use.
pub struct SecurityPermissionBuilder {
    /// Parent builder to return to after completion
    parent: PermissionSetBuilder,
    /// Named arguments being configured for this permission
    named_arguments: Vec<NamedArgument>,
}

impl SecurityPermissionBuilder {
    /// Creates a new SecurityPermissionBuilder.
    ///
    /// Internal constructor used by [`crate::metadata::security::builders::PermissionSetBuilder::add_security_permission`]
    /// to create a new builder instance with the parent context.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent [`crate::metadata::security::builders::PermissionSetBuilder`] to return to after completion
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::security::builders::SecurityPermissionBuilder`] instance.
    fn new(parent: PermissionSetBuilder) -> Self {
        SecurityPermissionBuilder {
            parent,
            named_arguments: Vec::new(),
        }
    }

    /// Sets the Unrestricted flag.
    ///
    /// Configures whether this SecurityPermission grants unrestricted access to
    /// all security operations. When set to `true`, this permission effectively
    /// grants full trust and bypasses most security checks.
    ///
    /// # Arguments
    ///
    /// * `value` - `true` for unrestricted access, `false` for restricted access
    ///
    /// # Returns
    ///
    /// Returns the builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// // Grant unrestricted security permissions
    /// let builder = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .unrestricted(true)
    ///         .build();
    ///
    /// // Restrict security permissions
    /// let builder = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .unrestricted(false)
    ///         .flags("Execution")
    ///         .build();
    /// ```
    #[must_use]
    pub fn unrestricted(mut self, value: bool) -> Self {
        self.named_arguments.push(NamedArgument {
            name: "Unrestricted".to_string(),
            arg_type: ArgumentType::Boolean,
            value: ArgumentValue::Boolean(value),
        });
        self
    }

    /// Sets security flags by name.
    ///
    /// Configures specific security permission flags using their string names.
    /// Multiple flags can be specified as a comma-separated string. This method
    /// provides a convenient way to set specific security permissions without
    /// using unrestricted access.
    ///
    /// # Arguments
    ///
    /// * `flags` - Comma-separated string of security permission flag names
    ///
    /// # Returns
    ///
    /// Returns the builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// // Single flag
    /// let builder = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .flags("Execution")
    ///         .build();
    ///
    /// // Multiple flags
    /// let builder = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .flags("Execution, SkipVerification, ControlEvidence")
    ///         .build();
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: &str) -> Self {
        self.named_arguments.push(NamedArgument {
            name: "Flags".to_string(),
            arg_type: ArgumentType::String,
            value: ArgumentValue::String(flags.to_string()),
        });
        self
    }

    /// Completes the SecurityPermission and returns to the parent builder.
    ///
    /// Finalizes the SecurityPermission configuration and adds it to the parent
    /// permission set builder. The created permission uses the standard
    /// `System.Security.Permissions.SecurityPermission` class from `mscorlib`.
    ///
    /// # Returns
    ///
    /// Returns the parent [`crate::metadata::security::builders::PermissionSetBuilder`] for continued method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// let permission_set = PermissionSetBuilder::new()
    ///     .add_security_permission()
    ///         .flags("Execution")
    ///         .build()  // <- This method
    ///     .add_file_io_permission()
    ///         .read_paths(&["C:\\Data"])
    ///         .build()
    ///     .permissions();
    /// ```
    #[must_use]
    pub fn build(self) -> PermissionSetBuilder {
        let permission = Permission {
            class_name: "System.Security.Permissions.SecurityPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: self.named_arguments,
        };
        self.parent.add_permission(permission)
    }
}

/// Builder for FileIOPermission instances.
///
/// The [`crate::metadata::security::builders::FileIOPermissionBuilder`] provides a fluent interface for creating
/// `System.Security.Permissions.FileIOPermission` instances with proper path
/// validation and access control configuration. FileIOPermissions control
/// file system access in the .NET Code Access Security model.
///
/// # File Access Types
///
/// FileIOPermission supports several types of file system access:
/// - **Read**: Permission to read from specified paths
/// - **Write**: Permission to write to specified paths
/// - **Append**: Permission to append to specified paths
/// - **PathDiscovery**: Permission to access path information
/// - **AllAccess**: Combination of all access types
///
/// # Path Specification
///
/// Paths can be specified as:
/// - **Absolute paths**: `C:\Data\file.txt`
/// - **Directory paths**: `C:\Data\` (with trailing slash for directories)
/// - **Wildcard paths**: `C:\Data\*` (for directory contents)
/// - **Multiple paths**: Separated by semicolons in a single string
///
/// # Usage Examples
///
/// ```rust,ignore
/// use dotscope::metadata::security::PermissionSetBuilder;
///
/// // Read-only access to specific directories
/// let builder = PermissionSetBuilder::new()
///     .add_file_io_permission()
///         .read_paths(&["C:\\Data", "C:\\Config"])
///         .build();
///
/// // Read/write access with restrictions
/// let builder = PermissionSetBuilder::new()
///     .add_file_io_permission()
///         .read_paths(&["C:\\Data"])
///         .write_paths(&["C:\\Logs", "C:\\Output"])
///         .unrestricted(false)
///         .build();
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] because it maintains mutable state during
/// the building process and is designed for single-threaded use.
pub struct FileIOPermissionBuilder {
    /// Parent builder to return to after completion
    parent: PermissionSetBuilder,
    /// Named arguments being configured for this permission
    named_arguments: Vec<NamedArgument>,
}

impl FileIOPermissionBuilder {
    /// Creates a new FileIOPermissionBuilder.
    ///
    /// Internal constructor used by [`crate::metadata::security::builders::PermissionSetBuilder::add_file_io_permission`]
    /// to create a new builder instance with the parent context.
    ///
    /// # Arguments
    ///
    /// * `parent` - The parent [`crate::metadata::security::builders::PermissionSetBuilder`] to return to after completion
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::metadata::security::builders::FileIOPermissionBuilder`] instance.
    fn new(parent: PermissionSetBuilder) -> Self {
        FileIOPermissionBuilder {
            parent,
            named_arguments: Vec::new(),
        }
    }

    /// Sets read paths.
    ///
    /// Configures the paths that this FileIOPermission grants read access to.
    /// Multiple paths are joined with semicolons as required by the .NET
    /// permission format. Paths should be absolute and can include directories
    /// and specific files.
    ///
    /// # Arguments
    ///
    /// * `paths` - Array of path strings to grant read access to
    ///
    /// # Returns
    ///
    /// Returns the builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// // Single path
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .read_paths(&["C:\\Data"])
    ///         .build();
    ///
    /// // Multiple paths
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .read_paths(&["C:\\Data", "C:\\Config", "C:\\Logs"])
    ///         .build();
    /// ```
    #[must_use]
    pub fn read_paths(mut self, paths: &[&str]) -> Self {
        let paths_str = paths.join(";");
        self.named_arguments.push(NamedArgument {
            name: "Read".to_string(),
            arg_type: ArgumentType::String,
            value: ArgumentValue::String(paths_str),
        });
        self
    }

    /// Sets write paths.
    ///
    /// Configures the paths that this FileIOPermission grants write access to.
    /// Multiple paths are joined with semicolons as required by the .NET
    /// permission format. Write access typically includes the ability to create,
    /// modify, and delete files in the specified locations.
    ///
    /// # Arguments
    ///
    /// * `paths` - Array of path strings to grant write access to
    ///
    /// # Returns
    ///
    /// Returns the builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// // Write access to output directories
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .write_paths(&["C:\\Logs", "C:\\Output"])
    ///         .build();
    ///
    /// // Combined read/write access
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .read_paths(&["C:\\Data"])
    ///         .write_paths(&["C:\\Logs"])
    ///         .build();
    /// ```
    #[must_use]
    pub fn write_paths(mut self, paths: &[&str]) -> Self {
        let paths_str = paths.join(";");
        self.named_arguments.push(NamedArgument {
            name: "Write".to_string(),
            arg_type: ArgumentType::String,
            value: ArgumentValue::String(paths_str),
        });
        self
    }

    /// Sets the Unrestricted flag.
    ///
    /// Configures whether this FileIOPermission grants unrestricted access to
    /// the entire file system. When set to `true`, this permission bypasses
    /// path restrictions and allows access to all files and directories.
    ///
    /// # Arguments
    ///
    /// * `value` - `true` for unrestricted file system access, `false` for path-restricted access
    ///
    /// # Returns
    ///
    /// Returns the builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// // Unrestricted file system access
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .unrestricted(true)
    ///         .build();
    ///
    /// // Restricted to specific paths
    /// let builder = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .unrestricted(false)
    ///         .read_paths(&["C:\\Data"])
    ///         .build();
    /// ```
    #[must_use]
    pub fn unrestricted(mut self, value: bool) -> Self {
        self.named_arguments.push(NamedArgument {
            name: "Unrestricted".to_string(),
            arg_type: ArgumentType::Boolean,
            value: ArgumentValue::Boolean(value),
        });
        self
    }

    /// Completes the FileIOPermission and returns to the parent builder.
    ///
    /// Finalizes the FileIOPermission configuration and adds it to the parent
    /// permission set builder. The created permission uses the standard
    /// `System.Security.Permissions.FileIOPermission` class from `mscorlib`.
    ///
    /// # Returns
    ///
    /// Returns the parent [`crate::metadata::security::builders::PermissionSetBuilder`] for continued method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::security::PermissionSetBuilder;
    ///
    /// let permission_set = PermissionSetBuilder::new()
    ///     .add_file_io_permission()
    ///         .read_paths(&["C:\\Data"])
    ///         .write_paths(&["C:\\Logs"])
    ///         .build()  // <- This method
    ///     .add_security_permission()
    ///         .flags("Execution")
    ///         .build()
    ///     .permissions();
    /// ```
    #[must_use]
    pub fn build(self) -> PermissionSetBuilder {
        let permission = Permission {
            class_name: "System.Security.Permissions.FileIOPermission".to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: self.named_arguments,
        };
        self.parent.add_permission(permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::security::{ArgumentValue, PermissionSetFormat};

    #[test]
    fn test_permission_set_builder_basic() {
        let permissions = PermissionSetBuilder::new()
            .add_security_permission()
            .unrestricted(true)
            .build()
            .permissions();

        assert_eq!(permissions.len(), 1);
        assert_eq!(
            permissions[0].class_name,
            "System.Security.Permissions.SecurityPermission"
        );
        assert_eq!(permissions[0].assembly_name, "mscorlib");
        assert_eq!(permissions[0].named_arguments.len(), 1);
        assert_eq!(permissions[0].named_arguments[0].name, "Unrestricted");

        if let ArgumentValue::Boolean(value) = &permissions[0].named_arguments[0].value {
            assert!(value);
        } else {
            panic!("Expected boolean value for Unrestricted");
        }
    }

    #[test]
    fn test_permission_set_builder_with_encoding() {
        let encoded = PermissionSetBuilder::new()
            .add_security_permission()
            .unrestricted(true)
            .build()
            .add_file_io_permission()
            .read_paths(&["C:\\temp"])
            .write_paths(&["C:\\logs"])
            .build()
            .encode(PermissionSetFormat::BinaryLegacy)
            .unwrap();

        // Should have format marker and 2 permissions
        assert_eq!(encoded[0], 0x2E);
        assert_eq!(encoded[1], 0x02);
    }

    #[test]
    fn test_security_permission_builder_flags() {
        let permissions = PermissionSetBuilder::new()
            .add_security_permission()
            .flags("SkipVerification, Execution")
            .build()
            .permissions();

        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].named_arguments.len(), 1);
        assert_eq!(permissions[0].named_arguments[0].name, "Flags");

        if let ArgumentValue::String(flags) = &permissions[0].named_arguments[0].value {
            assert_eq!(flags, "SkipVerification, Execution");
        } else {
            panic!("Expected string value for flags");
        }
    }

    #[test]
    fn test_file_io_permission_builder() {
        let permissions = PermissionSetBuilder::new()
            .add_file_io_permission()
            .read_paths(&["C:\\Data", "C:\\Config"])
            .write_paths(&["C:\\Logs"])
            .unrestricted(false)
            .build()
            .permissions();

        assert_eq!(permissions.len(), 1);
        assert_eq!(
            permissions[0].class_name,
            "System.Security.Permissions.FileIOPermission"
        );
        assert_eq!(permissions[0].named_arguments.len(), 3); // Read, Write, Unrestricted

        // Check read paths
        let read_arg = permissions[0]
            .named_arguments
            .iter()
            .find(|arg| arg.name == "Read")
            .expect("Should have Read argument");
        if let ArgumentValue::String(paths) = &read_arg.value {
            assert_eq!(paths, "C:\\Data;C:\\Config");
        } else {
            panic!("Expected string value for Read paths");
        }

        // Check write paths
        let write_arg = permissions[0]
            .named_arguments
            .iter()
            .find(|arg| arg.name == "Write")
            .expect("Should have Write argument");
        if let ArgumentValue::String(paths) = &write_arg.value {
            assert_eq!(paths, "C:\\Logs");
        } else {
            panic!("Expected string value for Write paths");
        }

        // Check unrestricted flag
        let unrestricted_arg = permissions[0]
            .named_arguments
            .iter()
            .find(|arg| arg.name == "Unrestricted")
            .expect("Should have Unrestricted argument");
        if let ArgumentValue::Boolean(value) = &unrestricted_arg.value {
            assert!(!value);
        } else {
            panic!("Expected boolean value for Unrestricted");
        }
    }

    #[test]
    fn test_mixed_permission_builder() {
        let permissions = PermissionSetBuilder::new()
            .add_security_permission()
            .flags("Execution, ControlEvidence")
            .build()
            .add_file_io_permission()
            .read_paths(&["C:\\Data"])
            .build()
            .permissions();

        assert_eq!(permissions.len(), 2);

        // Verify security permission
        let security_perm = &permissions[0];
        assert_eq!(
            security_perm.class_name,
            "System.Security.Permissions.SecurityPermission"
        );

        // Verify file IO permission
        let fileio_perm = &permissions[1];
        assert_eq!(
            fileio_perm.class_name,
            "System.Security.Permissions.FileIOPermission"
        );
    }

    #[test]
    fn test_builder_default_implementation() {
        let builder1 = PermissionSetBuilder::new();
        let builder2 = PermissionSetBuilder::default();

        assert_eq!(builder1.permissions().len(), builder2.permissions().len());
    }

    #[test]
    fn test_compressed_format_encoding() {
        let encoded = PermissionSetBuilder::new()
            .add_security_permission()
            .unrestricted(true)
            .build()
            .encode(PermissionSetFormat::BinaryCompressed)
            .unwrap();

        // Should have compressed format marker 0x2F
        assert_eq!(encoded[0], 0x2F);
    }

    #[test]
    fn test_xml_format_encoding() {
        let encoded = PermissionSetBuilder::new()
            .add_security_permission()
            .unrestricted(true)
            .build()
            .encode(PermissionSetFormat::Xml)
            .unwrap();

        let xml_str = String::from_utf8(encoded).unwrap();
        assert!(xml_str.contains("<PermissionSet"));
        assert!(xml_str.contains("System.Security.Permissions.SecurityPermission"));
        assert!(xml_str.contains("Unrestricted=\"true\""));
        assert!(xml_str.contains("</PermissionSet>"));
    }
}
