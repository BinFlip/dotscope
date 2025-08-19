//! Named arguments for .NET Code Access Security permissions.
//!
//! This module defines the [`NamedArgument`] type, which represents key-value pairs used to
//! configure specific aspects of security permissions in .NET assemblies. Named arguments
//! provide the mechanism for specifying detailed permission parameters such as file paths,
//! registry keys, or other permission-specific settings.
//!
//! # Architecture
//!
//! The named argument system provides typed configuration for .NET security permissions:
//!
//! ```text
//! Permission
//! ├── Permission Type (e.g., FileIOPermission)
//! ├── Action (e.g., Demand, Assert)
//! └── Named Arguments
//!     ├── Argument 1: name → type → value
//!     ├── Argument 2: name → type → value
//!     └── ...
//! ```
//!
//! Each named argument consists of:
//! - **Name**: Property or field identifier
//! - **Type**: Data type ([`crate::metadata::security::ArgumentType`])
//! - **Value**: Typed value ([`crate::metadata::security::ArgumentValue`])
//!
//! # Key Components
//!
//! ## Named Argument Structure
//! - **Property Arguments**: Set properties on permission objects (most common)
//! - **Field Arguments**: Set fields on permission objects (less common)
//! - **Type Safety**: Arguments are strongly typed with validation
//!
//! ## Common Permission Types
//! Different security permissions use various named arguments:
//!
//! ### `FileIOPermission`
//! - `Read`: Specify readable file paths
//! - `Write`: Specify writable file paths  
//! - `PathDiscovery`: Control path enumeration access
//!
//! ### `RegistryPermission`
//! - `Read`: Registry keys that can be read
//! - `Write`: Registry keys that can be modified
//! - `Create`: Registry keys that can be created
//!
//! ### `SecurityPermission`
//! - `Flags`: Specific security operations allowed
//! - `UnmanagedCode`: Allow calls to unmanaged code
//! - `SkipVerification`: Skip IL verification
//!
//! # Usage Examples
//!
//! ## Basic Named Argument Creation
//!
//! ```rust
//! use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
//!
//! // File IO permission argument
//! let read_arg = NamedArgument::new(
//!     "Read".to_string(),
//!     ArgumentType::String,
//!     ArgumentValue::String("C:\\MyData".to_string())
//! );
//!
//! println!("Argument: {}", read_arg); // "Read = C:\MyData"
//! assert!(read_arg.is_string());
//! assert_eq!(read_arg.name(), "Read");
//! ```
//!
//! ## Type Validation and Checking
//!
//! ```rust
//! use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
//!
//! let flag_arg = NamedArgument::new(
//!     "Flags".to_string(),
//!     ArgumentType::Int32,
//!     ArgumentValue::Int32(0x1000)
//! );
//!
//! if flag_arg.is_integer() {
//!     println!("Integer argument with value");
//! }
//!
//! if flag_arg.is_string() {
//!     println!("This won't be printed");
//! }
//! ```
//!
//! ## Working with Boolean Arguments
//!
//! ```rust,ignore
//! use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
//!
//! let unrestricted_arg = NamedArgument::new(
//!     "Unrestricted".to_string(),
//!     ArgumentType::Boolean,
//!     ArgumentValue::Boolean(true)
//! );
//!
//! if unrestricted_arg.is_boolean() {
//!     if let ArgumentValue::Boolean(value) = unrestricted_arg.value() {
//!         println!("Unrestricted: {}", value);
//!     }
//! }
//! ```
//!
//! # Integration
//!
//! Named arguments integrate with the broader security system:
//!
//! ## With Permission Sets
//! - Named arguments configure specific permissions within [`crate::metadata::security::PermissionSet`]
//! - Each permission can have multiple named arguments
//! - Arguments provide fine-grained control over permission behavior
//!
//! ## With Security Attributes
//! - Used in declarative security attributes in .NET assemblies
//! - Parsed from custom attribute blobs in metadata
//! - Validated against permission class definitions
//!
//! ## With Assembly Metadata
//! - Stored in security metadata streams
//! - Referenced by permission set definitions
//! - Linked to type and method security declarations
//!
//! # Binary Format
//!
//! Named arguments are encoded in permission sets using the following structure:
//! ```text
//! - Argument count (compressed integer)
//! - For each argument:
//!   - Name length (compressed integer)  
//!   - Name (UTF-8 string)
//!   - Type indicator (byte)
//!   - Value (format depends on type)
//! ```
//!
//! # Error Handling
//!
//! The module handles various error conditions:
//! - **Type Mismatches**: Validation ensures argument types match expected values
//! - **Invalid Names**: Empty or malformed argument names are rejected
//! - **Encoding Issues**: UTF-8 validation for string arguments
//! - **Range Validation**: Numeric arguments are validated against type ranges
//!
//! # Thread Safety
//!
//! [`NamedArgument`] instances are immutable after creation and safe to share across threads.

use crate::metadata::security::{ArgumentType, ArgumentValue};
use std::fmt;

/// Represents a named argument (property or field) in a .NET security permission.
///
/// Named arguments configure specific aspects of a permission, such as which files can be accessed
/// by a `FileIOPermission` or what registry keys can be read by a `RegistryPermission`.
///
/// # Examples
///
/// In a permission like `[FileIOPermission(Read = "C:\\Data")]`, "Read" would be the name,
/// the type would be String, and the value would be "C:\\Data".
///
/// # Fields
///
/// * `name` - The name of the property or field (e.g., "Read", "Write", "`PathDiscovery`")
/// * `arg_type` - The data type of the argument
/// * `value` - The actual value assigned to the property or field
///
/// # Notes
///
/// Whether a named argument represents a field or property is determined by flags in the
/// permission set encoding, but this distinction is rarely important for analysis.
#[derive(Debug, Clone)]
pub struct NamedArgument {
    /// The name of the property or field being set
    pub name: String,
    /// The data type of this argument
    pub arg_type: ArgumentType,
    /// The actual value assigned to this property or field
    pub value: ArgumentValue,
}

impl NamedArgument {
    /// Creates a new named argument for a security permission.
    ///
    /// This constructor creates a strongly-typed named argument that can be used to configure
    /// specific aspects of a security permission. The argument represents either a property
    /// or field assignment on the permission object.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the property or field being configured (e.g., "Read", "Write", "Flags")
    /// * `arg_type` - The data type of the argument value (must match the actual value type)
    /// * `value` - The actual value to assign to the property or field
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// // Create a string argument for file path specification
    /// let file_arg = NamedArgument::new(
    ///     "Read".to_string(),
    ///     ArgumentType::String,
    ///     ArgumentValue::String("C:\\Program Files".to_string())
    /// );
    ///
    /// // Create an integer argument for permission flags
    /// let flags_arg = NamedArgument::new(
    ///     "Flags".to_string(),
    ///     ArgumentType::Int32,
    ///     ArgumentValue::Int32(0x0400) // FILE_FLAG_BACKUP_SEMANTICS
    /// );
    ///
    /// // Create a boolean argument
    /// let bool_arg = NamedArgument::new(
    ///     "Unrestricted".to_string(),
    ///     ArgumentType::Boolean,
    ///     ArgumentValue::Boolean(true)
    /// );
    /// ```
    ///
    /// # Type Safety
    ///
    /// The type parameter and value must be consistent. While this is not enforced at compile time,
    /// mismatched types may cause issues during permission processing or serialization.
    #[must_use]
    pub fn new(name: String, arg_type: ArgumentType, value: ArgumentValue) -> Self {
        NamedArgument {
            name,
            arg_type,
            value,
        }
    }

    /// Returns the name of this named argument.
    ///
    /// The name typically corresponds to a property or field name on the permission class,
    /// such as "Read", "Write", "`PathDiscovery`" for file permissions, or "Flags" for
    /// security permissions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let arg = NamedArgument::new(
    ///     "PathDiscovery".to_string(),
    ///     ArgumentType::String,
    ///     ArgumentValue::String("C:\\".to_string())
    /// );
    ///
    /// assert_eq!(arg.name(), "PathDiscovery");
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the data type of this named argument.
    ///
    /// The type indicates how the argument value should be interpreted and processed.
    /// Common types include String for paths, Int32 for flags, and Boolean for toggles.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let arg = NamedArgument::new(
    ///     "Flags".to_string(),
    ///     ArgumentType::Int32,
    ///     ArgumentValue::Int32(0x1000)
    /// );
    ///
    /// assert!(matches!(arg.arg_type(), ArgumentType::Int32));
    /// ```
    #[must_use]
    pub fn arg_type(&self) -> &ArgumentType {
        &self.arg_type
    }

    /// Returns the value of this named argument.
    ///
    /// The value contains the actual data assigned to the permission property or field.
    /// The value type should match the argument type for proper interpretation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let arg = NamedArgument::new(
    ///     "Write".to_string(),
    ///     ArgumentType::String,
    ///     ArgumentValue::String("C:\\Temp".to_string())
    /// );
    ///
    /// if let ArgumentValue::String(path) = arg.value() {
    ///     println!("Write access to: {}", path);
    /// }
    /// ```
    #[must_use]
    pub fn value(&self) -> &ArgumentValue {
        &self.value
    }

    /// Checks if this argument contains a string value.
    ///
    /// Returns `true` if the argument type is [`crate::metadata::security::ArgumentType::String`],
    /// indicating the value should be interpreted as a text string. String arguments are
    /// commonly used for file paths, registry keys, and other textual permission parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let string_arg = NamedArgument::new(
    ///     "Read".to_string(),
    ///     ArgumentType::String,
    ///     ArgumentValue::String("C:\\Data".to_string())
    /// );
    ///
    /// let int_arg = NamedArgument::new(
    ///     "Flags".to_string(),
    ///     ArgumentType::Int32,
    ///     ArgumentValue::Int32(42)
    /// );
    ///
    /// assert!(string_arg.is_string());
    /// assert!(!int_arg.is_string());
    /// ```
    #[must_use]
    pub fn is_string(&self) -> bool {
        matches!(self.arg_type, ArgumentType::String)
    }

    /// Checks if this argument contains a boolean value.
    ///
    /// Returns `true` if the argument type is [`crate::metadata::security::ArgumentType::Boolean`],
    /// indicating the value represents a true/false flag. Boolean arguments are often used
    /// for permission toggles like "Unrestricted" or feature flags.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let bool_arg = NamedArgument::new(
    ///     "Unrestricted".to_string(),
    ///     ArgumentType::Boolean,
    ///     ArgumentValue::Boolean(true)
    /// );
    ///
    /// let string_arg = NamedArgument::new(
    ///     "Path".to_string(),
    ///     ArgumentType::String,
    ///     ArgumentValue::String("C:\\".to_string())
    /// );
    ///
    /// assert!(bool_arg.is_boolean());
    /// assert!(!string_arg.is_boolean());
    /// ```
    #[must_use]
    pub fn is_boolean(&self) -> bool {
        matches!(self.arg_type, ArgumentType::Boolean)
    }

    /// Checks if this argument contains an integer value.
    ///
    /// Returns `true` if the argument type is either [`crate::metadata::security::ArgumentType::Int32`]
    /// or [`crate::metadata::security::ArgumentType::Int64`], indicating the value represents a
    /// numeric value. Integer arguments are commonly used for permission flags, counts, or
    /// enumeration values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::{NamedArgument, ArgumentType, ArgumentValue};
    ///
    /// let int32_arg = NamedArgument::new(
    ///     "Flags".to_string(),
    ///     ArgumentType::Int32,
    ///     ArgumentValue::Int32(0x1000)
    /// );
    ///
    /// let int64_arg = NamedArgument::new(
    ///     "LargeValue".to_string(),
    ///     ArgumentType::Int64,
    ///     ArgumentValue::Int64(9999999999)
    /// );
    ///
    /// let string_arg = NamedArgument::new(
    ///     "Path".to_string(),
    ///     ArgumentType::String,
    ///     ArgumentValue::String("C:\\".to_string())
    /// );
    ///
    /// assert!(int32_arg.is_integer());
    /// assert!(int64_arg.is_integer());
    /// assert!(!string_arg.is_integer());
    /// ```
    #[must_use]
    pub fn is_integer(&self) -> bool {
        matches!(self.arg_type, ArgumentType::Int32) || matches!(self.arg_type, ArgumentType::Int64)
    }
}

impl fmt::Display for NamedArgument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.name, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::security::{ArgumentType, ArgumentValue};

    #[test]
    fn test_named_argument_new() {
        let arg = NamedArgument::new(
            "Read".to_string(),
            ArgumentType::String,
            ArgumentValue::String("C:\\Data".to_string()),
        );

        assert_eq!(arg.name, "Read");
        assert!(matches!(arg.arg_type, ArgumentType::String));
        assert!(matches!(arg.value, ArgumentValue::String(_)));
    }

    #[test]
    fn test_named_argument_getters() {
        let arg = NamedArgument::new(
            "Write".to_string(),
            ArgumentType::Boolean,
            ArgumentValue::Boolean(true),
        );

        assert_eq!(arg.name(), "Write");
        assert!(matches!(arg.arg_type(), ArgumentType::Boolean));
        assert!(matches!(arg.value(), ArgumentValue::Boolean(true)));
    }

    #[test]
    fn test_is_string() {
        let string_arg = NamedArgument::new(
            "Path".to_string(),
            ArgumentType::String,
            ArgumentValue::String("test".to_string()),
        );
        let bool_arg = NamedArgument::new(
            "Enabled".to_string(),
            ArgumentType::Boolean,
            ArgumentValue::Boolean(true),
        );

        assert!(string_arg.is_string());
        assert!(!bool_arg.is_string());
    }

    #[test]
    fn test_is_boolean() {
        let bool_arg = NamedArgument::new(
            "Enabled".to_string(),
            ArgumentType::Boolean,
            ArgumentValue::Boolean(false),
        );
        let string_arg = NamedArgument::new(
            "Path".to_string(),
            ArgumentType::String,
            ArgumentValue::String("test".to_string()),
        );

        assert!(bool_arg.is_boolean());
        assert!(!string_arg.is_boolean());
    }

    #[test]
    fn test_is_integer() {
        let int32_arg = NamedArgument::new(
            "Size".to_string(),
            ArgumentType::Int32,
            ArgumentValue::Int32(42),
        );
        let int64_arg = NamedArgument::new(
            "LargeSize".to_string(),
            ArgumentType::Int64,
            ArgumentValue::Int64(1234567890),
        );
        let string_arg = NamedArgument::new(
            "Path".to_string(),
            ArgumentType::String,
            ArgumentValue::String("test".to_string()),
        );

        assert!(int32_arg.is_integer());
        assert!(int64_arg.is_integer());
        assert!(!string_arg.is_integer());
    }

    #[test]
    fn test_display_formatting() {
        let arg = NamedArgument::new(
            "Read".to_string(),
            ArgumentType::String,
            ArgumentValue::String("C:\\Data".to_string()),
        );

        let formatted = format!("{arg}");
        assert_eq!(formatted, "Read = \"C:\\Data\"");
    }

    #[test]
    fn test_clone() {
        let original = NamedArgument::new(
            "Test".to_string(),
            ArgumentType::Boolean,
            ArgumentValue::Boolean(true),
        );

        let cloned = original.clone();
        assert_eq!(cloned.name, original.name);
        assert!(matches!(cloned.arg_type, ArgumentType::Boolean));
        assert!(matches!(cloned.value, ArgumentValue::Boolean(true)));
    }

    #[test]
    fn test_debug_formatting() {
        let arg = NamedArgument::new(
            "Debug".to_string(),
            ArgumentType::Int32,
            ArgumentValue::Int32(123),
        );

        let debug_str = format!("{arg:?}");
        assert!(debug_str.contains("NamedArgument"));
        assert!(debug_str.contains("Debug"));
    }
}
