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
    /// Create a new named argument
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the property or field
    /// * `arg_type` - The type of the argument
    /// * `value` - The value of the argument
    #[must_use]
    pub fn new(name: String, arg_type: ArgumentType, value: ArgumentValue) -> Self {
        NamedArgument {
            name,
            arg_type,
            value,
        }
    }

    /// Get the name of this argument
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the type of this argument
    #[must_use]
    pub fn arg_type(&self) -> &ArgumentType {
        &self.arg_type
    }

    /// Get the value of this argument
    #[must_use]
    pub fn value(&self) -> &ArgumentValue {
        &self.value
    }

    /// Check if this argument is a string
    #[must_use]
    pub fn is_string(&self) -> bool {
        matches!(self.arg_type, ArgumentType::String)
    }

    /// Check if this argument is a boolean
    #[must_use]
    pub fn is_boolean(&self) -> bool {
        matches!(self.arg_type, ArgumentType::Boolean)
    }

    /// Check if this argument is an integer
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

        let formatted = format!("{}", arg);
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

        let debug_str = format!("{:?}", arg);
        assert!(debug_str.contains("NamedArgument"));
        assert!(debug_str.contains("Debug"));
    }
}
