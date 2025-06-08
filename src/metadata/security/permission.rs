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
/// # Examples
///
/// A parsed permission might represent something like:
/// ```csharp
/// [FileIOPermission(Read = "C:\\Data", Write = "C:\\Logs")]
/// ```
///
/// # Fields
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
    /// The full type name of the permission class (e.g., "System.Security.Permissions.FileIOPermission")
    pub class_name: String,
    /// The assembly containing the permission class (typically "mscorlib" or "System")
    pub assembly_name: String,
    /// Collection of named property/field arguments that configure this permission
    pub named_arguments: Vec<NamedArgument>,
}

impl Permission {
    /// Create a new permission
    ///
    /// # Arguments
    ///
    /// * `class_name` - The full name of the permission class
    /// * `assembly_name` - The assembly containing the permission class
    /// * `named_arguments` - Collection of named property/field settings for this permission
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

    /// Check if this is a `FileIO` permission
    #[must_use]
    pub fn is_file_io(&self) -> bool {
        self.class_name == security_classes::FILE_IO_PERMISSION
    }

    /// Check if this is a Security permission
    #[must_use]
    pub fn is_security(&self) -> bool {
        self.class_name == security_classes::SECURITY_PERMISSION
    }

    /// Check if this is a Reflection permission
    #[must_use]
    pub fn is_reflection(&self) -> bool {
        self.class_name == security_classes::REFLECTION_PERMISSION
    }

    /// Check if this is a Registry permission
    #[must_use]
    pub fn is_registry(&self) -> bool {
        self.class_name == security_classes::REGISTRY_PERMISSION
    }

    /// Check if this is a UI permission
    #[must_use]
    pub fn is_ui(&self) -> bool {
        self.class_name == security_classes::UI_PERMISSION
    }

    /// Check if this is an Environment permission
    #[must_use]
    pub fn is_environment(&self) -> bool {
        self.class_name == security_classes::ENVIRONMENT_PERMISSION
    }

    /// Get a named argument by name
    #[must_use]
    pub fn get_argument(&self, name: &str) -> Option<&NamedArgument> {
        self.named_arguments.iter().find(|arg| arg.name == name)
    }

    /// Helper to get file paths granted read access
    ///
    /// Returns a list of paths specified in the Read property of a `FileIOPermission`
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

    /// Helper to get file paths granted write access
    ///
    /// Returns a list of paths specified in the Write property of a `FileIOPermission`
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

    /// Helper to get file paths granted path discovery access
    ///
    /// Returns a list of paths specified in the `PathDiscovery` property of a `FileIOPermission`
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

    /// Helper to determine if this permission grants unrestricted access
    ///
    /// Many permission classes have an "Unrestricted" property that grants full access
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        if let Some(arg) = self.get_argument("Unrestricted") {
            if let ArgumentValue::Boolean(b) = &arg.value {
                return *b;
            }
        }
        false
    }

    /// Helper to get specific flags from a security permission
    ///
    /// Security permissions use a flags enum to represent various capabilities
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

    /// Parse security permission flags from a string representation
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
            write!(f, "{}", arg)?;
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
        let formatted = format!("{}", permission);

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

        let formatted = format!("{}", permission);
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
        let debug_str = format!("{:?}", permission);

        assert!(debug_str.contains("Permission"));
        assert!(debug_str.contains(security_classes::FILE_IO_PERMISSION));
    }
}
