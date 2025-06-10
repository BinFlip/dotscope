use crate::{
    file::parser::Parser,
    metadata::security::{
        security_classes, ArgumentType, ArgumentValue, NamedArgument, Permission,
        PermissionSetFormat, SecurityPermissionFlags,
    },
    Error::OutOfBounds,
    Result,
};
use std::fmt;

/// `DeclSecurity` entries represent declarative security attributes that define the security requirements,
/// demands, and permissions for assemblies, types, and methods. They essentially declare what security
/// permissions the code requires, demands from callers, or promises not to use.
///
/// # Overview of .NET Security System
///
/// .NET's security system includes several key components:
///
/// 1. **Code Access Security (CAS)**: A mechanism that helps limit the access that code has to
///    protected resources and operations. CAS was the primary security mechanism in older .NET versions.
///
/// 2. **Permissions**: Classes that represent access to specific resources or operations.
///    Each permission class controls access to a different resource.
///
/// 3. **Permission Sets**: Collections of permissions that represent a security context.
///
/// 4. **Security Actions**: Define how permissions are enforced, such as demanding that callers
///    have a permission, denying access to certain resources, etc.
///
/// 5. **Security Declarations**: Attributes that apply permissions with specific actions to code elements.
///    These correspond to entries in the `DeclSecurity` metadata table.
///
/// # .NET Framework Security Evolution
///
/// - **.NET 1.0-3.5**: Extensive use of CAS with complex permission hierarchies
/// - **.NET 4.0**: Introduction of the "security transparency" model that simplified CAS
/// - **.NET Core/5+**: Significant reduction in use of CAS; many permissions became no-ops
///
/// # Common .NET Permission Classes
///
/// - **`FileIOPermission`**: Controls reading, writing, and appending to files and directories
/// - **`SecurityPermission`**: Controls security-sensitive operations like calling unmanaged code
/// - **`ReflectionPermission`**: Controls the ability to use reflection
/// - **`RegistryPermission`**: Controls reading and writing to registry keys
/// - **`UIPermission`**: Controls UI operations and clipboard access
///
/// # Note on Modern .NET
///
/// While newer .NET platforms have moved away from CAS, understanding these permission structures
/// remains important for reverse engineering legacy .NET Framework applications and understanding
/// their security characteristics.
#[derive(Debug, Clone)]
pub struct PermissionSet {
    /// The format of this permission set
    format: PermissionSetFormat,
    /// The parsed permissions in this set
    permissions: Vec<Permission>,
    /// The original raw data of this permission set
    data: Vec<u8>,
}

impl PermissionSet {
    /// Creates a new `PermissionSet` from binary data.
    ///
    /// # Arguments
    /// * `data` - The data slice to parse
    ///
    /// # Errors
    /// Returns an error if the data is empty or malformed.
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(malformed_error!("PermissionSet data is empty"));
        }

        // Determine format from first byte
        let (format, permissions) = match data[0] {
            /* '.' - Binary format marker */
            0x2E => Self::parse_binary_format(data)?,
            /* '<' - XML format marker */
            0x3C => Self::parse_xml_format(data)?,
            /* Other byte values might be compressed binary format */
            _ => (PermissionSetFormat::Unknown, Vec::new()),
        };

        Ok(PermissionSet {
            format,
            permissions,
            data: data.to_vec(),
        })
    }

    /// Parse a binary legacy format permission set
    ///
    /// This format follows the `CoreCLR` implementation and starts with a '.' character.
    /// The binary format is structured as:
    /// - '.' marker byte
    /// - Number of permissions (compressed integer)
    /// - For each permission:
    ///     - Class name length (compressed integer)
    ///     - Class name (UTF-8 bytes)
    ///     - Blob length (compressed integer)
    ///     - Number of properties (compressed integer)
    ///     - For each property:
    ///         - Property name (prefixed string)
    ///         - Property type (byte)
    ///         - Property value (format depends on type)
    ///
    /// ## Arguments
    /// * 'data' - The data slice to parse
    fn parse_binary_format(data: &[u8]) -> Result<(PermissionSetFormat, Vec<Permission>)> {
        let mut parser = Parser::new(data);

        // Binary format starts with '.' (0x2E) - skip the format marker
        parser.advance()?;

        let permission_count = parser.read_compressed_uint()? as usize;
        let mut permissions = Vec::with_capacity(permission_count);
        for _ in 0..permission_count {
            let class_name_length = parser.read_compressed_uint()? as usize;
            let class_name = if class_name_length > 0 {
                let start = parser.pos();
                let Some(end) = usize::checked_add(start, class_name_length) else {
                    return Err(OutOfBounds);
                };

                if end >= data.len() {
                    return Err(OutOfBounds);
                }

                parser.advance_by(class_name_length)?;

                let name_bytes = &data[start..end];
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                String::new()
            };

            let assembly_name = if class_name.starts_with("System.Security.Permissions.")
                || class_name.starts_with("System.Security.")
                || class_name.starts_with("System.Net.")
            {
                "mscorlib".to_string() // For .NET Framework
                                       // "System.Private.CoreLib".to_string() // For newer .NET
            } else if class_name.starts_with("System.Data.") {
                "System.Data".to_string()
            } else if class_name.starts_with("System.Xml.") {
                "System.Xml".to_string()
            } else {
                "Unknown".to_string()
            };

            let blob_length = parser.read_compressed_uint()? as usize;
            let mut named_arguments = Vec::new();
            if blob_length > 0 {
                let Some(blob_end) = blob_length.checked_add(parser.pos()) else {
                    return Err(malformed_error!(
                        "Blob end overflow - {} + {}",
                        blob_length,
                        parser.pos()
                    ));
                };

                if blob_end > data.len() {
                    return Err(malformed_error!(
                        "Blob end position {} exceeds data length {}",
                        blob_end,
                        data.len()
                    ));
                }

                let property_count = parser.read_compressed_uint()? as usize;
                for _ in 0..property_count {
                    // Read the field/property marker
                    let _ = parser.read_le::<u8>()?;

                    let prop_type = parser.read_le::<u8>()?;
                    let name_length = parser.read_compressed_uint()? as usize;

                    let prop_name = if name_length > 0 {
                        let start = parser.pos();
                        parser.advance_by(name_length)?;

                        let name_bytes = &data[start..start + name_length];
                        String::from_utf8_lossy(name_bytes).to_string()
                    } else {
                        String::new()
                    };

                    let (arg_type, value) = Self::parse_argument_value(&mut parser, prop_type)?;

                    named_arguments.push(NamedArgument {
                        name: prop_name,
                        arg_type,
                        value,
                    });
                }

                if parser.pos() < blob_end {
                    parser.seek(blob_end)?;
                }
            }

            permissions.push(Permission {
                class_name,
                assembly_name,
                named_arguments,
            });
        }

        Ok((PermissionSetFormat::BinaryLegacy, permissions))
    }

    /// Parse an XML format permission set
    ///
    /// XML format starts with '<' (0x3C) and contains an XML document
    /// representing the permission set. This method performs basic detection
    /// but doesn't fully parse the XML - that would be handled by an XML parser.
    ///
    /// ## Arguments
    /// * 'data' - The data slice to parse
    fn parse_xml_format(data: &[u8]) -> Result<(PermissionSetFormat, Vec<Permission>)> {
        // XML format starts with '<' (0x3C)
        // ToDo: Use XML crate do to full parsing

        if data.len() < 5 {
            return Err(malformed_error!("XML data too short"));
        }

        // Very basic validation that it looks like XML
        let xml_start = b"<Perm";
        if &data[0..5] != xml_start {
            return Err(malformed_error!("Invalid XML permission set format"));
        }

        Ok((PermissionSetFormat::Xml, Vec::new()))
    }

    /// Parse an argument value from the parser based on its type
    ///
    /// ## Arguments
    /// * `parser` - The parser to read from
    /// * `arg_type` - The type code of the argument
    fn parse_argument_value(
        parser: &mut Parser,
        arg_type: u8,
    ) -> Result<(ArgumentType, ArgumentValue)> {
        match arg_type {
            // Boolean
            0x02 => {
                let value = parser.read_le::<u8>()? != 0;
                Ok((ArgumentType::Boolean, ArgumentValue::Boolean(value)))
            }
            // Int32
            0x04 => {
                let value = parser.read_compressed_int()?;
                Ok((ArgumentType::Int32, ArgumentValue::Int32(value)))
            }
            // String
            0x0E => {
                let value = parser.read_prefixed_string_utf8()?;
                Ok((ArgumentType::String, ArgumentValue::String(value)))
            }
            _ => Err(malformed_error!("Unknown argument type: {}", arg_type)),
        }
    }

    /// Get the format of this permission set
    #[must_use]
    pub fn format(&self) -> &PermissionSetFormat {
        &self.format
    }

    /// Get all permissions in this set
    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// Get the raw data of this permission set
    #[must_use]
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Check if this permission set contains a specific permission class
    ///
    /// ## Arguments
    /// * `class_name` - The full name of the permission class to check for
    #[must_use]
    pub fn contains_permission(&self, class_name: &str) -> bool {
        self.permissions.iter().any(|p| p.class_name == class_name)
    }

    /// Get a specific permission by class name
    ///
    /// ## Arguments
    /// * `class_name` - The full name of the permission class to retrieve
    #[must_use]
    pub fn get_permission(&self, class_name: &str) -> Option<&Permission> {
        self.permissions.iter().find(|p| p.class_name == class_name)
    }

    /// Check if this permission set grants unrestricted access
    ///
    /// An unrestricted permission set typically has a `SecurityPermission` with Unrestricted=true
    /// or multiple permissions with Unrestricted=true
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.permissions
            .iter()
            .any(super::permission::Permission::is_unrestricted)
    }

    /// Check if this permission set contains file IO permissions
    #[must_use]
    pub fn has_file_io(&self) -> bool {
        self.contains_permission(security_classes::FILE_IO_PERMISSION)
    }

    /// Check if this permission set contains registry permissions
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.contains_permission(security_classes::REGISTRY_PERMISSION)
    }

    /// Check if this permission set contains reflection permissions
    #[must_use]
    pub fn has_reflection(&self) -> bool {
        self.contains_permission(security_classes::REFLECTION_PERMISSION)
    }

    /// Check if this permission set contains environment permissions
    #[must_use]
    pub fn has_environment(&self) -> bool {
        self.contains_permission(security_classes::ENVIRONMENT_PERMISSION)
    }

    /// Check if this permission set grants full trust
    ///
    /// Full trust is typically indicated by an unrestricted `SecurityPermission`
    /// or by having the SecurityPermission.AllFlags flag set.
    #[must_use]
    pub fn is_full_trust(&self) -> bool {
        if let Some(permission) = self.get_permission(security_classes::SECURITY_PERMISSION) {
            // Check for Unrestricted first
            if permission.is_unrestricted() {
                return true;
            }

            // Check SecurityPermissionFlag values
            if let Some(flags) = permission.get_security_flags() {
                // Check if all flags are set or if critical flags indicate full trust
                if flags.is_all() {
                    return true;
                }

                // Check for combinations that effectively grant full trust
                if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_SKIP_VERIFICATION)
                    && flags.contains(SecurityPermissionFlags::SECURITY_FLAG_CONTROL_POLICY)
                    && flags.contains(SecurityPermissionFlags::SECURITY_FLAG_CONTROL_EVIDENCE)
                {
                    return true;
                }
            }
        }

        // Also check if multiple unrestricted permissions indicate full trust
        let critical_permissions_count = [
            security_classes::SECURITY_PERMISSION,
            security_classes::FILE_IO_PERMISSION,
            security_classes::REFLECTION_PERMISSION,
            security_classes::REGISTRY_PERMISSION,
        ]
        .iter()
        .filter(|class| {
            if let Some(perm) = self.get_permission(class) {
                perm.is_unrestricted()
            } else {
                false
            }
        })
        .count();

        // If 3 or more critical permissions are unrestricted, consider it full trust
        critical_permissions_count >= 3
    }

    /// Get all file paths that this permission set grants read access to
    #[must_use]
    pub fn get_all_file_read_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();

        if let Some(permission) = self.get_permission(security_classes::FILE_IO_PERMISSION) {
            if let Some(read_paths) = permission.get_file_read_paths() {
                paths.extend(read_paths);
            }
        }

        paths
    }

    /// Get all file paths that this permission set grants write access to
    #[must_use]
    pub fn get_all_file_write_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();

        if let Some(permission) = self.get_permission(security_classes::FILE_IO_PERMISSION) {
            if let Some(write_paths) = permission.get_file_write_paths() {
                paths.extend(write_paths);
            }
        }

        paths
    }
}

impl fmt::Display for PermissionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.format == PermissionSetFormat::Xml {
            write!(f, "{}", String::from_utf8_lossy(&self.data))
        } else {
            writeln!(f, "Permission Set ({:?}):", self.format)?;

            for permission in &self.permissions {
                writeln!(
                    f,
                    "\t - {}, Assembly: {}",
                    permission.class_name, permission.assembly_name
                )?;

                for arg in &permission.named_arguments {
                    writeln!(f, "\t  * {} = {}", arg.name, arg.value)?;
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::security::{ArgumentType, ArgumentValue, NamedArgument, Permission};

    #[test]
    fn test_xml_format_detection() {
        let xml = b"<PermissionSet class=\"System.Security.PermissionSet\">\
                    <IPermission class=\"System.Security.Permissions.SecurityPermission\"/>\
                    </PermissionSet>";

        let permission_set = PermissionSet::new(xml).unwrap();
        assert!(matches!(permission_set.format, PermissionSetFormat::Xml));
    }

    #[test]
    fn test_binary_format() {
        /*
            .\x01                                   - Start marker (.) and permission count (1)
            \x80\x8a                                - Class name length (138 as compressed int)
            System.Security.Permissions.SecurityPermissionAttribute, System.Runtime, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a  - Class name
            \x15                                    - Blob length (21 bytes)
            \x01                                    - Property count (1)
            T                                       - Unknown byte (0x54) - possibly a field/property marker
            \x02                                    - Probably the property type (0x02 = Int32)
            \x10                                    - Property name length (16)
            SkipVerification                        - Property name
            \x01                                    - Property value (1)
        */

        let binary = include_bytes!("../../../tests/samples/WB_DeclSecurity_1.bin");
        let permission_set = PermissionSet::new(binary).unwrap();

        assert!(matches!(
            permission_set.format,
            PermissionSetFormat::BinaryLegacy
        ));
        assert_eq!(permission_set.permissions.len(), 1);
        assert_eq!(
            permission_set.permissions[0].class_name,
            "System.Security.Permissions.SecurityPermissionAttribute, System.Runtime, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
        );
        assert_eq!(permission_set.permissions[0].named_arguments.len(), 1);
        assert_eq!(
            permission_set.permissions[0].named_arguments[0].name,
            "SkipVerification"
        );
        match &permission_set.permissions[0].named_arguments[0].value {
            ArgumentValue::Boolean(value) => assert!(*value),
            _ => panic!("Expected Boolean value"),
        }
    }

    #[test]
    fn test_empty_data() {
        let result = PermissionSet::new(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_format() {
        let unknown = b"\xFF\x00\x01\x02";

        let permission_set = PermissionSet::new(unknown).unwrap();
        assert!(matches!(
            permission_set.format,
            PermissionSetFormat::Unknown
        ));
    }

    #[test]
    fn test_binary_format_empty_permission_set() {
        // Binary format with 0 permissions: '.' (0x2E) + 0 (permission count)
        let data = b".\x00";
        let permission_set = PermissionSet::new(data).unwrap();
        assert!(matches!(
            permission_set.format,
            PermissionSetFormat::BinaryLegacy
        ));
        assert_eq!(permission_set.permissions.len(), 0);
    }

    #[test]
    fn test_binary_format_zero_length_class_name() {
        // Binary format with permission with zero-length class name
        let data = b".\x01\x00\x00"; // '.' + 1 permission + 0 class name length + 0 blob length
        let permission_set = PermissionSet::new(data).unwrap();
        assert_eq!(permission_set.permissions.len(), 1);
        assert_eq!(permission_set.permissions[0].class_name, "");
        assert_eq!(permission_set.permissions[0].assembly_name, "Unknown");
    }

    #[test]
    fn test_binary_format_multiple_permissions() {
        // Create binary format with 2 permissions
        let mut data = vec![b'.', 0x02]; // '.' + 2 permissions

        // First permission: System.Security.Permissions.SecurityPermission
        let class_name1 = b"System.Security.Permissions.SecurityPermission";
        data.push(class_name1.len() as u8); // class name length
        data.extend_from_slice(class_name1); // class name
        data.push(0x00); // blob length (0)

        // Second permission: System.Security.Permissions.FileIOPermission
        let class_name2 = b"System.Security.Permissions.FileIOPermission";
        data.push(class_name2.len() as u8); // class name length
        data.extend_from_slice(class_name2); // class name
        data.push(0x00); // blob length (0)

        let permission_set = PermissionSet::new(&data).unwrap();
        assert_eq!(permission_set.permissions.len(), 2);
        assert_eq!(
            permission_set.permissions[0].class_name,
            "System.Security.Permissions.SecurityPermission"
        );
        assert_eq!(permission_set.permissions[0].assembly_name, "mscorlib");
        assert_eq!(
            permission_set.permissions[1].class_name,
            "System.Security.Permissions.FileIOPermission"
        );
        assert_eq!(permission_set.permissions[1].assembly_name, "mscorlib");
    }

    #[test]
    fn test_binary_format_different_assembly_names() {
        let mut data = vec![b'.', 0x03]; // '.' + 3 permissions

        // System.Data permission
        let class_name1 = b"System.Data.SqlClient.SqlPermission";
        data.push(class_name1.len() as u8);
        data.extend_from_slice(class_name1);
        data.push(0x00);

        // System.Xml permission
        let class_name2 = b"System.Xml.XmlPermission";
        data.push(class_name2.len() as u8);
        data.extend_from_slice(class_name2);
        data.push(0x00);

        // System.Net permission
        let class_name3 = b"System.Net.NetworkInformation.NetworkInformationPermission";
        data.push(class_name3.len() as u8);
        data.extend_from_slice(class_name3);
        data.push(0x00);

        let permission_set = PermissionSet::new(&data).unwrap();
        assert_eq!(permission_set.permissions.len(), 3);
        assert_eq!(permission_set.permissions[0].assembly_name, "System.Data");
        assert_eq!(permission_set.permissions[1].assembly_name, "System.Xml");
        assert_eq!(permission_set.permissions[2].assembly_name, "mscorlib");
    }

    #[test]
    fn test_binary_format_with_properties() {
        // Create binary format with one permission that has properties
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"System.Security.Permissions.SecurityPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);

        // Blob with properties
        let blob_start = data.len() + 1; // Position after blob length byte
        data.push(0x00); // Placeholder for blob length

        data.push(0x02); // 2 properties

        // Property 1: Boolean
        data.push(0x54); // Field marker
        data.push(0x02); // Boolean type
        let prop_name1 = b"Unrestricted";
        data.push(prop_name1.len() as u8);
        data.extend_from_slice(prop_name1);
        data.push(0x01); // true

        // Property 2: Int32
        data.push(0x54); // Field marker
        data.push(0x04); // Int32 type
        let prop_name2 = b"Flags";
        data.push(prop_name2.len() as u8);
        data.extend_from_slice(prop_name2);
        data.push(0x0E); // Value 7 encoded as compressed signed int (7 * 2 = 14 = 0x0E)

        // Set the actual blob length
        let blob_length = data.len() - blob_start;
        data[blob_start - 1] = blob_length as u8;

        let permission_set = PermissionSet::new(&data).unwrap();
        assert_eq!(permission_set.permissions.len(), 1);
        assert_eq!(permission_set.permissions[0].named_arguments.len(), 2);

        assert_eq!(
            permission_set.permissions[0].named_arguments[0].name,
            "Unrestricted"
        );
        assert!(matches!(
            permission_set.permissions[0].named_arguments[0].value,
            ArgumentValue::Boolean(true)
        ));

        assert_eq!(
            permission_set.permissions[0].named_arguments[1].name,
            "Flags"
        );
        assert!(matches!(
            permission_set.permissions[0].named_arguments[1].value,
            ArgumentValue::Int32(7)
        ));
    }

    #[test]
    fn test_binary_format_string_property() {
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"System.Security.Permissions.FileIOPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);

        // Blob with string property
        let blob_start = data.len() + 1;
        data.push(0x00); // Placeholder for blob length

        data.push(0x01); // 1 property
        data.push(0x54); // Field marker
        data.push(0x0E); // String type
        let prop_name = b"Read";
        data.push(prop_name.len() as u8);
        data.extend_from_slice(prop_name);

        // String value with length prefix
        let string_value = b"C:\\temp";
        data.push(string_value.len() as u8);
        data.extend_from_slice(string_value);

        // Set blob length
        let blob_length = data.len() - blob_start;
        data[blob_start - 1] = blob_length as u8;

        let permission_set = PermissionSet::new(&data).unwrap();
        assert_eq!(permission_set.permissions[0].named_arguments.len(), 1);
        assert_eq!(
            permission_set.permissions[0].named_arguments[0].name,
            "Read"
        );
        assert!(
            matches!(permission_set.permissions[0].named_arguments[0].value, ArgumentValue::String(ref s) if s == "C:\\temp")
        );
    }

    #[test]
    fn test_binary_format_unknown_argument_type() {
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"TestPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);

        let blob_start = data.len() + 1;
        data.push(0x00); // Placeholder for blob length

        data.push(0x01); // 1 property
        data.push(0x54); // Field marker
        data.push(0xFF); // Unknown type
        data.push(0x04); // Property name length
        data.extend_from_slice(b"Test");

        let blob_length = data.len() - blob_start;
        data[blob_start - 1] = blob_length as u8;

        let result = PermissionSet::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_format_out_of_bounds_class_name() {
        // Binary format with class name length that exceeds data
        let data = b".\x01\xFF"; // '.' + 1 permission + large class name length (255)
        let result = PermissionSet::new(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_xml_format_too_short() {
        let data = b"<Pe"; // Too short for proper XML
        let result = PermissionSet::new(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_xml_format_invalid_start() {
        let data = b"<Test"; // Doesn't start with <Perm
        let result = PermissionSet::new(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_permission_set_methods() {
        // Create a permission set with multiple permissions for testing
        let permissions = vec![
            // SecurityPermission with Unrestricted=true
            Permission {
                class_name: security_classes::SECURITY_PERMISSION.to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                }],
            },
            // FileIOPermission
            Permission {
                class_name: security_classes::FILE_IO_PERMISSION.to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Read".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\temp".to_string()),
                }],
            },
        ];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![1, 2, 3],
        };

        // Test basic getters
        assert!(matches!(
            permission_set.format(),
            PermissionSetFormat::BinaryLegacy
        ));
        assert_eq!(permission_set.permissions().len(), 2);
        assert_eq!(permission_set.raw_data(), &[1, 2, 3]);

        // Test contains_permission
        assert!(permission_set.contains_permission(security_classes::SECURITY_PERMISSION));
        assert!(permission_set.contains_permission(security_classes::FILE_IO_PERMISSION));
        assert!(!permission_set.contains_permission(security_classes::REGISTRY_PERMISSION));

        // Test get_permission
        assert!(permission_set
            .get_permission(security_classes::SECURITY_PERMISSION)
            .is_some());
        assert!(permission_set
            .get_permission(security_classes::REGISTRY_PERMISSION)
            .is_none());

        // Test permission type checks
        assert!(permission_set.is_unrestricted());
        assert!(permission_set.has_file_io());
        assert!(!permission_set.has_registry());
        assert!(!permission_set.has_reflection());
        assert!(!permission_set.has_environment());
    }

    #[test]
    fn test_is_full_trust_unrestricted_security_permission() {
        let permissions = vec![Permission {
            class_name: security_classes::SECURITY_PERMISSION.to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Unrestricted".to_string(),
                arg_type: ArgumentType::Boolean,
                value: ArgumentValue::Boolean(true),
            }],
        }];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        assert!(permission_set.is_full_trust());
    }

    #[test]
    fn test_is_full_trust_all_flags() {
        let permissions = vec![Permission {
            class_name: security_classes::SECURITY_PERMISSION.to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Flags".to_string(),
                arg_type: ArgumentType::String,
                value: ArgumentValue::String("AllFlags".to_string()),
            }],
        }];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        assert!(permission_set.is_full_trust());
    }

    #[test]
    fn test_is_full_trust_critical_flags_combination() {
        let permissions = vec![Permission {
            class_name: security_classes::SECURITY_PERMISSION.to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Flags".to_string(),
                arg_type: ArgumentType::String,
                value: ArgumentValue::String(
                    "SkipVerification, ControlPolicy, ControlEvidence".to_string(),
                ),
            }],
        }];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        assert!(permission_set.is_full_trust());
    }

    #[test]
    fn test_is_full_trust_multiple_unrestricted_permissions() {
        let permissions = vec![
            Permission {
                class_name: security_classes::SECURITY_PERMISSION.to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                }],
            },
            Permission {
                class_name: security_classes::FILE_IO_PERMISSION.to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                }],
            },
            Permission {
                class_name: security_classes::REFLECTION_PERMISSION.to_string(),
                assembly_name: "mscorlib".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "Unrestricted".to_string(),
                    arg_type: ArgumentType::Boolean,
                    value: ArgumentValue::Boolean(true),
                }],
            },
        ];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        assert!(permission_set.is_full_trust());
    }

    #[test]
    fn test_is_not_full_trust() {
        let permissions = vec![Permission {
            class_name: security_classes::FILE_IO_PERMISSION.to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![NamedArgument {
                name: "Read".to_string(),
                arg_type: ArgumentType::String,
                value: ArgumentValue::String("C:\\temp".to_string()),
            }],
        }];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        assert!(!permission_set.is_full_trust());
    }

    #[test]
    fn test_get_file_paths() {
        let permissions = vec![Permission {
            class_name: security_classes::FILE_IO_PERMISSION.to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![
                NamedArgument {
                    name: "Read".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\read\\path".to_string()),
                },
                NamedArgument {
                    name: "Write".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("C:\\write\\path".to_string()),
                },
            ],
        }];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        let read_paths = permission_set.get_all_file_read_paths();
        let write_paths = permission_set.get_all_file_write_paths();

        assert_eq!(read_paths.len(), 1);
        assert_eq!(read_paths[0], "C:\\read\\path");
        assert_eq!(write_paths.len(), 1);
        assert_eq!(write_paths[0], "C:\\write\\path");
    }

    #[test]
    fn test_get_file_paths_no_fileio_permission() {
        let permissions = vec![Permission {
            class_name: security_classes::SECURITY_PERMISSION.to_string(),
            assembly_name: "mscorlib".to_string(),
            named_arguments: vec![],
        }];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        let read_paths = permission_set.get_all_file_read_paths();
        let write_paths = permission_set.get_all_file_write_paths();

        assert_eq!(read_paths.len(), 0);
        assert_eq!(write_paths.len(), 0);
    }

    #[test]
    fn test_display_format_binary() {
        let permissions = vec![
            Permission {
                class_name: "TestPermission1".to_string(),
                assembly_name: "TestAssembly".to_string(),
                named_arguments: vec![NamedArgument {
                    name: "TestArg".to_string(),
                    arg_type: ArgumentType::String,
                    value: ArgumentValue::String("TestValue".to_string()),
                }],
            },
            Permission {
                class_name: "TestPermission2".to_string(),
                assembly_name: "TestAssembly2".to_string(),
                named_arguments: vec![],
            },
        ];

        let permission_set = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![],
        };

        let display_string = format!("{}", permission_set);
        assert!(display_string.contains("Permission Set (BinaryLegacy):"));
        assert!(display_string.contains("TestPermission1, Assembly: TestAssembly"));
        assert!(display_string.contains("TestPermission2, Assembly: TestAssembly2"));
        assert!(display_string.contains("TestArg = \"TestValue\""));
    }

    #[test]
    fn test_display_format_xml() {
        let xml_data = b"<PermissionSet>test</PermissionSet>";
        let permission_set = PermissionSet {
            format: PermissionSetFormat::Xml,
            permissions: vec![],
            data: xml_data.to_vec(),
        };

        let display_string = format!("{}", permission_set);
        assert_eq!(display_string, "<PermissionSet>test</PermissionSet>");
    }

    #[test]
    fn test_clone() {
        let permissions = vec![Permission {
            class_name: "TestPermission".to_string(),
            assembly_name: "TestAssembly".to_string(),
            named_arguments: vec![],
        }];

        let original = PermissionSet {
            format: PermissionSetFormat::BinaryLegacy,
            permissions,
            data: vec![1, 2, 3],
        };

        let cloned = original.clone();
        assert!(matches!(cloned.format, PermissionSetFormat::BinaryLegacy));
        assert_eq!(cloned.permissions.len(), 1);
        assert_eq!(cloned.permissions[0].class_name, "TestPermission");
        assert_eq!(cloned.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_binary_format_zero_blob_length() {
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"TestPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);
        data.push(0x00); // blob length = 0

        let permission_set = PermissionSet::new(&data).unwrap();
        assert_eq!(permission_set.permissions.len(), 1);
        assert_eq!(permission_set.permissions[0].named_arguments.len(), 0);
    }

    #[test]
    fn test_binary_format_zero_property_name_length() {
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"TestPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);

        let blob_start = data.len() + 1;
        data.push(0x00); // Placeholder for blob length

        data.push(0x01); // 1 property
        data.push(0x54); // Field marker
        data.push(0x02); // Boolean type
        data.push(0x00); // Property name length = 0
        data.push(0x01); // Boolean value = true

        let blob_length = data.len() - blob_start;
        data[blob_start - 1] = blob_length as u8;

        let permission_set = PermissionSet::new(&data).unwrap();
        assert_eq!(permission_set.permissions[0].named_arguments.len(), 1);
        assert_eq!(permission_set.permissions[0].named_arguments[0].name, "");
    }

    #[test]
    fn test_binary_format_blob_end_seeking() {
        // Test the case where parser position is less than blob_end and needs seeking
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"TestPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);

        // Create a blob that's longer than the actual content
        data.push(0x10); // blob length = 16
        data.push(0x00); // 0 properties (so parser won't consume all 16 bytes)

        // The blob length (16) includes the property count byte we just added
        // So we need 15 more bytes to complete the 16-byte blob
        data.extend(std::iter::repeat_n(0x00, 15));

        // This should now fail with proper bounds checking instead of requiring extra padding
        let result = PermissionSet::new(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_format_blob_bounds_checking() {
        // Test that we properly detect when blob_end would exceed data length
        let mut data = vec![b'.', 0x01]; // '.' + 1 permission

        let class_name = b"TestPermission";
        data.push(class_name.len() as u8);
        data.extend_from_slice(class_name);

        // Create a blob length that would go beyond the available data
        data.push(0x20); // blob length = 32 bytes, but we'll only have 1 byte of data
        data.push(0x00); // 0 properties

        // Total data length is now: 2 (header) + 14 (class name) + 1 (class name length) + 1 (blob length) + 1 (property count) = 19 bytes
        // But blob_end would be calculated as: current_pos (18) + blob_length (32) = 50, which exceeds data.len() (19)

        let result = PermissionSet::new(&data);
        assert!(result.is_err());

        // Verify the error message contains bounds information
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("Blob end position"));
        assert!(error_msg.contains("exceeds data length"));
    }
}
