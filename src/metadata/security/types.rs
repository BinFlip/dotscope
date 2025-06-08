use bitflags::bitflags;
use std::{fmt, sync::Arc};

use crate::metadata::security::PermissionSet;

/// Wrapper of the security information to store within the dotscope data types
pub struct Security {
    /// The action that describes how to apply the permission set to the code elements
    pub action: SecurityAction,
    /// The permission to be applied to the code elements
    pub permission_set: Arc<PermissionSet>,
}

/// Security actions as defined in ECMA-335 and .NET Framework
///
/// These values control how permissions are applied to code elements (methods, types, assemblies).
/// Each action has different semantics for how the CLR enforces permissions.
///
/// # Reference
/// * ECMA-335 II.20 + II.22.11
/// * <https://learn.microsoft.com/en-us/dotnet/api/system.security.permissions.securityaction>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SecurityAction {
    /// Without further checks, refuse Demand for the specified permission.
    /// Denies access to resources based on permission demands.
    Deny = 0x0001,
    /// Check that all callers in the call chain have been granted specified permission, throw `SecurityException` on failure.
    /// Used when code is demanding that its callers have a specific permission to execute.
    Demand = 0x0002,
    /// Without further checks, satisfy Demand for the specified permission.
    /// Causes the security system to skip any demands for the specified permission that might
    /// otherwise occur during execution.
    Assert = 0x0003,
    /// Check that the current assembly has been granted the specified permission; throw `SecurityException` otherwise.
    /// Used for demanding non-CAS permissions.
    NonCasDemand = 0x0004,
    /// Check that the immediate caller has been granted the specified permission; throw `SecurityException` on failure.
    /// Used to perform link-time access checks on method callers.
    LinkDemand = 0x0005,
    /// The specified permission shall be granted in order to inherit from class or override virtual method.
    /// Used to ensure that derived classes or overridden methods have specific permissions.
    InheritanceDemand = 0x0006,
    /// Specify the minimum permissions required to run (obsolete in newer .NET versions).
    /// Used in assembly-level security requests to specify minimum permissions.
    RequestMinimum = 0x0007,
    /// Specify the optional permissions to grant (obsolete in newer .NET versions).
    /// Used in assembly-level security requests to specify optional permissions.
    RequestOptional = 0x0008,
    /// Specify the permissions not to be granted (obsolete in newer .NET versions).
    /// Used in assembly-level security requests to specify permissions that should be refused.
    RequestRefuse = 0x0009,
    /// Reserved for implementation-specific use.
    /// Used for prejitting operations.
    PrejitGrant = 0x000A,
    /// Reserved for implementation-specific use.
    /// Used for prejitting operations.
    PrejitDeny = 0x000B,
    /// Check that the immediate caller has been granted the specified permission; throw `SecurityException` otherwise.
    /// Non-CAS version of `LinkDemand`.
    NonCasLinkDemand = 0x000C,
    /// The specified permission shall be granted in order to inherit from class or override virtual method.
    /// Non-CAS version of `InheritanceDemand`.
    NonCasInheritance = 0x000D,
    /// Used for transparent code in the .NET 4.0 security model.
    /// Specifies that the decorated method should have a link demand for the given permission.
    LinkDemandChoice = 0x000E,
    /// Used for transparent code in the .NET 4.0 security model.
    /// Specifies that classes deriving from the decorated class or overriding the decorated
    /// method must have the appropriate permission.
    InheritanceDemandChoice = 0x000F,
    /// Used for transparent code in the .NET 4.0 security model.
    /// Specifies that callers to the decorated method must have the given permission.
    DemandChoice = 0x0010,
    /// Without further checks, refuse Demand for all permissions other than those specified.
    /// Restricts the code's access to resources specified by the permission.
    PermitOnly = 0x0011,
    /// Unknown security action.
    Unknown(u16),
}

impl From<u16> for SecurityAction {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => SecurityAction::Deny,
            0x0002 => SecurityAction::Demand,
            0x0003 => SecurityAction::Assert,
            0x0004 => SecurityAction::NonCasDemand,
            0x0005 => SecurityAction::LinkDemand,
            0x0006 => SecurityAction::InheritanceDemand,
            0x0007 => SecurityAction::RequestMinimum,
            0x0008 => SecurityAction::RequestOptional,
            0x0009 => SecurityAction::RequestRefuse,
            0x000A => SecurityAction::PrejitGrant,
            0x000B => SecurityAction::PrejitDeny,
            0x000C => SecurityAction::NonCasLinkDemand,
            0x000D => SecurityAction::NonCasInheritance,
            0x000E => SecurityAction::LinkDemandChoice,
            0x000F => SecurityAction::InheritanceDemandChoice,
            0x0010 => SecurityAction::DemandChoice,
            0x0011 => SecurityAction::PermitOnly,
            _ => SecurityAction::Unknown(value),
        }
    }
}

/// The type of a named argument in a permission
///
/// .NET serializes permission arguments with type information, which this enum represents.
/// Each argument type maps to a different .NET type used in permissions.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgumentType {
    /// Boolean (true/false)
    Boolean,
    /// 32-bit integer
    Int32,
    /// 64-bit integer
    Int64,
    /// String value
    String,
    /// Type reference - represents a CLR type
    Type,
    /// Enumeration value (stored as string name and integer value)
    /// The string parameter represents the enum type name
    Enum(String),
    /// Array of another type
    Array(Box<ArgumentType>),
    /// Unknown type
    Unknown(u8),
}

/// The value of a named argument in a permission
///
/// This represents the actual value of a permission argument after deserialization.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgumentValue {
    /// Boolean value
    Boolean(bool),
    /// 32-bit integer
    Int32(i32),
    /// 64-bit integer
    Int64(i64),
    /// String value
    String(String),
    /// Type reference - full name of the type
    Type(String),
    /// Enumeration value - type name and integer value
    Enum(String, i32),
    /// Array of values
    Array(Vec<ArgumentValue>),
    /// Null value
    Null,
}

impl fmt::Display for ArgumentValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgumentValue::Boolean(v) => write!(f, "{}", v),
            ArgumentValue::Int32(v) => write!(f, "{}", v),
            ArgumentValue::Int64(v) => write!(f, "{}", v),
            ArgumentValue::String(v) => write!(f, "\"{}\"", v),
            ArgumentValue::Type(v) => write!(f, "typeof({})", v),
            ArgumentValue::Enum(t, v) => write!(f, "{}({})", t, v),
            ArgumentValue::Array(v) => {
                write!(f, "[")?;
                for (i, val) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, "]")
            }
            ArgumentValue::Null => write!(f, "null"),
        }
    }
}

/// Common .NET security permission classes
///
/// These constants represent the full type names of common permission classes
/// found in the .NET Framework.
pub mod security_classes {
    /// File IO Permission - Controls access to files and directories
    pub const FILE_IO_PERMISSION: &str = "System.Security.Permissions.FileIOPermission";

    /// Security Permission - Controls access to security-sensitive operations
    pub const SECURITY_PERMISSION: &str = "System.Security.Permissions.SecurityPermission";

    /// Registry Permission - Controls access to registry keys
    pub const REGISTRY_PERMISSION: &str = "System.Security.Permissions.RegistryPermission";

    /// Environment Permission - Controls access to environment variables
    pub const ENVIRONMENT_PERMISSION: &str = "System.Security.Permissions.EnvironmentPermission";

    /// Reflection Permission - Controls use of reflection
    pub const REFLECTION_PERMISSION: &str = "System.Security.Permissions.ReflectionPermission";

    /// UI Permission - Controls UI operations
    pub const UI_PERMISSION: &str = "System.Security.Permissions.UIPermission";

    /// Identity Permission - Controls identity operations
    pub const IDENTITY_PERMISSION: &str = "System.Security.Permissions.IdentityPermission";

    /// Principal Permission - Controls role-based security
    pub const PRINCIPAL_PERMISSION: &str = "System.Security.Permissions.PrincipalPermission";

    /// DNS Permission - Controls DNS access
    pub const DNS_PERMISSION: &str = "System.Net.DnsPermission";

    /// Socket Permission - Controls socket network access
    pub const SOCKET_PERMISSION: &str = "System.Net.SocketPermission";

    /// Web Permission - Controls web access
    pub const WEB_PERMISSION: &str = "System.Net.WebPermission";

    /// Isolated Storage Permission - Controls isolated storage access
    pub const STORAGE_PERMISSION: &str =
        "System.Security.Permissions.IsolatedStorageFilePermission";

    /// Key Container Permission - Controls cryptographic key access
    pub const KEY_CONTAINER_PERMISSION: &str = "System.Security.Permissions.KeyContainerPermission";

    /// Store Permission - Controls X.509 certificate store access
    pub const STORE_PERMISSION: &str = "System.Security.Permissions.StorePermission";

    /// Event Log Permission - Controls event log access
    pub const EVENT_LOG_PERMISSION: &str = "System.Diagnostics.EventLogPermission";

    /// Performance Counter Permission - Controls performance counter access
    pub const PERF_COUNTER_PERMISSION: &str = "System.Diagnostics.PerformanceCounterPermission";
}

/// The supported `PermissionSet` formats
///
/// .NET has used different formats for permission sets over its evolution.
/// This enum represents the known formats that we can parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionSetFormat {
    /// XML format - permission sets serialized as XML
    Xml,
    /// Legacy binary format - older .NET Framework binary format
    BinaryLegacy,
    /// Compressed binary format - newer .NET Framework binary format
    BinaryCompressed,
    /// Unknown format that couldn't be identified
    Unknown,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// SecurityPermissionFlags - Controls access to security-sensitive operations.
    ///
    /// These flags correspond to the SecurityPermissionFlag enumeration in .NET and determine
    /// what security-sensitive operations code is allowed to perform.
    pub struct SecurityPermissionFlags: i32 {
        /// Enables code execution. Required for any code to run.
        /// This is the most basic permission required in the runtime.
        const SECURITY_FLAG_EXECUTION = 0x0000_0008;
        /// Enables bypassing of code verification by the runtime.
        /// This allows potentially unsafe code to execute without verification checks.
        /// This is a highly sensitive permission that can compromise system security.
        const SECURITY_FLAG_SKIP_VERIFICATION = 0x0000_0004;
        /// Enables the code to assert that it is authorized to access resources.
        /// Assertion allows code to claim it has permission even when its callers don't.
        /// This can create security holes if misused, as it bypasses stack walks.
        const SECURITY_FLAG_ASSERTION = 0x0000_0001;
        /// Enables the execution of unsafe or unverified code.
        /// Required for code using the 'unsafe' keyword in C# or other unverifiable code.
        /// This allows memory manipulation that could potentially cause security issues.
        const SECURITY_FLAG_UNSAFE_CODE = 0x0000_0020;
        /// Enables creation and control of application domains.
        /// This permission is needed to create, unload, or set the security policy of AppDomains.
        /// It provides significant control over application isolation boundaries.
        const SECURITY_FLAG_CONTROL_APPDOMAINS = 0x0000_1000;
        /// Enables modification of security policy.
        /// This allows code to change the security policy for the application domain.
        /// This is a highly powerful permission that can completely change security behavior.
        const SECURITY_FLAG_CONTROL_POLICY = 0x0000_0800;
        /// Enables serialization and deserialization operations.
        /// Required for object serialization functionality, which can reconstruct objects
        /// and potentially execute code during deserialization.
        const SECURITY_FLAG_SERIALIZATION = 0x0000_0080;
        /// Enables control over threads, including creating threads and setting thread properties.
        /// This permission allows manipulation of thread state, apartment state, and interruption.
        const SECURITY_FLAG_CONTROL_THREAD = 0x0000_0200;
        /// Enables access and manipulation of evidence objects used in security decisions.
        /// This allows code to create or manipulate evidence, which is used to determine
        /// what permissions should be granted to assemblies.
        const SECURITY_FLAG_CONTROL_EVIDENCE = 0x0000_0040;
        /// Enables control over security principal objects.
        /// This allows code to manipulate the current principal, which affects role-based security.
        const SECURITY_FLAG_CONTROL_PRINCIPAL = 0x0000_0400;
        /// Enables access to security infrastructure functionality.
        /// This allows code to interact with lower-level security mechanisms.
        const SECURITY_FLAG_INFRASTRUCTURE = 0x0000_2000;
        /// Enables the use of code binding redirects.
        /// This allows code to modify assembly binding behavior at runtime.
        const SECURITY_FLAG_BINDING = 0x0000_0100;
        /// Enables access to .NET remoting functionality.
        /// This allows code to configure remoting channels, serialization formats,
        /// and other remoting infrastructure.
        const SECURITY_FLAG_REMOTING = 0x0000_4000;
        /// Enables the ability to manipulate the application domain's behavior.
        /// This allows control over application domain properties and settings.
        const SECURITY_FLAG_CONTROL_DOMAIN = 0x0000_8000;
        /// Enables the use of reflection to discover private members.
        /// This allows code to access non-public members of types through reflection.
        const SECURITY_FLAG_REFLECTION = 0x0001_0000;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_action_from_u16() {
        assert_eq!(SecurityAction::from(0x0001), SecurityAction::Deny);
        assert_eq!(SecurityAction::from(0x0002), SecurityAction::Demand);
        assert_eq!(SecurityAction::from(0x0003), SecurityAction::Assert);
        assert_eq!(
            SecurityAction::from(0x9999),
            SecurityAction::Unknown(0x9999)
        );
    }

    #[test]
    fn test_argument_value_display() {
        assert_eq!(ArgumentValue::Boolean(true).to_string(), "true");
        assert_eq!(ArgumentValue::Int32(42).to_string(), "42");
        assert_eq!(
            ArgumentValue::String("test".to_string()).to_string(),
            "\"test\""
        );
        assert_eq!(ArgumentValue::Null.to_string(), "null");

        let array = ArgumentValue::Array(vec![
            ArgumentValue::Int32(1),
            ArgumentValue::Int32(2),
            ArgumentValue::Int32(3),
        ]);
        assert_eq!(array.to_string(), "[1, 2, 3]");
    }
}
