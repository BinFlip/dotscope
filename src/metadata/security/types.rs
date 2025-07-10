//! .NET declarative security type definitions and security action enumerations.
//!
//! This module provides comprehensive type definitions for analyzing .NET's Code Access Security (CAS)
//! system, including security actions, permission argument types, and security permission flags.
//! These types support the parsing and analysis of declarative security attributes stored in
//! .NET assembly metadata.
//!
//! # .NET Security Architecture
//!
//! The .NET security system uses several key concepts that are represented by the types in this module:
//!
//! 1. **Security Actions**: Control how permissions are enforced (Demand, Assert, Deny, etc.)
//! 2. **Permission Arguments**: Typed values that configure individual permissions
//! 3. **Security Permission Flags**: Bitflags controlling access to security-sensitive operations
//! 4. **Permission Set Formats**: Different serialization formats for permission collections
//!
//! ## Security Action Enforcement
//!
//! Security actions determine when and how the CLR enforces permission checks:
//!
//! - **Runtime Actions**: `Demand`, `Assert`, `Deny`, `PermitOnly` (checked during execution)
//! - **Link-Time Actions**: `LinkDemand`, `InheritanceDemand` (checked during JIT compilation)
//! - **Assembly Request Actions**: `RequestMinimum`, `RequestOptional`, `RequestRefuse` (legacy)
//!
//! # Common Use Cases
//!
//! ## Security Action Analysis
//!
//! ```rust
//! use dotscope::metadata::security::{SecurityAction, Security};
//!
//! # fn analyze_security_action(security: &Security) -> Result<(), Box<dyn std::error::Error>> {
//! match security.action {
//!     SecurityAction::Demand => {
//!         println!("Runtime permission demand - callers must have permission");
//!     },
//!     SecurityAction::LinkDemand => {
//!         println!("Link-time demand - immediate caller must have permission");
//!     },
//!     SecurityAction::Assert => {
//!         println!("Permission assertion - bypasses caller checks");
//!     },
//!     SecurityAction::Deny => {
//!         println!("Permission denial - blocks access regardless of grants");
//!     },
//!     SecurityAction::PermitOnly => {
//!         println!("Permit only - restricts to specified permissions");
//!     },
//!     _ => println!("Other security action: {:?}", security.action),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Permission Argument Analysis
//!
//! ```rust
//! use dotscope::metadata::security::{ArgumentType, ArgumentValue};
//!
//! # fn analyze_permission_argument(arg_type: &ArgumentType, arg_value: &ArgumentValue) -> Result<(), Box<dyn std::error::Error>> {
//! match (arg_type, arg_value) {
//!     (ArgumentType::String, ArgumentValue::String(path)) => {
//!         println!("String argument: {}", path);
//!     },
//!     (ArgumentType::Boolean, ArgumentValue::Boolean(flag)) => {
//!         println!("Boolean argument: {}", flag);
//!     },
//!     (ArgumentType::Enum(enum_type), ArgumentValue::Enum(_, value)) => {
//!         println!("Enum argument: {} = {}", enum_type, value);
//!     },
//!     (ArgumentType::Array(_), ArgumentValue::Array(values)) => {
//!         println!("Array argument with {} elements", values.len());
//!         for (i, value) in values.iter().enumerate() {
//!             println!("  [{}]: {}", i, value);
//!         }
//!     },
//!     _ => println!("Other argument type/value combination"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Permission Flag Analysis  
//!
//! ```rust
//! use dotscope::metadata::security::SecurityPermissionFlags;
//!
//! # fn analyze_security_flags(flags: SecurityPermissionFlags) -> Result<(), Box<dyn std::error::Error>> {
//! // Check for dangerous permissions
//! if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_SKIP_VERIFICATION) {
//!     println!("WARNING: Can skip code verification");
//! }
//!
//! if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_UNSAFE_CODE) {
//!     println!("WARNING: Can execute unsafe code");
//! }
//!
//! if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_CONTROL_POLICY) {
//!     println!("WARNING: Can modify security policy");
//! }
//!
//! // Check for common permissions
//! if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_EXECUTION) {
//!     println!("Can execute code (basic permission)");
//! }
//!
//! if flags.contains(SecurityPermissionFlags::SECURITY_FLAG_ASSERTION) {
//!     println!("Can assert permissions");
//! }
//!
//! println!("Security flags: 0x{:08X}", flags.bits());
//! # Ok(())
//! # }
//! ```
//!
//! ## Permission Class Identification
//!
//! ```rust
//! use dotscope::metadata::security::security_classes;
//!
//! # fn identify_permission_class(class_name: &str) -> Result<(), Box<dyn std::error::Error>> {
//! match class_name {
//!     security_classes::FILE_IO_PERMISSION => {
//!         println!("File I/O permission detected");
//!     },
//!     security_classes::SECURITY_PERMISSION => {
//!         println!("Security permission detected");
//!     },
//!     security_classes::REGISTRY_PERMISSION => {
//!         println!("Registry permission detected");
//!     },
//!     security_classes::REFLECTION_PERMISSION => {
//!         println!("Reflection permission detected");
//!     },
//!     _ => println!("Unknown or custom permission: {}", class_name),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Permission Set Formats
//!
//! .NET has used different serialization formats for permission sets over time:
//!
//! ## XML Format
//! Used in security policy files and some assembly attributes:
//! ```xml
//! <PermissionSet class="System.Security.PermissionSet" version="1">
//!   <IPermission class="System.Security.Permissions.FileIOPermission" version="1">
//!     <Read>C:\Data</Read>
//!   </IPermission>
//! </PermissionSet>
//! ```
//!
//! ## Binary Formats
//! - **Legacy Binary**: Older .NET Framework format with simple binary encoding
//! - **Compressed Binary**: Newer format using compressed integers and optimized layout
//!
//! # Security Action Evolution
//!
//! The .NET security model has evolved significantly:
//!
//! ## .NET Framework 1.0-3.5
//! - Full CAS implementation with all security actions
//! - Assembly-level security requests (`RequestMinimum`, `RequestOptional`, `RequestRefuse`)
//! - Extensive use of link-time and inheritance demands
//!
//! ## .NET Framework 4.0+
//! - Security transparency model
//! - Many CAS features deprecated or simplified
//! - Introduction of "choice" security actions for transparent code
//!
//! ## .NET Core/.NET 5+
//! - Most CAS features removed or become no-ops
//! - Focus shifted to other security mechanisms
//! - Legacy support for analysis of older assemblies
//!
//! # Thread Safety
//!
//! All types in this module are safe to share across threads:
//! - Enums and bitflags are Copy types
//! - Argument values are immutable after creation
//! - String data is owned or reference-counted
//!
//! # ECMA-335 Compliance
//!
//! This implementation follows ECMA-335 specifications for declarative security:
//! - **Partition II, Section 22.11**: `DeclSecurity` table format
//! - **Partition II, Section 23.1.16**: Security action values
//! - **Partition I, Section 10**: Security model overview

use bitflags::bitflags;
use std::{fmt, sync::Arc};

use crate::metadata::security::PermissionSet;

/// Security information wrapper for storing declarative security attributes.
///
/// Represents a single declarative security entry that combines a security action
/// with a permission set. These entries are stored in the `DeclSecurity` metadata table
/// and define security requirements for assemblies, types, and methods.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::{Security, SecurityAction, PermissionSet};
/// use std::sync::Arc;
///
/// # fn create_security_entry() -> Result<(), Box<dyn std::error::Error>> {
/// # let permission_data = vec![0x2E, 0x00]; // Minimal binary permission set
/// let permission_set = Arc::new(PermissionSet::new(&permission_data)?);
///
/// let security = Security {
///     action: SecurityAction::Demand,
///     permission_set,
/// };
///
/// match security.action {
///     SecurityAction::Demand => {
///         println!("This code demands specific permissions from callers");
///     },
///     _ => println!("Other security action"),
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `Security` instances are safe to share across threads due to the use of `Arc`
/// for the permission set and the `Copy` nature of `SecurityAction`.
pub struct Security {
    /// The security action that defines how to enforce the permission set.
    ///
    /// Determines when and how the CLR will check the associated permissions.
    /// For example, `Demand` checks callers at runtime, while `LinkDemand`
    /// checks the immediate caller at JIT compilation time.
    pub action: SecurityAction,

    /// The collection of permissions to be enforced according to the security action.
    ///
    /// Contains all the individual permissions that make up this security requirement.
    /// Uses `Arc` for efficient sharing across multiple security contexts and threads.
    /// The permission set defines what specific resources or operations are controlled.
    pub permission_set: Arc<PermissionSet>,
}

/// Security actions that control when and how permissions are enforced in .NET assemblies.
///
/// Security actions define the enforcement semantics for declarative security attributes.
/// Each action specifies when the CLR should check permissions and what happens when
/// permission checks fail. These correspond directly to the `SecurityAction` enumeration
/// in the .NET Framework and ECMA-335 specifications.
///
/// # Action Categories
///
/// ## Runtime Actions
/// Actions that are checked during code execution:
/// - [`Demand`](SecurityAction::Demand): Check all callers in the call stack
/// - [`Assert`](SecurityAction::Assert): Skip permission checks for the asserted permission
/// - [`Deny`](SecurityAction::Deny): Block access to the specified resource
/// - [`PermitOnly`](SecurityAction::PermitOnly): Allow only the specified permissions
///
/// ## Link-Time Actions  
/// Actions that are checked during JIT compilation:
/// - [`LinkDemand`](SecurityAction::LinkDemand): Check the immediate caller only
/// - [`InheritanceDemand`](SecurityAction::InheritanceDemand): Check classes that inherit or override
///
/// ## Assembly Request Actions (Legacy)
/// Actions used for assembly-level permission requests (obsolete in modern .NET):
/// - [`RequestMinimum`](SecurityAction::RequestMinimum): Minimum required permissions
/// - [`RequestOptional`](SecurityAction::RequestOptional): Optional permissions to grant
/// - [`RequestRefuse`](SecurityAction::RequestRefuse): Permissions to refuse
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::SecurityAction;
///
/// // Check if an action is runtime-enforced
/// fn is_runtime_action(action: SecurityAction) -> bool {
///     matches!(action,
///         SecurityAction::Demand |
///         SecurityAction::Assert |
///         SecurityAction::Deny |
///         SecurityAction::PermitOnly
///     )
/// }
///
/// // Check if an action is security-sensitive
/// fn is_security_sensitive(action: SecurityAction) -> bool {
///     matches!(action,
///         SecurityAction::Assert |           // Can bypass security
///         SecurityAction::Deny |             // Can block access
///         SecurityAction::PermitOnly         // Can restrict permissions
///     )
/// }
/// ```
///
/// # .NET Framework Evolution
///
/// - **.NET 1.0-3.5**: All actions supported with full CAS enforcement
/// - **.NET 4.0**: Security transparency model, some actions deprecated
/// - **.NET Core/5+**: Most actions become no-ops, kept for compatibility
///
/// # ECMA-335 References
///
/// - **Partition II, Section 23.1.16**: Security action enumeration values
/// - **Partition II, Section 22.11**: `DeclSecurity` table structure
/// - **Partition I, Section 10**: Security model overview
///
/// # Binary Representation
///
/// Security actions are stored as 16-bit unsigned integers in .NET metadata.
/// The numeric values are defined by ECMA-335 and must remain stable for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SecurityAction {
    /// Denies access to the specified resources, overriding any grants.
    ///
    /// When a Deny action is encountered, the CLR will refuse any demands for the
    /// specified permissions, regardless of whether the code has been granted those
    /// permissions. This is used to restrict access even when code would normally
    /// have the required permissions.
    ///
    /// # Security Implications
    /// - Overrides permission grants, creating a "security hole" prevention mechanism
    /// - Useful for restricting untrusted code or creating security boundaries
    /// - Can prevent code from accessing sensitive resources even if granted permission
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.Deny, Read = @"C:\Sensitive")]
    /// public void RestrictedMethod() {
    ///     // This method cannot read from C:\Sensitive even if normally allowed
    /// }
    /// ```
    Deny = 0x0001,

    /// Demands that all callers in the call chain have the specified permission.
    ///
    /// This action causes the CLR to perform a stack walk, checking that every caller
    /// in the call chain has been granted the specified permission. If any caller
    /// lacks the permission, a `SecurityException` is thrown.
    ///
    /// # Security Implications
    /// - Most common security action for runtime permission checks
    /// - Ensures all code in the call stack is trusted for the operation
    /// - Can impact performance due to stack walking
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.Demand, Read = @"C:\Data")]
    /// public void ReadSensitiveFile() {
    ///     // All callers must have read permission for C:\Data
    /// }
    /// ```
    Demand = 0x0002,

    /// Asserts that the specified permission should be granted without further checks.
    ///
    /// When code asserts a permission, subsequent demands for that permission will
    /// succeed without performing a stack walk beyond the asserting frame. This
    /// effectively "shields" callers from needing the asserted permission.
    ///
    /// # Security Implications
    /// - Bypasses normal security checks, creating potential security risks
    /// - Should only be used by highly trusted code
    /// - Can create privilege escalation if misused
    /// - Requires `SecurityPermission` with `Assertion` flag to use
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.Assert, Read = @"C:\SystemData")]
    /// public void TrustedSystemOperation() {
    ///     // This method can read system data regardless of caller permissions
    /// }
    /// ```
    Assert = 0x0003,

    /// Demands that the current assembly has been granted the specified permission.
    ///
    /// This action checks that the currently executing assembly has the required permission,
    /// but does not perform a stack walk to check callers. It is used for permissions that
    /// are not part of the Code Access Security (CAS) system.
    ///
    /// # Security Implications
    /// - Only checks the immediate assembly, not the entire call stack
    /// - Used for permissions outside the traditional CAS model
    /// - Less expensive than full stack walking demands
    ///
    /// # Example Usage
    /// ```csharp
    /// [MyCustomPermission(SecurityAction.NonCasDemand, Value = "required")]
    /// public void NonCasSecuredMethod() {
    ///     // Only this assembly needs the custom permission
    /// }
    /// ```
    NonCasDemand = 0x0004,

    /// Demands that the immediate caller has been granted the specified permission.
    ///
    /// Link demands are checked at JIT compilation time rather than runtime. They verify
    /// that the immediate caller (not the entire call stack) has the required permission.
    /// This provides security with better performance than runtime demands.
    ///
    /// # Security Implications
    /// - Checked at JIT time, not runtime, for better performance
    /// - Only checks immediate caller, potentially less secure than full stack walk
    /// - Can be bypassed by reflection in some scenarios
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.LinkDemand, Unrestricted = true)]
    /// public void FileOperationMethod() {
    ///     // Immediate caller must have unrestricted file access
    /// }
    /// ```
    LinkDemand = 0x0005,

    /// Demands that classes inheriting from or overriding this method have the specified permission.
    ///
    /// This action ensures that any code that derives from a class or overrides a method
    /// has the required permission. It is checked when the derived class is loaded or
    /// when the override is JIT compiled.
    ///
    /// # Security Implications
    /// - Protects against malicious inheritance or method overriding
    /// - Checked at class loading or method compilation time
    /// - Ensures derived classes maintain security requirements
    ///
    /// # Example Usage
    /// ```csharp
    /// [SecurityPermission(SecurityAction.InheritanceDemand, ControlPrincipal = true)]
    /// public virtual void SecuritySensitiveMethod() {
    ///     // Classes inheriting this must have ControlPrincipal permission
    /// }
    /// ```
    InheritanceDemand = 0x0006,

    /// Specifies the minimum permissions required for the assembly to run (legacy).
    ///
    /// This action was used in early .NET versions to specify the minimum set of permissions
    /// that an assembly required to function. It is now obsolete and ignored in modern
    /// .NET implementations, but remains for compatibility with older assemblies.
    ///
    /// # Legacy Status
    /// - Obsolete in .NET Framework 4.0 and later
    /// - Ignored by modern .NET runtimes
    /// - Maintained for compatibility with older assemblies
    ///
    /// # Example Usage (Legacy)
    /// ```csharp
    /// [assembly: FileIOPermission(SecurityAction.RequestMinimum, Unrestricted = true)]
    /// // Assembly requests minimum file I/O permissions
    /// ```
    RequestMinimum = 0x0007,

    /// Specifies optional permissions that would be beneficial for the assembly (legacy).
    ///
    /// This action was used to specify permissions that an assembly could use if available,
    /// but could function without. Like `RequestMinimum`, it is now obsolete and ignored
    /// in modern .NET implementations.
    ///
    /// # Legacy Status
    /// - Obsolete in .NET Framework 4.0 and later
    /// - Ignored by modern .NET runtimes
    /// - Assembly would receive these permissions if security policy allowed
    ///
    /// # Example Usage (Legacy)
    /// ```csharp
    /// [assembly: RegistryPermission(SecurityAction.RequestOptional, Unrestricted = true)]
    /// // Assembly would like registry access if possible
    /// ```
    RequestOptional = 0x0008,

    /// Specifies permissions that the assembly explicitly refuses (legacy).
    ///
    /// This action was used to specify permissions that an assembly explicitly did not
    /// want to be granted, even if security policy would normally grant them. This
    /// provided a way for assemblies to limit their own privileges.
    ///
    /// # Legacy Status
    /// - Obsolete in .NET Framework 4.0 and later
    /// - Ignored by modern .NET runtimes
    /// - Was used for defense-in-depth security practices
    ///
    /// # Example Usage (Legacy)
    /// ```csharp
    /// [assembly: FileIOPermission(SecurityAction.RequestRefuse, Unrestricted = true)]
    /// // Assembly explicitly refuses all file I/O permissions
    /// ```
    RequestRefuse = 0x0009,

    /// Reserved for pre-JIT compilation grants (implementation-specific).
    ///
    /// This action is used internally by the .NET runtime during ahead-of-time (AOT)
    /// compilation scenarios. It is not intended for use in user code and represents
    /// permissions that should be granted during pre-compilation.
    ///
    /// # Implementation Details
    /// - Used internally by runtime pre-compilation systems
    /// - Not for use in application code
    /// - Related to Native Image Generator (ngen.exe) and similar tools
    PrejitGrant = 0x000A,

    /// Reserved for pre-JIT compilation denials (implementation-specific).
    ///
    /// This action is used internally by the .NET runtime during ahead-of-time (AOT)
    /// compilation scenarios. It represents permissions that should be denied during
    /// pre-compilation.
    ///
    /// # Implementation Details
    /// - Used internally by runtime pre-compilation systems
    /// - Not for use in application code
    /// - Related to Native Image Generator (ngen.exe) and similar tools
    PrejitDeny = 0x000B,

    /// Link-time demand for non-CAS permissions.
    ///
    /// Similar to `LinkDemand`, but for permissions that are not part of the traditional
    /// Code Access Security system. This provides JIT-time checking for custom permission
    /// types while maintaining the performance benefits of link-time verification.
    ///
    /// # Security Implications
    /// - JIT-time checking for better performance
    /// - Only checks immediate caller
    /// - Used for custom permission types outside CAS
    ///
    /// # Example Usage
    /// ```csharp
    /// [MyCustomPermission(SecurityAction.NonCasLinkDemand, Level = "High")]
    /// public void CustomSecuredMethod() {
    ///     // Immediate caller needs custom permission at JIT time
    /// }
    /// ```
    NonCasLinkDemand = 0x000C,

    /// Inheritance demand for non-CAS permissions.
    ///
    /// Similar to `InheritanceDemand`, but for permissions that are not part of the
    /// traditional Code Access Security system. This ensures that classes inheriting
    /// from or overriding this code have the required custom permissions.
    ///
    /// # Security Implications
    /// - Protects inheritance chains with custom permissions
    /// - Checked at class loading or method compilation time
    /// - Used for custom permission types outside CAS
    ///
    /// # Example Usage
    /// ```csharp
    /// [MyCustomPermission(SecurityAction.NonCasInheritance, Level = "High")]
    /// public virtual void InheritanceProtectedMethod() {
    ///     // Derived classes need custom permission
    /// }
    /// ```
    NonCasInheritance = 0x000D,

    /// Choice-based link demand for transparent code in .NET 4.0 security model.
    ///
    /// This action is part of the .NET 4.0 security transparency model, where it allows
    /// transparent code to specify link demands. The "choice" aspect relates to the
    /// transparency model's approach to security decisions.
    ///
    /// # .NET 4.0 Security Transparency
    /// - Used in security-transparent assemblies
    /// - Part of the simplified security model introduced in .NET 4.0
    /// - Allows transparent code to participate in security decisions
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.LinkDemandChoice, Unrestricted = true)]
    /// public void TransparentLinkDemand() {
    ///     // Transparent code can specify link demands
    /// }
    /// ```
    LinkDemandChoice = 0x000E,

    /// Choice-based inheritance demand for transparent code in .NET 4.0 security model.
    ///
    /// This action allows security-transparent code to specify inheritance demands as
    /// part of the .NET 4.0 security transparency model. It provides a way for transparent
    /// code to control inheritance security requirements.
    ///
    /// # .NET 4.0 Security Transparency
    /// - Used in security-transparent assemblies
    /// - Allows transparent code to control inheritance security
    /// - Part of the simplified security model
    ///
    /// # Example Usage
    /// ```csharp
    /// [SecurityPermission(SecurityAction.InheritanceDemandChoice, ControlPrincipal = true)]
    /// public virtual void TransparentInheritanceDemand() {
    ///     // Transparent code can specify inheritance demands
    /// }
    /// ```
    InheritanceDemandChoice = 0x000F,

    /// Choice-based demand for transparent code in .NET 4.0 security model.
    ///
    /// This action allows security-transparent code to specify runtime demands as part
    /// of the .NET 4.0 security transparency model. It enables transparent code to
    /// participate in runtime security decisions with explicit choice semantics.
    ///
    /// # .NET 4.0 Security Transparency
    /// - Used in security-transparent assemblies
    /// - Allows transparent code to make runtime security demands
    /// - Part of the choice-based security model
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.DemandChoice, Read = @"C:\Data")]
    /// public void TransparentDemand() {
    ///     // Transparent code can specify runtime demands
    /// }
    /// ```
    DemandChoice = 0x0010,

    /// Restricts code to only the specified permissions, denying all others.
    ///
    /// When a `PermitOnly` action is encountered, the CLR restricts the code to only
    /// the permissions specified, effectively denying all other permissions even if
    /// they were previously granted. This creates a privilege restriction mechanism.
    ///
    /// # Security Implications
    /// - Reduces the effective permission set of code
    /// - Useful for creating security boundaries within trusted code
    /// - Can prevent code from using permissions it was granted
    /// - Complements `Deny` by allowing only specific permissions
    ///
    /// # Example Usage
    /// ```csharp
    /// [FileIOPermission(SecurityAction.PermitOnly, Read = @"C:\SafeData")]
    /// public void RestrictedFileOperation() {
    ///     // This method can only read from C:\SafeData, no other file operations
    /// }
    /// ```
    PermitOnly = 0x0011,
    /// Unknown security action.
    Unknown(u16),
}

impl From<SecurityAction> for u16 {
    fn from(action: SecurityAction) -> Self {
        match action {
            SecurityAction::Deny => 0x0001,
            SecurityAction::Demand => 0x0002,
            SecurityAction::Assert => 0x0003,
            SecurityAction::NonCasDemand => 0x0004,
            SecurityAction::LinkDemand => 0x0005,
            SecurityAction::InheritanceDemand => 0x0006,
            SecurityAction::RequestMinimum => 0x0007,
            SecurityAction::RequestOptional => 0x0008,
            SecurityAction::RequestRefuse => 0x0009,
            SecurityAction::PrejitGrant => 0x000A,
            SecurityAction::PrejitDeny => 0x000B,
            SecurityAction::NonCasLinkDemand => 0x000C,
            SecurityAction::NonCasInheritance => 0x000D,
            SecurityAction::LinkDemandChoice => 0x000E,
            SecurityAction::InheritanceDemandChoice => 0x000F,
            SecurityAction::DemandChoice => 0x0010,
            SecurityAction::PermitOnly => 0x0011,
            SecurityAction::Unknown(invalid) => invalid,
        }
    }
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

/// Type information for named arguments in .NET permission attributes.
///
/// When .NET serializes permission attributes, each argument includes type information
/// that specifies how to interpret the argument value. This enum represents all the
/// supported argument types in the .NET security system.
///
/// # Type System Mapping
///
/// Each variant corresponds to a .NET type used in permission arguments:
/// - `Boolean` → `System.Boolean`
/// - `Int32` → `System.Int32`  
/// - `Int64` → `System.Int64`
/// - `String` → `System.String`
/// - `Type` → `System.Type`
/// - `Enum` → Any enumeration type (with type name)
/// - `Array` → Any array type (with element type)
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::ArgumentType;
///
/// // Simple types
/// assert_eq!(std::mem::discriminant(&ArgumentType::Boolean),
///            std::mem::discriminant(&ArgumentType::Boolean));
///
/// // Complex types
/// let array_type = ArgumentType::Array(Box::new(ArgumentType::String));
/// let enum_type = ArgumentType::Enum("MyEnum".to_string());
/// ```
///
/// # Serialization Format
///
/// In the binary format, argument types are encoded as single bytes with additional
/// data for complex types like enums and arrays. The encoding follows the .NET
/// binary serialization format for custom attributes.
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

/// Runtime values for named arguments in .NET permission attributes.
///
/// After parsing permission argument data, this enum holds the actual values with their
/// appropriate .NET types. Each variant corresponds to a supported argument type and
/// contains the deserialized value ready for analysis.
///
/// # Value Semantics
///
/// Each variant preserves the original .NET type semantics:
/// - `Boolean`: True/false values from permission flags
/// - `Int32`/`Int64`: Numeric values for permissions and flags
/// - `String`: File paths, registry keys, and other text data
/// - `Type`: Full type names for type-based permissions  
/// - `Enum`: Enumeration values with type information
/// - `Array`: Collections of homogeneous values
/// - `Null`: Explicit null values in permission arguments
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::ArgumentValue;
///
/// // File paths in FileIOPermission
/// let read_path = ArgumentValue::String("C:\\Data".to_string());
///
/// // Security flags
/// let flags = ArgumentValue::Int32(0x0008); // Execution flag
///
/// // Boolean permission settings
/// let unrestricted = ArgumentValue::Boolean(true);
///
/// // Array of paths
/// let multiple_paths = ArgumentValue::Array(vec![
///     ArgumentValue::String("C:\\Data1".to_string()),
///     ArgumentValue::String("C:\\Data2".to_string()),
/// ]);
/// ```
///
/// # Display Format
///
/// The `Display` implementation formats values in a human-readable way that resembles
/// C# syntax, making it useful for security analysis and reporting.
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
            ArgumentValue::Boolean(v) => write!(f, "{v}"),
            ArgumentValue::Int32(v) => write!(f, "{v}"),
            ArgumentValue::Int64(v) => write!(f, "{v}"),
            ArgumentValue::String(v) => write!(f, "\"{v}\""),
            ArgumentValue::Type(v) => write!(f, "typeof({v})"),
            ArgumentValue::Enum(t, v) => write!(f, "{t}({v})"),
            ArgumentValue::Array(v) => {
                write!(f, "[")?;
                for (i, val) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{val}")?;
                }
                write!(f, "]")
            }
            ArgumentValue::Null => write!(f, "null"),
        }
    }
}

/// Common .NET security permission classes
///
/// This module contains string constants for the full type names of standard permission
/// classes defined in the .NET Framework. These constants are useful for identifying
/// and categorizing permissions when analyzing .NET assemblies.
///
/// # Permission Categories
///
/// ## File System Permissions
/// - [`crate::metadata::security::types::security_classes::FILE_IO_PERMISSION`]: Controls file and directory access
/// - [`crate::metadata::security::types::security_classes::STORAGE_PERMISSION`]: Controls isolated storage access
///
/// ## System Resource Permissions  
/// - [`crate::metadata::security::types::security_classes::REGISTRY_PERMISSION`]: Controls Windows registry access
/// - [`crate::metadata::security::types::security_classes::ENVIRONMENT_PERMISSION`]: Controls environment variable access
/// - [`crate::metadata::security::types::security_classes::EVENT_LOG_PERMISSION`]: Controls Windows event log access
/// - [`crate::metadata::security::types::security_classes::PERF_COUNTER_PERMISSION`]: Controls performance counter access
///
/// ## Security and Identity Permissions
/// - [`crate::metadata::security::types::security_classes::SECURITY_PERMISSION`]: Controls security-sensitive operations
/// - [`crate::metadata::security::types::security_classes::IDENTITY_PERMISSION`]: Controls identity verification
/// - [`crate::metadata::security::types::security_classes::PRINCIPAL_PERMISSION`]: Controls role-based security
/// - [`crate::metadata::security::types::security_classes::KEY_CONTAINER_PERMISSION`]: Controls cryptographic key access
/// - [`crate::metadata::security::types::security_classes::STORE_PERMISSION`]: Controls X.509 certificate store access
///
/// ## Code Access Permissions
/// - [`crate::metadata::security::types::security_classes::REFLECTION_PERMISSION`]: Controls reflection usage
/// - [`crate::metadata::security::types::security_classes::UI_PERMISSION`]: Controls user interface operations
///
/// ## Network Permissions
/// - [`crate::metadata::security::types::security_classes::DNS_PERMISSION`]: Controls DNS resolution
/// - [`crate::metadata::security::types::security_classes::SOCKET_PERMISSION`]: Controls socket networking
/// - [`crate::metadata::security::types::security_classes::WEB_PERMISSION`]: Controls web access
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::security_classes;
///
/// // Check if a permission class is file-related
/// fn is_file_permission(class_name: &str) -> bool {
///     matches!(class_name,
///         security_classes::FILE_IO_PERMISSION |
///         security_classes::STORAGE_PERMISSION
///     )
/// }
///
/// // Check if a permission class is network-related
/// fn is_network_permission(class_name: &str) -> bool {
///     matches!(class_name,
///         security_classes::DNS_PERMISSION |
///         security_classes::SOCKET_PERMISSION |
///         security_classes::WEB_PERMISSION
///     )
/// }
///
/// // Check if a permission class is security-sensitive
/// fn is_security_sensitive(class_name: &str) -> bool {
///     matches!(class_name,
///         security_classes::SECURITY_PERMISSION |
///         security_classes::REFLECTION_PERMISSION |
///         security_classes::KEY_CONTAINER_PERMISSION
///     )
/// }
/// ```
///
/// # Usage in Security Analysis
///
/// These constants are commonly used when parsing declarative security attributes
/// to categorize and analyze the types of permissions an assembly requires:
///
/// ```rust
/// use dotscope::metadata::security::security_classes;
///
/// fn analyze_permission_risk(class_name: &str) -> &'static str {
///     match class_name {
///         security_classes::SECURITY_PERMISSION => "High - Can bypass security",
///         security_classes::REFLECTION_PERMISSION => "Medium - Can access private members",
///         security_classes::FILE_IO_PERMISSION => "Medium - Can access file system",
///         security_classes::REGISTRY_PERMISSION => "Medium - Can modify registry",
///         security_classes::DNS_PERMISSION => "Low - Can resolve DNS names",
///         security_classes::UI_PERMISSION => "Low - Can interact with UI",
///         _ => "Unknown - Custom permission class",
///     }
/// }
/// ```
pub mod security_classes {
    /// `FileIOPermission` - Controls access to files and directories.
    ///
    /// This permission controls read, write, append, and path discovery operations
    /// on the file system. It can specify individual files, directories, or use
    /// wildcards and environment variables.
    ///
    /// # Common Parameters
    /// - `Read`: Specifies files/directories that can be read
    /// - `Write`: Specifies files/directories that can be written
    /// - `Append`: Specifies files that can be appended to
    /// - `PathDiscovery`: Specifies paths that can be discovered
    /// - `Unrestricted`: Grants full file system access
    pub const FILE_IO_PERMISSION: &str = "System.Security.Permissions.FileIOPermission";

    /// `SecurityPermission` - Controls access to security-sensitive operations.
    ///
    /// This is one of the most powerful permissions, controlling fundamental security
    /// operations like asserting permissions, skipping verification, executing unsafe
    /// code, and controlling security policy.
    ///
    /// # Common Parameters
    /// - `Execution`: Basic permission to run code
    /// - `SkipVerification`: Can run unverified code  
    /// - `UnmanagedCode`: Can call unmanaged code
    /// - `Assertion`: Can assert permissions
    /// - `ControlPolicy`: Can modify security policy
    /// - `ControlPrincipal`: Can manipulate principal objects
    pub const SECURITY_PERMISSION: &str = "System.Security.Permissions.SecurityPermission";

    /// `RegistryPermission` - Controls access to Windows registry keys.
    ///
    /// This permission controls reading, writing, and creating registry keys and values.
    /// It can specify individual keys or entire registry hives.
    ///
    /// # Common Parameters
    /// - `Read`: Registry keys that can be read
    /// - `Write`: Registry keys that can be written
    /// - `Create`: Registry keys that can be created
    /// - `Unrestricted`: Full registry access
    pub const REGISTRY_PERMISSION: &str = "System.Security.Permissions.RegistryPermission";

    /// `EnvironmentPermission` - Controls access to environment variables.
    ///
    /// This permission controls reading and writing system and user environment
    /// variables. It can specify individual variables or patterns.
    ///
    /// # Common Parameters
    /// - `Read`: Environment variables that can be read
    /// - `Write`: Environment variables that can be written
    /// - `Unrestricted`: Access to all environment variables
    pub const ENVIRONMENT_PERMISSION: &str = "System.Security.Permissions.EnvironmentPermission";

    /// `ReflectionPermission` - Controls use of reflection.
    ///
    /// This permission controls the ability to reflect over types, access non-public
    /// members, and perform other reflection operations that could bypass normal
    /// access controls.
    ///
    /// # Common Parameters
    /// - `NoRestriction`: Full reflection access
    /// - `RestrictedMemberAccess`: Limited reflection access
    /// - `ReflectionEmit`: Can emit dynamic assemblies
    /// - `MemberAccess`: Can access non-public members
    pub const REFLECTION_PERMISSION: &str = "System.Security.Permissions.ReflectionPermission";

    /// `UIPermission` - Controls user interface operations.
    ///
    /// This permission controls clipboard access, window manipulation, and other
    /// user interface operations that could be used for social engineering attacks.
    ///
    /// # Common Parameters
    /// - `NoRestriction`: Full UI access
    /// - `SafeSubWindows`: Can create safe subwindows
    /// - `SafeTopLevelWindows`: Can create safe top-level windows
    /// - `Clipboard`: Can access clipboard
    pub const UI_PERMISSION: &str = "System.Security.Permissions.UIPermission";

    /// `IdentityPermission` - Controls identity verification operations.
    ///
    /// This permission is used to verify the identity of assemblies and can control
    /// access based on strong names, publisher certificates, or other identity markers.
    ///
    /// # Usage
    /// Typically used in conjunction with other permissions to create identity-based
    /// access controls for sensitive operations.
    pub const IDENTITY_PERMISSION: &str = "System.Security.Permissions.IdentityPermission";

    /// `PrincipalPermission` - Controls role-based security operations.
    ///
    /// This permission works with the .NET role-based security system to control
    /// access based on user identity and role membership.
    ///
    /// # Common Parameters
    /// - `Name`: Required user name
    /// - `Role`: Required role membership
    /// - `Authenticated`: Requires authenticated user
    pub const PRINCIPAL_PERMISSION: &str = "System.Security.Permissions.PrincipalPermission";

    /// `DnsPermission` - Controls DNS resolution operations.
    ///
    /// This permission controls the ability to resolve domain names to IP addresses
    /// using the Domain Name System. It can specify allowed or denied hostnames.
    ///
    /// # Common Parameters
    /// - `Unrestricted`: Can resolve any hostname
    /// - Individual hostnames or patterns can be specified
    pub const DNS_PERMISSION: &str = "System.Net.DnsPermission";

    /// `SocketPermission` - Controls socket-based network access.
    ///
    /// This permission controls low-level network access through sockets, including
    /// TCP and UDP connections. It can specify hosts, ports, and connection types.
    ///
    /// # Common Parameters
    /// - `Connect`: Can connect to specified hosts/ports
    /// - `Accept`: Can accept connections on specified ports
    /// - `Unrestricted`: Full socket access
    pub const SOCKET_PERMISSION: &str = "System.Net.SocketPermission";

    /// `WebPermission` - Controls web-based network access.
    ///
    /// This permission controls high-level web access through HTTP and HTTPS protocols.
    /// It can specify allowed URLs and connection patterns.
    ///
    /// # Common Parameters
    /// - `Connect`: Can connect to specified URLs
    /// - `ConnectPattern`: Can connect to URLs matching patterns
    /// - `Unrestricted`: Can access any web resource
    pub const WEB_PERMISSION: &str = "System.Net.WebPermission";

    /// `IsolatedStorageFilePermission` - Controls isolated storage access.
    ///
    /// This permission controls access to the .NET isolated storage system, which
    /// provides secure per-application or per-user storage areas.
    ///
    /// # Common Parameters
    /// - `UserQuota`: Maximum storage quota for user isolation
    /// - `DomainQuota`: Maximum storage quota for domain isolation
    /// - `AssemblyQuota`: Maximum storage quota for assembly isolation
    /// - `Unrestricted`: Unlimited isolated storage access
    pub const STORAGE_PERMISSION: &str =
        "System.Security.Permissions.IsolatedStorageFilePermission";

    /// `KeyContainerPermission` - Controls cryptographic key container access.
    ///
    /// This permission controls access to cryptographic key containers in the
    /// Cryptographic Service Provider (CSP) system. It can specify individual
    /// key containers and access types.
    ///
    /// # Common Parameters
    /// - `KeyContainerName`: Specific key container names
    /// - `Flags`: Access flags (Create, Delete, Decrypt, etc.)
    /// - `Unrestricted`: Access to all key containers
    pub const KEY_CONTAINER_PERMISSION: &str = "System.Security.Permissions.KeyContainerPermission";

    /// `StorePermission` - Controls X.509 certificate store access.
    ///
    /// This permission controls access to X.509 certificate stores, including
    /// reading, writing, and enumerating certificates in various store locations.
    ///
    /// # Common Parameters
    /// - `Flags`: Store access flags (`ReadStore`, `WriteStore`, etc.)
    /// - `Unrestricted`: Full certificate store access
    pub const STORE_PERMISSION: &str = "System.Security.Permissions.StorePermission";

    /// `EventLogPermission` - Controls Windows event log access.
    ///
    /// This permission controls reading from and writing to Windows event logs.
    /// It can specify individual log names and access types.
    ///
    /// # Common Parameters
    /// - `MachineName`: Target machine for event log access
    /// - `Write`: Can write to specified event logs
    /// - `Administer`: Can create and delete event logs
    /// - `Unrestricted`: Full event log access
    pub const EVENT_LOG_PERMISSION: &str = "System.Diagnostics.EventLogPermission";

    /// `PerformanceCounterPermission` - Controls performance counter access.
    ///
    /// This permission controls access to Windows performance counters, including
    /// reading counter values, creating custom counters, and managing counter categories.
    ///
    /// # Common Parameters
    /// - `CategoryName`: Performance counter category names
    /// - `MachineName`: Target machine for counter access
    /// - `Unrestricted`: Full performance counter access
    pub const PERF_COUNTER_PERMISSION: &str = "System.Diagnostics.PerformanceCounterPermission";
}

/// The supported `PermissionSet` serialization formats in .NET assemblies.
///
/// .NET has used different formats for serializing permission sets over its evolution,
/// reflecting changes in the security model and performance requirements. This enum
/// represents the known formats that the dotscope library can parse and analyze.
///
/// # Format Evolution
///
/// ## XML Format (.NET 1.0+)
/// The original permission set format used XML serialization with a standardized schema.
/// This format is human-readable but verbose, making it suitable for policy files and
/// manual configuration but inefficient for embedded assembly metadata.
///
/// ## Binary Legacy (.NET 1.0-2.0)
/// An early binary format that provided more compact storage than XML but used
/// straightforward binary encoding without compression. This format was used in
/// early versions of declarative security attributes.
///
/// ## Binary Compressed (.NET 2.0+)
/// A more efficient binary format introduced to reduce metadata size. Uses compressed
/// integers, optimized encoding for common permission types, and other space-saving
/// techniques while maintaining compatibility with the security model.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::PermissionSetFormat;
///
/// fn analyze_format_characteristics(format: &PermissionSetFormat) {
///     match format {
///         PermissionSetFormat::Xml => {
///             println!("Human-readable, verbose, used in policy files");
///         },
///         PermissionSetFormat::BinaryLegacy => {
///             println!("Compact, early binary format, limited compression");
///         },
///         PermissionSetFormat::BinaryCompressed => {
///             println!("Highly compact, compressed binary format, modern");
///         },
///         PermissionSetFormat::Unknown => {
///             println!("Unrecognized format, may be custom or corrupted");
///         },
///     }
/// }
/// ```
///
/// # Format Detection
///
/// The format is typically detected by examining the first few bytes of the
/// permission set data:
/// - XML format starts with '<' character or XML declaration
/// - Binary formats have specific magic numbers or headers
/// - Unknown formats don't match any recognized pattern
///
/// # Compatibility Considerations
///
/// Different .NET runtime versions have varying support for these formats:
/// - **.NET Framework 1.0-3.5**: All formats supported
/// - **.NET Framework 4.0+**: All formats supported but CAS deprecated
/// - **.NET Core/.NET 5+**: Limited support, mainly for compatibility analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSetFormat {
    /// XML format - permission sets serialized as XML.
    ///
    /// Uses the standard .NET XML serialization format with a well-defined schema.
    /// This format is human-readable and was commonly used in security policy files
    /// and some early assembly attributes.
    ///
    /// # Characteristics
    /// - Human-readable and editable
    /// - Verbose and larger in size
    /// - Used in machine.config and security policy files
    /// - Supports full .NET type information
    Xml,

    /// Legacy binary format - older .NET Framework binary format.
    ///
    /// An early binary serialization format used in .NET Framework versions 1.0-2.0.
    /// Provides more compact storage than XML but without advanced compression
    /// techniques.
    ///
    /// # Characteristics
    /// - More compact than XML
    /// - Simple binary encoding
    /// - Used in early declarative security attributes
    /// - Limited optimization compared to compressed format
    BinaryLegacy,

    /// Compressed binary format - newer .NET Framework binary format.
    ///
    /// An optimized binary format introduced in .NET Framework 2.0 that uses
    /// compression techniques to minimize metadata size while preserving full
    /// semantic information.
    ///
    /// # Characteristics
    /// - Highly compact storage
    /// - Uses compressed integers and optimized encoding
    /// - Default format for modern assembly attributes
    /// - Balances size and parsing performance
    BinaryCompressed,

    /// Unknown format that couldn't be identified.
    ///
    /// Represents permission set data that doesn't match any known format.
    /// This could indicate a custom format, corrupted data, or a format
    /// version not yet supported by this library.
    ///
    /// # Potential Causes
    /// - Corrupted or truncated permission set data
    /// - Custom or proprietary serialization format
    /// - Future .NET format not yet implemented
    /// - Malformed assembly metadata
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
