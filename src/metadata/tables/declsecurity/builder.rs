//! DeclSecurityBuilder for creating declarative security attribute specifications.
//!
//! This module provides [`DeclSecurityBuilder`] for creating DeclSecurity table entries
//! with a fluent API. Declarative security defines security permissions and restrictions
//! that apply to assemblies, types, and methods through Code Access Security (CAS),
//! enabling fine-grained security control and permission management.

use crate::{
    metadata::{
        cilassembly::BuilderContext,
        security::SecurityAction,
        tables::{CodedIndex, CodedIndexType, DeclSecurityRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating DeclSecurity metadata entries.
///
/// `DeclSecurityBuilder` provides a fluent API for creating DeclSecurity table entries
/// with validation and automatic blob management. Declarative security defines security
/// permissions, restrictions, and policies that apply to assemblies, types, and methods
/// through .NET's Code Access Security (CAS) framework.
///
/// # Declarative Security Model
///
/// .NET declarative security follows a structured pattern:
/// - **Security Action**: How the permission should be applied (demand, assert, deny, etc.)
/// - **Parent Entity**: The assembly, type, or method that the security applies to
/// - **Permission Set**: Serialized collection of security permissions and their parameters
/// - **Enforcement Point**: When and how the security check is performed
///
/// # Coded Index Types
///
/// Declarative security uses the `HasDeclSecurity` coded index to specify targets:
/// - **TypeDef**: Security applied to types (classes, interfaces, structs)
/// - **MethodDef**: Security applied to individual methods
/// - **Assembly**: Security applied to entire assemblies
///
/// # Security Actions and Scenarios
///
/// Different security actions serve various security enforcement scenarios:
/// - **Demand**: Runtime security checks requiring callers to have permissions
/// - **LinkDemand**: Compile-time security checks during JIT compilation
/// - **Assert**: Temporarily elevate permissions for trusted code paths
/// - **Deny**: Explicitly block access to specific permissions
/// - **PermitOnly**: Allow only specified permissions, blocking all others
/// - **Request**: Assembly-level permission requests (minimum, optional, refuse)
///
/// # Permission Set Serialization
///
/// Permission sets are stored as binary blobs containing serialized .NET security
/// permissions. Common permission types include:
/// - **FileIOPermission**: File system access control
/// - **SecurityPermission**: Core security infrastructure permissions
/// - **RegistryPermission**: Windows registry access control
/// - **ReflectionPermission**: Reflection and metadata access control
/// - **EnvironmentPermission**: Environment variable access control
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(&mut assembly);
///
/// // Create a demand for FileIOPermission on a method
/// let method_ref = CodedIndex::new(TableId::MethodDef, 1); // Target method
/// let file_permission = vec![0x01, 0x02, 0x03, 0x04]; // Simple permission blob
///
/// let file_security = DeclSecurityBuilder::new()
///     .action(SecurityAction::Demand)
///     .parent(method_ref)
///     .permission_set(&file_permission)
///     .build(&mut context)?;
///
/// // Create an assembly-level security request for minimum permissions
/// let assembly_ref = CodedIndex::new(TableId::Assembly, 1); // Assembly target
/// let min_permissions = vec![0x01, 0x01, 0x00, 0xFF]; // Minimum permission set
///
/// let assembly_security = DeclSecurityBuilder::new()
///     .action(SecurityAction::RequestMinimum)
///     .parent(assembly_ref)
///     .permission_set(&min_permissions)
///     .build(&mut context)?;
///
/// // Create a type-level link demand for full trust
/// let type_ref = CodedIndex::new(TableId::TypeDef, 1); // Target type
/// let full_trust = vec![0x01, 0x01, 0x00, 0x00]; // Full trust permission set
///
/// let type_security = DeclSecurityBuilder::new()
///     .action(SecurityAction::LinkDemand)
///     .parent(type_ref)
///     .permission_set(&full_trust)
///     .build(&mut context)?;
///
/// // Create a security assertion for elevated privileges
/// let trusted_method = CodedIndex::new(TableId::MethodDef, 2); // Trusted method
///
/// let assertion_security = DeclSecurityBuilder::new()
///     .action(SecurityAction::Assert)
///     .parent(trusted_method)
///     .unrestricted_permission_set() // Use the convenience method
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct DeclSecurityBuilder {
    action: Option<u16>,
    parent: Option<CodedIndex>,
    permission_set: Option<Vec<u8>>,
}

impl Default for DeclSecurityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeclSecurityBuilder {
    /// Creates a new DeclSecurityBuilder.
    ///
    /// # Returns
    ///
    /// A new [`DeclSecurityBuilder`] instance ready for configuration.
    pub fn new() -> Self {
        Self {
            action: None,
            parent: None,
            permission_set: None,
        }
    }

    /// Sets the security action using the SecurityAction enumeration.
    ///
    /// The security action determines how the permission set should be applied
    /// and when security checks are performed. Different actions have different
    /// enforcement semantics and timing characteristics.
    ///
    /// Security action categories:
    /// - **Runtime Actions**: Demand, Assert, Deny, PermitOnly (checked during execution)
    /// - **Link Actions**: LinkDemand, NonCasLinkDemand (checked during JIT compilation)
    /// - **Inheritance Actions**: InheritanceDemand, NonCasInheritance (checked during inheritance)
    /// - **Request Actions**: RequestMinimum, RequestOptional, RequestRefuse (assembly-level)
    /// - **PreJIT Actions**: PrejitGrant, PrejitDeny (ahead-of-time compilation)
    ///
    /// # Arguments
    ///
    /// * `action` - The security action enumeration value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn action(mut self, action: SecurityAction) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Sets the security action using a raw u16 value.
    ///
    /// This method allows setting security actions that may not be covered by
    /// the standard SecurityAction enumeration, including future extensions
    /// and custom security action values.
    ///
    /// # Arguments
    ///
    /// * `action` - The raw security action value
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn action_raw(mut self, action: u16) -> Self {
        self.action = Some(action);
        self
    }

    /// Sets the parent entity that this security declaration applies to.
    ///
    /// The parent must be a valid `HasDeclSecurity` coded index that references
    /// an assembly, type definition, or method definition. This establishes
    /// the scope and target of the security declaration.
    ///
    /// Valid parent types include:
    /// - `Assembly` - Assembly-level security policies and permission requests
    /// - `TypeDef` - Type-level security applied to classes, interfaces, and structs
    /// - `MethodDef` - Method-level security for individual method implementations
    ///
    /// Security scope considerations:
    /// - **Assembly security**: Affects the entire assembly and all contained code
    /// - **Type security**: Affects all members of the type including methods and properties
    /// - **Method security**: Affects only the specific method implementation
    /// - **Inheritance**: Type and method security can be inherited by derived types
    ///
    /// # Arguments
    ///
    /// * `parent` - A `HasDeclSecurity` coded index pointing to the target entity
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn parent(mut self, parent: CodedIndex) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the permission set blob containing serialized security permissions.
    ///
    /// The permission set contains the binary representation of .NET security
    /// permissions that define what operations are allowed, denied, or required.
    /// This data is serialized according to .NET's security permission format.
    ///
    /// Permission set structure:
    /// - **Permission Count**: Number of permissions in the set
    /// - **Permission Entries**: Each permission with type and parameters
    /// - **Serialization Format**: Binary format specific to .NET security
    /// - **Version Compatibility**: Must match the target .NET Framework version
    ///
    /// Common permission types:
    /// - **FileIOPermission**: File system access (read, write, append, path discovery)
    /// - **SecurityPermission**: Core security operations (assertion, serialization, etc.)
    /// - **ReflectionPermission**: Metadata and reflection access control
    /// - **RegistryPermission**: Windows registry access control
    /// - **EnvironmentPermission**: Environment variable access control
    /// - **UIPermission**: User interface access control
    ///
    /// # Arguments
    ///
    /// * `permission_set` - The binary blob containing serialized security permissions
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn permission_set(mut self, permission_set: &[u8]) -> Self {
        self.permission_set = Some(permission_set.to_vec());
        self
    }

    /// Creates an unrestricted permission set for full trust scenarios.
    ///
    /// This convenience method creates a permission set that grants unrestricted
    /// access to all security permissions. This is typically used for fully
    /// trusted assemblies and methods that require elevated privileges.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    pub fn unrestricted_permission_set(mut self) -> Self {
        // Create a minimal unrestricted permission set blob
        // This is a simplified representation - in practice, you'd want to create
        // a proper .NET permission set with the SecurityPermission class
        let unrestricted_blob = vec![
            0x01, // Permission set version
            0x01, // Number of permissions
            0x00, // SecurityPermission type indicator (simplified)
            0xFF, // Unrestricted flag
        ];
        self.permission_set = Some(unrestricted_blob);
        self
    }

    /// Builds the declarative security entry and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the permission set
    /// blob to the blob heap, creates the raw security declaration structure,
    /// and adds it to the DeclSecurity table with proper token generation.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`Token`] representing the newly created security declaration, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if action is not set
    /// - Returns error if parent is not set
    /// - Returns error if permission_set is not set or empty
    /// - Returns error if parent is not a valid HasDeclSecurity coded index
    /// - Returns error if blob operations fail
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let action = self
            .action
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Security action is required".to_string(),
            })?;

        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Security parent is required".to_string(),
            })?;

        let permission_set =
            self.permission_set
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Permission set is required".to_string(),
                })?;

        if permission_set.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Permission set cannot be empty".to_string(),
            });
        }

        let valid_parent_tables = CodedIndexType::HasDeclSecurity.tables();
        if !valid_parent_tables.contains(&parent.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Parent must be a HasDeclSecurity coded index (TypeDef/MethodDef/Assembly), got {:?}",
                    parent.tag
                ),
            });
        }

        if action == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "Security action cannot be 0".to_string(),
            });
        }

        let permission_set_index = context.add_blob(&permission_set)?;

        let rid = context.next_rid(TableId::DeclSecurity);

        let token_value = ((TableId::DeclSecurity as u32) << 24) | rid;
        let token = Token::new(token_value);

        let decl_security_raw = DeclSecurityRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            action,
            parent,
            permission_set: permission_set_index,
        };

        context.add_table_row(
            TableId::DeclSecurity,
            TableDataOwned::DeclSecurity(decl_security_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        cilassembly::{BuilderContext, CilAssembly},
        cilassemblyview::CilAssemblyView,
        security::SecurityAction,
    };
    use std::path::PathBuf;

    #[test]
    fn test_decl_security_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);

            // Check existing DeclSecurity table count
            let existing_count = assembly.original_table_row_count(TableId::DeclSecurity);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(&mut assembly);

            // Create a basic security declaration
            let method_ref = CodedIndex::new(TableId::MethodDef, 1); // Method target
            let permission_blob = vec![0x01, 0x02, 0x03, 0x04]; // Simple test blob

            let token = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(method_ref)
                .permission_set(&permission_blob)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x0E000000); // DeclSecurity table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_decl_security_builder_different_actions() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            // Test different security actions
            let actions = [
                SecurityAction::Demand,
                SecurityAction::Assert,
                SecurityAction::Deny,
                SecurityAction::LinkDemand,
                SecurityAction::InheritanceDemand,
                SecurityAction::RequestMinimum,
                SecurityAction::PermitOnly,
            ];

            for (i, &action) in actions.iter().enumerate() {
                let parent = CodedIndex::new(TableId::TypeDef, (i + 1) as u32);

                let token = DeclSecurityBuilder::new()
                    .action(action)
                    .parent(parent)
                    .permission_set(&permission_blob)
                    .build(&mut context)
                    .unwrap();

                // All should succeed with DeclSecurity table prefix
                assert_eq!(token.value() & 0xFF000000, 0x0E000000);
            }
        }
    }

    #[test]
    fn test_decl_security_builder_different_parents() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            // Test different parent types (HasDeclSecurity coded index)
            let assembly_parent = CodedIndex::new(TableId::Assembly, 1);
            let type_parent = CodedIndex::new(TableId::TypeDef, 1);
            let method_parent = CodedIndex::new(TableId::MethodDef, 1);

            // Assembly security
            let assembly_security = DeclSecurityBuilder::new()
                .action(SecurityAction::RequestMinimum)
                .parent(assembly_parent)
                .permission_set(&permission_blob)
                .build(&mut context)
                .unwrap();

            // Type security
            let type_security = DeclSecurityBuilder::new()
                .action(SecurityAction::LinkDemand)
                .parent(type_parent)
                .permission_set(&permission_blob)
                .build(&mut context)
                .unwrap();

            // Method security
            let method_security = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(method_parent)
                .permission_set(&permission_blob)
                .build(&mut context)
                .unwrap();

            // All should succeed with different tokens
            assert_eq!(assembly_security.value() & 0xFF000000, 0x0E000000);
            assert_eq!(type_security.value() & 0xFF000000, 0x0E000000);
            assert_eq!(method_security.value() & 0xFF000000, 0x0E000000);
            assert_ne!(assembly_security.value(), type_security.value());
            assert_ne!(assembly_security.value(), method_security.value());
            assert_ne!(type_security.value(), method_security.value());
        }
    }

    #[test]
    fn test_decl_security_builder_raw_action() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let parent_ref = CodedIndex::new(TableId::MethodDef, 1);
            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            // Test setting action with raw u16 value
            let token = DeclSecurityBuilder::new()
                .action_raw(0x0002) // Demand action as raw value
                .parent(parent_ref)
                .permission_set(&permission_blob)
                .build(&mut context)
                .unwrap();

            // Should succeed
            assert_eq!(token.value() & 0xFF000000, 0x0E000000);
        }
    }

    #[test]
    fn test_decl_security_builder_unrestricted_permission() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let parent_ref = CodedIndex::new(TableId::TypeDef, 1);

            // Test unrestricted permission set convenience method
            let token = DeclSecurityBuilder::new()
                .action(SecurityAction::Assert)
                .parent(parent_ref)
                .unrestricted_permission_set()
                .build(&mut context)
                .unwrap();

            // Should succeed
            assert_eq!(token.value() & 0xFF000000, 0x0E000000);
        }
    }

    #[test]
    fn test_decl_security_builder_missing_action() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let parent_ref = CodedIndex::new(TableId::MethodDef, 1);
            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            let result = DeclSecurityBuilder::new()
                .parent(parent_ref)
                .permission_set(&permission_blob)
                // Missing action
                .build(&mut context);

            // Should fail because action is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decl_security_builder_missing_parent() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            let result = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .permission_set(&permission_blob)
                // Missing parent
                .build(&mut context);

            // Should fail because parent is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decl_security_builder_missing_permission_set() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let parent_ref = CodedIndex::new(TableId::MethodDef, 1);

            let result = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(parent_ref)
                // Missing permission_set
                .build(&mut context);

            // Should fail because permission set is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decl_security_builder_empty_permission_set() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let parent_ref = CodedIndex::new(TableId::MethodDef, 1);
            let empty_blob = vec![]; // Empty permission set

            let result = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(parent_ref)
                .permission_set(&empty_blob)
                .build(&mut context);

            // Should fail because permission set cannot be empty
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decl_security_builder_invalid_parent_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Use a table type that's not valid for HasDeclSecurity
            let invalid_parent = CodedIndex::new(TableId::Field, 1); // Field not in HasDeclSecurity
            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            let result = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(invalid_parent)
                .permission_set(&permission_blob)
                .build(&mut context);

            // Should fail because parent type is not valid for HasDeclSecurity
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decl_security_builder_zero_action() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let parent_ref = CodedIndex::new(TableId::MethodDef, 1);
            let permission_blob = vec![0x01, 0x02, 0x03, 0x04];

            let result = DeclSecurityBuilder::new()
                .action_raw(0) // Invalid zero action
                .parent(parent_ref)
                .permission_set(&permission_blob)
                .build(&mut context);

            // Should fail because action cannot be 0
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decl_security_builder_security_action_conversion() {
        // Test SecurityAction enum conversion methods
        assert_eq!(SecurityAction::Demand, 0x0002.into());
        assert_eq!(SecurityAction::Assert, 0x0003.into());
        assert_eq!(SecurityAction::Deny, 0x0001.into());

        assert_eq!(SecurityAction::from(0x0002), SecurityAction::Demand);
        assert_eq!(SecurityAction::from(0x0003), SecurityAction::Assert);
        assert_eq!(SecurityAction::from(0x0001), SecurityAction::Deny);
        assert_eq!(
            SecurityAction::from(0xFFFF),
            SecurityAction::Unknown(0xFFFF)
        ); // Invalid value
    }

    #[test]
    fn test_decl_security_builder_multiple_declarations() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            let method_ref = CodedIndex::new(TableId::MethodDef, 1);
            let permission_blob1 = vec![0x01, 0x02, 0x03, 0x04]; // First permission set
            let permission_blob2 = vec![0x05, 0x06, 0x07, 0x08]; // Second permission set

            // Create multiple security declarations for the same method
            let demand_security = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(method_ref.clone())
                .permission_set(&permission_blob1)
                .build(&mut context)
                .unwrap();

            let assert_security = DeclSecurityBuilder::new()
                .action(SecurityAction::Assert)
                .parent(method_ref) // Same method, different action
                .permission_set(&permission_blob2)
                .build(&mut context)
                .unwrap();

            // Both should succeed and have different RIDs
            assert_eq!(demand_security.value() & 0xFF000000, 0x0E000000);
            assert_eq!(assert_security.value() & 0xFF000000, 0x0E000000);
            assert_ne!(
                demand_security.value() & 0x00FFFFFF,
                assert_security.value() & 0x00FFFFFF
            );
        }
    }

    #[test]
    fn test_decl_security_builder_realistic_scenario() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let mut assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(&mut assembly);

            // Realistic scenario: Secure file access method
            let file_method = CodedIndex::new(TableId::MethodDef, 1);

            // Create a realistic permission blob (simplified for testing)
            let file_io_permission = vec![
                0x01, // Version
                0x01, // Number of permissions
                0x10, 0x20, 0x30, 0x40, // FileIOPermission type info (simplified)
                0x02, // Read flag
                0x00, 0x08, // Path length
                b'C', 0x00, b':', 0x00, b'\\', 0x00, b'*', 0x00, // C:\* in UTF-16
            ];

            let file_security = DeclSecurityBuilder::new()
                .action(SecurityAction::Demand)
                .parent(file_method)
                .permission_set(&file_io_permission)
                .build(&mut context)
                .unwrap();

            // Assembly-level security request
            let assembly_ref = CodedIndex::new(TableId::Assembly, 1);

            let assembly_security = DeclSecurityBuilder::new()
                .action(SecurityAction::RequestMinimum)
                .parent(assembly_ref)
                .unrestricted_permission_set() // Full trust request
                .build(&mut context)
                .unwrap();

            // Privileged method with assertion
            let privileged_method = CodedIndex::new(TableId::MethodDef, 2);

            let privilege_security = DeclSecurityBuilder::new()
                .action(SecurityAction::Assert)
                .parent(privileged_method)
                .unrestricted_permission_set()
                .build(&mut context)
                .unwrap();

            // All should succeed with proper tokens
            assert_eq!(file_security.value() & 0xFF000000, 0x0E000000);
            assert_eq!(assembly_security.value() & 0xFF000000, 0x0E000000);
            assert_eq!(privilege_security.value() & 0xFF000000, 0x0E000000);

            // All should have different RIDs
            assert_ne!(
                file_security.value() & 0x00FFFFFF,
                assembly_security.value() & 0x00FFFFFF
            );
            assert_ne!(
                file_security.value() & 0x00FFFFFF,
                privilege_security.value() & 0x00FFFFFF
            );
            assert_ne!(
                assembly_security.value() & 0x00FFFFFF,
                privilege_security.value() & 0x00FFFFFF
            );
        }
    }
}
