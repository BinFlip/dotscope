//! GenericParamConstraintBuilder for creating generic parameter constraint specifications.
//!
//! This module provides [`crate::metadata::tables::genericparamconstraint::GenericParamConstraintBuilder`] for creating GenericParamConstraint table entries
//! with a fluent API. Generic parameter constraints specify type restrictions on generic parameters,
//! enabling type-safe generic programming with base class constraints, interface requirements,
//! and complex type relationships in .NET assemblies.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{CodedIndex, CodedIndexType, GenericParamConstraintRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating GenericParamConstraint metadata entries.
///
/// `GenericParamConstraintBuilder` provides a fluent API for creating GenericParamConstraint table entries
/// with validation and automatic table management. Generic parameter constraints define type restrictions
/// on generic parameters, enabling sophisticated type-safe programming with inheritance constraints,
/// interface requirements, value/reference type restrictions, and constructor constraints.
///
/// # Generic Constraint Model
///
/// .NET generic parameter constraints follow a structured pattern:
/// - **Owner Parameter**: The generic parameter that has this constraint applied
/// - **Constraint Type**: The type that the parameter must satisfy (base class, interface, etc.)
/// - **Multiple Constraints**: A parameter can have multiple constraint entries
/// - **Constraint Hierarchy**: Constraints interact with variance and inheritance rules
///
/// # Coded Index Types
///
/// Generic parameter constraints use specific table references:
/// - **Owner**: Direct GenericParam table index (RID or Token)
/// - **Constraint**: `TypeDefOrRef` coded index for the constraint type
///
/// # Constraint Types and Scenarios
///
/// Generic parameter constraints support various type restriction scenarios:
/// - **Base Class Constraints**: `where T : BaseClass` (TypeDef/TypeRef)
/// - **Interface Constraints**: `where T : IInterface` (TypeDef/TypeRef)
/// - **Generic Type Constraints**: `where T : IComparable<T>` (TypeSpec)
/// - **Value Type Constraints**: `where T : struct` (handled via GenericParamAttributes)
/// - **Reference Type Constraints**: `where T : class` (handled via GenericParamAttributes)
/// - **Constructor Constraints**: `where T : new()` (handled via GenericParamAttributes)
///
/// # Multiple Constraints
///
/// A single generic parameter can have multiple constraint entries:
/// ```text
/// where T : BaseClass, IInterface1, IInterface2, new()
/// ```
/// This creates multiple GenericParamConstraint entries (one for BaseClass, one for each interface),
/// plus GenericParamAttributes flags for the constructor constraint.
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{GenericParamConstraintBuilder, CodedIndex, TableId};
/// # use dotscope::metadata::token::Token;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create a base class constraint: where T : BaseClass
/// let generic_param_token = Token::new(0x2A000001); // GenericParam RID 1
/// let base_class_ref = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Local base class
///
/// let base_constraint = GenericParamConstraintBuilder::new()
///     .owner(generic_param_token)
///     .constraint(base_class_ref)
///     .build(&mut context)?;
///
/// // Create an interface constraint: where T : IComparable
/// let interface_ref = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // External interface
///
/// let interface_constraint = GenericParamConstraintBuilder::new()
///     .owner(generic_param_token) // Same parameter can have multiple constraints
///     .constraint(interface_ref)
///     .build(&mut context)?;
///
/// // Create a generic interface constraint: where T : IEnumerable<string>
/// let generic_interface_spec = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic type spec
///
/// let generic_constraint = GenericParamConstraintBuilder::new()
///     .owner(generic_param_token)
///     .constraint(generic_interface_spec)
///     .build(&mut context)?;
///
/// // Create constraints for a method-level generic parameter
/// let method_param_token = Token::new(0x2A000002); // GenericParam RID 2 (method parameter)
/// let system_object_ref = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // System.Object
///
/// let method_constraint = GenericParamConstraintBuilder::new()
///     .owner(method_param_token)
///     .constraint(system_object_ref)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct GenericParamConstraintBuilder {
    owner: Option<Token>,
    constraint: Option<CodedIndex>,
}

impl Default for GenericParamConstraintBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericParamConstraintBuilder {
    /// Creates a new GenericParamConstraintBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::genericparamconstraint::GenericParamConstraintBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: None,
            constraint: None,
        }
    }

    /// Sets the owning generic parameter.
    ///
    /// The owner must be a valid GenericParam token that references a generic parameter
    /// defined in the current assembly. This establishes which generic parameter will
    /// have this constraint applied to it during type checking and instantiation.
    ///
    /// Multiple constraints can be applied to the same parameter by creating multiple
    /// GenericParamConstraint entries with the same owner token.
    ///
    /// Parameter types that can own constraints:
    /// - **Type-level parameters**: Generic parameters defined on classes, interfaces, structs
    /// - **Method-level parameters**: Generic parameters defined on individual methods
    /// - **Delegate parameters**: Generic parameters defined on delegate types
    ///
    /// # Arguments
    ///
    /// * `owner` - A GenericParam token pointing to the owning generic parameter
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn owner(mut self, owner: Token) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets the constraint type specification.
    ///
    /// The constraint must be a valid `TypeDefOrRef` coded index that references
    /// a type that the generic parameter must satisfy. This type becomes a compile-time
    /// and runtime constraint that limits which types can be used as arguments for
    /// the generic parameter.
    ///
    /// Valid constraint types include:
    /// - `TypeDef` - Base classes and interfaces defined in the current assembly
    /// - `TypeRef` - External base classes and interfaces from other assemblies
    /// - `TypeSpec` - Complex types including generic instantiations and constructed types
    ///
    /// Common constraint scenarios:
    /// - **Base Class**: Requires parameter to inherit from a specific class
    /// - **Interface**: Requires parameter to implement a specific interface
    /// - **Generic Interface**: Requires parameter to implement a generic interface with specific type arguments
    /// - **Constructed Type**: Complex type relationships involving arrays, pointers, or nested generics
    ///
    /// # Arguments
    ///
    /// * `constraint` - A `TypeDefOrRef` coded index pointing to the constraint type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn constraint(mut self, constraint: CodedIndex) -> Self {
        self.constraint = Some(constraint);
        self
    }

    /// Builds the generic parameter constraint and adds it to the assembly.
    ///
    /// This method validates all required fields are set, verifies the coded index types
    /// are correct, creates the raw constraint structure, and adds it to the
    /// GenericParamConstraint table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created generic parameter constraint, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if owner is not set
    /// - Returns error if constraint is not set
    /// - Returns error if owner is not a valid GenericParam token
    /// - Returns error if constraint is not a valid TypeDefOrRef coded index
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let owner = self
            .owner
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "GenericParamConstraint owner is required".to_string(),
            })?;

        let constraint = self
            .constraint
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "GenericParamConstraint constraint is required".to_string(),
            })?;

        if owner.table() != TableId::GenericParam as u8 {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Owner must be a GenericParam token, got table {:?}",
                    owner.table()
                ),
            });
        }

        if owner.row() == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "GenericParamConstraint owner RID cannot be 0".to_string(),
            });
        }

        let valid_constraint_tables = CodedIndexType::TypeDefOrRef.tables();
        if !valid_constraint_tables.contains(&constraint.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Constraint must be a TypeDefOrRef coded index (TypeDef/TypeRef/TypeSpec), got {:?}",
                    constraint.tag
                ),
            });
        }

        let rid = context.next_rid(TableId::GenericParamConstraint);

        let token_value = ((TableId::GenericParamConstraint as u32) << 24) | rid;
        let token = Token::new(token_value);

        let constraint_raw = GenericParamConstraintRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            owner: owner.row(),
            constraint,
        };

        context.table_row_add(
            TableId::GenericParamConstraint,
            TableDataOwned::GenericParamConstraint(constraint_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
    };
    use std::path::PathBuf;

    #[test]
    fn test_generic_param_constraint_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);

            // Check existing GenericParamConstraint table count
            let existing_count = assembly.original_table_row_count(TableId::GenericParamConstraint);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(assembly);

            // Create a basic generic parameter constraint
            let owner_token = Token::new(0x2A000001); // GenericParam RID 1
            let constraint_type =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // External base class

            let token = GenericParamConstraintBuilder::new()
                .owner(owner_token)
                .constraint(constraint_type)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x2C000000); // GenericParamConstraint table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_base_class() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create a base class constraint
            let generic_param = Token::new(0x2A000001); // GenericParam RID 1
            let base_class = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Local base class

            let token = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(base_class)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x2C000000);
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_interface() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create an interface constraint
            let generic_param = Token::new(0x2A000002); // GenericParam RID 2
            let interface_ref = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // External interface

            let token = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(interface_ref)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x2C000000);
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_generic_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create a generic type constraint (e.g., IComparable<T>)
            let generic_param = Token::new(0x2A000003); // GenericParam RID 3
            let generic_interface =
                CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface instantiation

            let token = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(generic_interface)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x2C000000);
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_missing_owner() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let constraint_type =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

            let result = GenericParamConstraintBuilder::new()
                .constraint(constraint_type)
                .build(&mut context);

            // Should fail because owner is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_missing_constraint() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let owner_token = Token::new(0x2A000001); // GenericParam RID 1

            let result = GenericParamConstraintBuilder::new()
                .owner(owner_token)
                .build(&mut context);

            // Should fail because constraint is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_invalid_owner_table() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Use a token that's not from GenericParam table
            let invalid_owner = Token::new(0x02000001); // TypeDef token instead
            let constraint_type =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

            let result = GenericParamConstraintBuilder::new()
                .owner(invalid_owner)
                .constraint(constraint_type)
                .build(&mut context);

            // Should fail because owner must be a GenericParam token
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_zero_owner_rid() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Use a GenericParam token with RID 0 (invalid)
            let invalid_owner = Token::new(0x2A000000); // GenericParam with RID 0
            let constraint_type =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

            let result = GenericParamConstraintBuilder::new()
                .owner(invalid_owner)
                .constraint(constraint_type)
                .build(&mut context);

            // Should fail because owner RID cannot be 0
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_invalid_constraint_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let owner_token = Token::new(0x2A000001); // GenericParam RID 1
                                                      // Use a table type that's not valid for TypeDefOrRef
            let invalid_constraint =
                CodedIndex::new(TableId::Field, 1, CodedIndexType::TypeDefOrRef); // Field not in TypeDefOrRef

            let result = GenericParamConstraintBuilder::new()
                .owner(owner_token)
                .constraint(invalid_constraint)
                .build(&mut context);

            // Should fail because constraint type is not valid for TypeDefOrRef
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_multiple_constraints() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let generic_param = Token::new(0x2A000001); // GenericParam RID 1

            // Create multiple constraints for the same parameter
            let base_class = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Base class constraint
            let interface1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // First interface
            let interface2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // Second interface
            let generic_interface =
                CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface

            let constraint1 = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(base_class)
                .build(&mut context)
                .unwrap();

            let constraint2 = GenericParamConstraintBuilder::new()
                .owner(generic_param) // Same parameter
                .constraint(interface1)
                .build(&mut context)
                .unwrap();

            let constraint3 = GenericParamConstraintBuilder::new()
                .owner(generic_param) // Same parameter
                .constraint(interface2)
                .build(&mut context)
                .unwrap();

            let constraint4 = GenericParamConstraintBuilder::new()
                .owner(generic_param) // Same parameter
                .constraint(generic_interface)
                .build(&mut context)
                .unwrap();

            // All should succeed and have different RIDs
            assert_ne!(
                constraint1.value() & 0x00FFFFFF,
                constraint2.value() & 0x00FFFFFF
            );
            assert_ne!(
                constraint1.value() & 0x00FFFFFF,
                constraint3.value() & 0x00FFFFFF
            );
            assert_ne!(
                constraint1.value() & 0x00FFFFFF,
                constraint4.value() & 0x00FFFFFF
            );
            assert_ne!(
                constraint2.value() & 0x00FFFFFF,
                constraint3.value() & 0x00FFFFFF
            );
            assert_ne!(
                constraint2.value() & 0x00FFFFFF,
                constraint4.value() & 0x00FFFFFF
            );
            assert_ne!(
                constraint3.value() & 0x00FFFFFF,
                constraint4.value() & 0x00FFFFFF
            );

            // All should have GenericParamConstraint table prefix
            assert_eq!(constraint1.value() & 0xFF000000, 0x2C000000);
            assert_eq!(constraint2.value() & 0xFF000000, 0x2C000000);
            assert_eq!(constraint3.value() & 0xFF000000, 0x2C000000);
            assert_eq!(constraint4.value() & 0xFF000000, 0x2C000000);
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_different_parameters() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Create constraints for different generic parameters
            let type_param = Token::new(0x2A000001); // Type-level parameter
            let method_param = Token::new(0x2A000002); // Method-level parameter

            let type_constraint =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // System.Object
            let method_constraint =
                CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // IDisposable

            let type_const = GenericParamConstraintBuilder::new()
                .owner(type_param)
                .constraint(type_constraint)
                .build(&mut context)
                .unwrap();

            let method_const = GenericParamConstraintBuilder::new()
                .owner(method_param)
                .constraint(method_constraint)
                .build(&mut context)
                .unwrap();

            // Both should succeed with different tokens
            assert_ne!(type_const.value(), method_const.value());
            assert_eq!(type_const.value() & 0xFF000000, 0x2C000000);
            assert_eq!(method_const.value() & 0xFF000000, 0x2C000000);
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_all_constraint_types() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let generic_param = Token::new(0x2A000001); // GenericParam RID 1

            // Test all valid TypeDefOrRef coded index types

            // TypeDef constraint (local type)
            let typedef_constraint = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(CodedIndex::new(
                    TableId::TypeDef,
                    1,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(&mut context)
                .unwrap();

            // TypeRef constraint (external type)
            let typeref_constraint = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(CodedIndex::new(
                    TableId::TypeRef,
                    1,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(&mut context)
                .unwrap();

            // TypeSpec constraint (generic type instantiation)
            let typespec_constraint = GenericParamConstraintBuilder::new()
                .owner(generic_param)
                .constraint(CodedIndex::new(
                    TableId::TypeSpec,
                    1,
                    CodedIndexType::TypeDefOrRef,
                ))
                .build(&mut context)
                .unwrap();

            // All should succeed and have different RIDs
            assert_ne!(
                typedef_constraint.value() & 0x00FFFFFF,
                typeref_constraint.value() & 0x00FFFFFF
            );
            assert_ne!(
                typedef_constraint.value() & 0x00FFFFFF,
                typespec_constraint.value() & 0x00FFFFFF
            );
            assert_ne!(
                typeref_constraint.value() & 0x00FFFFFF,
                typespec_constraint.value() & 0x00FFFFFF
            );

            // All should have GenericParamConstraint table prefix
            assert_eq!(typedef_constraint.value() & 0xFF000000, 0x2C000000);
            assert_eq!(typeref_constraint.value() & 0xFF000000, 0x2C000000);
            assert_eq!(typespec_constraint.value() & 0xFF000000, 0x2C000000);
        }
    }

    #[test]
    fn test_generic_param_constraint_builder_realistic_scenario() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Realistic scenario: class MyClass<T> where T : BaseClass, IComparable<T>, IDisposable
            let type_param_t = Token::new(0x2A000001); // T parameter

            // Base class constraint: T : BaseClass
            let base_class_constraint = GenericParamConstraintBuilder::new()
                .owner(type_param_t)
                .constraint(CodedIndex::new(
                    TableId::TypeDef,
                    1,
                    CodedIndexType::TypeDefOrRef,
                )) // Local BaseClass
                .build(&mut context)
                .unwrap();

            // Generic interface constraint: T : IComparable<T>
            let comparable_constraint = GenericParamConstraintBuilder::new()
                .owner(type_param_t)
                .constraint(CodedIndex::new(
                    TableId::TypeSpec,
                    1,
                    CodedIndexType::TypeDefOrRef,
                )) // IComparable<T> type spec
                .build(&mut context)
                .unwrap();

            // Interface constraint: T : IDisposable
            let disposable_constraint = GenericParamConstraintBuilder::new()
                .owner(type_param_t)
                .constraint(CodedIndex::new(
                    TableId::TypeRef,
                    1,
                    CodedIndexType::TypeDefOrRef,
                )) // External IDisposable
                .build(&mut context)
                .unwrap();

            // All constraints should be created successfully
            assert_eq!(base_class_constraint.value() & 0xFF000000, 0x2C000000);
            assert_eq!(comparable_constraint.value() & 0xFF000000, 0x2C000000);
            assert_eq!(disposable_constraint.value() & 0xFF000000, 0x2C000000);

            // All should have different RIDs but same table
            assert_ne!(
                base_class_constraint.value() & 0x00FFFFFF,
                comparable_constraint.value() & 0x00FFFFFF
            );
            assert_ne!(
                base_class_constraint.value() & 0x00FFFFFF,
                disposable_constraint.value() & 0x00FFFFFF
            );
            assert_ne!(
                comparable_constraint.value() & 0x00FFFFFF,
                disposable_constraint.value() & 0x00FFFFFF
            );
        }
    }
}
