//! InterfaceImplBuilder for creating interface implementation declarations.
//!
//! This module provides [`crate::metadata::tables::interfaceimpl::InterfaceImplBuilder`] for creating InterfaceImpl table entries
//! with a fluent API. Interface implementations establish the relationship between types
//! and the interfaces they implement, enabling .NET's interface-based polymorphism,
//! multiple inheritance support, and runtime type compatibility.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{CodedIndex, CodedIndexType, InterfaceImplRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating InterfaceImpl metadata entries.
///
/// `InterfaceImplBuilder` provides a fluent API for creating InterfaceImpl table entries
/// with validation and automatic heap management. Interface implementations define the
/// relationship between implementing types and their interfaces, enabling polymorphic
/// dispatch, multiple inheritance scenarios, and runtime type compatibility checking.
///
/// # Interface Implementation Model
///
/// .NET interface implementations follow a standard pattern:
/// - **Implementing Type**: The class or interface that implements the target interface
/// - **Implemented Interface**: The interface being implemented or extended
/// - **Method Resolution**: Runtime mapping of interface methods to concrete implementations
/// - **Type Compatibility**: Enables casting between implementing types and interfaces
///
/// # Coded Index Types
///
/// Interface implementations use specific table references:
/// - **Class**: Direct `TypeDef` index referencing the implementing type
/// - **Interface**: `TypeDefOrRef` coded index for the implemented interface
///
/// # Implementation Scenarios
///
/// Interface implementations support several important scenarios:
/// - **Class Interface Implementation**: Classes implementing one or more interfaces
/// - **Interface Extension**: Interfaces extending other interfaces (inheritance)
/// - **Generic Interface Implementation**: Types implementing generic interfaces with specific type arguments
/// - **Multiple Interface Implementation**: Types implementing multiple unrelated interfaces
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{InterfaceImplBuilder, CodedIndex, TableId};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create a class implementing an interface
/// let implementing_class = 1; // TypeDef RID for MyClass
/// let target_interface = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // IDisposable from mscorlib
///
/// let impl_declaration = InterfaceImplBuilder::new()
///     .class(implementing_class)
///     .interface(target_interface)
///     .build(&mut context)?;
///
/// // Create an interface extending another interface  
/// let derived_interface = 2; // TypeDef RID for IMyInterface
/// let base_interface = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // IComparable from mscorlib
///
/// let interface_extension = InterfaceImplBuilder::new()
///     .class(derived_interface)
///     .interface(base_interface)
///     .build(&mut context)?;
///
/// // Create a generic interface implementation
/// let generic_class = 3; // TypeDef RID for MyGenericClass
/// let generic_interface = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // IEnumerable<string>
///
/// let generic_impl = InterfaceImplBuilder::new()
///     .class(generic_class)
///     .interface(generic_interface)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct InterfaceImplBuilder {
    class: Option<u32>,
    interface: Option<CodedIndex>,
}

impl Default for InterfaceImplBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceImplBuilder {
    /// Creates a new InterfaceImplBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::interfaceimpl::InterfaceImplBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: None,
            interface: None,
        }
    }

    /// Sets the implementing type (class or interface).
    ///
    /// The class must be a valid `TypeDef` RID that references a type definition
    /// in the current assembly. This type will be marked as implementing or extending
    /// the target interface specified in the interface field.
    ///
    /// Implementation scenarios:
    /// - **Class Implementation**: A class implementing an interface contract
    /// - **Interface Extension**: An interface extending another interface (inheritance)
    /// - **Generic Type Implementation**: Generic types implementing parameterized interfaces
    /// - **Value Type Implementation**: Structs and enums implementing interface contracts
    ///
    /// # Arguments
    ///
    /// * `class` - A `TypeDef` RID pointing to the implementing type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn class(mut self, class: u32) -> Self {
        self.class = Some(class);
        self
    }

    /// Sets the target interface being implemented.
    ///
    /// The interface must be a valid `TypeDefOrRef` coded index that references
    /// an interface type. This establishes which interface contract the implementing
    /// type must fulfill through method implementations.
    ///
    /// Valid interface types include:
    /// - `TypeDef` - Interfaces defined in the current assembly
    /// - `TypeRef` - Interfaces from external assemblies (e.g., system interfaces)
    /// - `TypeSpec` - Generic interface instantiations with specific type arguments
    ///
    /// # Arguments
    ///
    /// * `interface` - A `TypeDefOrRef` coded index pointing to the target interface
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn interface(mut self, interface: CodedIndex) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Builds the interface implementation and adds it to the assembly.
    ///
    /// This method validates all required fields are set, creates the raw interface
    /// implementation structure, and adds it to the InterfaceImpl table with proper
    /// token generation and table management.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created interface implementation, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if class is not set
    /// - Returns error if interface is not set
    /// - Returns error if class RID is 0 (invalid RID)
    /// - Returns error if interface is not a valid TypeDefOrRef coded index
    /// - Returns error if table operations fail
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let class = self
            .class
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "InterfaceImpl class is required".to_string(),
            })?;

        let interface = self
            .interface
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "InterfaceImpl interface is required".to_string(),
            })?;

        if class == 0 {
            return Err(Error::ModificationInvalidOperation {
                details: "InterfaceImpl class RID cannot be 0".to_string(),
            });
        }

        let valid_interface_tables = CodedIndexType::TypeDefOrRef.tables();
        if !valid_interface_tables.contains(&interface.tag) {
            return Err(Error::ModificationInvalidOperation {
                details: format!(
                    "Interface must be a TypeDefOrRef coded index (TypeDef/TypeRef/TypeSpec), got {:?}",
                    interface.tag
                ),
            });
        }

        let rid = context.next_rid(TableId::InterfaceImpl);

        let token_value = ((TableId::InterfaceImpl as u32) << 24) | rid;
        let token = Token::new(token_value);

        let interface_impl_raw = InterfaceImplRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            class,
            interface,
        };

        context.table_row_add(
            TableId::InterfaceImpl,
            TableDataOwned::InterfaceImpl(interface_impl_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::BuilderContext, test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_interface_impl_builder_basic() {
        if let Ok(assembly) = get_test_assembly() {
            // Check existing InterfaceImpl table count
            let existing_count = assembly.original_table_row_count(TableId::InterfaceImpl);
            let expected_rid = existing_count + 1;

            let mut context = BuilderContext::new(assembly);

            // Create a basic interface implementation
            let implementing_class = 1; // TypeDef RID
            let target_interface =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // External interface

            let token = InterfaceImplBuilder::new()
                .class(implementing_class)
                .interface(target_interface)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x09000000); // InterfaceImpl table prefix
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid); // RID should be existing + 1
        }
    }

    #[test]
    fn test_interface_impl_builder_interface_extension() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            // Create an interface extending another interface
            let derived_interface = 2; // TypeDef RID for derived interface
            let base_interface = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Local base interface

            let token = InterfaceImplBuilder::new()
                .class(derived_interface)
                .interface(base_interface)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x09000000);
        }
    }

    #[test]
    fn test_interface_impl_builder_generic_interface() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            // Create a generic interface implementation
            let implementing_class = 3; // TypeDef RID
            let generic_interface =
                CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface instantiation

            let token = InterfaceImplBuilder::new()
                .class(implementing_class)
                .interface(generic_interface)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x09000000);
        }
    }

    #[test]
    fn test_interface_impl_builder_missing_class() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            let target_interface =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

            let result = InterfaceImplBuilder::new()
                .interface(target_interface)
                .build(&mut context);

            // Should fail because class is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_interface_impl_builder_missing_interface() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            let implementing_class = 1; // TypeDef RID

            let result = InterfaceImplBuilder::new()
                .class(implementing_class)
                .build(&mut context);

            // Should fail because interface is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_interface_impl_builder_zero_class_rid() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            let target_interface =
                CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

            let result = InterfaceImplBuilder::new()
                .class(0) // Invalid RID
                .interface(target_interface)
                .build(&mut context);

            // Should fail because class RID cannot be 0
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_interface_impl_builder_invalid_interface_type() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            let implementing_class = 1; // TypeDef RID
                                        // Use a table type that's not valid for TypeDefOrRef
            let invalid_interface =
                CodedIndex::new(TableId::Field, 1, CodedIndexType::TypeDefOrRef); // Field not in TypeDefOrRef

            let result = InterfaceImplBuilder::new()
                .class(implementing_class)
                .interface(invalid_interface)
                .build(&mut context);

            // Should fail because interface type is not valid for TypeDefOrRef
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_interface_impl_builder_multiple_implementations() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            let class1 = 1; // TypeDef RID
            let class2 = 2; // TypeDef RID
            let class3 = 3; // TypeDef RID

            let interface1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // IDisposable
            let interface2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // IComparable
            let interface3 = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface

            // Create multiple interface implementations
            let impl1 = InterfaceImplBuilder::new()
                .class(class1)
                .interface(interface1.clone())
                .build(&mut context)
                .unwrap();

            let impl2 = InterfaceImplBuilder::new()
                .class(class1) // Same class implementing multiple interfaces
                .interface(interface2.clone())
                .build(&mut context)
                .unwrap();

            let impl3 = InterfaceImplBuilder::new()
                .class(class2)
                .interface(interface1) // Same interface implemented by multiple classes
                .build(&mut context)
                .unwrap();

            let impl4 = InterfaceImplBuilder::new()
                .class(class3)
                .interface(interface3)
                .build(&mut context)
                .unwrap();

            // All should succeed and have different RIDs
            assert_ne!(impl1.value() & 0x00FFFFFF, impl2.value() & 0x00FFFFFF);
            assert_ne!(impl1.value() & 0x00FFFFFF, impl3.value() & 0x00FFFFFF);
            assert_ne!(impl1.value() & 0x00FFFFFF, impl4.value() & 0x00FFFFFF);
            assert_ne!(impl2.value() & 0x00FFFFFF, impl3.value() & 0x00FFFFFF);
            assert_ne!(impl2.value() & 0x00FFFFFF, impl4.value() & 0x00FFFFFF);
            assert_ne!(impl3.value() & 0x00FFFFFF, impl4.value() & 0x00FFFFFF);

            // All should have InterfaceImpl table prefix
            assert_eq!(impl1.value() & 0xFF000000, 0x09000000);
            assert_eq!(impl2.value() & 0xFF000000, 0x09000000);
            assert_eq!(impl3.value() & 0xFF000000, 0x09000000);
            assert_eq!(impl4.value() & 0xFF000000, 0x09000000);
        }
    }

    #[test]
    fn test_interface_impl_builder_complex_inheritance() {
        if let Ok(assembly) = get_test_assembly() {
            let mut context = BuilderContext::new(assembly);

            // Create a complex inheritance scenario
            let base_class = 1; // TypeDef RID for base class
            let derived_class = 2; // TypeDef RID for derived class
            let interface1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // Base interface
            let interface2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // Derived interface

            // Base class implements interface1
            let base_impl = InterfaceImplBuilder::new()
                .class(base_class)
                .interface(interface1)
                .build(&mut context)
                .unwrap();

            // Derived class implements interface2 (additional interface)
            let derived_impl = InterfaceImplBuilder::new()
                .class(derived_class)
                .interface(interface2)
                .build(&mut context)
                .unwrap();

            // Both should succeed with different tokens
            assert_ne!(base_impl.value(), derived_impl.value());
            assert_eq!(base_impl.value() & 0xFF000000, 0x09000000);
            assert_eq!(derived_impl.value() & 0xFF000000, 0x09000000);
        }
    }
}
