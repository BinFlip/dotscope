//! # ExportedType Builder
//!
//! Provides a fluent API for building ExportedType table entries that define types exported from assemblies.
//! The ExportedType table enables cross-assembly type access, type forwarding during assembly refactoring,
//! and public interface definition for complex assembly structures. It supports multi-module assemblies
//! and type forwarding scenarios.
//!
//! ## Overview
//!
//! The `ExportedTypeBuilder` enables creation of exported type entries with:
//! - Type name and namespace specification (required)
//! - Type visibility and attribute configuration
//! - Implementation location setup (file-based or external assembly)
//! - TypeDef ID hints for optimization
//! - Automatic heap management and token generation
//!
//! ## Usage
//!
//! ```rust,ignore
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
//! # let assembly = CilAssembly::new(view);
//! # let mut context = BuilderContext::new(assembly);
//!
//! // Create a type forwarding entry
//! let assembly_ref_token = AssemblyRefBuilder::new()
//!     .name("MyApp.Core")
//!     .version(2, 0, 0, 0)
//!     .build(&mut context)?;
//!
//! let forwarded_type_token = ExportedTypeBuilder::new()
//!     .name("Customer")
//!     .namespace("MyApp.Models")
//!     .public()
//!     .implementation_assembly_ref(assembly_ref_token)
//!     .build(&mut context)?;
//!
//! // Create a multi-module assembly type export
//! let file_token = FileBuilder::new()
//!     .name("DataLayer.netmodule")
//!     .contains_metadata()
//!     .build(&mut context)?;
//!
//! let module_type_token = ExportedTypeBuilder::new()
//!     .name("Repository")
//!     .namespace("MyApp.Data")
//!     .public()
//!     .type_def_id(0x02000001) // TypeDef hint
//!     .implementation_file(file_token)
//!     .build(&mut context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Type name is required, implementation must be valid
//! - **Heap Management**: Strings are automatically added to heaps
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Implementation Support**: Methods for file-based and external assembly exports

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, ExportedTypeRaw, TableDataOwned, TableId, TypeAttributes,
        },
        token::Token,
    },
    Error, Result,
};

/// Builder for creating ExportedType table entries.
///
/// `ExportedTypeBuilder` provides a fluent API for creating entries in the ExportedType
/// metadata table, which contains information about types exported from assemblies for
/// cross-assembly access and type forwarding scenarios.
///
/// # Purpose
///
/// The ExportedType table serves several key functions:
/// - **Type Forwarding**: Redirecting type references during assembly refactoring
/// - **Multi-Module Assemblies**: Exposing types from different files within assemblies
/// - **Assembly Facades**: Creating simplified public interfaces over complex implementations
/// - **Cross-Assembly Access**: Enabling external assemblies to access exported types
/// - **Version Management**: Supporting type migration between assembly versions
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing ExportedType entries:
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
///
/// let exported_type_token = ExportedTypeBuilder::new()
///     .name("Customer")
///     .namespace("MyApp.Models")
///     .public()
///     .type_def_id(0x02000001)
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: A type name must be provided
/// - **Name Not Empty**: Type names cannot be empty strings
/// - **Implementation Validity**: Implementation references must point to valid tables
/// - **Table Type Validation**: Implementation must reference File, AssemblyRef, or ExportedType
///
/// # Integration
///
/// ExportedType entries integrate with other metadata structures:
/// - **File**: Multi-module assembly types reference File table entries
/// - **AssemblyRef**: Type forwarding references AssemblyRef entries
/// - **TypeDef**: Optional hints for efficient type resolution
#[derive(Debug, Clone)]
pub struct ExportedTypeBuilder {
    /// The name of the exported type
    name: Option<String>,
    /// The namespace of the exported type
    namespace: Option<String>,
    /// Type visibility and attribute flags
    flags: u32,
    /// Optional TypeDef ID hint for resolution optimization
    type_def_id: u32,
    /// Implementation reference for type location
    implementation: Option<CodedIndex>,
}

impl Default for ExportedTypeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportedTypeBuilder {
    /// Creates a new `ExportedTypeBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods. Type visibility defaults to
    /// `PUBLIC` and implementation defaults to None (must be set).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            namespace: None,
            flags: TypeAttributes::PUBLIC,
            type_def_id: 0,
            implementation: None,
        }
    }

    /// Sets the name of the exported type.
    ///
    /// Type names should be simple identifiers without namespace qualifiers
    /// (e.g., "Customer", "Repository", "ServiceProvider").
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the exported type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the namespace of the exported type.
    ///
    /// Namespaces organize types hierarchically and typically follow
    /// dot-separated naming conventions (e.g., "MyApp.Models", "System.Data").
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace of the exported type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .namespace("MyApp.Models");
    /// ```
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets type attributes using a bitmask.
    ///
    /// Type attributes control visibility, inheritance, and behavior characteristics.
    /// Use the `TypeAttributes` constants for standard values.
    ///
    /// # Arguments
    ///
    /// * `flags` - Type attributes bitmask
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::tables::TypeAttributes;
    /// let builder = ExportedTypeBuilder::new()
    ///     .flags(TypeAttributes::PUBLIC);
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Marks the type as public (accessible from external assemblies).
    ///
    /// Public types can be accessed by other assemblies and are part
    /// of the assembly's public API surface.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("PublicService")
    ///     .public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.flags = TypeAttributes::PUBLIC;
        self
    }

    /// Marks the type as not public (internal to the assembly).
    ///
    /// Non-public types are not accessible from external assemblies
    /// and are considered internal implementation details.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("InternalHelper")
    ///     .not_public();
    /// ```
    #[must_use]
    pub fn not_public(mut self) -> Self {
        self.flags = TypeAttributes::NOT_PUBLIC;
        self
    }

    /// Sets the TypeDef ID hint for resolution optimization.
    ///
    /// The TypeDef ID provides a hint for efficient type resolution
    /// when the exported type maps to a specific TypeDef entry.
    /// This is optional and may be 0 if no hint is available.
    ///
    /// # Arguments
    ///
    /// * `type_def_id` - The TypeDef ID hint (without table prefix)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .type_def_id(0x02000001); // TypeDef hint
    /// ```
    #[must_use]
    pub fn type_def_id(mut self, type_def_id: u32) -> Self {
        self.type_def_id = type_def_id;
        self
    }

    /// Sets the implementation to reference a File table entry.
    ///
    /// Use this for multi-module assembly scenarios where the type
    /// is defined in a different file within the same assembly.
    ///
    /// # Arguments
    ///
    /// * `file_token` - Token of the File table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let file_token = FileBuilder::new()
    ///     .name("DataLayer.netmodule")
    ///     .build(&mut context)?;
    ///
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Repository")
    ///     .implementation_file(file_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_file(mut self, file_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(
            TableId::File,
            file_token.row(),
            CodedIndexType::Implementation,
        ));
        self
    }

    /// Sets the implementation to reference an AssemblyRef table entry.
    ///
    /// Use this for type forwarding scenarios where the type has been
    /// moved to a different assembly and needs to be redirected.
    ///
    /// # Arguments
    ///
    /// * `assembly_ref_token` - Token of the AssemblyRef table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let assembly_ref_token = AssemblyRefBuilder::new()
    ///     .name("MyApp.Core")
    ///     .version(2, 0, 0, 0)
    ///     .build(&mut context)?;
    ///
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .implementation_assembly_ref(assembly_ref_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_assembly_ref(mut self, assembly_ref_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(
            TableId::AssemblyRef,
            assembly_ref_token.row(),
            CodedIndexType::Implementation,
        ));
        self
    }

    /// Sets the implementation to reference another ExportedType table entry.
    ///
    /// Use this for complex scenarios with nested export references,
    /// though this is rarely used in practice.
    ///
    /// # Arguments
    ///
    /// * `exported_type_token` - Token of the ExportedType table entry
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let base_export_token = ExportedTypeBuilder::new()
    ///     .name("BaseType")
    ///     .build(&mut context)?;
    ///
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("DerivedType")
    ///     .implementation_exported_type(base_export_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_exported_type(mut self, exported_type_token: Token) -> Self {
        self.implementation = Some(CodedIndex::new(
            TableId::ExportedType,
            exported_type_token.row(),
            CodedIndexType::Implementation,
        ));
        self
    }

    /// Builds the ExportedType entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings to the appropriate heaps,
    /// creates the ExportedType table entry, and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created ExportedType entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The type name is not set
    /// - The type name is empty
    /// - The implementation reference is not set
    /// - The implementation reference uses an invalid table type (must be File, AssemblyRef, or ExportedType)
    /// - The implementation reference has a row index of 0
    /// - There are issues adding strings to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    ///
    /// let exported_type_token = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .namespace("MyApp.Models")
    ///     .public()
    ///     .build(&mut context)?;
    ///
    /// println!("Created ExportedType with token: {}", exported_type_token);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let name = self
            .name
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "Type name is required for ExportedType".to_string(),
            })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Type name cannot be empty for ExportedType".to_string(),
            });
        }

        let implementation =
            self.implementation
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "Implementation is required for ExportedType".to_string(),
                })?;

        // Validate implementation reference
        match implementation.tag {
            TableId::File | TableId::AssemblyRef | TableId::ExportedType => {
                if implementation.row == 0 {
                    return Err(Error::ModificationInvalidOperation {
                        details: "Implementation reference row cannot be 0".to_string(),
                    });
                }
            }
            _ => {
                return Err(Error::ModificationInvalidOperation {
                    details: format!(
                        "Invalid implementation table type: {:?}. Must be File, AssemblyRef, or ExportedType",
                        implementation.tag
                    ),
                });
            }
        }

        let name_index = context.string_get_or_add(&name)?;
        let namespace_index = if let Some(namespace) = self.namespace {
            if namespace.is_empty() {
                0
            } else {
                context.string_get_or_add(&namespace)?
            }
        } else {
            0
        };

        let rid = context.next_rid(TableId::ExportedType);
        let token = Token::new(((TableId::ExportedType as u32) << 24) | rid);

        let exported_type = ExportedTypeRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags: self.flags,
            type_def_id: self.type_def_id,
            name: name_index,
            namespace: namespace_index,
            implementation,
        };

        let table_data = TableDataOwned::ExportedType(exported_type);
        context.table_row_add(TableId::ExportedType, table_data)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::tables::{TableId, TypeAttributes},
        test::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_exported_type_builder_basic() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // First create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("TestType")
            .implementation_file(file_token)
            .build(&mut context)?;

        // Verify the token has the correct table ID
        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_default() -> Result<()> {
        let builder = ExportedTypeBuilder::default();
        assert!(builder.name.is_none());
        assert!(builder.namespace.is_none());
        assert_eq!(builder.flags, TypeAttributes::PUBLIC);
        assert_eq!(builder.type_def_id, 0);
        assert!(builder.implementation.is_none());
        Ok(())
    }

    #[test]
    fn test_exported_type_builder_missing_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let result = ExportedTypeBuilder::new()
            .implementation_file(file_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Type name is required"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_empty_name() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let result = ExportedTypeBuilder::new()
            .name("")
            .implementation_file(file_token)
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Type name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_missing_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        let result = ExportedTypeBuilder::new()
            .name("TestType")
            .build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation is required"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_with_namespace() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("Customer")
            .namespace("MyApp.Models")
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_public() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("PublicType")
            .public()
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_not_public() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("InternalType")
            .not_public()
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_with_typedef_id() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("TypeWithHint")
            .type_def_id(0x02000001)
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_assembly_ref_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create an AssemblyRef to reference
        let assembly_ref_token = crate::metadata::tables::AssemblyRefBuilder::new()
            .name("MyApp.Core")
            .version(1, 0, 0, 0)
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("ForwardedType")
            .namespace("MyApp.Models")
            .implementation_assembly_ref(assembly_ref_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_exported_type_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File for the first ExportedType
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        // Create a base exported type
        let base_token = ExportedTypeBuilder::new()
            .name("BaseType")
            .implementation_file(file_token)
            .build(&mut context)?;

        // Create a derived exported type that references the base
        let token = ExportedTypeBuilder::new()
            .name("DerivedType")
            .implementation_exported_type(base_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_invalid_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a builder with an invalid implementation reference
        let mut builder = ExportedTypeBuilder::new().name("InvalidType");

        // Manually set an invalid implementation (TypeDef is not valid for Implementation coded index)
        builder.implementation = Some(CodedIndex::new(
            TableId::TypeDef,
            1,
            CodedIndexType::Implementation,
        ));

        let result = builder.build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid implementation table type"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_zero_row_implementation() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a builder with a zero row implementation reference
        let mut builder = ExportedTypeBuilder::new().name("ZeroRowType");

        // Manually set an implementation with row 0 (invalid)
        builder.implementation = Some(CodedIndex::new(
            TableId::File,
            0,
            CodedIndexType::Implementation,
        ));

        let result = builder.build(&mut context);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation reference row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_multiple_types() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create Files to reference
        let file_token1 = crate::metadata::tables::FileBuilder::new()
            .name("Module1.netmodule")
            .build(&mut context)?;

        let file_token2 = crate::metadata::tables::FileBuilder::new()
            .name("Module2.netmodule")
            .build(&mut context)?;

        let token1 = ExportedTypeBuilder::new()
            .name("Type1")
            .namespace("MyApp.A")
            .implementation_file(file_token1)
            .build(&mut context)?;

        let token2 = ExportedTypeBuilder::new()
            .name("Type2")
            .namespace("MyApp.B")
            .implementation_file(file_token2)
            .build(&mut context)?;

        // Verify tokens are different and sequential
        assert_ne!(token1, token2);
        assert_eq!(token1.table(), TableId::ExportedType as u8);
        assert_eq!(token2.table(), TableId::ExportedType as u8);
        assert_eq!(token2.row(), token1.row() + 1);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_comprehensive() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("ComprehensiveModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("ComprehensiveType")
            .namespace("MyApp.Comprehensive")
            .public()
            .type_def_id(0x02000042)
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_fluent_api() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("FluentModule.netmodule")
            .build(&mut context)?;

        // Test fluent API chaining
        let token = ExportedTypeBuilder::new()
            .name("FluentType")
            .namespace("MyApp.Fluent")
            .not_public()
            .type_def_id(0x02000123)
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_clone() {
        let builder1 = ExportedTypeBuilder::new()
            .name("CloneTest")
            .namespace("MyApp.Test")
            .public();
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.namespace, builder2.namespace);
        assert_eq!(builder1.flags, builder2.flags);
        assert_eq!(builder1.type_def_id, builder2.type_def_id);
    }

    #[test]
    fn test_exported_type_builder_debug() {
        let builder = ExportedTypeBuilder::new()
            .name("DebugType")
            .namespace("MyApp.Debug");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ExportedTypeBuilder"));
        assert!(debug_str.contains("DebugType"));
        assert!(debug_str.contains("MyApp.Debug"));
    }

    #[test]
    fn test_exported_type_builder_empty_namespace() -> Result<()> {
        let assembly = get_test_assembly()?;
        let mut context = BuilderContext::new(assembly);

        // Create a File to reference
        let file_token = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut context)?;

        let token = ExportedTypeBuilder::new()
            .name("GlobalType")
            .namespace("") // Empty namespace should work
            .implementation_file(file_token)
            .build(&mut context)?;

        assert_eq!(token.table(), TableId::ExportedType as u8);
        assert!(token.row() > 0);

        Ok(())
    }
}
