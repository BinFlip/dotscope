//! TypeDefBuilder for creating type definitions.
//!
//! This module provides [`crate::metadata::tables::typedef::TypeDefBuilder`] for creating TypeDef table entries
//! with a fluent API. The TypeDef table defines types (classes, interfaces,
//! value types, enums) within the current module.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    Result,
};

/// Builder for creating TypeDef metadata entries.
///
/// `TypeDefBuilder` provides a fluent API for creating TypeDef table entries
/// with validation and automatic heap management. TypeDef entries define types
/// (classes, interfaces, value types, enums) within the current assembly.
///
/// # Examples
///
/// ```rust,ignore
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{CodedIndex, TableId, TypeDefBuilder};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create a simple class
/// let my_class = TypeDefBuilder::new()
///     .name("MyClass")
///     .namespace("MyNamespace")
///     .extends(CodedIndex::new(TableId::TypeRef, 1)) // System.Object
///     .flags(0x00100001) // Public | Class
///     .build(&mut context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct TypeDefBuilder {
    name: Option<String>,
    namespace: Option<String>,
    extends: Option<CodedIndex>,
    flags: Option<u32>,
    field_list: Option<u32>,
    method_list: Option<u32>,
}

impl Default for TypeDefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeDefBuilder {
    /// Creates a new TypeDefBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::typedef::TypeDefBuilder`] ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            namespace: None,
            extends: None,
            flags: None,
            field_list: None,
            method_list: None,
        }
    }

    /// Sets the type name.
    ///
    /// # Arguments
    ///
    /// * `name` - The simple name of the type (without namespace)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the type namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace containing this type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets the base type that this type extends.
    ///
    /// # Arguments
    ///
    /// * `extends` - CodedIndex pointing to the base type (TypeDef, TypeRef, or TypeSpec)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn extends(mut self, extends: CodedIndex) -> Self {
        self.extends = Some(extends);
        self
    }

    /// Sets the type flags (attributes).
    ///
    /// # Arguments
    ///
    /// * `flags` - Type attributes bitmask controlling visibility, layout, and semantics
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the field list starting index.
    ///
    /// # Arguments
    ///
    /// * `field_list` - Index into the Field table marking the first field of this type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn field_list(mut self, field_list: u32) -> Self {
        self.field_list = Some(field_list);
        self
    }

    /// Sets the method list starting index.
    ///
    /// # Arguments
    ///
    /// * `method_list` - Index into the MethodDef table marking the first method of this type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn method_list(mut self, method_list: u32) -> Self {
        self.method_list = Some(method_list);
        self
    }

    /// Convenience method to set common class flags.
    ///
    /// Sets the type as a public class.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_class(mut self) -> Self {
        self.flags = Some(0x0010_0001); // Public | Class
        self
    }

    /// Convenience method to set common interface flags.
    ///
    /// Sets the type as a public interface.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_interface(mut self) -> Self {
        self.flags = Some(0x0010_0161); // Public | Interface | Abstract
        self
    }

    /// Convenience method to set common value type flags.
    ///
    /// Sets the type as a public sealed value type.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_value_type(mut self) -> Self {
        self.flags = Some(0x0010_0101); // Public | Sealed
        self
    }

    /// Builds the TypeDef entry and adds it to the assembly.
    ///
    /// This method validates the configuration, adds required strings
    /// to the string heap, creates the TypeDefRaw entry, and adds it
    /// to the assembly via the BuilderContext.
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for heap management and table operations
    ///
    /// # Returns
    ///
    /// The [`crate::metadata::token::Token`] for the newly created TypeDef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing (name)
    /// - Heap operations fail
    /// - TypeDef table row creation fails
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| malformed_error!("TypeDef name is required"))?;

        // Add strings to heaps and get indices
        let name_index = context.string_add(&name)?;

        let namespace_index = if let Some(namespace) = &self.namespace {
            if namespace.is_empty() {
                0 // Global namespace
            } else {
                context.string_get_or_add(namespace)?
            }
        } else {
            0 // Default to global namespace
        };

        // Get the next RID for the TypeDef table
        let rid = context.next_rid(TableId::TypeDef);

        // Create the TypeDefRaw entry
        let typedef_raw = TypeDefRaw {
            rid,
            token: Token::new(rid | 0x0200_0000), // TypeDef table token prefix
            offset: 0,                            // Will be set during binary generation
            flags: self.flags.unwrap_or(0x0010_0001), // Default to public class
            type_name: name_index,
            type_namespace: namespace_index,
            extends: self.extends.unwrap_or(CodedIndex::new(
                TableId::TypeRef,
                0,
                CodedIndexType::TypeDefOrRef,
            )), // No base type
            field_list: self.field_list.unwrap_or(1), // Default field list start
            method_list: self.method_list.unwrap_or(1), // Default method list start
        };

        // Add the row to the assembly and return the token
        context.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, tables::TypeAttributes},
    };
    use std::path::PathBuf;

    #[test]
    fn test_typedef_builder_basic() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let token = TypeDefBuilder::new()
                .name("TestClass")
                .namespace("TestNamespace")
                .public_class()
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x02000000); // TypeDef table prefix
            assert!(token.value() & 0x00FFFFFF > 0); // RID should be > 0
        }
    }

    #[test]
    fn test_typedef_builder_interface() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let token = TypeDefBuilder::new()
                .name("ITestInterface")
                .namespace("TestNamespace")
                .public_interface()
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x02000000); // TypeDef table prefix
        }
    }

    #[test]
    fn test_typedef_builder_value_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let token = TypeDefBuilder::new()
                .name("TestStruct")
                .namespace("TestNamespace")
                .public_value_type()
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x02000000); // TypeDef table prefix
        }
    }

    #[test]
    fn test_typedef_builder_with_base_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let base_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // Assume System.Object
            let token = TypeDefBuilder::new()
                .name("DerivedClass")
                .namespace("TestNamespace")
                .extends(base_type)
                .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS)
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x02000000); // TypeDef table prefix
        }
    }

    #[test]
    fn test_typedef_builder_missing_name() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = TypeDefBuilder::new()
                .namespace("TestNamespace")
                .public_class()
                .build(&mut context);

            // Should fail because name is required
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_typedef_builder_global_namespace() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let token = TypeDefBuilder::new()
                .name("GlobalClass")
                .namespace("") // Empty namespace = global
                .public_class()
                .build(&mut context)
                .unwrap();

            // Verify token is created correctly
            assert_eq!(token.value() & 0xFF000000, 0x02000000); // TypeDef table prefix
        }
    }
}
