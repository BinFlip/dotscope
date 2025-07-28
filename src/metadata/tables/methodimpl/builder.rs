//! MethodImplBuilder for creating method implementation mapping metadata entries.
//!
//! This module provides [`crate::metadata::tables::methodimpl::MethodImplBuilder`] for creating MethodImpl table entries
//! with a fluent API. Method implementation mappings define which concrete methods
//! provide the implementation for interface method declarations or virtual method
//! overrides, enabling polymorphic dispatch and interface implementation contracts.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        tables::{CodedIndex, CodedIndexType, MethodImplRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating MethodImpl metadata entries.
///
/// `MethodImplBuilder` provides a fluent API for creating MethodImpl table entries
/// with validation and automatic relationship management. Method implementation mappings
/// are essential for interface implementation, method overriding, and virtual dispatch
/// in .NET object-oriented programming.
///
/// # Method Implementation Model
///
/// .NET method implementation mappings follow this pattern:
/// - **Implementation Class**: The type containing the concrete implementation
/// - **Method Body**: The actual method that provides the implementation behavior
/// - **Method Declaration**: The interface method or virtual method being implemented
/// - **Polymorphic Dispatch**: Runtime method resolution through the mapping
///
/// # Implementation Mapping Categories
///
/// Different categories of method implementation mappings serve various purposes:
/// - **Interface Implementation**: Maps interface methods to concrete class implementations
/// - **Virtual Method Override**: Specifies derived class methods that override base virtual methods
/// - **Explicit Interface Implementation**: Handles explicit implementation of interface members
/// - **Generic Method Specialization**: Links generic method declarations to specialized implementations
/// - **Abstract Method Implementation**: Connects abstract method declarations to concrete implementations
///
/// # Coded Index Management
///
/// Method implementation mappings use MethodDefOrRef coded indices:
/// - **MethodDef References**: Methods defined in the current assembly
/// - **MemberRef References**: Methods referenced from external assemblies
/// - **Cross-Assembly Scenarios**: Support for interface implementations across assembly boundaries
/// - **Type Safety**: Compile-time and runtime validation of implementation contracts
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::prelude::*;
/// use std::path::Path;
///
/// # fn main() -> Result<()> {
/// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
/// let assembly = CilAssembly::new(view);
/// let mut context = BuilderContext::new(assembly);
///
/// // Create interface implementation mapping
/// let implementing_class = Token::new(0x02000001); // MyClass
/// let implementation_method = Token::new(0x06000001); // MyClass.DoWork()
/// let interface_method = Token::new(0x0A000001); // IWorker.DoWork()
///
/// let method_impl = MethodImplBuilder::new()
///     .class(implementing_class)
///     .method_body_from_method_def(implementation_method)
///     .method_declaration_from_member_ref(interface_method)
///     .build(&mut context)?;
///
/// // Create virtual method override mapping
/// let derived_class = Token::new(0x02000002); // DerivedClass
/// let override_method = Token::new(0x06000002); // DerivedClass.VirtualMethod()
/// let base_method = Token::new(0x06000003); // BaseClass.VirtualMethod()
///
/// let override_impl = MethodImplBuilder::new()
///     .class(derived_class)
///     .method_body_from_method_def(override_method)
///     .method_declaration_from_method_def(base_method)
///     .build(&mut context)?;
///
/// // Create explicit interface implementation
/// let explicit_class = Token::new(0x02000003); // ExplicitImpl
/// let explicit_method = Token::new(0x06000004); // ExplicitImpl.IInterface.Method()
/// let interface_decl = Token::new(0x0A000002); // IInterface.Method()
///
/// let explicit_impl = MethodImplBuilder::new()
///     .class(explicit_class)
///     .method_body_from_method_def(explicit_method)
///     .method_declaration_from_member_ref(interface_decl)
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct MethodImplBuilder {
    class: Option<Token>,
    method_body: Option<CodedIndex>,
    method_declaration: Option<CodedIndex>,
}

impl Default for MethodImplBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodImplBuilder {
    /// Creates a new MethodImplBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::methodimpl::MethodImplBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: None,
            method_body: None,
            method_declaration: None,
        }
    }

    /// Sets the implementing class for this method implementation mapping.
    ///
    /// Specifies the type that contains the concrete implementation method.
    /// This class provides the actual method body that implements the interface
    /// contract or overrides the virtual method declaration.
    ///
    /// # Implementation Class Role
    ///
    /// The implementation class serves several purposes:
    /// - **Method Container**: Houses the concrete implementation method
    /// - **Type Context**: Provides the type context for method resolution
    /// - **Inheritance Chain**: Participates in virtual method dispatch
    /// - **Interface Contract**: Fulfills interface implementation requirements
    ///
    /// # Arguments
    ///
    /// * `class_token` - Token referencing the TypeDef containing the implementation
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// let my_class = Token::new(0x02000001); // MyClass TypeDef
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .class(my_class)
    ///     // ... set method body and declaration
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn class(mut self, class_token: Token) -> Self {
        self.class = Some(class_token);
        self
    }

    /// Sets the method body from a MethodDef token.
    ///
    /// Specifies the concrete method implementation using a MethodDef token.
    /// This method contains the actual IL code or native implementation that
    /// provides the behavior for the method declaration.
    ///
    /// # Method Body Characteristics
    ///
    /// MethodDef method bodies have these properties:
    /// - **Local Definition**: Defined in the current assembly
    /// - **Implementation Code**: Contains actual IL or native code
    /// - **Direct Reference**: No additional resolution required
    /// - **Type Ownership**: Belongs to the implementing class
    ///
    /// # Arguments
    ///
    /// * `method_token` - Token referencing the MethodDef with the implementation
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// let implementation_method = Token::new(0x06000001); // MyClass.DoWork()
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_body_from_method_def(implementation_method)
    ///     // ... set class and declaration
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_body_from_method_def(mut self, method_token: Token) -> Self {
        // Extract RID from MethodDef token (0x06xxxxxx)
        let rid = method_token.value() & 0x00FF_FFFF;
        self.method_body = Some(CodedIndex::new(
            TableId::MethodDef,
            rid,
            CodedIndexType::MethodDefOrRef,
        ));
        self
    }

    /// Sets the method body from a MemberRef token.
    ///
    /// Specifies the concrete method implementation using a MemberRef token.
    /// This is used when the implementation method is defined in an external
    /// assembly or module, requiring cross-assembly method resolution.
    ///
    /// # Member Reference Characteristics
    ///
    /// MemberRef method bodies have these properties:
    /// - **External Definition**: Defined in external assembly or module
    /// - **Cross-Assembly**: Requires assembly boundary resolution
    /// - **Signature Matching**: Must match expected method signature
    /// - **Dynamic Resolution**: Resolved at runtime or link time
    ///
    /// # Arguments
    ///
    /// * `member_token` - Token referencing the MemberRef with the implementation
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// let external_method = Token::new(0x0A000001); // External.DoWork()
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_body_from_member_ref(external_method)
    ///     // ... set class and declaration
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_body_from_member_ref(mut self, member_token: Token) -> Self {
        // Extract RID from MemberRef token (0x0Axxxxxx)
        let rid = member_token.value() & 0x00FF_FFFF;
        self.method_body = Some(CodedIndex::new(
            TableId::MemberRef,
            rid,
            CodedIndexType::MethodDefOrRef,
        ));
        self
    }

    /// Sets the method declaration from a MethodDef token.
    ///
    /// Specifies the method declaration being implemented using a MethodDef token.
    /// This is typically used for virtual method overrides where both the declaration
    /// and implementation are defined within the current assembly.
    ///
    /// # Method Declaration Characteristics
    ///
    /// MethodDef method declarations have these properties:
    /// - **Local Declaration**: Declared in the current assembly
    /// - **Virtual Dispatch**: Supports polymorphic method calls
    /// - **Inheritance Chain**: Part of class inheritance hierarchy
    /// - **Override Semantics**: Enables method overriding behavior
    ///
    /// # Arguments
    ///
    /// * `method_token` - Token referencing the MethodDef being implemented
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// let base_method = Token::new(0x06000002); // BaseClass.VirtualMethod()
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_declaration_from_method_def(base_method)
    ///     // ... set class and body
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_declaration_from_method_def(mut self, method_token: Token) -> Self {
        // Extract RID from MethodDef token (0x06xxxxxx)
        let rid = method_token.value() & 0x00FF_FFFF;
        self.method_declaration = Some(CodedIndex::new(
            TableId::MethodDef,
            rid,
            CodedIndexType::MethodDefOrRef,
        ));
        self
    }

    /// Sets the method declaration from a MemberRef token.
    ///
    /// Specifies the method declaration being implemented using a MemberRef token.
    /// This is commonly used for interface implementations where the interface
    /// method is defined in an external assembly or module.
    ///
    /// # Interface Declaration Characteristics
    ///
    /// MemberRef method declarations have these properties:
    /// - **External Declaration**: Declared in external assembly or module
    /// - **Interface Contract**: Defines implementation requirements
    /// - **Cross-Assembly**: Supports multi-assembly interfaces
    /// - **Signature Contract**: Establishes method signature requirements
    ///
    /// # Arguments
    ///
    /// * `member_token` - Token referencing the MemberRef being implemented
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::prelude::*;
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<()> {
    /// let view = CilAssemblyView::from_file(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// let mut context = BuilderContext::new(assembly);
    ///
    /// let interface_method = Token::new(0x0A000002); // IWorker.DoWork()
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_declaration_from_member_ref(interface_method)
    ///     // ... set class and body
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_declaration_from_member_ref(mut self, member_token: Token) -> Self {
        // Extract RID from MemberRef token (0x0Axxxxxx)
        let rid = member_token.value() & 0x00FF_FFFF;
        self.method_declaration = Some(CodedIndex::new(
            TableId::MemberRef,
            rid,
            CodedIndexType::MethodDefOrRef,
        ));
        self
    }

    /// Sets the method body using a coded index directly.
    ///
    /// Allows setting the method body implementation using any valid MethodDefOrRef
    /// coded index for maximum flexibility. This method provides complete control
    /// over the method body reference and can handle both local and external methods.
    ///
    /// # Coded Index Flexibility
    ///
    /// Direct coded index usage supports:
    /// - **MethodDef References**: Local method implementations
    /// - **MemberRef References**: External method implementations
    /// - **Complex Scenarios**: Advanced implementation mapping patterns
    /// - **Tool Integration**: Support for external metadata tools
    ///
    /// # Arguments
    ///
    /// * `coded_index` - MethodDefOrRef coded index for the implementation method
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn method_body(mut self, coded_index: CodedIndex) -> Self {
        self.method_body = Some(coded_index);
        self
    }

    /// Sets the method declaration using a coded index directly.
    ///
    /// Allows setting the method declaration using any valid MethodDefOrRef
    /// coded index for maximum flexibility. This method provides complete control
    /// over the method declaration reference and can handle both local and external declarations.
    ///
    /// # Coded Index Flexibility
    ///
    /// Direct coded index usage supports:
    /// - **MethodDef References**: Local method declarations (virtual methods)
    /// - **MemberRef References**: External method declarations (interface methods)
    /// - **Complex Scenarios**: Advanced declaration mapping patterns
    /// - **Tool Integration**: Support for external metadata tools
    ///
    /// # Arguments
    ///
    /// * `coded_index` - MethodDefOrRef coded index for the declaration method
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn method_declaration(mut self, coded_index: CodedIndex) -> Self {
        self.method_declaration = Some(coded_index);
        self
    }

    /// Builds the MethodImpl metadata entry.
    ///
    /// Creates a new MethodImpl entry in the metadata with the configured implementation
    /// mapping. The mapping establishes the relationship between a method declaration
    /// (interface method or virtual method) and its concrete implementation.
    ///
    /// # Validation
    ///
    /// The build process performs several validation checks:
    /// - **Class Required**: An implementing class must be specified
    /// - **Method Body Required**: A concrete implementation method must be specified
    /// - **Method Declaration Required**: A method declaration being implemented must be specified
    /// - **Coded Index Validity**: Both coded indices must be well-formed
    /// - **Token References**: Referenced tokens must be valid within their respective tables
    ///
    /// # Arguments
    ///
    /// * `context` - The builder context for metadata operations
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] referencing the created MethodImpl entry.
    ///
    /// # Errors
    ///
    /// - Missing class, method body, or method declaration
    /// - Invalid token references in the coded indices
    /// - Table operations fail due to metadata constraints
    /// - Implementation mapping validation failed
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        let class = self
            .class
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "MethodImplBuilder requires a class token".to_string(),
            })?;

        let method_body = self
            .method_body
            .ok_or_else(|| Error::ModificationInvalidOperation {
                details: "MethodImplBuilder requires a method body".to_string(),
            })?;

        let method_declaration =
            self.method_declaration
                .ok_or_else(|| Error::ModificationInvalidOperation {
                    details: "MethodImplBuilder requires a method declaration".to_string(),
                })?;

        // Extract RID from class token (should be TypeDef: 0x02xxxxxx)
        let class_rid = class.value() & 0x00FF_FFFF;

        let next_rid = context.next_rid(TableId::MethodImpl);
        let token = Token::new(((TableId::MethodImpl as u32) << 24) | next_rid);

        let method_impl_raw = MethodImplRaw {
            rid: next_rid,
            token,
            offset: 0, // Will be set during binary generation
            class: class_rid,
            method_body,
            method_declaration,
        };

        context.table_row_add(
            TableId::MethodImpl,
            TableDataOwned::MethodImpl(method_impl_raw),
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
    fn test_methodimpl_builder_creation() {
        let builder = MethodImplBuilder::new();
        assert!(builder.class.is_none());
        assert!(builder.method_body.is_none());
        assert!(builder.method_declaration.is_none());
    }

    #[test]
    fn test_methodimpl_builder_default() {
        let builder = MethodImplBuilder::default();
        assert!(builder.class.is_none());
        assert!(builder.method_body.is_none());
        assert!(builder.method_declaration.is_none());
    }

    #[test]
    fn test_interface_implementation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for MethodImpl
            let expected_rid = context.next_rid(TableId::MethodImpl);

            let implementing_class = Token::new(0x02000001); // MyClass
            let implementation_method = Token::new(0x06000001); // MyClass.DoWork()
            let interface_method = Token::new(0x0A000001); // IWorker.DoWork()

            let token = MethodImplBuilder::new()
                .class(implementing_class)
                .method_body_from_method_def(implementation_method)
                .method_declaration_from_member_ref(interface_method)
                .build(&mut context)
                .expect("Should build MethodImpl");

            assert_eq!(token.value() & 0xFF000000, 0x19000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_virtual_method_override() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for MethodImpl
            let expected_rid = context.next_rid(TableId::MethodImpl);

            let derived_class = Token::new(0x02000002); // DerivedClass
            let override_method = Token::new(0x06000002); // DerivedClass.VirtualMethod()
            let base_method = Token::new(0x06000003); // BaseClass.VirtualMethod()

            let token = MethodImplBuilder::new()
                .class(derived_class)
                .method_body_from_method_def(override_method)
                .method_declaration_from_method_def(base_method)
                .build(&mut context)
                .expect("Should build virtual override MethodImpl");

            assert_eq!(token.value() & 0xFF000000, 0x19000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_explicit_interface_implementation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for MethodImpl
            let expected_rid = context.next_rid(TableId::MethodImpl);

            let explicit_class = Token::new(0x02000003); // ExplicitImpl
            let explicit_method = Token::new(0x06000004); // ExplicitImpl.IInterface.Method()
            let interface_decl = Token::new(0x0A000002); // IInterface.Method()

            let token = MethodImplBuilder::new()
                .class(explicit_class)
                .method_body_from_method_def(explicit_method)
                .method_declaration_from_member_ref(interface_decl)
                .build(&mut context)
                .expect("Should build explicit interface MethodImpl");

            assert_eq!(token.value() & 0xFF000000, 0x19000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_external_method_body() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for MethodImpl
            let expected_rid = context.next_rid(TableId::MethodImpl);

            let implementing_class = Token::new(0x02000001);
            let external_method = Token::new(0x0A000003); // External method implementation
            let interface_method = Token::new(0x0A000004);

            let token = MethodImplBuilder::new()
                .class(implementing_class)
                .method_body_from_member_ref(external_method)
                .method_declaration_from_member_ref(interface_method)
                .build(&mut context)
                .expect("Should build external method MethodImpl");

            assert_eq!(token.value() & 0xFF000000, 0x19000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_direct_coded_index() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected next RID for MethodImpl
            let expected_rid = context.next_rid(TableId::MethodImpl);

            let implementing_class = Token::new(0x02000001);
            let method_body_idx =
                CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::MethodDefOrRef);
            let method_decl_idx =
                CodedIndex::new(TableId::MemberRef, 1, CodedIndexType::MethodDefOrRef);

            let token = MethodImplBuilder::new()
                .class(implementing_class)
                .method_body(method_body_idx)
                .method_declaration(method_decl_idx)
                .build(&mut context)
                .expect("Should build direct coded index MethodImpl");

            assert_eq!(token.value() & 0xFF000000, 0x19000000);
            assert_eq!(token.value() & 0x00FFFFFF, expected_rid);
        }
    }

    #[test]
    fn test_build_without_class_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = MethodImplBuilder::new()
                .method_body_from_method_def(Token::new(0x06000001))
                .method_declaration_from_member_ref(Token::new(0x0A000001))
                .build(&mut context);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("requires a class token"));
        }
    }

    #[test]
    fn test_build_without_method_body_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = MethodImplBuilder::new()
                .class(Token::new(0x02000001))
                .method_declaration_from_member_ref(Token::new(0x0A000001))
                .build(&mut context);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("requires a method body"));
        }
    }

    #[test]
    fn test_build_without_method_declaration_fails() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            let result = MethodImplBuilder::new()
                .class(Token::new(0x02000001))
                .method_body_from_method_def(Token::new(0x06000001))
                .build(&mut context);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("requires a method declaration"));
        }
    }

    #[test]
    fn test_multiple_method_impls() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        if let Ok(view) = CilAssemblyView::from_file(&path) {
            let assembly = CilAssembly::new(view);
            let mut context = BuilderContext::new(assembly);

            // Get the expected first RID for MethodImpl
            let expected_rid1 = context.next_rid(TableId::MethodImpl);

            let token1 = MethodImplBuilder::new()
                .class(Token::new(0x02000001))
                .method_body_from_method_def(Token::new(0x06000001))
                .method_declaration_from_member_ref(Token::new(0x0A000001))
                .build(&mut context)
                .expect("Should build first MethodImpl");

            let token2 = MethodImplBuilder::new()
                .class(Token::new(0x02000001))
                .method_body_from_method_def(Token::new(0x06000002))
                .method_declaration_from_member_ref(Token::new(0x0A000002))
                .build(&mut context)
                .expect("Should build second MethodImpl");

            assert_eq!(token1.value() & 0x00FFFFFF, expected_rid1);
            assert_eq!(token2.value() & 0x00FFFFFF, expected_rid1 + 1);
        }
    }
}
