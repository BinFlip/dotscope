//! High-level interface builder for creating .NET interface definitions.
//!
//! This module provides [`InterfaceBuilder`] for creating complete interface definitions
//! including method signatures, properties, and events. It orchestrates the existing
//! low-level builders to provide a fluent, high-level API for interface creation.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        signatures::{encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature},
        tables::{
            CodedIndex, CodedIndexType, InterfaceImplBuilder, MethodDefBuilder, TableId,
            TypeAttributes, TypeDefBuilder,
        },
        token::Token,
    },
    Error, Result,
};

use super::property::PropertyBuilder;

/// Method signature definition for the interface builder.
struct InterfaceMethodDefinition {
    name: String,
    return_type: TypeSignature,
    parameters: Vec<(String, TypeSignature)>,
    attributes: u32,
}

/// Property definition for the interface builder.
struct InterfacePropertyDefinition {
    name: String,
    property_type: TypeSignature,
    has_getter: bool,
    has_setter: bool,
}

/// High-level builder for creating complete interface definitions.
///
/// `InterfaceBuilder` provides a fluent API for creating interfaces with method
/// signatures, properties, and events. It composes the existing low-level builders
/// to provide a convenient high-level interface for .NET interface creation.
///
/// # Design
///
/// The builder follows a composition approach:
/// - Uses existing `TypeDefBuilder` for the interface definition with INTERFACE flag
/// - Uses `MethodDefBuilder` for abstract method signatures
/// - Uses `PropertyBuilder` for property definitions
/// - Manages inheritance relationships between interfaces
/// - Validates interface constraints (no fields, only abstract methods)
///
/// # Examples
///
/// ## Simple Interface
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let interface_token = InterfaceBuilder::new("ICalculator")
///     .public()
///     .method_signature("Add", TypeSignature::I4, vec![
///         ("a".to_string(), TypeSignature::I4),
///         ("b".to_string(), TypeSignature::I4)
///     ])
///     .method_signature("Subtract", TypeSignature::I4, vec![
///         ("a".to_string(), TypeSignature::I4),
///         ("b".to_string(), TypeSignature::I4)
///     ])
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Interface with Properties
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let interface_token = InterfaceBuilder::new("IRepository")
///     .public()
///     .property("Count", TypeSignature::I4, true, false) // getter only
///     .property("IsReadOnly", TypeSignature::Boolean, true, false)
///     .method_signature("GetItem", TypeSignature::Object, vec![
///         ("id".to_string(), TypeSignature::I4)
///     ])
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Interface Inheritance
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// # let base_interface = Token::new(0x02000001);
/// let derived_interface = InterfaceBuilder::new("IAdvancedCalculator")
///     .public()
///     .extends_token(base_interface) // Inherit from ICalculator
///     .method_signature("Power", TypeSignature::R8, vec![
///         ("base".to_string(), TypeSignature::R8),
///         ("exponent".to_string(), TypeSignature::R8)
///     ])
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct InterfaceBuilder {
    /// Interface name
    name: String,

    /// Namespace (optional)
    namespace: Option<String>,

    /// Interface visibility attributes
    visibility: u32,

    /// Additional interface attributes
    attributes: u32,

    /// Method signatures in this interface
    methods: Vec<InterfaceMethodDefinition>,

    /// Properties in this interface
    properties: Vec<InterfacePropertyDefinition>,

    /// Inherited interfaces
    extends: Vec<CodedIndex>,
}

impl InterfaceBuilder {
    /// Create a new interface builder with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IMyInterface");
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: None,
            visibility: TypeAttributes::PUBLIC,
            attributes: TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT,
            methods: Vec::new(),
            properties: Vec::new(),
            extends: Vec::new(),
        }
    }

    /// Set the namespace for this interface.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Namespace string
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IMyInterface")
    ///     .namespace("MyApp.Interfaces");
    /// ```
    #[must_use]
    pub fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }

    /// Make this interface public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IMyInterface")
    ///     .public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.visibility = TypeAttributes::PUBLIC;
        self
    }

    /// Make this interface internal (assembly visibility).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IMyInterface")
    ///     .internal();
    /// ```
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.visibility = TypeAttributes::NOT_PUBLIC;
        self
    }

    /// Add interface inheritance.
    ///
    /// # Arguments
    ///
    /// * `interface` - CodedIndex of the interface to extend
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let base_interface = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);
    /// let builder = InterfaceBuilder::new("IDerived")
    ///     .extends(base_interface);
    /// ```
    #[must_use]
    pub fn extends(mut self, interface: CodedIndex) -> Self {
        self.extends.push(interface);
        self
    }

    /// Add interface inheritance using a token.
    ///
    /// # Arguments
    ///
    /// * `interface_token` - Token of the interface to extend
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let base_token = Token::new(0x02000001);
    /// let builder = InterfaceBuilder::new("IDerived")
    ///     .extends_token(base_token);
    /// ```
    #[must_use]
    pub fn extends_token(mut self, interface_token: Token) -> Self {
        let coded_index = CodedIndex::new(
            TableId::TypeDef,
            interface_token.row(),
            CodedIndexType::TypeDefOrRef,
        );
        self.extends.push(coded_index);
        self
    }

    /// Add a method signature to the interface.
    ///
    /// # Arguments
    ///
    /// * `name` - Method name
    /// * `return_type` - Method return type
    /// * `parameters` - Method parameters as (name, type) pairs
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("ICalculator")
    ///     .method_signature("Add", TypeSignature::I4, vec![
    ///         ("a".to_string(), TypeSignature::I4),
    ///         ("b".to_string(), TypeSignature::I4)
    ///     ]);
    /// ```
    #[must_use]
    pub fn method_signature(
        mut self,
        name: &str,
        return_type: TypeSignature,
        parameters: Vec<(String, TypeSignature)>,
    ) -> Self {
        self.methods.push(InterfaceMethodDefinition {
            name: name.to_string(),
            return_type,
            parameters,
            attributes: 0x0400 | 0x0006 | 0x0080, // PUBLIC | VIRTUAL | ABSTRACT
        });
        self
    }

    /// Add a simple method signature with no parameters.
    ///
    /// # Arguments
    ///
    /// * `name` - Method name
    /// * `return_type` - Method return type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IService")
    ///     .simple_method("Start", TypeSignature::Void)
    ///     .simple_method("Stop", TypeSignature::Void);
    /// ```
    #[must_use]
    pub fn simple_method(self, name: &str, return_type: TypeSignature) -> Self {
        self.method_signature(name, return_type, vec![])
    }

    /// Add a property to the interface.
    ///
    /// # Arguments
    ///
    /// * `name` - Property name
    /// * `property_type` - Property type
    /// * `has_getter` - Whether the property has a getter
    /// * `has_setter` - Whether the property has a setter
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IRepository")
    ///     .property("Count", TypeSignature::I4, true, false); // read-only
    /// ```
    #[must_use]
    pub fn property(
        mut self,
        name: &str,
        property_type: TypeSignature,
        has_getter: bool,
        has_setter: bool,
    ) -> Self {
        self.properties.push(InterfacePropertyDefinition {
            name: name.to_string(),
            property_type,
            has_getter,
            has_setter,
        });
        self
    }

    /// Add a read-only property to the interface.
    ///
    /// # Arguments
    ///
    /// * `name` - Property name
    /// * `property_type` - Property type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IRepository")
    ///     .readonly_property("Count", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn readonly_property(self, name: &str, property_type: TypeSignature) -> Self {
        self.property(name, property_type, true, false)
    }

    /// Add a read-write property to the interface.
    ///
    /// # Arguments
    ///
    /// * `name` - Property name
    /// * `property_type` - Property type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = InterfaceBuilder::new("IRepository")
    ///     .readwrite_property("IsEnabled", TypeSignature::Boolean);
    /// ```
    #[must_use]
    pub fn readwrite_property(self, name: &str, property_type: TypeSignature) -> Self {
        self.property(name, property_type, true, true)
    }

    /// Build the interface and add it to the assembly.
    ///
    /// This method creates:
    /// 1. TypeDef table entry with INTERFACE flag
    /// 2. Abstract method definitions for interface methods
    /// 3. Property definitions with abstract accessors
    /// 4. InterfaceImpl entries for inheritance
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A token representing the newly created interface definition.
    ///
    /// # Errors
    ///
    /// Returns an error if interface creation fails at any step.
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Validate interface constraints
        if self.name.is_empty() {
            return Err(Error::ModificationInvalidOperation {
                details: "Interface name cannot be empty".to_string(),
            });
        }

        // Create the interface TypeDef entry
        let mut typedef_builder = TypeDefBuilder::new()
            .name(&self.name)
            .flags(self.visibility | self.attributes);

        if let Some(namespace) = &self.namespace {
            typedef_builder = typedef_builder.namespace(namespace);
        }

        let interface_token = typedef_builder.build(context)?;

        // Create method signatures
        for method_def in self.methods {
            // Build method signature
            let signature_params: Vec<SignatureParameter> = method_def
                .parameters
                .iter()
                .map(|(_, param_type)| SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: param_type.clone(),
                })
                .collect();

            let method_signature = SignatureMethod {
                has_this: true,
                explicit_this: false,
                default: true,
                vararg: false,
                cdecl: false,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                param_count_generic: 0,
                param_count: u32::try_from(method_def.parameters.len())
                    .map_err(|_| malformed_error!("Method parameter count exceeds u32 range"))?,
                return_type: SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: method_def.return_type.clone(),
                },
                params: signature_params,
                varargs: Vec::new(),
            };

            // Encode the signature
            let signature_bytes = encode_method_signature(&method_signature)?;

            MethodDefBuilder::new()
                .name(&method_def.name)
                .flags(method_def.attributes)
                .impl_flags(0x0000) // MANAGED | IL
                .signature(&signature_bytes)
                .build(context)?;
        }

        // Create properties with abstract accessors
        for prop_def in self.properties {
            if prop_def.has_getter {
                // Create abstract getter
                let getter_name = format!("get_{}", prop_def.name);

                // Create getter signature - no parameters, returns property type
                let getter_signature = SignatureMethod {
                    has_this: true,
                    explicit_this: false,
                    default: true,
                    vararg: false,
                    cdecl: false,
                    stdcall: false,
                    thiscall: false,
                    fastcall: false,
                    param_count_generic: 0,
                    param_count: 0,
                    return_type: SignatureParameter {
                        modifiers: Vec::new(),
                        by_ref: false,
                        base: prop_def.property_type.clone(),
                    },
                    params: Vec::new(),
                    varargs: Vec::new(),
                };
                let getter_signature_bytes = encode_method_signature(&getter_signature)?;

                MethodDefBuilder::new()
                    .name(&getter_name)
                    .flags(0x0400 | 0x0006 | 0x0080 | 0x0800) // PUBLIC | VIRTUAL | ABSTRACT | SPECIAL_NAME
                    .impl_flags(0x0000) // MANAGED | IL
                    .signature(&getter_signature_bytes)
                    .build(context)?;
            }

            if prop_def.has_setter {
                // Create abstract setter
                let setter_name = format!("set_{}", prop_def.name);

                // Create setter signature - takes property type parameter, returns void
                let setter_signature = SignatureMethod {
                    has_this: true,
                    explicit_this: false,
                    default: true,
                    vararg: false,
                    cdecl: false,
                    stdcall: false,
                    thiscall: false,
                    fastcall: false,
                    param_count_generic: 0,
                    param_count: 1,
                    return_type: SignatureParameter {
                        modifiers: Vec::new(),
                        by_ref: false,
                        base: TypeSignature::Void,
                    },
                    params: vec![SignatureParameter {
                        modifiers: Vec::new(),
                        by_ref: false,
                        base: prop_def.property_type.clone(),
                    }],
                    varargs: Vec::new(),
                };
                let setter_signature_bytes = encode_method_signature(&setter_signature)?;

                MethodDefBuilder::new()
                    .name(&setter_name)
                    .flags(0x0400 | 0x0006 | 0x0080 | 0x0800) // PUBLIC | VIRTUAL | ABSTRACT | SPECIAL_NAME
                    .impl_flags(0x0000) // MANAGED | IL
                    .signature(&setter_signature_bytes)
                    .build(context)?;
            }

            // Create property entry using PropertyBuilder
            PropertyBuilder::new(&prop_def.name, prop_def.property_type).build(context)?;
        }

        // Create InterfaceImpl entries for inheritance
        for interface_index in self.extends {
            InterfaceImplBuilder::new()
                .class(interface_token.row())
                .interface(interface_index)
                .build(context)?;
        }

        Ok(interface_token)
    }
}

impl Default for InterfaceBuilder {
    fn default() -> Self {
        Self::new("DefaultInterface")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{BuilderContext, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, signatures::TypeSignature},
    };
    use std::path::PathBuf;

    fn get_test_context() -> Result<BuilderContext> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
        let view = CilAssemblyView::from_file(&path)?;
        let assembly = CilAssembly::new(view);
        Ok(BuilderContext::new(assembly))
    }

    #[test]
    fn test_simple_interface() -> Result<()> {
        let mut context = get_test_context()?;

        let interface_token = InterfaceBuilder::new("ICalculator")
            .public()
            .namespace("MyApp.Interfaces")
            .method_signature(
                "Add",
                TypeSignature::I4,
                vec![
                    ("a".to_string(), TypeSignature::I4),
                    ("b".to_string(), TypeSignature::I4),
                ],
            )
            .build(&mut context)?;

        // Should create a valid TypeDef token
        assert_eq!(interface_token.value() & 0xFF000000, 0x02000000); // TypeDef table

        Ok(())
    }

    #[test]
    fn test_interface_with_properties() -> Result<()> {
        let mut context = get_test_context()?;

        let interface_token = InterfaceBuilder::new("IRepository")
            .public()
            .readonly_property("Count", TypeSignature::I4)
            .readwrite_property("IsEnabled", TypeSignature::Boolean)
            .build(&mut context)?;

        assert_eq!(interface_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_interface_inheritance() -> Result<()> {
        let mut context = get_test_context()?;

        // Create base interface
        let base_token = InterfaceBuilder::new("IBase")
            .public()
            .simple_method("BaseMethod", TypeSignature::Void)
            .build(&mut context)?;

        // Create derived interface
        let derived_token = InterfaceBuilder::new("IDerived")
            .public()
            .extends_token(base_token)
            .simple_method("DerivedMethod", TypeSignature::Void)
            .build(&mut context)?;

        assert_eq!(base_token.value() & 0xFF000000, 0x02000000);
        assert_eq!(derived_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_internal_interface() -> Result<()> {
        let mut context = get_test_context()?;

        let interface_token = InterfaceBuilder::new("IInternalInterface")
            .internal()
            .simple_method("InternalMethod", TypeSignature::Void)
            .build(&mut context)?;

        assert_eq!(interface_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_empty_interface() -> Result<()> {
        let mut context = get_test_context()?;

        let interface_token = InterfaceBuilder::new("IMarker")
            .public()
            .build(&mut context)?;

        assert_eq!(interface_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_empty_name_fails() {
        let mut context = get_test_context().unwrap();

        let result = InterfaceBuilder::new("").public().build(&mut context);

        assert!(result.is_err());
    }
}
