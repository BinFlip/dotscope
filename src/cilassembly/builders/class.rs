//! High-level class builder for creating complete .NET type definitions.
//!
//! This module provides [`ClassBuilder`] for creating complete class definitions
//! including fields, methods, properties, and other members. It orchestrates
//! the existing low-level builders to provide a fluent, high-level API.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        signatures::{encode_field_signature, SignatureField, TypeSignature},
        tables::{
            CodedIndex, CodedIndexType, FieldBuilder, InterfaceImplBuilder, TableId, TypeDefBuilder,
        },
        token::Token,
    },
    Error, Result,
};

// Use field attributes constants directly from the tables module

use super::method::MethodBuilder;

/// Field definition for the class builder.
struct FieldDefinition {
    name: String,
    field_type: TypeSignature,
    attributes: u32,
}

/// Property definition for the class builder.
struct PropertyDefinition {
    name: String,
    property_type: TypeSignature,
    has_getter: bool,
    has_setter: bool,
    backing_field_name: Option<String>,
}

/// High-level builder for creating complete class definitions.
///
/// `ClassBuilder` provides a fluent API for creating classes with fields,
/// methods, properties, and other members. It composes the existing
/// low-level builders to provide a convenient high-level interface.
///
/// # Design
///
/// The builder follows a composition approach:
/// - Uses existing `TypeDefBuilder` for the class definition
/// - Uses `FieldBuilder` for fields
/// - Uses `MethodBuilder` for methods and constructors
/// - Manages relationships between backing fields and properties
/// - Handles inheritance and interface implementations
///
/// # Examples
///
/// ## Simple Class
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let class_token = ClassBuilder::new("Person")
///     .public()
///     .field("name", TypeSignature::String)
///     .field("age", TypeSignature::I4)
///     .default_constructor()
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Class with Properties
///
/// ```rust,no_run
/// use dotscope::prelude::*;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let class_token = ClassBuilder::new("Employee")
///     .public()
///     .auto_property("Name", TypeSignature::String)
///     .auto_property("Salary", TypeSignature::R8)
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Class with Custom Methods
///
/// ```rust,no_run
/// use dotscope::prelude::*;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = dotscope::CilAssembly::new(view);
/// # let mut context = dotscope::BuilderContext::new(assembly);
/// let class_token = ClassBuilder::new("Calculator")
///     .public()
///     .field("lastResult", TypeSignature::I4)
///     .method(|_m| MethodBuilder::new("Add")
///         .public()
///         .parameter("a", TypeSignature::I4)
///         .parameter("b", TypeSignature::I4)
///         .returns(TypeSignature::I4)
///         .implementation(|body| {
///             body.implementation(|asm| {
///                 asm.ldarg_1()?
///                    .ldarg_2()?
///                    .add()?
///                    .dup()? // Duplicate for storing
///                    .ldarg_0()? // Load 'this'
///                    .stfld(Token::new(0x04000001))? // Store to lastResult (placeholder)
///                    .ret()?;
///                 Ok(())
///             })
///         }))
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct ClassBuilder {
    /// Class name
    name: String,

    /// Namespace (optional)
    namespace: Option<String>,

    /// Type attributes
    flags: u32,

    /// Base class token (defaults to System.Object)
    extends: Option<CodedIndex>,

    /// Implemented interfaces
    implements: Vec<CodedIndex>,

    /// Field definitions
    fields: Vec<FieldDefinition>,

    /// Method builders
    methods: Vec<MethodBuilder>,

    /// Property definitions
    properties: Vec<PropertyDefinition>,

    /// Whether to generate a default constructor
    generate_default_ctor: bool,

    /// Nested types (future enhancement)
    nested_types: Vec<ClassBuilder>,
}

impl ClassBuilder {
    /// Create a new class builder with the given name.
    ///
    /// # Arguments
    ///
    /// * `name` - Class name (without namespace)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("MyClass");
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: None,
            flags: 0x0010_0001, // CLASS | AUTO_LAYOUT | ANSI_CLASS
            extends: None,
            implements: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            properties: Vec::new(),
            generate_default_ctor: false,
            nested_types: Vec::new(),
        }
    }

    /// Set the namespace for the class.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Namespace (e.g., "System.Collections.Generic")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("MyClass")
    ///     .namespace("MyCompany.MyProduct");
    /// ```
    #[must_use]
    pub fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }

    /// Make the class public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("PublicClass").public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.flags = (self.flags & !0x0000_0007) | 0x0000_0001; // Clear visibility bits, set PUBLIC
        self
    }

    /// Make the class internal (not visible outside the assembly).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("InternalClass").internal();
    /// ```
    #[must_use]
    pub fn internal(mut self) -> Self {
        self.flags &= !0x0000_0007; // Clear visibility bits, set NOT_PUBLIC (0)
        self
    }

    /// Make the class sealed (cannot be inherited).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("SealedClass").sealed();
    /// ```
    #[must_use]
    pub fn sealed(mut self) -> Self {
        self.flags |= 0x0000_0100; // SEALED
        self
    }

    /// Make the class abstract (cannot be instantiated).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("AbstractClass").abstract_class();
    /// ```
    #[must_use]
    pub fn abstract_class(mut self) -> Self {
        self.flags |= 0x0000_0080; // ABSTRACT
        self
    }

    /// Set the base class to inherit from.
    ///
    /// # Arguments
    ///
    /// * `base_class` - CodedIndex of the base class
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::tables::{CodedIndex, CodedIndexType, TableId};
    ///
    /// let builder = ClassBuilder::new("DerivedClass")
    ///     .inherits(CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef)); // Base class coded index
    /// ```
    #[must_use]
    pub fn inherits(mut self, base_class: CodedIndex) -> Self {
        self.extends = Some(base_class);
        self
    }

    /// Add an interface implementation.
    ///
    /// # Arguments
    ///
    /// * `interface` - CodedIndex of the interface to implement
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::tables::{CodedIndex, CodedIndexType, TableId};
    ///
    /// let builder = ClassBuilder::new("MyClass")
    ///     .implements(CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef)) // IDisposable
    ///     .implements(CodedIndex::new(TableId::TypeRef, 3, CodedIndexType::TypeDefOrRef)); // IEnumerable
    /// ```
    #[must_use]
    pub fn implements(mut self, interface: CodedIndex) -> Self {
        self.implements.push(interface);
        self
    }

    /// Add a field to the class.
    ///
    /// # Arguments
    ///
    /// * `name` - Field name
    /// * `field_type` - Field type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = ClassBuilder::new("Person")
    ///     .field("name", TypeSignature::String)
    ///     .field("age", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn field(mut self, name: &str, field_type: TypeSignature) -> Self {
        self.fields.push(FieldDefinition {
            name: name.to_string(),
            field_type,
            attributes: 0x0001, // PRIVATE
        });
        self
    }

    /// Add a public field to the class.
    ///
    /// # Arguments
    ///
    /// * `name` - Field name
    /// * `field_type` - Field type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = ClassBuilder::new("Point")
    ///     .public_field("X", TypeSignature::I4)
    ///     .public_field("Y", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn public_field(mut self, name: &str, field_type: TypeSignature) -> Self {
        self.fields.push(FieldDefinition {
            name: name.to_string(),
            field_type,
            attributes: 0x0006, // PUBLIC
        });
        self
    }

    /// Add a static field to the class.
    ///
    /// # Arguments
    ///
    /// * `name` - Field name
    /// * `field_type` - Field type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = ClassBuilder::new("Settings")
    ///     .static_field("instance", TypeSignature::Object);
    /// ```
    #[must_use]
    pub fn static_field(mut self, name: &str, field_type: TypeSignature) -> Self {
        self.fields.push(FieldDefinition {
            name: name.to_string(),
            field_type,
            attributes: 0x0001 | 0x0010, // PRIVATE | STATIC
        });
        self
    }

    /// Add a method to the class using a method builder.
    ///
    /// # Arguments
    ///
    /// * `builder_fn` - Function that configures a MethodBuilder
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = dotscope::CilAssemblyView::from_file("test.dll".as_ref())?;
    /// # let assembly = dotscope::CilAssembly::new(view);
    /// # let mut context = dotscope::BuilderContext::new(assembly);
    /// let class_token = ClassBuilder::new("Calculator")
    ///     .method(|_m| MethodBuilder::new("Add")
    ///         .public()
    ///         .parameter("a", TypeSignature::I4)
    ///         .parameter("b", TypeSignature::I4)
    ///         .returns(TypeSignature::I4)
    ///         .implementation(|body| {
    ///             body.implementation(|asm| {
    ///                 asm.ldarg_1()?.ldarg_2()?.add()?.ret()?;
    ///                 Ok(())
    ///             })
    ///         }))
    ///     .build(&mut context)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method<F>(mut self, builder_fn: F) -> Self
    where
        F: FnOnce(MethodBuilder) -> MethodBuilder,
    {
        let method_builder = builder_fn(MethodBuilder::new("method"));
        self.methods.push(method_builder);
        self
    }

    /// Add an auto-property to the class.
    ///
    /// This creates a property with automatic backing field and getter/setter.
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
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = ClassBuilder::new("Person")
    ///     .auto_property("Name", TypeSignature::String)
    ///     .auto_property("Age", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn auto_property(mut self, name: &str, property_type: TypeSignature) -> Self {
        let backing_field_name = format!("<{name}>k__BackingField");

        // Add the property definition
        self.properties.push(PropertyDefinition {
            name: name.to_string(),
            property_type: property_type.clone(),
            has_getter: true,
            has_setter: true,
            backing_field_name: Some(backing_field_name.clone()),
        });

        // Add the backing field
        self.fields.push(FieldDefinition {
            name: backing_field_name,
            field_type: property_type,
            attributes: 0x0001, // PRIVATE | COMPILER_CONTROLLED (0x0000)
        });

        self
    }

    /// Add a read-only property to the class.
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
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = ClassBuilder::new("Circle")
    ///     .field("radius", TypeSignature::R8)
    ///     .readonly_property("Area", TypeSignature::R8);
    /// ```
    #[must_use]
    pub fn readonly_property(mut self, name: &str, property_type: TypeSignature) -> Self {
        let backing_field_name = format!("<{name}>k__BackingField");

        self.properties.push(PropertyDefinition {
            name: name.to_string(),
            property_type: property_type.clone(),
            has_getter: true,
            has_setter: false,
            backing_field_name: Some(backing_field_name.clone()),
        });

        self.fields.push(FieldDefinition {
            name: backing_field_name,
            field_type: property_type,
            attributes: 0x0001 | 0x0020, // PRIVATE | INIT_ONLY
        });

        self
    }

    /// Generate a default parameterless constructor.
    ///
    /// This will create a constructor that calls the base class constructor.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = ClassBuilder::new("MyClass")
    ///     .default_constructor();
    /// ```
    #[must_use]
    pub fn default_constructor(mut self) -> Self {
        self.generate_default_ctor = true;
        self
    }

    /// Build the complete class and add it to the assembly.
    ///
    /// This method orchestrates the creation of:
    /// 1. TypeDef table entry for the class
    /// 2. Field table entries for all fields
    /// 3. Method table entries for all methods and property accessors
    /// 4. Property table entries (future enhancement)
    /// 5. InterfaceImpl table entries for implemented interfaces
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A token representing the newly created class definition.
    ///
    /// # Errors
    ///
    /// Returns an error if class creation fails at any step.
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Build the full type name
        let _full_name = match &self.namespace {
            Some(ns) => format!("{}.{}", ns, self.name),
            None => self.name.clone(),
        };

        // Create the TypeDef entry
        let typedef_token = TypeDefBuilder::new()
            .name(&self.name)
            .namespace(self.namespace.as_deref().unwrap_or(""))
            .flags(self.flags)
            .extends(self.extends.unwrap_or(CodedIndex::new(
                TableId::TypeRef,
                0,
                CodedIndexType::TypeDefOrRef,
            ))) // 0 = no base class (will default to Object)
            .build(context)?;

        // Create field definitions and store their tokens
        let mut field_tokens = Vec::new();
        for field_def in &self.fields {
            // Encode the field signature
            let field_sig = SignatureField {
                modifiers: Vec::new(),
                base: field_def.field_type.clone(),
            };
            let sig_bytes = encode_field_signature(&field_sig)?;

            let field_token = FieldBuilder::new()
                .name(&field_def.name)
                .flags(field_def.attributes)
                .signature(&sig_bytes)
                .build(context)?;
            field_tokens.push((field_def.name.clone(), field_token));
        }

        // Generate default constructor if requested
        if self.generate_default_ctor {
            let base_ctor_token = Token::new(0x0A00_0001); // Placeholder for Object::.ctor

            MethodBuilder::constructor()
                .implementation(move |body| {
                    body.implementation(move |asm| {
                        asm.ldarg_0()? // Load 'this'
                            .call(base_ctor_token)? // Call base constructor
                            .ret()?;
                        Ok(())
                    })
                })
                .build(context)?;
        }

        // Create property getter/setter methods
        for prop_def in &self.properties {
            if let Some(backing_field_name) = &prop_def.backing_field_name {
                // Find the backing field token
                let backing_field_token = field_tokens
                    .iter()
                    .find(|(name, _)| name == backing_field_name)
                    .map(|(_, token)| *token)
                    .ok_or_else(|| Error::ModificationInvalidOperation {
                        details: format!("Backing field {backing_field_name} not found"),
                    })?;

                // Create getter
                if prop_def.has_getter {
                    let getter_field_token = backing_field_token; // Copy token for move
                    MethodBuilder::property_getter(&prop_def.name, prop_def.property_type.clone())
                        .implementation(move |body| {
                            body.implementation(move |asm| {
                                asm.ldarg_0()? // Load 'this'
                                    .ldfld(getter_field_token)? // Load field
                                    .ret()?;
                                Ok(())
                            })
                        })
                        .build(context)?;
                }

                // Create setter
                if prop_def.has_setter {
                    let setter_field_token = backing_field_token; // Copy token for move
                    MethodBuilder::property_setter(&prop_def.name, prop_def.property_type.clone())
                        .implementation(move |body| {
                            body.implementation(move |asm| {
                                asm.ldarg_0()? // Load 'this'
                                    .ldarg_1()? // Load value
                                    .stfld(setter_field_token)? // Store to field
                                    .ret()?;
                                Ok(())
                            })
                        })
                        .build(context)?;
                }
            }
        }

        // Build custom methods
        for method_builder in self.methods {
            method_builder.build(context)?;
        }

        // Create InterfaceImpl entries
        for interface_index in self.implements {
            InterfaceImplBuilder::new()
                .class(typedef_token.into())
                .interface(interface_index)
                .build(context)?;
        }

        Ok(typedef_token)
    }
}

impl Default for ClassBuilder {
    fn default() -> Self {
        Self::new("DefaultClass")
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
    fn test_simple_class() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("SimpleClass")
            .public()
            .field("value", TypeSignature::I4)
            .default_constructor()
            .build(&mut context)?;

        // Should create a valid TypeDef token
        assert_eq!(class_token.value() & 0xFF000000, 0x02000000); // TypeDef table

        Ok(())
    }

    #[test]
    fn test_class_with_namespace() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("MyClass")
            .namespace("MyCompany.MyProduct")
            .public()
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_class_with_auto_properties() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("Person")
            .public()
            .auto_property("Name", TypeSignature::String)
            .auto_property("Age", TypeSignature::I4)
            .default_constructor()
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_class_with_methods() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("Calculator")
            .public()
            .field("lastResult", TypeSignature::I4)
            .method(|_m| {
                MethodBuilder::new("Add")
                    .public()
                    .static_method()
                    .parameter("a", TypeSignature::I4)
                    .parameter("b", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                            Ok(())
                        })
                    })
            })
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_sealed_class() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("SealedClass")
            .public()
            .sealed()
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_abstract_class() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("AbstractBase")
            .public()
            .abstract_class()
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_class_with_static_fields() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("Configuration")
            .public()
            .static_field("instance", TypeSignature::Object)
            .public_field("settings", TypeSignature::String)
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_class_with_readonly_property() -> Result<()> {
        let mut context = get_test_context()?;

        let class_token = ClassBuilder::new("Circle")
            .public()
            .field("radius", TypeSignature::R8)
            .readonly_property("Diameter", TypeSignature::R8)
            .default_constructor()
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_class_with_inheritance() -> Result<()> {
        let mut context = get_test_context()?;

        let base_class_index = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // Placeholder base class

        let class_token = ClassBuilder::new("DerivedClass")
            .public()
            .inherits(base_class_index)
            .default_constructor()
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }

    #[test]
    fn test_class_with_interfaces() -> Result<()> {
        let mut context = get_test_context()?;

        let interface1 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // Placeholder interface
        let interface2 = CodedIndex::new(TableId::TypeRef, 3, CodedIndexType::TypeDefOrRef); // Another interface

        let class_token = ClassBuilder::new("Implementation")
            .public()
            .implements(interface1)
            .implements(interface2)
            .build(&mut context)?;

        assert_eq!(class_token.value() & 0xFF000000, 0x02000000);

        Ok(())
    }
}
