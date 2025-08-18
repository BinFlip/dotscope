//! High-level property builder for creating .NET property definitions.
//!
//! This module provides [`PropertyBuilder`] for creating complete property definitions
//! including backing fields, getter/setter methods, and property metadata. It orchestrates
//! the existing low-level builders to provide a fluent, high-level API for various property patterns.

use crate::{
    cilassembly::BuilderContext,
    metadata::{
        signatures::{
            encode_field_signature, encode_property_signature, SignatureField, SignatureParameter,
            SignatureProperty, TypeSignature,
        },
        tables::{FieldBuilder, PropertyBuilder as PropertyTableBuilder},
        token::Token,
    },
    Error, Result,
};

use super::method::MethodBuilder;

/// Property accessor type for determining what accessors to generate.
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyAccessors {
    /// Property has both getter and setter
    GetterAndSetter,
    /// Property has only a getter (read-only)
    GetterOnly,
    /// Property has only a setter (write-only, rare)
    SetterOnly,
    /// No automatic accessors (custom implementation required)
    None,
}

/// Property implementation strategy.
pub enum PropertyImplementation {
    /// Auto-property with automatic backing field
    Auto {
        /// Name of the backing field (auto-generated if None)
        backing_field_name: Option<String>,
        /// Backing field attributes
        backing_field_attributes: u32,
    },
    /// Computed property with custom getter/setter logic
    Computed {
        /// Custom getter implementation
        getter: Option<Box<dyn FnOnce(MethodBuilder) -> MethodBuilder + Send>>,
        /// Custom setter implementation  
        setter: Option<Box<dyn FnOnce(MethodBuilder) -> MethodBuilder + Send>>,
    },
    /// Manual implementation (user provides all methods separately)
    Manual,
}

/// High-level builder for creating complete property definitions.
///
/// `PropertyBuilder` provides a fluent API for creating properties with various patterns:
/// auto-properties, computed properties, indexed properties, and custom implementations.
/// It composes the existing low-level builders to provide convenient high-level interfaces.
///
/// # Design
///
/// The builder supports multiple property patterns:
/// - **Auto-properties**: Automatic backing fields with generated getters/setters
/// - **Computed properties**: Custom logic without backing fields
/// - **Read-only/Write-only**: Properties with only getter or setter
/// - **Indexed properties**: Properties with parameters (C# indexers)
/// - **Manual**: Complete custom control over implementation
///
/// # Examples
///
/// ## Simple Auto-Property
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let property_token = CilPropertyBuilder::new("Name", TypeSignature::String)
///     .auto_property()
///     .public_accessors()
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Read-Only Computed Property
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let property_token = CilPropertyBuilder::new("FullName", TypeSignature::String)
///     .computed()
///     .getter(|method| method
///         .implementation(|body| {
///             body.implementation(|asm| {
///                 // Custom logic to compute full name
///                 asm.ldstr(Token::new(0x70000001))? // "Computed Value"
///                    .ret()?;
///                 Ok(())
///             })
///         }))
///     .readonly()
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Property with Custom Backing Field
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
/// # let assembly = CilAssembly::new(view);
/// # let mut context = BuilderContext::new(assembly);
/// let property_token = CilPropertyBuilder::new("Value", TypeSignature::I4)
///     .auto_property()
///     .backing_field("_customValue")
///     .private_backing_field()
///     .public_accessors()
///     .build(&mut context)?;
/// # Ok(())
/// # }
/// ```
pub struct PropertyBuilder {
    /// Property name
    name: String,

    /// Property type
    property_type: TypeSignature,

    /// Property attributes
    attributes: u32,

    /// What accessors to generate
    accessors: PropertyAccessors,

    /// Accessor visibility (separate from property attributes)
    getter_attributes: u32,
    setter_attributes: u32,

    /// Implementation strategy
    implementation: PropertyImplementation,

    /// Whether this is an indexed property (has parameters)
    is_indexed: bool,

    /// Parameters for indexed properties
    parameters: Vec<(String, TypeSignature)>,
}

impl PropertyBuilder {
    /// Create a new property builder with the given name and type.
    ///
    /// # Arguments
    ///
    /// * `name` - Property name
    /// * `property_type` - Property type signature
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Name", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn new(name: &str, property_type: TypeSignature) -> Self {
        Self {
            name: name.to_string(),
            property_type,
            attributes: 0x0000, // Default property attributes
            accessors: PropertyAccessors::GetterAndSetter,
            getter_attributes: 0x0006, // PUBLIC
            setter_attributes: 0x0006, // PUBLIC
            implementation: PropertyImplementation::Auto {
                backing_field_name: None,
                backing_field_attributes: 0x0001, // PRIVATE
            },
            is_indexed: false,
            parameters: Vec::new(),
        }
    }

    /// Configure this as an auto-property with automatic backing field.
    ///
    /// This is the default behavior and creates a property similar to C# auto-properties.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Name", TypeSignature::String)
    ///     .auto_property();
    /// ```
    #[must_use]
    pub fn auto_property(mut self) -> Self {
        self.implementation = PropertyImplementation::Auto {
            backing_field_name: None,
            backing_field_attributes: 0x0001, // PRIVATE
        };
        self
    }

    /// Configure this as a computed property with custom logic.
    ///
    /// Computed properties don't have backing fields and require custom getter/setter implementations.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Area", TypeSignature::R8)
    ///     .computed();
    /// ```
    #[must_use]
    pub fn computed(mut self) -> Self {
        self.implementation = PropertyImplementation::Computed {
            getter: None,
            setter: None,
        };
        self
    }

    /// Configure this as a manual property where all methods are provided separately.
    ///
    /// Manual properties give complete control but require the user to provide all implementations.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Complex", TypeSignature::Object)
    ///     .manual();
    /// ```
    #[must_use]
    pub fn manual(mut self) -> Self {
        self.implementation = PropertyImplementation::Manual;
        self
    }

    /// Set a custom name for the backing field (auto-properties only).
    ///
    /// # Arguments
    ///
    /// * `field_name` - Custom backing field name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .backing_field("_value");
    /// ```
    #[must_use]
    pub fn backing_field(mut self, field_name: &str) -> Self {
        if let PropertyImplementation::Auto {
            backing_field_name, ..
        } = &mut self.implementation
        {
            *backing_field_name = Some(field_name.to_string());
        }
        self
    }

    /// Make the backing field private (default for auto-properties).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .private_backing_field();
    /// ```
    #[must_use]
    pub fn private_backing_field(mut self) -> Self {
        if let PropertyImplementation::Auto {
            backing_field_attributes,
            ..
        } = &mut self.implementation
        {
            *backing_field_attributes = 0x0001; // PRIVATE
        }
        self
    }

    /// Make the backing field public (unusual but possible).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .public_backing_field();
    /// ```
    #[must_use]
    pub fn public_backing_field(mut self) -> Self {
        if let PropertyImplementation::Auto {
            backing_field_attributes,
            ..
        } = &mut self.implementation
        {
            *backing_field_attributes = 0x0006; // PUBLIC
        }
        self
    }

    /// Make this a read-only property (getter only).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("ReadOnlyValue", TypeSignature::I4)
    ///     .readonly();
    /// ```
    #[must_use]
    pub fn readonly(mut self) -> Self {
        self.accessors = PropertyAccessors::GetterOnly;
        self
    }

    /// Make this a write-only property (setter only, rare).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("WriteOnlyValue", TypeSignature::I4)
    ///     .writeonly();
    /// ```
    #[must_use]
    pub fn writeonly(mut self) -> Self {
        self.accessors = PropertyAccessors::SetterOnly;
        self
    }

    /// Configure both getter and setter accessors (default).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .getter_and_setter();
    /// ```
    #[must_use]
    pub fn getter_and_setter(mut self) -> Self {
        self.accessors = PropertyAccessors::GetterAndSetter;
        self
    }

    /// Make both accessors public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .public_accessors();
    /// ```
    #[must_use]
    pub fn public_accessors(mut self) -> Self {
        self.getter_attributes = 0x0006; // PUBLIC
        self.setter_attributes = 0x0006; // PUBLIC
        self
    }

    /// Make both accessors private.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .private_accessors();
    /// ```
    #[must_use]
    pub fn private_accessors(mut self) -> Self {
        self.getter_attributes = 0x0001; // PRIVATE
        self.setter_attributes = 0x0001; // PRIVATE
        self
    }

    /// Set getter visibility separately.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Method attributes for the getter
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .getter_visibility(0x0006); // PUBLIC
    /// ```
    #[must_use]
    pub fn getter_visibility(mut self, attributes: u32) -> Self {
        self.getter_attributes = attributes;
        self
    }

    /// Set setter visibility separately.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Method attributes for the setter
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .setter_visibility(0x0001); // PRIVATE
    /// ```
    #[must_use]
    pub fn setter_visibility(mut self, attributes: u32) -> Self {
        self.setter_attributes = attributes;
        self
    }

    /// Add a custom getter implementation (for computed properties).
    ///
    /// # Arguments
    ///
    /// * `implementation` - Function that configures the getter method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let builder = CilPropertyBuilder::new("ComputedValue", TypeSignature::I4)
    ///     .computed()
    ///     .getter(|method| method
    ///         .implementation(|body| {
    ///             body.implementation(|asm| {
    ///                 asm.ldc_i4(42)?.ret()?;
    ///                 Ok(())
    ///             })
    ///         }));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn getter<F>(mut self, implementation: F) -> Self
    where
        F: FnOnce(MethodBuilder) -> MethodBuilder + Send + 'static,
    {
        if let PropertyImplementation::Computed { getter, .. } = &mut self.implementation {
            *getter = Some(Box::new(implementation));
        }
        self
    }

    /// Add a custom setter implementation (for computed properties).
    ///
    /// # Arguments
    ///
    /// * `implementation` - Function that configures the setter method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_file("test.dll".as_ref())?;
    /// # let assembly = CilAssembly::new(view);
    /// # let mut context = BuilderContext::new(assembly);
    /// let builder = CilPropertyBuilder::new("ComputedValue", TypeSignature::I4)
    ///     .computed()
    ///     .setter(|method| method
    ///         .implementation(|body| {
    ///             body.implementation(|asm| {
    ///                 // Custom setter logic
    ///                 asm.ret()?;
    ///                 Ok(())
    ///             })
    ///         }));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn setter<F>(mut self, implementation: F) -> Self
    where
        F: FnOnce(MethodBuilder) -> MethodBuilder + Send + 'static,
    {
        if let PropertyImplementation::Computed { setter, .. } = &mut self.implementation {
            *setter = Some(Box::new(implementation));
        }
        self
    }

    /// Make this an indexed property with parameters.
    ///
    /// Indexed properties are like C# indexers and take parameters.
    ///
    /// # Arguments
    ///
    /// * `param_name` - Parameter name
    /// * `param_type` - Parameter type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Item", TypeSignature::String)
    ///     .indexed("index", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn indexed(mut self, param_name: &str, param_type: TypeSignature) -> Self {
        self.is_indexed = true;
        self.parameters.push((param_name.to_string(), param_type));
        self
    }

    /// Add additional parameters to an indexed property.
    ///
    /// # Arguments
    ///
    /// * `param_name` - Parameter name  
    /// * `param_type` - Parameter type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Item", TypeSignature::String)
    ///     .indexed("row", TypeSignature::I4)
    ///     .parameter("column", TypeSignature::I4);
    /// ```
    #[must_use]
    pub fn parameter(mut self, param_name: &str, param_type: TypeSignature) -> Self {
        self.parameters.push((param_name.to_string(), param_type));
        self
    }

    /// Set property attributes.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Property attributes bitmask
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CilPropertyBuilder::new("Value", TypeSignature::I4)
    ///     .attributes(0x0200); // SPECIAL_NAME
    /// ```
    #[must_use]
    pub fn attributes(mut self, attributes: u32) -> Self {
        self.attributes = attributes;
        self
    }

    /// Build the complete property and add it to the assembly.
    ///
    /// This method orchestrates the creation of:
    /// 1. Property table entry
    /// 2. Backing field (for auto-properties)
    /// 3. Getter method (if applicable)
    /// 4. Setter method (if applicable)
    /// 5. PropertyMap entry linking property to parent type
    ///
    /// # Arguments
    ///
    /// * `context` - Builder context for managing the assembly
    ///
    /// # Returns
    ///
    /// A token representing the newly created property definition.
    ///
    /// # Errors
    ///
    /// Returns an error if property creation fails at any step.
    pub fn build(self, context: &mut BuilderContext) -> Result<Token> {
        // Create property signature with parameters for indexed properties
        let mut signature_params = Vec::new();
        for (_param_name, param_type) in &self.parameters {
            signature_params.push(SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: param_type.clone(),
            });
        }

        let property_signature = SignatureProperty {
            has_this: true, // Most properties are instance properties
            modifiers: Vec::new(),
            base: self.property_type.clone(),
            params: signature_params,
        };

        // Encode property signature to bytes
        let signature_bytes = encode_property_signature(&property_signature)?;

        // Create the property table entry
        let property_token = PropertyTableBuilder::new()
            .name(&self.name)
            .flags(self.attributes)
            .signature(&signature_bytes)
            .build(context)?;

        // Handle different implementation strategies
        match self.implementation {
            PropertyImplementation::Auto {
                backing_field_name,
                backing_field_attributes,
            } => {
                // Generate backing field name if not provided
                let field_name =
                    backing_field_name.unwrap_or_else(|| format!("<{}>k__BackingField", self.name));

                // Create backing field
                let field_sig = SignatureField {
                    modifiers: Vec::new(),
                    base: self.property_type.clone(),
                };
                let sig_bytes = encode_field_signature(&field_sig)?;

                let backing_field_token = FieldBuilder::new()
                    .name(&field_name)
                    .flags(backing_field_attributes)
                    .signature(&sig_bytes)
                    .build(context)?;

                // Create getter if needed
                if matches!(
                    self.accessors,
                    PropertyAccessors::GetterAndSetter | PropertyAccessors::GetterOnly
                ) {
                    let getter_field_token = backing_field_token; // Copy for move
                    let getter_name = self.name.clone();
                    let getter_type = self.property_type.clone();
                    let getter_visibility = self.getter_attributes;

                    let getter = MethodBuilder::property_getter(&getter_name, getter_type);
                    let getter = match getter_visibility {
                        0x0001 => getter.private(),
                        _ => getter.public(),
                    };

                    getter
                        .implementation(move |body| {
                            body.implementation(move |asm| {
                                asm.ldarg_0()? // Load 'this'
                                    .ldfld(getter_field_token)? // Load backing field
                                    .ret()?;
                                Ok(())
                            })
                        })
                        .build(context)?;
                }

                // Create setter if needed
                if matches!(
                    self.accessors,
                    PropertyAccessors::GetterAndSetter | PropertyAccessors::SetterOnly
                ) {
                    let setter_field_token = backing_field_token; // Copy for move
                    let setter_name = self.name.clone();
                    let setter_type = self.property_type.clone();
                    let setter_visibility = self.setter_attributes;

                    let setter = MethodBuilder::property_setter(&setter_name, setter_type);
                    let setter = match setter_visibility {
                        0x0001 => setter.private(),
                        _ => setter.public(),
                    };

                    setter
                        .implementation(move |body| {
                            body.implementation(move |asm| {
                                asm.ldarg_0()? // Load 'this'
                                    .ldarg_1()? // Load value
                                    .stfld(setter_field_token)? // Store to backing field
                                    .ret()?;
                                Ok(())
                            })
                        })
                        .build(context)?;
                }

                Ok(property_token)
            }
            PropertyImplementation::Computed { getter, setter } => {
                // Create getter if provided and needed
                if matches!(
                    self.accessors,
                    PropertyAccessors::GetterAndSetter | PropertyAccessors::GetterOnly
                ) {
                    if let Some(getter_impl) = getter {
                        let getter_method =
                            MethodBuilder::property_getter(&self.name, self.property_type.clone());
                        let getter_method = match self.getter_attributes {
                            0x0001 => getter_method.private(),
                            _ => getter_method.public(),
                        };

                        let configured_getter = getter_impl(getter_method);
                        configured_getter.build(context)?;
                    } else {
                        return Err(Error::ModificationInvalidOperation {
                            details: "Computed property requires getter implementation".to_string(),
                        });
                    }
                }

                // Create setter if provided and needed
                if matches!(
                    self.accessors,
                    PropertyAccessors::GetterAndSetter | PropertyAccessors::SetterOnly
                ) {
                    if let Some(setter_impl) = setter {
                        let setter_method =
                            MethodBuilder::property_setter(&self.name, self.property_type.clone());
                        let setter_method = match self.setter_attributes {
                            0x0001 => setter_method.private(),
                            _ => setter_method.public(),
                        };

                        let configured_setter = setter_impl(setter_method);
                        configured_setter.build(context)?;
                    } else {
                        return Err(Error::ModificationInvalidOperation {
                            details: "Computed property requires setter implementation".to_string(),
                        });
                    }
                }

                Ok(property_token)
            }
            PropertyImplementation::Manual => {
                // For manual implementation, just return the property token
                // User is responsible for creating methods separately
                Ok(property_token)
            }
        }
    }
}

impl Default for PropertyBuilder {
    fn default() -> Self {
        Self::new("DefaultProperty", TypeSignature::Object)
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
    fn test_simple_auto_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("Name", TypeSignature::String)
            .auto_property()
            .public_accessors()
            .build(&mut context)?;

        // Should create a valid Property token
        assert_eq!(property_token.value() & 0xFF000000, 0x17000000); // Property table

        Ok(())
    }

    #[test]
    fn test_readonly_auto_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("ReadOnlyValue", TypeSignature::I4)
            .auto_property()
            .readonly()
            .public_accessors()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_computed_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("ComputedValue", TypeSignature::I4)
            .computed()
            .getter(|method| {
                method.implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldc_i4(42)?.ret()?;
                        Ok(())
                    })
                })
            })
            .readonly()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_custom_backing_field() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("Value", TypeSignature::R8)
            .auto_property()
            .backing_field("_customValue")
            .private_backing_field()
            .public_accessors()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_indexed_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("Item", TypeSignature::String)
            .auto_property()
            .indexed("index", TypeSignature::I4)
            .public_accessors()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_multi_parameter_indexed_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("Matrix", TypeSignature::I4)
            .auto_property()
            .indexed("row", TypeSignature::I4)
            .parameter("column", TypeSignature::I4)
            .public_accessors()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_writeonly_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("WriteOnly", TypeSignature::String)
            .auto_property()
            .writeonly()
            .public_accessors()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_manual_property() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("Manual", TypeSignature::Object)
            .manual()
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_property_with_different_accessor_visibility() -> Result<()> {
        let mut context = get_test_context()?;

        let property_token = PropertyBuilder::new("MixedVisibility", TypeSignature::I4)
            .auto_property()
            .getter_visibility(0x0006) // PUBLIC
            .setter_visibility(0x0001) // PRIVATE
            .build(&mut context)?;

        assert_eq!(property_token.value() & 0xFF000000, 0x17000000);

        Ok(())
    }

    #[test]
    fn test_computed_property_missing_getter_fails() {
        let mut context = get_test_context().unwrap();

        let result = PropertyBuilder::new("InvalidComputed", TypeSignature::I4)
            .computed()
            .readonly()
            .build(&mut context);

        assert!(result.is_err());
    }

    #[test]
    fn test_computed_property_missing_setter_fails() {
        let mut context = get_test_context().unwrap();

        let result = PropertyBuilder::new("InvalidComputed", TypeSignature::I4)
            .computed()
            .writeonly()
            .build(&mut context);

        assert!(result.is_err());
    }
}
