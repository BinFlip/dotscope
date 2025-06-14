//! Custom attribute builders for creating mock custom attributes with various argument types
//!
//! This module provides builders for creating custom attributes with different constructors,
//! named arguments, and value types commonly used in .NET metadata.

use std::sync::Arc;

use crate::metadata::{
    customattributes::{
        CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue,
        CustomAttributeValueList,
    },
    tables::{CustomAttribute, CustomAttributeRc},
    token::Token,
    typesystem::CilTypeReference,
};

/// Argument types for custom attributes (simplified interface)
#[derive(Debug, Clone)]
pub enum AttributeArgument {
    /// Boolean argument
    Bool(bool),
    /// 8-bit signed integer
    I1(i8),
    /// 8-bit unsigned integer
    U1(u8),
    /// 16-bit signed integer
    I2(i16),
    /// 16-bit unsigned integer
    U2(u16),
    /// 32-bit signed integer
    I4(i32),
    /// 32-bit unsigned integer
    U4(u32),
    /// 64-bit signed integer
    I8(i64),
    /// 64-bit unsigned integer
    U8(u64),
    /// 32-bit floating point
    R4(f32),
    /// 64-bit floating point
    R8(f64),
    /// Character argument
    Char(char),
    /// String argument
    String(String),
    /// Type argument (Type token)
    Type(Token),
    /// Enum value (token + value)
    Enum(String, i32),
    /// Array of arguments
    Array(Vec<AttributeArgument>),
    /// Null reference
    Null,
}

impl AttributeArgument {
    /// Convert to CustomAttributeArgument for storage
    pub fn to_custom_attribute_arg(&self) -> CustomAttributeArgument {
        match self {
            AttributeArgument::Bool(val) => CustomAttributeArgument::Bool(*val),
            AttributeArgument::I1(val) => CustomAttributeArgument::I1(*val),
            AttributeArgument::U1(val) => CustomAttributeArgument::U1(*val),
            AttributeArgument::I2(val) => CustomAttributeArgument::I2(*val),
            AttributeArgument::U2(val) => CustomAttributeArgument::U2(*val),
            AttributeArgument::I4(val) => CustomAttributeArgument::I4(*val),
            AttributeArgument::U4(val) => CustomAttributeArgument::U4(*val),
            AttributeArgument::I8(val) => CustomAttributeArgument::I8(*val),
            AttributeArgument::U8(val) => CustomAttributeArgument::U8(*val),
            AttributeArgument::R4(val) => CustomAttributeArgument::R4(*val),
            AttributeArgument::R8(val) => CustomAttributeArgument::R8(*val),
            AttributeArgument::Char(val) => CustomAttributeArgument::Char(*val),
            AttributeArgument::String(val) => CustomAttributeArgument::String(val.clone()),
            AttributeArgument::Type(_) => CustomAttributeArgument::Type("System.Type".to_string()),
            AttributeArgument::Enum(type_name, val) => CustomAttributeArgument::Enum(
                type_name.clone(),
                Box::new(CustomAttributeArgument::I4(*val)),
            ),
            AttributeArgument::Array(args) => CustomAttributeArgument::Array(
                args.iter()
                    .map(|arg| arg.to_custom_attribute_arg())
                    .collect(),
            ),
            AttributeArgument::Null => CustomAttributeArgument::Void, // Use Void for null values
        }
    }
}

/// Named argument for custom attributes (property or field assignment)
#[derive(Debug, Clone)]
pub struct NamedArgument {
    /// Name of the property or field
    pub name: String,
    /// Whether this is a field (true) or property (false)
    pub is_field: bool,
    /// Argument value
    pub value: AttributeArgument,
    /// Type name for the argument
    pub arg_type: String,
}

impl NamedArgument {
    pub fn new_property(name: &str, value: AttributeArgument) -> Self {
        let arg_type = match &value {
            AttributeArgument::Bool(_) => "System.Boolean",
            AttributeArgument::I4(_) => "System.Int32",
            AttributeArgument::String(_) => "System.String",
            _ => "System.Object",
        };

        Self {
            name: name.to_string(),
            is_field: false,
            value,
            arg_type: arg_type.to_string(),
        }
    }

    pub fn new_field(name: &str, value: AttributeArgument) -> Self {
        let arg_type = match &value {
            AttributeArgument::Bool(_) => "System.Boolean",
            AttributeArgument::I4(_) => "System.Int32",
            AttributeArgument::String(_) => "System.String",
            _ => "System.Object",
        };

        Self {
            name: name.to_string(),
            is_field: true,
            value,
            arg_type: arg_type.to_string(),
        }
    }
}

/// Builder for creating mock custom attributes with various argument types
pub struct CustomAttributeBuilder {
    rid: u32,
    parent: Token,
    constructor: Token,
    fixed_args: Vec<AttributeArgument>,
    named_args: Vec<NamedArgument>,
}

impl CustomAttributeBuilder {
    pub fn new(parent: Token, constructor: Token) -> Self {
        Self {
            rid: 1,
            parent,
            constructor,
            fixed_args: Vec::new(),
            named_args: Vec::new(),
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_fixed_arg(mut self, arg: AttributeArgument) -> Self {
        self.fixed_args.push(arg);
        self
    }

    pub fn with_fixed_args(mut self, args: Vec<AttributeArgument>) -> Self {
        self.fixed_args.extend(args);
        self
    }

    pub fn with_named_arg(mut self, arg: NamedArgument) -> Self {
        self.named_args.push(arg);
        self
    }

    pub fn with_named_args(mut self, args: Vec<NamedArgument>) -> Self {
        self.named_args.extend(args);
        self
    }

    // Convenience methods for common fixed arguments
    pub fn add_string_arg(mut self, value: &str) -> Self {
        self.fixed_args
            .push(AttributeArgument::String(value.to_string()));
        self
    }

    pub fn add_int_arg(mut self, value: i32) -> Self {
        self.fixed_args.push(AttributeArgument::I4(value));
        self
    }

    pub fn add_bool_arg(mut self, value: bool) -> Self {
        self.fixed_args.push(AttributeArgument::Bool(value));
        self
    }

    pub fn add_type_arg(mut self, type_token: Token) -> Self {
        self.fixed_args.push(AttributeArgument::Type(type_token));
        self
    }

    // Convenience methods for common named arguments
    pub fn add_named_string(mut self, name: &str, value: &str) -> Self {
        self.named_args.push(NamedArgument::new_property(
            name,
            AttributeArgument::String(value.to_string()),
        ));
        self
    }

    pub fn add_named_int(mut self, name: &str, value: i32) -> Self {
        self.named_args.push(NamedArgument::new_property(
            name,
            AttributeArgument::I4(value),
        ));
        self
    }

    pub fn add_named_bool(mut self, name: &str, value: bool) -> Self {
        self.named_args.push(NamedArgument::new_property(
            name,
            AttributeArgument::Bool(value),
        ));
        self
    }

    /// Create an Obsolete attribute
    pub fn obsolete_attribute(parent: Token, message: &str) -> Self {
        Self::new(parent, Token::new(0x0A000001)) // Simplified token for System.ObsoleteAttribute constructor
            .add_string_arg(message)
    }

    /// Create a Conditional attribute
    pub fn conditional_attribute(parent: Token, condition: &str) -> Self {
        Self::new(parent, Token::new(0x0A000002)) // Simplified token for System.Diagnostics.ConditionalAttribute constructor
            .add_string_arg(condition)
    }

    /// Create a DllImport attribute
    pub fn dllimport_attribute(parent: Token, dll_name: &str) -> Self {
        Self::new(parent, Token::new(0x0A000003)) // Simplified token for System.Runtime.InteropServices.DllImportAttribute constructor
            .add_string_arg(dll_name)
    }

    /// Create a Serializable attribute
    pub fn serializable_attribute(parent: Token) -> Self {
        Self::new(parent, Token::new(0x0A000004)) // Simplified token for System.SerializableAttribute constructor
    }

    /// Create a ComVisible attribute
    pub fn comvisible_attribute(parent: Token, visible: bool) -> Self {
        Self::new(parent, Token::new(0x0A000005)) // Simplified token for System.Runtime.InteropServices.ComVisibleAttribute constructor
            .add_bool_arg(visible)
    }

    /// Create a DebuggerDisplay attribute
    pub fn debugger_display_attribute(parent: Token, value: &str) -> Self {
        Self::new(parent, Token::new(0x0A000006)) // Simplified token for System.Diagnostics.DebuggerDisplayAttribute constructor
            .add_string_arg(value)
    }

    /// Create a custom attribute with typical assembly-level information
    pub fn assembly_info_attribute(parent: Token, title: &str, version: &str) -> Self {
        Self::new(parent, Token::new(0x0A000007)) // Simplified token for AssemblyTitleAttribute constructor
            .add_string_arg(title)
            .add_named_string("Version", version)
    }

    pub fn build(self) -> CustomAttributeRc {
        // Create custom attribute value
        let value = CustomAttributeValue {
            fixed_args: self
                .fixed_args
                .iter()
                .map(|arg| arg.to_custom_attribute_arg())
                .collect(),
            named_args: self
                .named_args
                .iter()
                .map(|arg| CustomAttributeNamedArgument {
                    is_field: arg.is_field,
                    name: arg.name.clone(),
                    arg_type: arg.arg_type.clone(),
                    value: arg.value.to_custom_attribute_arg(),
                })
                .collect(),
        };

        Arc::new(CustomAttribute {
            rid: self.rid,
            token: Token::new(0x0C000000 + self.rid), // CustomAttribute table
            offset: 0,
            parent: CilTypeReference::None, // Simplified for testing
            constructor: CilTypeReference::None, // Simplified for testing
            value,
        })
    }
}

/// Builder for creating lists of custom attributes for common scenarios
pub struct CustomAttributeListBuilder {
    attributes: Vec<CustomAttributeBuilder>,
}

impl CustomAttributeListBuilder {
    pub fn new() -> Self {
        Self {
            attributes: Vec::new(),
        }
    }

    pub fn add_attribute(mut self, builder: CustomAttributeBuilder) -> Self {
        self.attributes.push(builder);
        self
    }

    pub fn add_obsolete(mut self, parent: Token, message: &str) -> Self {
        self.attributes
            .push(CustomAttributeBuilder::obsolete_attribute(parent, message));
        self
    }

    pub fn add_conditional(mut self, parent: Token, condition: &str) -> Self {
        self.attributes
            .push(CustomAttributeBuilder::conditional_attribute(
                parent, condition,
            ));
        self
    }

    pub fn add_dllimport(mut self, parent: Token, dll_name: &str) -> Self {
        self.attributes
            .push(CustomAttributeBuilder::dllimport_attribute(
                parent, dll_name,
            ));
        self
    }

    pub fn add_serializable(mut self, parent: Token) -> Self {
        self.attributes
            .push(CustomAttributeBuilder::serializable_attribute(parent));
        self
    }

    pub fn add_comvisible(mut self, parent: Token, visible: bool) -> Self {
        self.attributes
            .push(CustomAttributeBuilder::comvisible_attribute(
                parent, visible,
            ));
        self
    }

    /// Create common assembly-level attributes
    pub fn assembly_attributes(assembly_token: Token) -> Self {
        Self::new()
            .add_attribute(CustomAttributeBuilder::assembly_info_attribute(
                assembly_token,
                "Test Assembly",
                "1.0.0.0",
            ))
            .add_comvisible(assembly_token, false)
    }

    /// Create common method attributes for P/Invoke
    pub fn pinvoke_method_attributes(method_token: Token, dll_name: &str) -> Self {
        Self::new().add_dllimport(method_token, dll_name)
    }

    /// Create common type attributes
    pub fn serializable_type_attributes(type_token: Token) -> Self {
        Self::new()
            .add_serializable(type_token)
            .add_comvisible(type_token, false)
    }

    pub fn build(self) -> CustomAttributeValueList {
        let attribute_values: Vec<_> = self
            .attributes
            .into_iter()
            .map(|builder| Arc::new(builder.build().value.clone()))
            .collect();

        Arc::new(boxcar::Vec::from_iter(attribute_values))
    }
}

impl Default for CustomAttributeListBuilder {
    fn default() -> Self {
        Self::new()
    }
}
