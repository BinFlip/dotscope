//! Property builders for creating mock Property instances with various configurations
//!
//! This module provides builders for creating Property instances with getters, setters,
//! default values, and custom attributes.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        signatures::{SignatureProperty, TypeSignature},
        tables::{Property, PropertyRc},
        token::Token,
        typesystem::CilPrimitive,
    },
    prelude::SignatureParameter,
};

/// Property constant value types for default values
#[derive(Debug, Clone)]
pub enum PropertyConstant {
    /// Boolean constant
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
    /// String constant
    String(String),
    /// Null reference
    Null,
}

impl PropertyConstant {
    /// Convert to CilPrimitive for use in tests
    pub fn to_primitive(&self) -> CilPrimitive {
        match self {
            PropertyConstant::Bool(val) => CilPrimitive::boolean(*val),
            PropertyConstant::I1(val) => CilPrimitive::i1(*val),
            PropertyConstant::U1(val) => CilPrimitive::u1(*val),
            PropertyConstant::I2(val) => CilPrimitive::i2(*val),
            PropertyConstant::U2(val) => CilPrimitive::u2(*val),
            PropertyConstant::I4(val) => CilPrimitive::i4(*val),
            PropertyConstant::U4(val) => CilPrimitive::u4(*val),
            PropertyConstant::I8(val) => CilPrimitive::i8(*val),
            PropertyConstant::U8(val) => CilPrimitive::u8(*val),
            PropertyConstant::R4(val) => CilPrimitive::r4(*val),
            PropertyConstant::R8(val) => CilPrimitive::r8(*val),
            PropertyConstant::String(val) => CilPrimitive::string(val),
            PropertyConstant::Null => CilPrimitive::null(),
        }
    }
}

/// Builder for creating mock Property instances with various configurations
pub struct PropertyBuilder {
    rid: u32,
    name: String,
    signature: SignatureProperty,
    flags: u32,
    default_value: Option<PropertyConstant>,
}

impl PropertyBuilder {
    pub fn new(name: &str, return_type: TypeSignature) -> Self {
        Self {
            rid: 1,
            name: name.to_string(),
            signature: SignatureProperty {
                has_this: false,
                modifiers: Vec::new(),
                params: Vec::new(),
                base: return_type,
            },
            flags: 0,
            default_value: None,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_params(mut self, params: Vec<SignatureParameter>) -> Self {
        self.signature.params = params;
        self
    }

    pub fn with_default(mut self, default: PropertyConstant) -> Self {
        self.default_value = Some(default);
        self
    }

    /// Create a simple property with no parameters (getter/setter property)
    pub fn simple_property(name: &str, property_type: TypeSignature) -> Self {
        Self::new(name, property_type)
    }

    /// Create a property with a default constant value
    pub fn property_with_default(
        name: &str,
        property_type: TypeSignature,
        default: PropertyConstant,
    ) -> Self {
        Self::new(name, property_type).with_default(default)
    }

    /// Build the Property instance
    pub fn build(self) -> PropertyRc {
        let token = Token::new(0x17000000 + self.rid);
        let property = Property {
            token,
            flags: self.flags,
            name: self.name,
            signature: self.signature,
            default: OnceLock::new(),
            fn_setter: OnceLock::new(),
            fn_getter: OnceLock::new(),
            fn_other: OnceLock::new(),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        };

        let property_rc = Arc::new(property);

        // Set default value if provided
        if let Some(default) = self.default_value {
            let _ = property_rc.default.set(default.to_primitive());
        }

        property_rc
    }
}

/// Create a property that accepts constants (int32 type)
pub fn property_accepting_constants(name: &str) -> PropertyRc {
    PropertyBuilder::simple_property(name, TypeSignature::I4).build()
}

/// Create a property that doesn't accept certain constants (object type)
pub fn property_rejecting_constants(name: &str) -> PropertyRc {
    PropertyBuilder::simple_property(name, TypeSignature::Object).build()
}

/// Create a property with a pre-set default value
pub fn property_with_default_set(name: &str, default: PropertyConstant) -> PropertyRc {
    PropertyBuilder::property_with_default(name, TypeSignature::I4, default).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_builder_basic() {
        let property = PropertyBuilder::new("TestProperty", TypeSignature::I4)
            .with_rid(42)
            .build();

        assert_eq!(property.name, "TestProperty");
        assert_eq!(property.signature.base, TypeSignature::I4);
        assert_eq!(property.token.value(), 0x1700002A);
    }

    #[test]
    fn test_property_with_default() {
        let property = PropertyBuilder::property_with_default(
            "DefaultProp",
            TypeSignature::I4,
            PropertyConstant::I4(123),
        )
        .build();

        assert!(property.default.get().is_some());
        let default = property.default.get().unwrap();
        assert_eq!(
            default.data,
            crate::metadata::typesystem::CilPrimitiveData::I4(123)
        );
    }

    #[test]
    fn test_helper_functions() {
        let accepting = property_accepting_constants("AcceptsProp");
        assert_eq!(accepting.signature.base, TypeSignature::I4);

        let rejecting = property_rejecting_constants("RejectsProp");
        assert_eq!(rejecting.signature.base, TypeSignature::Object);

        let with_default = property_with_default_set("DefaultProp", PropertyConstant::I4(456));
        assert!(with_default.default.get().is_some());
    }
}
