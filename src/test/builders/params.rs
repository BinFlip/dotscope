//! Parameter builders for creating mock Param instances for method testing
//!
//! This module provides builders for creating Param instances with various
//! characteristics including input/output parameters, defaults, and marshalling.

use std::sync::{atomic::AtomicBool, Arc, OnceLock};

use crate::{
    metadata::{
        marshalling::MarshallingInfo,
        tables::{Param, ParamRc},
        token::Token,
        typesystem::{CilFlavor, CilPrimitive, TypeRegistry},
    },
    prelude::{CilPrimitiveData, CilPrimitiveKind, ParamAttributes},
};

/// Parameter attribute flags for various parameter characteristics
#[derive(Debug, Clone, Copy)]
pub enum ParamDirection {
    /// Input parameter (default)
    In,
    /// Output parameter
    Out,
    /// Input/output parameter
    InOut,
}

/// Parameter default value types
#[derive(Debug, Clone)]
pub enum ParamDefault {
    /// Boolean default
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
    /// String default
    String(String),
    /// Null reference
    Null,
}

/// Builder for creating mock Param instances
pub struct ParamBuilder {
    rid: u32,
    sequence: u32,
    name: Option<String>,
    flags: u32,
    direction: ParamDirection,
    default_value: Option<ParamDefault>,
    marshal_info: Option<MarshallingInfo>,
    is_optional: bool,
    type_flavor: Option<CilFlavor>,
}

impl ParamBuilder {
    /// Create a new parameter builder
    pub fn new(sequence: u32, name: Option<String>) -> Self {
        Self {
            rid: sequence,
            sequence,
            name,
            flags: 0,
            direction: ParamDirection::In,
            default_value: None,
            marshal_info: None,
            is_optional: false,
            type_flavor: None,
        }
    }

    /// Create a return value parameter (sequence 0)
    pub fn return_value() -> Self {
        Self::new(0, None)
    }

    /// Create a named input parameter
    pub fn input_param(sequence: u32, name: &str) -> Self {
        Self::new(sequence, Some(name.to_string())).with_direction(ParamDirection::In)
    }

    /// Create a named output parameter
    pub fn output_param(sequence: u32, name: &str) -> Self {
        Self::new(sequence, Some(name.to_string())).with_direction(ParamDirection::Out)
    }

    /// Create an input/output parameter
    pub fn inout_param(sequence: u32, name: &str) -> Self {
        Self::new(sequence, Some(name.to_string())).with_direction(ParamDirection::InOut)
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_direction(mut self, direction: ParamDirection) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_default_value(mut self, default: ParamDefault) -> Self {
        self.default_value = Some(default);
        self
    }

    pub fn with_marshal_info(mut self, marshal: MarshallingInfo) -> Self {
        self.marshal_info = Some(marshal);
        self
    }

    pub fn with_optional(mut self) -> Self {
        self.is_optional = true;
        self
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Set the parameter type from a CilFlavor
    pub fn with_type_from_flavor(mut self, flavor: CilFlavor) -> Self {
        // Store the flavor - it will be resolved to an actual type during build()
        self.type_flavor = Some(flavor);
        self
    }

    /// Set the parameter type from a CilPrimitiveKind
    pub fn with_primitive_type(mut self, kind: CilPrimitiveKind) -> Self {
        self.type_flavor = Some(match kind {
            CilPrimitiveKind::Boolean => CilFlavor::Boolean,
            CilPrimitiveKind::Char => CilFlavor::Char,
            CilPrimitiveKind::I1 => CilFlavor::I1,
            CilPrimitiveKind::U1 => CilFlavor::U1,
            CilPrimitiveKind::I2 => CilFlavor::I2,
            CilPrimitiveKind::U2 => CilFlavor::U2,
            CilPrimitiveKind::I4 => CilFlavor::I4,
            CilPrimitiveKind::U4 => CilFlavor::U4,
            CilPrimitiveKind::I8 => CilFlavor::I8,
            CilPrimitiveKind::U8 => CilFlavor::U8,
            CilPrimitiveKind::R4 => CilFlavor::R4,
            CilPrimitiveKind::R8 => CilFlavor::R8,
            CilPrimitiveKind::I => CilFlavor::I,
            CilPrimitiveKind::U => CilFlavor::U,
            CilPrimitiveKind::String => CilFlavor::String,
            CilPrimitiveKind::Object => CilFlavor::Object,
            CilPrimitiveKind::Void => CilFlavor::Void,
            CilPrimitiveKind::Null => CilFlavor::Object, // Treat null as object reference
            CilPrimitiveKind::TypedReference => CilFlavor::Object, // Special case
            CilPrimitiveKind::ValueType => CilFlavor::ValueType,
            // Handle remaining variants - these may not have direct CilFlavor equivalents
            _ => CilFlavor::Object, // Default fallback
        });
        self
    }

    /// Build the Param instance
    pub fn build(self) -> ParamRc {
        let mut flags = self.flags;

        // Set direction flags
        match self.direction {
            ParamDirection::In => flags |= ParamAttributes::IN,
            ParamDirection::Out => flags |= ParamAttributes::OUT,
            ParamDirection::InOut => {
                flags |= ParamAttributes::IN | ParamAttributes::OUT;
            }
        }

        // Set optional flag
        if self.is_optional {
            flags |= ParamAttributes::OPTIONAL;
        }

        // Set default value flag
        if self.default_value.is_some() {
            flags |= ParamAttributes::HAS_DEFAULT;
        }

        // Set marshal flag
        if self.marshal_info.is_some() {
            flags |= ParamAttributes::HAS_FIELD_MARSHAL;
        }

        let param = Arc::new(Param {
            rid: self.rid,
            token: Token::new(0x08000000 + self.rid),
            offset: 0,
            flags,
            sequence: self.sequence,
            name: self.name,
            default: OnceLock::new(),
            marshal: OnceLock::new(),
            modifiers: Arc::new(boxcar::Vec::new()),
            base: OnceLock::new(),
            is_by_ref: AtomicBool::new(false),
            custom_attributes: Arc::new(boxcar::Vec::new()),
        });

        // Set default value if provided
        if let Some(default) = self.default_value {
            let primitive = match default {
                ParamDefault::Bool(v) => CilPrimitive {
                    kind: CilPrimitiveKind::Boolean,
                    data: CilPrimitiveData::Boolean(v),
                },
                ParamDefault::I1(v) => CilPrimitive {
                    kind: CilPrimitiveKind::I1,
                    data: CilPrimitiveData::I1(v),
                },
                ParamDefault::U1(v) => CilPrimitive {
                    kind: CilPrimitiveKind::U1,
                    data: CilPrimitiveData::U1(v),
                },
                ParamDefault::I2(v) => CilPrimitive {
                    kind: CilPrimitiveKind::I2,
                    data: CilPrimitiveData::I2(v),
                },
                ParamDefault::U2(v) => CilPrimitive {
                    kind: CilPrimitiveKind::U2,
                    data: CilPrimitiveData::U2(v),
                },
                ParamDefault::I4(v) => CilPrimitive {
                    kind: CilPrimitiveKind::I4,
                    data: CilPrimitiveData::I4(v),
                },
                ParamDefault::U4(v) => CilPrimitive {
                    kind: CilPrimitiveKind::U4,
                    data: CilPrimitiveData::U4(v),
                },
                ParamDefault::I8(v) => CilPrimitive {
                    kind: CilPrimitiveKind::I8,
                    data: CilPrimitiveData::I8(v),
                },
                ParamDefault::U8(v) => CilPrimitive {
                    kind: CilPrimitiveKind::U8,
                    data: CilPrimitiveData::U8(v),
                },
                ParamDefault::R4(v) => CilPrimitive {
                    kind: CilPrimitiveKind::R4,
                    data: CilPrimitiveData::R4(v),
                },
                ParamDefault::R8(v) => CilPrimitive {
                    kind: CilPrimitiveKind::R8,
                    data: CilPrimitiveData::R8(v),
                },
                ParamDefault::String(v) => CilPrimitive {
                    kind: CilPrimitiveKind::String,
                    data: CilPrimitiveData::String(v),
                },
                ParamDefault::Null => CilPrimitive {
                    kind: CilPrimitiveKind::Class,
                    data: CilPrimitiveData::None,
                },
            };
            let _ = param.default.set(primitive);
        }

        // Set marshal info if provided
        if let Some(marshal) = self.marshal_info {
            let _ = param.marshal.set(marshal);
        }

        // Set parameter type if provided
        if let Some(flavor) = self.type_flavor {
            // Get or create a global type registry for tests to avoid dropping type references
            static TEST_TYPE_REGISTRY: std::sync::OnceLock<Arc<TypeRegistry>> =
                std::sync::OnceLock::new();

            let type_registry = TEST_TYPE_REGISTRY.get_or_init(|| {
                Arc::new(
                    crate::metadata::typesystem::TypeRegistry::new()
                        .expect("Failed to create test type registry"),
                )
            });

            let param_type = match flavor {
                CilFlavor::Boolean => type_registry
                    .get_primitive(CilPrimitiveKind::Boolean)
                    .unwrap(),
                CilFlavor::Char => type_registry.get_primitive(CilPrimitiveKind::Char).unwrap(),
                CilFlavor::I1 => type_registry.get_primitive(CilPrimitiveKind::I1).unwrap(),
                CilFlavor::U1 => type_registry.get_primitive(CilPrimitiveKind::U1).unwrap(),
                CilFlavor::I2 => type_registry.get_primitive(CilPrimitiveKind::I2).unwrap(),
                CilFlavor::U2 => type_registry.get_primitive(CilPrimitiveKind::U2).unwrap(),
                CilFlavor::I4 => type_registry.get_primitive(CilPrimitiveKind::I4).unwrap(),
                CilFlavor::U4 => type_registry.get_primitive(CilPrimitiveKind::U4).unwrap(),
                CilFlavor::I8 => type_registry.get_primitive(CilPrimitiveKind::I8).unwrap(),
                CilFlavor::U8 => type_registry.get_primitive(CilPrimitiveKind::U8).unwrap(),
                CilFlavor::R4 => type_registry.get_primitive(CilPrimitiveKind::R4).unwrap(),
                CilFlavor::R8 => type_registry.get_primitive(CilPrimitiveKind::R8).unwrap(),
                CilFlavor::I => type_registry.get_primitive(CilPrimitiveKind::I).unwrap(),
                CilFlavor::U => type_registry.get_primitive(CilPrimitiveKind::U).unwrap(),
                CilFlavor::String => type_registry
                    .get_primitive(CilPrimitiveKind::String)
                    .unwrap(),
                CilFlavor::Object => type_registry
                    .get_primitive(CilPrimitiveKind::Object)
                    .unwrap(),
                CilFlavor::Void => type_registry.get_primitive(CilPrimitiveKind::Void).unwrap(),
                other_flavor => {
                    // For complex types, create them properly in the registry
                    type_registry
                        .get_or_create_type(
                            &mut None,
                            other_flavor,
                            "System",
                            "TestType",
                            crate::metadata::typesystem::TypeSource::CurrentModule,
                        )
                        .unwrap()
                }
            };

            let _ = param
                .base
                .set(crate::metadata::typesystem::CilTypeRef::from(param_type));
        }

        param
    }
}

impl Default for ParamBuilder {
    fn default() -> Self {
        Self::new(1, Some("param".to_string()))
    }
}

/// Helper builder for creating parameter lists for methods
pub struct ParamListBuilder {
    params: Vec<ParamBuilder>,
    include_return_param: bool,
}

impl ParamListBuilder {
    pub fn new() -> Self {
        Self {
            params: Vec::new(),
            include_return_param: false,
        }
    }

    /// Include a return value parameter (sequence 0)
    pub fn with_return_param(mut self) -> Self {
        self.include_return_param = true;
        self
    }

    /// Add a parameter to the list
    pub fn add_param(mut self, param: ParamBuilder) -> Self {
        self.params.push(param);
        self
    }

    /// Add an input parameter with the given name
    pub fn add_input_param(mut self, name: &str) -> Self {
        let sequence = self.params.len() as u32 + 1;
        self.params.push(ParamBuilder::input_param(sequence, name));
        self
    }

    /// Add an output parameter with the given name
    pub fn add_output_param(mut self, name: &str) -> Self {
        let sequence = self.params.len() as u32 + 1;
        self.params.push(ParamBuilder::output_param(sequence, name));
        self
    }

    /// Build the parameter list
    pub fn build(self) -> Arc<boxcar::Vec<ParamRc>> {
        let params = Arc::new(boxcar::Vec::new());

        // Add return parameter if requested
        if self.include_return_param {
            params.push(ParamBuilder::return_value().build());
        }

        // Add all other parameters
        for param_builder in self.params {
            params.push(param_builder.build());
        }

        params
    }
}

impl Default for ParamListBuilder {
    fn default() -> Self {
        Self::new()
    }
}
