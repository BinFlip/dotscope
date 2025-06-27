//! Method signature builders for creating mock method signatures with various calling conventions
//!
//! This module provides builders for creating method signatures with different calling
//! conventions, parameter types, return types, and generic constraints.

use crate::metadata::{
    signatures::{CustomModifier, SignatureMethod, SignatureParameter, TypeSignature},
    token::Token,
};

/// Calling convention types for methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Default managed calling convention
    Default,
    /// Variable arguments (C-style varargs)
    Varargs,
    /// C calling convention
    CCall,
    /// Standard calling convention
    StdCall,
    /// This calling convention
    ThisCall,
    /// Fast calling convention
    FastCall,
    /// Generic method with type parameters
    Generic(u8), // Number of generic parameters
}

/// Parameter direction and usage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterDirection {
    /// Input parameter
    In,
    /// Output parameter
    Out,
    /// Input/output parameter
    InOut,
    /// Reference parameter
    Ref,
}

/// Method parameter information
#[derive(Debug, Clone)]
pub struct MethodParameter {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub param_type: TypeSignature,
    /// Parameter direction
    pub direction: ParameterDirection,
    /// Whether parameter is optional
    pub is_optional: bool,
    /// Default value (if optional)
    pub default_value: Option<String>,
    /// Custom modifiers
    pub modifiers: Vec<CustomModifier>,
}

impl MethodParameter {
    pub fn new(name: &str, param_type: TypeSignature) -> Self {
        Self {
            name: name.to_string(),
            param_type,
            direction: ParameterDirection::In,
            is_optional: false,
            default_value: None,
            modifiers: Vec::new(),
        }
    }

    pub fn with_direction(mut self, direction: ParameterDirection) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_optional(mut self, default_value: Option<String>) -> Self {
        self.is_optional = true;
        self.default_value = default_value;
        self
    }

    pub fn with_modifiers(mut self, modifiers: Vec<CustomModifier>) -> Self {
        self.modifiers = modifiers;
        self
    }
}

/// Builder for creating mock method signatures with various configurations
pub struct MethodSignatureBuilder {
    calling_convention: CallingConvention,
    has_this: bool,
    explicit_this: bool,
    return_type: TypeSignature,
    parameters: Vec<MethodParameter>,
    vararg_parameters: Vec<MethodParameter>,
    generic_param_count: u8,
}

impl MethodSignatureBuilder {
    pub fn new() -> Self {
        Self {
            calling_convention: CallingConvention::Default,
            has_this: false,
            explicit_this: false,
            return_type: TypeSignature::Void,
            parameters: Vec::new(),
            vararg_parameters: Vec::new(),
            generic_param_count: 0,
        }
    }

    pub fn with_calling_convention(mut self, convention: CallingConvention) -> Self {
        self.calling_convention = convention;
        if let CallingConvention::Generic(count) = convention {
            self.generic_param_count = count;
        }
        self
    }

    pub fn with_this(mut self) -> Self {
        self.has_this = true;
        self
    }

    pub fn with_explicit_this(mut self) -> Self {
        self.has_this = true;
        self.explicit_this = true;
        self
    }

    pub fn with_return_type(mut self, return_type: TypeSignature) -> Self {
        self.return_type = return_type;
        self
    }

    pub fn with_parameter(mut self, parameter: MethodParameter) -> Self {
        self.parameters.push(parameter);
        self
    }

    pub fn with_parameters(mut self, parameters: Vec<MethodParameter>) -> Self {
        self.parameters.extend(parameters);
        self
    }

    pub fn add_parameter(mut self, name: &str, param_type: TypeSignature) -> Self {
        self.parameters.push(MethodParameter::new(name, param_type));
        self
    }

    pub fn add_ref_parameter(mut self, name: &str, param_type: TypeSignature) -> Self {
        self.parameters
            .push(MethodParameter::new(name, param_type).with_direction(ParameterDirection::Ref));
        self
    }

    pub fn add_out_parameter(mut self, name: &str, param_type: TypeSignature) -> Self {
        self.parameters
            .push(MethodParameter::new(name, param_type).with_direction(ParameterDirection::Out));
        self
    }

    pub fn add_optional_parameter(
        mut self,
        name: &str,
        param_type: TypeSignature,
        default: &str,
    ) -> Self {
        self.parameters
            .push(MethodParameter::new(name, param_type).with_optional(Some(default.to_string())));
        self
    }

    pub fn with_varargs(mut self, vararg_params: Vec<MethodParameter>) -> Self {
        self.calling_convention = CallingConvention::Varargs;
        self.vararg_parameters = vararg_params;
        self
    }

    pub fn with_generic_params(mut self, count: u8) -> Self {
        self.calling_convention = CallingConvention::Generic(count);
        self.generic_param_count = count;
        self
    }

    /// Create a simple method signature (void method with no parameters)
    pub fn simple_void_method() -> Self {
        Self::new()
    }

    /// Create a simple method with return type
    pub fn simple_method(return_type: TypeSignature) -> Self {
        Self::new().with_return_type(return_type)
    }

    /// Create an instance method (with 'this' pointer)
    pub fn instance_method(return_type: TypeSignature) -> Self {
        Self::new().with_this().with_return_type(return_type)
    }

    /// Create a static method
    pub fn static_method(return_type: TypeSignature) -> Self {
        Self::new().with_return_type(return_type)
    }

    /// Create a generic method
    pub fn generic_method(return_type: TypeSignature, generic_count: u8) -> Self {
        Self::new()
            .with_return_type(return_type)
            .with_generic_params(generic_count)
    }

    /// Create a property getter
    pub fn property_getter(return_type: TypeSignature) -> Self {
        Self::instance_method(return_type)
    }

    /// Create a property setter
    pub fn property_setter(value_type: TypeSignature) -> Self {
        Self::instance_method(TypeSignature::Void).add_parameter("value", value_type)
    }

    /// Create a constructor
    pub fn constructor() -> Self {
        Self::instance_method(TypeSignature::Void)
    }

    /// Create a P/Invoke method
    pub fn pinvoke_method(return_type: TypeSignature, convention: CallingConvention) -> Self {
        Self::new()
            .with_calling_convention(convention)
            .with_return_type(return_type)
    }

    pub fn build(self) -> SignatureMethod {
        // Convert our parameters to SignatureParameter
        let signature_params: Vec<SignatureParameter> = self
            .parameters
            .into_iter()
            .map(|param| SignatureParameter {
                modifiers: param.modifiers,
                by_ref: false,
                base: param.param_type,
            })
            .collect();

        let signature_varargs: Vec<SignatureParameter> = self
            .vararg_parameters
            .into_iter()
            .map(|param| SignatureParameter {
                modifiers: param.modifiers,
                by_ref: false,
                base: param.param_type,
            })
            .collect();

        SignatureMethod {
            has_this: self.has_this,
            explicit_this: self.explicit_this,
            default: matches!(self.calling_convention, CallingConvention::Default),
            vararg: !signature_varargs.is_empty(),
            cdecl: matches!(self.calling_convention, CallingConvention::CCall),
            stdcall: matches!(self.calling_convention, CallingConvention::StdCall),
            thiscall: matches!(self.calling_convention, CallingConvention::ThisCall),
            fastcall: matches!(self.calling_convention, CallingConvention::FastCall),
            param_count_generic: self.generic_param_count as u32,
            param_count: signature_params.len() as u32,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: self.return_type,
            },
            params: signature_params,
            varargs: signature_varargs,
        }
    }
}

impl Default for MethodSignatureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating method parameter lists for common scenarios
pub struct ParameterListBuilder {
    parameters: Vec<MethodParameter>,
}

impl ParameterListBuilder {
    pub fn new() -> Self {
        Self {
            parameters: Vec::new(),
        }
    }

    pub fn add_int32(mut self, name: &str) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::I4));
        self
    }

    pub fn add_string(mut self, name: &str) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::String));
        self
    }

    pub fn add_bool(mut self, name: &str) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::Boolean));
        self
    }

    pub fn add_float(mut self, name: &str) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::R4));
        self
    }

    pub fn add_double(mut self, name: &str) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::R8));
        self
    }

    pub fn add_object(mut self, name: &str, token: Token) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::Class(token)));
        self
    }

    pub fn add_value_type(mut self, name: &str, token: Token) -> Self {
        self.parameters
            .push(MethodParameter::new(name, TypeSignature::ValueType(token)));
        self
    }

    pub fn add_ref_int32(mut self, name: &str) -> Self {
        self.parameters.push(
            MethodParameter::new(name, TypeSignature::I4).with_direction(ParameterDirection::Ref),
        );
        self
    }

    pub fn add_out_int32(mut self, name: &str) -> Self {
        self.parameters.push(
            MethodParameter::new(name, TypeSignature::I4).with_direction(ParameterDirection::Out),
        );
        self
    }

    pub fn build(self) -> Vec<MethodParameter> {
        self.parameters
    }
}

impl Default for ParameterListBuilder {
    fn default() -> Self {
        Self::new()
    }
}
