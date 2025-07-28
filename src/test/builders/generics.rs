//! Generic type builders for creating mock generic types and constraints
//!
//! This module provides builders for creating generic type definitions, instantiations,
//! and constraints. It supports complex generic scenarios including type parameters,
//! constraints, variance, and generic type instantiations.

use std::sync::{Arc, OnceLock};

use crate::metadata::{
    tables::{GenericParam, GenericParamRc},
    token::Token,
    typesystem::{CilFlavor, CilType, CilTypeRc, CilTypeRef, CilTypeReference},
};

/// Generic parameter variance annotations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericVariance {
    /// No variance (invariant)
    None,
    /// Covariant (out parameter in C#)
    Covariant,
    /// Contravariant (in parameter in C#)
    Contravariant,
}

/// Generic constraint types for type parameters
#[derive(Clone)]
pub enum GenericConstraint {
    /// Must be a reference type (class constraint)
    Class,
    /// Must be a value type (struct constraint)  
    Struct,
    /// Must have a parameterless constructor (new() constraint)
    New,
    /// Must implement a specific interface or inherit from a type
    Type(CilTypeRc),
}

/// Builder for creating mock generic type parameters
pub struct GenericParameterBuilder {
    number: u32,
    name: String,
    flags: u32,
    variance: GenericVariance,
    constraints: Vec<GenericConstraint>,
}

impl GenericParameterBuilder {
    pub fn new(name: &str, number: u32) -> Self {
        Self {
            number,
            name: name.to_string(),
            flags: 0,
            variance: GenericVariance::None,
            constraints: Vec::new(),
        }
    }

    pub fn with_variance(mut self, variance: GenericVariance) -> Self {
        self.variance = variance;
        // Update flags based on variance
        match variance {
            GenericVariance::None => {}
            GenericVariance::Covariant => self.flags |= 0x0001, // VARIANCE_COVARIANT
            GenericVariance::Contravariant => self.flags |= 0x0002, // VARIANCE_CONTRAVARIANT
        }
        self
    }

    pub fn with_class_constraint(mut self) -> Self {
        self.constraints.push(GenericConstraint::Class);
        self.flags |= 0x0004; // REFERENCE_TYPE_CONSTRAINT
        self
    }

    pub fn with_struct_constraint(mut self) -> Self {
        self.constraints.push(GenericConstraint::Struct);
        self.flags |= 0x0008; // NOT_NULLABLE_VALUE_TYPE_CONSTRAINT
        self
    }

    pub fn with_new_constraint(mut self) -> Self {
        self.constraints.push(GenericConstraint::New);
        self.flags |= 0x0010; // DEFAULT_CONSTRUCTOR_CONSTRAINT
        self
    }

    pub fn with_type_constraint(mut self, type_constraint: CilTypeRc) -> Self {
        self.constraints
            .push(GenericConstraint::Type(type_constraint));
        self
    }

    pub fn build(self, owner: CilTypeReference) -> GenericParamRc {
        Arc::new(GenericParam {
            rid: self.number,
            token: Token::new(0x2A000000 + self.number), // GenericParam table token
            offset: self.number as usize,
            number: self.number,
            flags: self.flags,
            owner: {
                let owner_lock = OnceLock::new();
                owner_lock.set(owner).ok();
                owner_lock
            },
            constraints: Arc::new(boxcar::Vec::new()), // Will be populated by constraints
            name: self.name,
            custom_attributes: Arc::new(boxcar::Vec::new()),
        })
    }
}

/// Builder for creating mock generic types with type parameters
pub struct GenericTypeBuilder {
    token: Token,
    namespace: String,
    name: String,
    external: Option<CilTypeReference>,
    flavor: Option<CilFlavor>,
    flags: u32,
    type_parameters: Vec<GenericParameterBuilder>,
    generic_args: Vec<CilTypeRc>, // For instantiated generic types
}

impl GenericTypeBuilder {
    pub fn new(namespace: &str, name: &str) -> Self {
        Self {
            token: Token::new(0x02000001),
            namespace: namespace.to_string(),
            name: name.to_string(),
            external: None,
            flavor: Some(CilFlavor::Class),
            flags: 0,
            type_parameters: Vec::new(),
            generic_args: Vec::new(),
        }
    }

    pub fn with_token(mut self, token: Token) -> Self {
        self.token = token;
        self
    }

    pub fn with_flavor(mut self, flavor: CilFlavor) -> Self {
        self.flavor = Some(flavor);
        self
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Add a generic type parameter to this type
    pub fn with_generic_parameter(mut self, name: &str) -> Self {
        let parameter = GenericParameterBuilder::new(name, self.type_parameters.len() as u32);
        self.type_parameters.push(parameter);
        self
    }

    /// Add a generic type parameter with constraints
    pub fn with_constrained_parameter<F>(mut self, name: &str, configure: F) -> Self
    where
        F: FnOnce(GenericParameterBuilder) -> GenericParameterBuilder,
    {
        let parameter = GenericParameterBuilder::new(name, self.type_parameters.len() as u32);
        let configured_parameter = configure(parameter);
        self.type_parameters.push(configured_parameter);
        self
    }

    /// Create a generic type instantiation (closed generic type)
    pub fn instantiate(generic_type: CilTypeRc) -> GenericTypeInstantiationBuilder {
        GenericTypeInstantiationBuilder::new(generic_type)
    }

    /// Build the generic type definition
    pub fn build(self) -> CilTypeRc {
        // Create the base type first
        let type_name = if self.type_parameters.is_empty() {
            self.name
        } else {
            format!("{}`{}", self.name, self.type_parameters.len())
        };

        let cil_type = Arc::new(CilType::new(
            self.token,
            self.namespace,
            type_name,
            self.external,
            None, // base type
            self.flags,
            Arc::new(boxcar::Vec::new()), // fields
            Arc::new(boxcar::Vec::new()), // methods
            self.flavor,
        ));

        // Add generic parameters
        if !self.type_parameters.is_empty() {
            let type_ref = CilTypeRef::new(&cil_type);
            let type_reference = CilTypeReference::TypeDef(type_ref);

            for param_builder in self.type_parameters {
                let generic_param = param_builder.build(type_reference.clone());
                cil_type.generic_params.push(generic_param);
            }
        }

        cil_type
    }

    /// Create common generic type scenarios
    /// Create a generic collection type like List<T>
    pub fn generic_collection(name: &str) -> Self {
        Self::new("System.Collections.Generic", name).with_constrained_parameter("T", |p| p)
        // No constraints for collection item type
    }

    /// Create a generic interface like IEnumerable<T>
    pub fn generic_interface(name: &str) -> Self {
        Self::new("System.Collections.Generic", name)
            .with_flavor(CilFlavor::Interface)
            .with_constrained_parameter("T", |p| p)
    }

    /// Create a generic delegate like Func<T, TResult>
    pub fn generic_delegate(name: &str, param_count: usize) -> Self {
        let mut builder = Self::new("System", name).with_flavor(CilFlavor::Class); // Delegates are classes

        // Add type parameters T1, T2, ..., TResult
        for i in 0..param_count {
            let param_name = if i == param_count - 1 {
                "TResult".to_string()
            } else {
                format!("T{}", i + 1)
            };
            builder = builder.with_generic_parameter(&param_name);
        }

        builder
    }

    /// Create a constrained generic type like where T : class, new()
    pub fn constrained_generic(namespace: &str, name: &str) -> Self {
        Self::new(namespace, name)
            .with_constrained_parameter("T", |p| p.with_class_constraint().with_new_constraint())
    }
}

/// Builder for creating instantiated generic types (closed generics)
pub struct GenericTypeInstantiationBuilder {
    generic_type: CilTypeRc,
    type_arguments: Vec<CilTypeRc>,
}

impl GenericTypeInstantiationBuilder {
    pub fn new(generic_type: CilTypeRc) -> Self {
        Self {
            generic_type,
            type_arguments: Vec::new(),
        }
    }

    pub fn with_type_argument(mut self, type_arg: CilTypeRc) -> Self {
        self.type_arguments.push(type_arg);
        self
    }

    pub fn with_type_arguments(mut self, type_args: Vec<CilTypeRc>) -> Self {
        self.type_arguments.extend(type_args);
        self
    }

    pub fn build(self) -> CilTypeRc {
        // Create a new token for the instantiated type (TypeSpec)
        let instantiated_token = Token::new(0x1B000001); // TypeSpec token

        // Build the instantiated type name
        let type_arg_names: Vec<String> = self
            .type_arguments
            .iter()
            .map(|t| format!("{}.{}", t.namespace, t.name))
            .collect();

        let instantiated_name = format!("{}[{}]", self.generic_type.name, type_arg_names.join(","));

        Arc::new(CilType::new(
            instantiated_token,
            self.generic_type.namespace.clone(),
            instantiated_name,
            self.generic_type.get_external().cloned(),
            None, // base type
            self.generic_type.flags,
            self.generic_type.fields.clone(),
            self.generic_type.methods.clone(),
            Some(self.generic_type.flavor().clone()),
        ))
    }
}

impl Default for GenericTypeBuilder {
    fn default() -> Self {
        Self::new("Test", "GenericType")
    }
}
