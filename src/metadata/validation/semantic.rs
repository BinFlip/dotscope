//! Semantic validation for .NET metadata
//!
//! This module provides semantic consistency validation that aligns with
//! .NET runtime behavior, focusing on ECMA-335 violations that would cause runtime failures.

use crate::metadata::{
    loader::CilObjectData,
    streams::TypeAttributes,
    typesystem::{CilFlavor, CilType, TypeRegistry},
};
use rayon::prelude::*;

/// Validator for semantic consistency in metadata
///
/// This validator aligns with .NET runtime validation patterns, focusing on
/// ECMA-335 violations that would cause actual runtime failures rather than
/// style or best practice issues.
pub struct SemanticValidator;

impl SemanticValidator {
    /// Validates semantic consistency that the .NET runtime requires
    ///
    /// Based on .NET runtime source analysis, this focuses on:
    /// - Critical inheritance relationship violations
    /// - Type system consistency issues that cause runtime failures
    /// - Essential interface and abstract type rules
    ///
    /// # Arguments
    /// * `data` - The CIL object data containing metadata
    ///
    /// # Returns
    /// Vector of validation errors found
    pub fn validate_semantic_consistency(data: &CilObjectData) -> Vec<String> {
        let type_registry = &data.types;

        // Use parallel iteration for better performance on large type systems
        type_registry
            .all_types()
            .par_iter()
            .flat_map(|type_entry| {
                let mut errors = Vec::new();

                // Validate inheritance - this is critical for runtime
                Self::validate_inheritance_critical(type_entry, type_registry, &mut errors);

                // Validate sealed/abstract combinations - runtime enforced
                Self::validate_sealed_abstract_rules(type_entry, &mut errors);

                // Validate interface constraints - runtime enforced
                Self::validate_interface_constraints(type_entry, &mut errors);

                errors
            })
            .collect()
    }
    /// Validates critical inheritance relationships
    ///
    /// This focuses on inheritance rules that the .NET runtime enforces
    /// and would cause type loading failures.
    fn validate_inheritance_critical(
        cil_type: &std::sync::Arc<CilType>,
        _type_registry: &TypeRegistry,
        errors: &mut Vec<String>,
    ) {
        if let Some(base_type) = cil_type.base() {
            // Critical: Cannot inherit from sealed types (runtime enforced)
            if (base_type.flags & TypeAttributes::SEALED) != 0
                && (cil_type.flags & TypeAttributes::INTERFACE) == 0
            {
                errors.push(format!(
                    "Type '{}' cannot inherit from sealed type '{}'",
                    cil_type.name, base_type.name
                ));
            }

            // Critical: Value type inheritance rules (runtime enforced)
            if base_type.flavor() == &CilFlavor::ValueType
                && cil_type.flavor() != &CilFlavor::ValueType
                && cil_type.name != "System.Enum"
            {
                // Enum is special case
                errors.push(format!(
                    "Type '{}' cannot inherit from value type '{}'",
                    cil_type.name, base_type.name
                ));
            }

            // Critical: Interface cannot inherit from non-interface (runtime enforced)
            if (cil_type.flags & TypeAttributes::INTERFACE) != 0
                && (base_type.flags & TypeAttributes::INTERFACE) == 0
                && base_type.name != "System.Object"
            {
                // Object is allowed base
                errors.push(format!(
                    "Interface '{}' cannot inherit from non-interface type '{}'",
                    cil_type.name, base_type.name
                ));
            }
        }
    }

    /// Validates sealed and abstract type rules
    ///
    /// These are enforced by the .NET runtime during type loading.
    fn validate_sealed_abstract_rules(
        cil_type: &std::sync::Arc<CilType>,
        errors: &mut Vec<String>,
    ) {
        // Critical: Sealed + Abstract is invalid (runtime enforced)
        if (cil_type.flags & TypeAttributes::SEALED) != 0
            && (cil_type.flags & TypeAttributes::ABSTRACT) != 0
        {
            errors.push(format!(
                "Type '{}' cannot be both sealed and abstract",
                cil_type.name
            ));
        }
    }

    /// Validates interface-specific constraints
    ///
    /// These are enforced by the .NET runtime for interface types.
    fn validate_interface_constraints(
        cil_type: &std::sync::Arc<CilType>,
        errors: &mut Vec<String>,
    ) {
        if (cil_type.flags & TypeAttributes::INTERFACE) != 0 {
            // Critical: Interfaces must be abstract (runtime enforced)
            if (cil_type.flags & TypeAttributes::ABSTRACT) == 0 {
                errors.push(format!(
                    "Interface '{}' must be marked abstract",
                    cil_type.name
                ));
            }

            // Check for instance constructors in interfaces (not allowed)
            for (_, method_ref) in cil_type.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    if method.name == ".ctor" {
                        errors.push(format!(
                            "Interface '{}' cannot have instance constructor",
                            cil_type.name
                        ));
                    }
                }
            }
        }
    }
}
