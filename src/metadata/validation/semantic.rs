//! Semantic validation for .NET metadata
//!
//! This module provides semantic consistency validation that aligns with
//! .NET runtime behavior, focusing on ECMA-335 violations that would cause runtime failures.

use crate::metadata::{
    loader::CilObjectData,
    tables::TypeAttributes,
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
            // Skip validation for pointer types, array types, and generic instantiations
            // These often have misleading base type relationships in metadata
            if cil_type.name.contains('*')
                || cil_type.name.contains('[')
                || cil_type.name.contains('`') && base_type.name.contains('`')
            {
                return; // Skip validation for these complex types
            }

            // Critical: Cannot inherit from sealed types (runtime enforced)
            if (base_type.flags & TypeAttributes::SEALED) != 0
                && (cil_type.flags & TypeAttributes::INTERFACE) == 0
                && cil_type.name != base_type.name
            // Avoid self-reference issues
            {
                errors.push(format!(
                    "Type '{}' cannot inherit from sealed type '{}'",
                    cil_type.name, base_type.name
                ));
            }

            // Critical: Value type inheritance rules (runtime enforced)
            // Value types should inherit from ValueType, but non-value types should not
            if base_type.flavor() == &CilFlavor::ValueType {
                // If base is ValueType, child should also be a value type (or special cases)
                if cil_type.flavor() != &CilFlavor::ValueType
                    && cil_type.name != "System.Enum"
                    && !cil_type.name.starts_with("System.")  // Allow system types
                    && !is_primitive_type(&cil_type.name)
                // Allow primitive types
                {
                    errors.push(format!(
                        "Type '{}' cannot inherit from value type '{}'",
                        cil_type.name, base_type.name
                    ));
                }
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
        // Note: Static classes in C# compile to "sealed abstract" in IL, which is valid
        // Only flag sealed+abstract if it's NOT a static class (has instance members)
        if (cil_type.flags & TypeAttributes::SEALED) != 0
            && (cil_type.flags & TypeAttributes::ABSTRACT) != 0
        {
            // Check if this appears to be a static class by looking for instance constructors
            let has_instance_constructor = cil_type.methods.iter().any(|(_, method_ref)| {
                if let Some(method) = method_ref.upgrade() {
                    method.name == ".ctor" // Instance constructor
                } else {
                    false
                }
            });

            // If it has instance constructors, it's not a valid static class
            if has_instance_constructor {
                errors.push(format!(
                    "Type '{}' cannot be both sealed and abstract (not a static class)",
                    cil_type.name
                ));
            }
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

/// Helper function to check if a type name is a primitive type
/// These types are legitimately allowed to inherit from `ValueType`
fn is_primitive_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "Void"
            | "Boolean"
            | "Char"
            | "SByte"
            | "Byte"
            | "Int16"
            | "UInt16"
            | "Int32"
            | "UInt32"
            | "Int64"
            | "UInt64"
            | "Single"
            | "Double"
            | "IntPtr"
            | "UIntPtr"
            | "TypedReference"
    )
}
