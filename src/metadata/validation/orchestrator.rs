//! Validation orchestration for metadata loading
//!
//! This module provides orchestration of the validation process across
//! the entire loaded metadata system.

use crate::{
    metadata::{
        loader::CilObjectData,
        signatures::TypeSignature,
        typesystem::TypeRegistry,
        validation::{
            config::ValidationConfig, FieldValidator, MethodValidator, NestedClassValidator,
            SemanticValidator, TokenValidator,
        },
    },
    Result,
};
use rayon::prelude::*;

/// Performs post-loading validation across the entire metadata system
pub struct Orchestrator;

impl Orchestrator {
    /// Internal validation method that works with `CilObjectData`
    ///
    /// This method is called internally and should not be exposed to users.
    /// It performs the actual validation work using the parsed metadata.
    /// Validations are run in parallel where possible for optimal performance.
    ///
    /// # Arguments
    /// * `data` - The internal CIL object data containing all parsed metadata
    /// * `config` - Validation configuration specifying which validations to perform
    ///
    /// # Errors
    /// Returns validation errors found during cross-table analysis
    pub fn validate_loaded_data(data: &CilObjectData, config: ValidationConfig) -> Result<()> {
        if !config.enable_cross_table_validation {
            return Ok(());
        }

        // Run independent validations in parallel for better performance
        let validation_results: Vec<Vec<String>> = [
            // Token consistency validation
            config.enable_token_validation,
            // Semantic validation
            config.enable_semantic_validation,
            // Method validation
            config.enable_method_validation,
        ]
        .into_par_iter()
        .enumerate()
        .filter_map(|(index, enabled)| {
            if !enabled {
                return None;
            }

            let errors = match index {
                0 => TokenValidator::validate_token_consistency(data),
                1 => SemanticValidator::validate_semantic_consistency(data),
                2 => MethodValidator::validate_method_rules(data),
                _ => Vec::new(),
            };

            Some(errors)
        })
        .collect();

        // Flatten all validation errors
        let all_errors: Vec<String> = validation_results.into_iter().flatten().collect();

        // Sequential validations that require exclusive access or have dependencies
        // Validate nested class relationships across the entire type system
        if config.enable_type_system_validation {
            Self::validate_nested_class_hierarchy(&data.types, config.max_nesting_depth)?;
        }

        // Validate field layouts for types with explicit layout
        if config.enable_field_layout_validation {
            Self::validate_field_layouts(&data.types)?;
        }

        // If we found any validation errors, report them
        if !all_errors.is_empty() {
            eprintln!("Validation found {} issues:", all_errors.len());
            for (i, error) in all_errors.iter().enumerate() {
                eprintln!("  {}: {}", i + 1, error);
            }
            // For now, we'll just log the errors rather than fail validation
            // In the future, this could be configurable
        }

        // TODO: Add more cross-table validations here:
        // - Generic constraint validation across type hierarchy
        // - Interface implementation validation
        // - Cross-assembly checks
        // - Security attribute validation

        Ok(())
    }

    /// Validates nested class relationships for circular references and depth limits
    fn validate_nested_class_hierarchy(types: &TypeRegistry, max_depth: usize) -> Result<()> {
        // Collect all nested class relationships
        let mut relationships = Vec::new();

        for entry in types {
            let cil_type = entry.value();
            for (_index, nested_type_ref) in cil_type.nested_types.iter() {
                if let Some(nested_type) = nested_type_ref.upgrade() {
                    relationships.push((nested_type.token, cil_type.token));
                }
            }
        }

        // Validate no circular references
        NestedClassValidator::validate_no_circular_nesting(&relationships)?;

        // Validate nesting depth
        NestedClassValidator::validate_nesting_depth(&relationships, max_depth)?;

        Ok(())
    }

    /// Validates field layouts for types with explicit layout using parallel processing
    fn validate_field_layouts(types: &TypeRegistry) -> Result<()> {
        // Collect all types with explicit layout
        let types_with_layout: Vec<_> = types
            .iter()
            .filter_map(|entry| {
                let cil_type = entry.value();
                if cil_type.class_size.get().is_some() {
                    Some(cil_type.clone())
                } else {
                    None
                }
            })
            .collect();

        // Validate field layouts in parallel using rayon
        types_with_layout
            .par_iter()
            .try_for_each(|cil_type| -> Result<()> {
                let class_size = *cil_type.class_size.get().unwrap();
                let mut field_layouts = Vec::new();

                // Collect field layout information
                for (_index, field) in cil_type.fields.iter() {
                    if let Some(field_offset) = field.layout.get() {
                        // Calculate actual field size based on type signature and type registry
                        let field_size = Self::calculate_field_size_with_type_resolution(
                            &field.signature.base,
                            types,
                        );
                        field_layouts.push((*field_offset, field_size));
                    }
                }

                // Validate field overlaps
                if !field_layouts.is_empty() {
                    FieldValidator::validate_field_overlaps(&field_layouts)?;

                    // Validate fields fit within class size
                    FieldValidator::validate_explicit_layout_coverage(class_size, &field_layouts)?;
                }

                Ok(())
            })?;

        Ok(())
    }

    /// Calculates field size based on the field's type signature with type resolution
    ///
    /// This implementation uses the actual field type information from the metadata
    /// and attempts to resolve value types to get their actual size when possible.
    #[allow(clippy::match_same_arms)]
    fn calculate_field_size_with_type_resolution(
        field_signature: &TypeSignature,
        types: &TypeRegistry,
    ) -> u32 {
        match field_signature {
            // Primitive types with known sizes
            TypeSignature::Void => 0,
            TypeSignature::Boolean => 1,
            TypeSignature::I1 | TypeSignature::U1 => 1,
            TypeSignature::I2 | TypeSignature::U2 | TypeSignature::Char => 2,
            TypeSignature::I4 | TypeSignature::U4 | TypeSignature::R4 => 4,
            TypeSignature::I8 | TypeSignature::U8 | TypeSignature::R8 => 8,

            // ToDo: Handle I/U better, depending on compilation target of the assembly
            // Platform-dependent sizes (assuming 64-bit)
            TypeSignature::I | TypeSignature::U => 8, // IntPtr/UIntPtr on 64-bit

            // Reference types (pointers on 64-bit systems)
            TypeSignature::String | TypeSignature::Object => 8,
            TypeSignature::Class(_) | TypeSignature::SzArray(_) | TypeSignature::Array(_) => 8,

            // Pointer types
            TypeSignature::Ptr(_) | TypeSignature::ByRef(_) | TypeSignature::FnPtr(_) => 8,

            // Value types - try to resolve their actual size
            TypeSignature::ValueType(token) => {
                if let Some(value_type) = types.get(token) {
                    // Check if we have explicit class size information
                    if let Some(class_size) = value_type.class_size.get() {
                        *class_size
                    } else {
                        // For well-known value types, return their known sizes
                        match (value_type.namespace.as_str(), value_type.name.as_str()) {
                            ("System", "DateTime") => 8,           // DateTime is 8 bytes
                            ("System", "TimeSpan") => 8,           // TimeSpan is 8 bytes
                            ("System", "Decimal") => 16,           // Decimal is 16 bytes
                            ("System", "Guid") => 16,              // Guid is 16 bytes
                            ("System", "IntPtr" | "UIntPtr") => 8, // Platform pointers
                            _ => 8, // Conservative estimate for unknown value types
                        }
                    }
                } else {
                    8 // Conservative fallback
                }
            }

            // Generic types - conservative estimate
            TypeSignature::GenericParamType(_) | TypeSignature::GenericParamMethod(_) => 8,
            TypeSignature::GenericInst(_, _) => 8,

            // Modified types - recurse to base type
            TypeSignature::ModifiedRequired(_) | TypeSignature::ModifiedOptional(_) => 8,
            TypeSignature::Pinned(inner) => {
                Self::calculate_field_size_with_type_resolution(inner, types)
            }

            // Special types
            TypeSignature::TypedByRef => 16, // TypedReference is 16 bytes

            // Unknown or complex types - conservative estimate
            _ => 8,
        }
    }

    /// Calculates field size based on the field's type signature (legacy method)
    ///
    /// This implementation uses the actual field type information from the metadata
    /// to calculate proper field sizes for overlap validation.
    #[allow(clippy::match_same_arms)]
    fn calculate_field_size(field_signature: &TypeSignature) -> u32 {
        match field_signature {
            // Primitive types with known sizes
            TypeSignature::Void => 0,
            TypeSignature::Boolean => 1,
            TypeSignature::I1 | TypeSignature::U1 => 1,
            TypeSignature::I2 | TypeSignature::U2 | TypeSignature::Char => 2,
            TypeSignature::I4 | TypeSignature::U4 | TypeSignature::R4 => 4,
            TypeSignature::I8 | TypeSignature::U8 | TypeSignature::R8 => 8,

            // Platform-dependent sizes (assuming 64-bit)
            TypeSignature::I | TypeSignature::U => 8, // IntPtr/UIntPtr on 64-bit

            // Reference types (pointers on 64-bit systems)
            TypeSignature::String | TypeSignature::Object => 8,
            TypeSignature::Class(_) | TypeSignature::SzArray(_) | TypeSignature::Array(_) => 8,

            // Pointer types
            TypeSignature::Ptr(_) | TypeSignature::ByRef(_) | TypeSignature::FnPtr(_) => 8,

            // Value types need type resolution - for now use conservative estimate
            TypeSignature::ValueType(_) => 8, // Could be 1-many bytes, needs type lookup

            // Generic types - conservative estimate
            TypeSignature::GenericParamType(_) | TypeSignature::GenericParamMethod(_) => 8,
            TypeSignature::GenericInst(_, _) => 8,

            // Modified types - recurse to base type
            TypeSignature::ModifiedRequired(_) | TypeSignature::ModifiedOptional(_) => 8,
            TypeSignature::Pinned(inner) => Self::calculate_field_size(inner),

            // Special types
            TypeSignature::TypedByRef => 16, // TypedReference is 16 bytes

            // Unknown or complex types - conservative estimate
            _ => 8,
        }
    }
}
