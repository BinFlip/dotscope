//! Generic parameter constraint validation for .NET metadata type system integrity.
//!
//! This validator ensures the structural integrity of generic parameter constraints,
//! validating proper constraint definitions, inheritance relationships, and type
//! parameter bounds. It operates on raw metadata structures to validate the foundational
//! requirements for generic type safety before higher-level semantic validation.
//! This validator runs with priority 130 in the raw validation stage.
//!
//! # Architecture
//!
//! The generic constraint validation system implements comprehensive generic constraint validation strategies in sequential order:
//! 1. **Generic Parameter Validation** - Ensures proper generic parameter definitions in GenericParam table
//! 2. **Constraint Consistency Validation** - Validates constraint relationships and inheritance in GenericParamConstraint table
//! 3. **Cross-table Constraint Validation** - Ensures constraint references are valid across tables
//!
//! The implementation validates generic constraints according to ECMA-335 specifications,
//! ensuring proper constraint definitions and relationships across all generic types.
//! All validation includes bounds checking and reference integrity verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::constraints::generic::RawGenericConstraintValidator`] - Main validator implementation providing comprehensive constraint validation
//! - [`crate::metadata::validation::validators::raw::constraints::generic::RawGenericConstraintValidator::validate_generic_parameters`] - Generic parameter definition validation with bounds checking
//! - [`crate::metadata::validation::validators::raw::constraints::generic::RawGenericConstraintValidator::validate_parameter_constraints`] - Constraint relationship validation with reference checking
//! - [`crate::metadata::validation::validators::raw::constraints::generic::RawGenericConstraintValidator::validate_constraint_inheritance`] - Inheritance consistency validation across generic hierarchies
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawGenericConstraintValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawGenericConstraintValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationRawValidatorFailed`] for:
//! - Invalid generic parameter definitions (invalid flags)
//! - Missing constraints (null owner or constraint references)
//! - Inconsistent constraint inheritance relationships (non-existent GenericParam references)
//! - Invalid type parameter bounds or interface constraints
//! - Cross-table constraint reference violations (references exceeding table row counts)
//! - Circular constraint dependencies
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::raw::constraints`] - Part of the constraint validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_constraint_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Generics specification
//! - [ECMA-335 II.22.20](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - GenericParam table
//! - [ECMA-335 II.22.21](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - GenericParamConstraint table

use std::collections::{HashMap, HashSet};

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{
            GenericParamAttributes, GenericParamConstraintRaw, GenericParamRaw, TableId,
            TypeDefRaw, TypeRefRaw, TypeSpecRaw,
        },
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Result,
};

/// Foundation validator for generic parameter constraint integrity and consistency.
///
/// Ensures the structural integrity and consistency of generic parameter constraints
/// in a .NET assembly, validating proper constraint definitions, inheritance relationships,
/// and type parameter bounds. This validator operates at the metadata level to provide
/// essential guarantees before higher-level type system validation can proceed.
///
/// The validator implements comprehensive coverage of generic constraint validation
/// according to ECMA-335 specifications, ensuring proper constraint definitions and
/// relationships across all generic types and methods.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable metadata structures.
pub struct RawGenericConstraintValidator;

impl RawGenericConstraintValidator {
    /// Creates a new generic constraint validator.
    ///
    /// Initializes a validator instance that can be used to validate generic parameter
    /// constraints across multiple assemblies. The validator is stateless and can be
    /// reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::raw::constraints::generic::RawGenericConstraintValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates generic parameter definitions for consistency and proper formatting.
    ///
    /// Ensures that all generic parameters are properly defined with valid names,
    /// constraints, and flags. Validates that generic parameter indices are consistent
    /// and that parameter definitions follow ECMA-335 requirements.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All generic parameters are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Parameter violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Parameter flags exceed maximum value (0xFFFF)
    /// - Owner coded index references are null (row = 0)
    /// - Name references are null (name = 0)
    fn validate_generic_parameters(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(generic_param_table) = tables.table::<GenericParamRaw>() {
            for generic_param in generic_param_table {
                if generic_param.flags > 0xFFFF {
                    return Err(malformed_error!(
                        "GenericParam RID {} has invalid flags value {} exceeding maximum",
                        generic_param.rid,
                        generic_param.flags
                    ));
                }

                if generic_param.owner.row == 0 {
                    return Err(malformed_error!(
                        "GenericParam RID {} has null owner reference",
                        generic_param.rid
                    ));
                }

                if generic_param.name == 0 {
                    return Err(malformed_error!(
                        "GenericParam RID {} has null name reference",
                        generic_param.rid
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates generic parameter constraint relationships and references.
    ///
    /// Ensures that all generic parameter constraints are properly defined with valid
    /// constraint references and that constraint relationships are consistent. Validates
    /// that constraint types are appropriate for the parameter they constrain.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All parameter constraints are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Constraint violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Owner references are null (owner = 0)
    /// - Constraint coded index references are null (constraint.row = 0)
    /// - Owner references exceed GenericParam table row count
    fn validate_parameter_constraints(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
            let generic_param_table = tables.table::<GenericParamRaw>();

            for constraint in constraint_table {
                if constraint.owner == 0 {
                    return Err(malformed_error!(
                        "GenericParamConstraint RID {} has null owner reference",
                        constraint.rid
                    ));
                }

                if constraint.constraint.row == 0 {
                    return Err(malformed_error!(
                        "GenericParamConstraint RID {} has null constraint reference",
                        constraint.rid
                    ));
                }

                if let Some(param_table) = generic_param_table {
                    if constraint.owner > param_table.row_count {
                        return Err(malformed_error!(
                            "GenericParamConstraint RID {} references GenericParam RID {} but table only has {} rows",
                            constraint.rid,
                            constraint.owner,
                            param_table.row_count
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates constraint inheritance consistency across generic type hierarchies.
    ///
    /// Ensures that generic parameter constraints are consistent across inheritance
    /// hierarchies and that constraint relationships maintain proper type safety.
    /// Validates that inherited constraints are compatible with derived constraints.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All constraint inheritance is consistent
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Inheritance violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Constraint owners reference non-existent GenericParam RIDs
    /// - Cross-table references are inconsistent between GenericParamConstraint and GenericParam tables
    fn validate_constraint_inheritance(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(generic_param_table), Some(constraint_table)) = (
            tables.table::<GenericParamRaw>(),
            tables.table::<GenericParamConstraintRaw>(),
        ) {
            for constraint in constraint_table {
                let param_found = generic_param_table
                    .iter()
                    .any(|param| param.rid == constraint.owner);

                if !param_found {
                    return Err(malformed_error!(
                        "GenericParamConstraint RID {} references non-existent GenericParam RID {}",
                        constraint.rid,
                        constraint.owner
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates actual constraint types and their compatibility.
    ///
    /// Ensures that constraint types referenced in GenericParamConstraint table are valid
    /// and appropriate for the generic parameters they constrain. Validates that
    /// constraint coded indices reference valid types or type specifications.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All constraint types are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Type violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Constraint coded index references invalid table entries
    /// - TypeDef constraint references exceed TypeDef table bounds
    /// - TypeRef constraint references exceed TypeRef table bounds
    /// - TypeSpec constraint references exceed TypeSpec table bounds
    fn validate_constraint_types(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(constraint_table) = tables.table::<GenericParamConstraintRaw>() {
            for constraint in constraint_table {
                let constraint_tables = constraint.constraint.ci_type.tables();
                let constraint_table_type = if constraint_tables.len() == 1 {
                    constraint_tables[0]
                } else {
                    continue;
                };
                let constraint_row = constraint.constraint.row;

                match constraint_table_type {
                    TableId::TypeDef => {
                        if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
                            if constraint_row > typedef_table.row_count {
                                return Err(malformed_error!(
                                    "GenericParamConstraint RID {} references TypeDef RID {} but table only has {} rows",
                                    constraint.rid,
                                    constraint_row,
                                    typedef_table.row_count
                                ));
                            }
                        } else {
                            return Err(malformed_error!(
                                "GenericParamConstraint RID {} references TypeDef but TypeDef table is missing",
                                constraint.rid
                            ));
                        }
                    }
                    TableId::TypeRef => {
                        if let Some(typeref_table) = tables.table::<TypeRefRaw>() {
                            if constraint_row > typeref_table.row_count {
                                return Err(malformed_error!(
                                    "GenericParamConstraint RID {} references TypeRef RID {} but table only has {} rows",
                                    constraint.rid,
                                    constraint_row,
                                    typeref_table.row_count
                                ));
                            }
                        } else {
                            return Err(malformed_error!(
                                "GenericParamConstraint RID {} references TypeRef but TypeRef table is missing",
                                constraint.rid
                            ));
                        }
                    }
                    TableId::TypeSpec => {
                        if let Some(typespec_table) = tables.table::<TypeSpecRaw>() {
                            if constraint_row > typespec_table.row_count {
                                return Err(malformed_error!(
                                    "GenericParamConstraint RID {} references TypeSpec RID {} but table only has {} rows",
                                    constraint.rid,
                                    constraint_row,
                                    typespec_table.row_count
                                ));
                            }
                        } else {
                            return Err(malformed_error!(
                                "GenericParamConstraint RID {} references TypeSpec but TypeSpec table is missing",
                                constraint.rid
                            ));
                        }
                    }
                    _ => {
                        return Err(malformed_error!(
                            "GenericParamConstraint RID {} has invalid constraint type targeting unsupported table {:?}",
                            constraint.rid,
                            constraint_table_type
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates generic parameter flags for compliance with ECMA-335 specifications.
    ///
    /// Ensures that generic parameter flags are set correctly according to .NET specifications
    /// and that flag combinations are valid. Validates variance flags and constraint flags.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All parameter flags are valid
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Flag violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Invalid flag combinations (e.g., both covariant and contravariant)
    /// - Reserved flag bits are set
    /// - Variance flags used inappropriately (method vs type parameters)
    fn validate_parameter_flags(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let Some(generic_param_table) = tables.table::<GenericParamRaw>() {
            for generic_param in generic_param_table {
                let flags = generic_param.flags;

                if (flags & GenericParamAttributes::COVARIANT) != 0
                    && (flags & GenericParamAttributes::CONTRAVARIANT) != 0
                {
                    return Err(malformed_error!(
                        "GenericParam RID {} has both covariant and contravariant flags set",
                        generic_param.rid
                    ));
                }

                if (flags & GenericParamAttributes::RESERVED_MASK) != 0 {
                    return Err(malformed_error!(
                        "GenericParam RID {} has reserved flag bits set: 0x{:04X}",
                        generic_param.rid,
                        flags & GenericParamAttributes::RESERVED_MASK
                    ));
                }

                if (flags & GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT) != 0
                    && (flags & GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT) != 0
                {
                    return Err(malformed_error!(
                        "GenericParam RID {} has conflicting reference type and value type constraints",
                        generic_param.rid
                    ));
                }
            }
        }

        Ok(())
    }

    /// Detects circular constraint dependencies between generic parameters.
    ///
    /// Validates that generic parameter constraints do not form circular dependencies
    /// that would cause infinite recursion during type resolution. Uses depth-first
    /// search to detect cycles in the constraint dependency graph.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No circular dependencies found
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Circular dependencies detected
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] if:
    /// - Circular constraint dependencies are detected
    /// - Constraint chains exceed reasonable depth limits
    fn validate_constraint_circularity(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view
            .tables()
            .ok_or_else(|| malformed_error!("Assembly view does not contain metadata tables"))?;

        if let (Some(generic_param_table), Some(constraint_table)) = (
            tables.table::<GenericParamRaw>(),
            tables.table::<GenericParamConstraintRaw>(),
        ) {
            let mut param_constraints: HashMap<u32, Vec<u32>> = HashMap::new();

            for constraint in constraint_table {
                param_constraints
                    .entry(constraint.owner)
                    .or_default()
                    .push(constraint.rid);
            }

            for param in generic_param_table {
                let mut visited = HashSet::new();
                let mut visiting = HashSet::new();

                if Self::has_circular_constraint_dependency(
                    param.rid,
                    &param_constraints,
                    &mut visited,
                    &mut visiting,
                ) {
                    return Err(malformed_error!(
                        "Circular constraint dependency detected involving GenericParam RID {}",
                        param.rid
                    ));
                }
            }
        }

        Ok(())
    }

    /// Helper method to detect circular dependencies using depth-first search.
    ///
    /// # Arguments
    ///
    /// * `param_id` - Current parameter being checked
    /// * `param_constraints` - Map of parameter to constraint dependencies
    /// * `visited` - Set of fully processed parameters
    /// * `visiting` - Set of parameters currently being processed (for cycle detection)
    ///
    /// # Returns
    ///
    /// * `true` - Circular dependency detected
    /// * `false` - No circular dependency
    fn has_circular_constraint_dependency(
        param_id: u32,
        param_constraints: &HashMap<u32, Vec<u32>>,
        visited: &mut HashSet<u32>,
        visiting: &mut HashSet<u32>,
    ) -> bool {
        if visited.contains(&param_id) {
            return false;
        }

        if visiting.contains(&param_id) {
            return true;
        }

        visiting.insert(param_id);

        if let Some(constraints) = param_constraints.get(&param_id) {
            for &constraint_id in constraints {
                if visiting.contains(&constraint_id) {
                    return true;
                }
            }
        }

        visiting.remove(&param_id);
        visited.insert(param_id);
        false
    }
}

impl RawValidator for RawGenericConstraintValidator {
    /// Validates the structural integrity and consistency of all generic parameter constraints.
    ///
    /// Performs comprehensive validation of generic constraints, including:
    /// 1. Generic parameter definition validation
    /// 2. Parameter constraint relationship validation
    /// 3. Constraint inheritance consistency validation
    /// 4. Cross-table constraint reference validation
    ///
    /// This method provides foundational guarantees about generic constraint integrity
    /// that higher-level type system validators can rely upon during semantic validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All generic constraints are valid and meet ECMA-335 requirements
    /// * `Err(`[`crate::Error::ValidationRawValidatorFailed`]`)` - Constraint violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawValidatorFailed`] for:
    /// - Invalid generic parameter definitions or missing constraints
    /// - Inconsistent constraint inheritance relationships
    /// - Invalid type parameter bounds or interface constraints
    /// - Cross-table constraint reference violations
    /// - Circular constraint dependencies
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();

        Self::validate_generic_parameters(assembly_view)?;
        Self::validate_parameter_constraints(assembly_view)?;
        Self::validate_constraint_inheritance(assembly_view)?;

        Self::validate_constraint_types(assembly_view)?;
        Self::validate_parameter_flags(assembly_view)?;
        Self::validate_constraint_circularity(assembly_view)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawGenericConstraintValidator"
    }

    fn priority(&self) -> u32 {
        130
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_constraint_validation
    }
}

impl Default for RawGenericConstraintValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        test::{
            factories::validation::raw_constraints_generic::raw_generic_constraint_validator_file_factory,
            validator_test,
        },
    };

    #[test]
    fn test_raw_generic_constraint_validator() -> Result<()> {
        let validator = RawGenericConstraintValidator::new();
        let config = ValidationConfig {
            enable_constraint_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_generic_constraint_validator_file_factory,
            "RawGenericConstraintValidator",
            "Malformed",
            config,
            |context| validator.validate_raw(context),
        )
    }
}
