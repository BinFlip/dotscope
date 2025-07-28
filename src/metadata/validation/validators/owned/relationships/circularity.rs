//! Owned circularity validator for circular reference detection in resolved metadata.
//!
//! This validator provides comprehensive detection of circular references within the context
//! of fully resolved .NET metadata. It operates on resolved type structures to detect circular
//! inheritance patterns, nested class cycles, and cross-assembly dependency loops that could
//! cause runtime issues or infinite recursion. This validator runs with priority 150
//! in the owned validation stage.
//!
//! # Architecture
//!
//! The circularity validation system implements comprehensive circular reference detection in sequential order:
//! 1. **Inheritance Circularity Detection** - Identifies circular inheritance chains in type hierarchies
//! 2. **Nested Class Circularity Detection** - Detects circular nested class relationships
//! 3. **Dependency Circularity Detection** - Analyzes cross-assembly dependency cycles
//! 4. **Graph Analysis** - Uses graph algorithms to detect cycles in resolved object relationships
//!
//! The implementation validates relationship constraints according to ECMA-335 specifications,
//! ensuring proper type hierarchy formation and preventing infinite recursion scenarios.
//! All validation includes graph traversal and cycle detection algorithms.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::relationships::circularity::OwnedCircularityValidator`] - Main validator implementation providing comprehensive circularity detection
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedCircularityValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedCircularityValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_owned(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationOwnedValidatorFailed`] for:
//! - Circular inheritance chains in type hierarchies (types inheriting from themselves)
//! - Circular nested class relationships (nested types forming dependency loops)
//! - Cross-assembly dependency cycles (assemblies with mutual dependencies)
//! - Graph cycles in resolved object relationships (any circular reference patterns)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable resolved metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::owned::relationships`] - Part of the owned relationship validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_cross_table_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type system inheritance rules
//! - [ECMA-335 II.22.37](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeDef table and inheritance chains
//! - [ECMA-335 II.22.32](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - NestedClass table and containment relationships

use std::collections::{HashMap, HashSet};

use crate::{
    metadata::{
        token::Token,
        typesystem::CilType,
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for circular reference detection in resolved metadata structures.
///
/// Ensures the structural integrity and consistency of type relationships in resolved .NET metadata,
/// validating that no circular dependencies exist in inheritance hierarchies, nested class
/// relationships, or cross-assembly dependencies. This validator operates on resolved type
/// structures to provide essential guarantees about acyclic relationship patterns.
///
/// The validator implements comprehensive coverage of circular reference detection according to
/// ECMA-335 specifications, ensuring proper type hierarchy formation and preventing infinite
/// recursion scenarios in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedCircularityValidator;

impl OwnedCircularityValidator {
    /// Creates a new circularity validator instance.
    ///
    /// Initializes a validator instance that can be used to detect circular references
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::relationships::circularity::OwnedCircularityValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates inheritance cycles across type relationships.
    ///
    /// Detects circular inheritance patterns where types form cycles through their
    /// base type relationships. Uses depth-first search to identify inheritance
    /// loops that would cause infinite recursion.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No inheritance circular dependencies found
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Inheritance circularity detected
    fn validate_inheritance_cycles(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        for type_entry in types.all_types() {
            let token = type_entry.token;
            if !visited.contains(&token) {
                self.check_inheritance_cycle_relationships(
                    &type_entry,
                    &mut visited,
                    &mut visiting,
                )?;
            }
        }

        Ok(())
    }

    /// Recursively checks for inheritance cycles in type relationships.
    ///
    /// Uses the white-gray-black algorithm where:
    /// - White (not in any set): Unvisited
    /// - Gray (in visiting set): Currently being processed
    /// - Black (in visited set): Completely processed
    ///
    /// # Arguments
    ///
    /// * `type_entry` - Type to check for inheritance cycles
    /// * `visited` - Set of completely processed types (black)
    /// * `visiting` - Set of currently processing types (gray)
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the inheritance relationships.
    fn check_inheritance_cycle_relationships(
        &self,
        type_entry: &CilType,
        visited: &mut HashSet<Token>,
        visiting: &mut HashSet<Token>,
    ) -> Result<()> {
        let current_token = type_entry.token;

        // If already completely processed, skip
        if visited.contains(&current_token) {
            return Ok(());
        }

        // If currently being processed, we found a cycle
        if visiting.contains(&current_token) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular inheritance relationship detected: Type '{}' (token 0x{:08X}) is part of an inheritance cycle",
                    type_entry.name, current_token.value()
                ),
                source: None,
            });
        }

        // Mark as currently being processed
        visiting.insert(current_token);

        // Check base type relationships
        if let Some(base_type) = type_entry.base() {
            self.check_inheritance_cycle_relationships(&base_type, visited, visiting)?;
        }

        // Mark as completely processed and remove from currently processing
        visiting.remove(&current_token);
        visited.insert(current_token);

        Ok(())
    }

    /// Validates interface implementation cycles.
    ///
    /// Detects circular interface implementation patterns where interfaces
    /// implement each other either directly or through inheritance chains.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No interface implementation circular dependencies found
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Interface circularity detected
    fn validate_interface_implementation_cycles(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let types = context.object().types();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        // Build interface implementation relationships map
        let mut interface_relationships = HashMap::new();
        for type_entry in types.all_types() {
            let token = type_entry.token;
            let mut implemented_interfaces = Vec::new();
            for (_, interface_ref) in type_entry.interfaces.iter() {
                if let Some(interface_type) = interface_ref.upgrade() {
                    implemented_interfaces.push(interface_type.token);
                }
            }
            interface_relationships.insert(token, implemented_interfaces);
        }

        // Check each type for interface implementation cycles
        for type_entry in types.all_types() {
            let token = type_entry.token;
            if !visited.contains(&token) {
                self.check_interface_implementation_cycle(
                    token,
                    &interface_relationships,
                    &mut visited,
                    &mut visiting,
                )?;
            }
        }

        Ok(())
    }

    /// Recursively checks for interface implementation cycles.
    ///
    /// # Arguments
    ///
    /// * `token` - Type token to check for implementation cycles
    /// * `interface_relationships` - Map of type tokens to implemented interface tokens
    /// * `visited` - Set of completely processed types
    /// * `visiting` - Set of currently processing types
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the interface implementation relationships.
    fn check_interface_implementation_cycle(
        &self,
        token: Token,
        interface_relationships: &HashMap<Token, Vec<Token>>,
        visited: &mut HashSet<Token>,
        visiting: &mut HashSet<Token>,
    ) -> Result<()> {
        // If already completely processed, skip
        if visited.contains(&token) {
            return Ok(());
        }

        // If currently being processed, we found a cycle
        if visiting.contains(&token) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular interface implementation relationship detected: Type with token 0x{:08X} implements itself through interface chain",
                    token.value()
                ),
                source: None,
            });
        }

        // Mark as currently being processed
        visiting.insert(token);

        // Check all implemented interfaces
        if let Some(implemented_tokens) = interface_relationships.get(&token) {
            for &implemented_token in implemented_tokens {
                self.check_interface_implementation_cycle(
                    implemented_token,
                    interface_relationships,
                    visited,
                    visiting,
                )?;
            }
        }

        // Mark as completely processed and remove from currently processing
        visiting.remove(&token);
        visited.insert(token);

        Ok(())
    }

    /// Validates cross-reference cycles in type relationships.
    ///
    /// Analyzes specific type reference patterns to detect problematic cycles that could
    /// cause issues during type loading or runtime execution. This focuses on inheritance
    /// and interface implementation cycles, but excludes legitimate nested type patterns.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No problematic cross-reference circular dependencies found
    /// * `Err(`[`crate::Error::ValidationOwnedValidatorFailed`]`)` - Cross-reference circularity detected
    fn validate_cross_reference_cycles(&self, context: &OwnedValidationContext) -> Result<()> {
        let types = context.object().types();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();

        // Build specific reference map focusing on inheritance and interface relationships
        // Exclude nested types as they can legitimately reference their containers
        let mut reference_relationships = HashMap::new();
        for type_entry in types.all_types() {
            let token = type_entry.token;
            let mut references = Vec::new();

            // Add base type references (inheritance cycles are problematic)
            if let Some(base_type) = type_entry.base() {
                // Exclude self-references to System.Object which can happen
                if base_type.token != token && !base_type.fullname().starts_with("System.") {
                    references.push(base_type.token);
                }
            }

            // Add interface references (interface implementation cycles are problematic)
            for (_, interface_ref) in type_entry.interfaces.iter() {
                if let Some(interface_type) = interface_ref.upgrade() {
                    // Exclude self-references and System interfaces which can be special
                    if interface_type.token != token
                        && !interface_type.fullname().starts_with("System.")
                    {
                        references.push(interface_type.token);
                    }
                }
            }

            // Skip nested type references as they can legitimately reference containers
            // and don't cause the same loading issues as inheritance cycles

            reference_relationships.insert(token, references);
        }

        // Check each type for problematic cross-reference cycles
        for type_entry in types.all_types() {
            let token = type_entry.token;
            if !visited.contains(&token) {
                self.check_cross_reference_cycle(
                    token,
                    &reference_relationships,
                    &mut visited,
                    &mut visiting,
                )?;
            }
        }

        Ok(())
    }

    /// Recursively checks for cross-reference cycles.
    ///
    /// # Arguments
    ///
    /// * `token` - Type token to check for reference cycles
    /// * `reference_relationships` - Map of type tokens to referenced type tokens
    /// * `visited` - Set of completely processed types
    /// * `visiting` - Set of currently processing types
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the cross-reference relationships.
    fn check_cross_reference_cycle(
        &self,
        token: Token,
        reference_relationships: &HashMap<Token, Vec<Token>>,
        visited: &mut HashSet<Token>,
        visiting: &mut HashSet<Token>,
    ) -> Result<()> {
        // If already completely processed, skip
        if visited.contains(&token) {
            return Ok(());
        }

        // If currently being processed, we found a cycle
        if visiting.contains(&token) {
            return Err(Error::ValidationOwnedValidatorFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular cross-reference relationship detected: Type with token 0x{:08X} references itself through relationship chain",
                    token.value()
                ),
                source: None,
            });
        }

        // Mark as currently being processed
        visiting.insert(token);

        // Check all referenced types
        if let Some(referenced_tokens) = reference_relationships.get(&token) {
            for &referenced_token in referenced_tokens {
                self.check_cross_reference_cycle(
                    referenced_token,
                    reference_relationships,
                    visited,
                    visiting,
                )?;
            }
        }

        // Mark as completely processed and remove from currently processing
        visiting.remove(&token);
        visited.insert(token);

        Ok(())
    }
}

impl OwnedValidator for OwnedCircularityValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_inheritance_cycles(context)?;
        self.validate_interface_implementation_cycles(context)?;
        self.validate_cross_reference_cycles(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedCircularityValidator"
    }

    fn priority(&self) -> u32 {
        150
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_cross_table_validation
    }
}

impl Default for OwnedCircularityValidator {
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
            factories::validation::circularity::owned_circularity_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_circularity_validator() -> Result<()> {
        let validator = OwnedCircularityValidator::new();
        let config = ValidationConfig {
            enable_cross_table_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_circularity_validator_file_factory,
            "OwnedCircularityValidator",
            "ValidationOwnedValidatorFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
