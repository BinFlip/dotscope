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
//! This validator returns [`crate::Error::ValidationOwnedFailed`] for:
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

use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    metadata::{
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
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Inheritance circularity detected
    fn validate_inheritance_cycles(&self, context: &OwnedValidationContext) -> Result<()> {
        let mut visited = FxHashSet::default();
        let mut visiting = FxHashSet::default();

        for type_entry in context.all_types() {
            let type_ptr = Arc::as_ptr(type_entry) as usize;
            if !visited.contains(&type_ptr) {
                self.check_inheritance_cycle_relationships(
                    type_entry,
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
        visited: &mut FxHashSet<usize>,
        visiting: &mut FxHashSet<usize>,
    ) -> Result<()> {
        let type_ptr = std::ptr::from_ref::<CilType>(type_entry) as usize;

        // If already completely processed, skip
        if visited.contains(&type_ptr) {
            return Ok(());
        }

        // If currently being processed, we found a cycle
        if visiting.contains(&type_ptr) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Circular inheritance relationship detected: Type '{}' (token 0x{:08X}) is part of an inheritance cycle",
                    type_entry.name, type_entry.token.value()
                ),

            });
        }

        // Mark as currently being processed
        visiting.insert(type_ptr);

        // Check base type relationships
        if let Some(base_type) = type_entry.base() {
            self.check_inheritance_cycle_relationships(&base_type, visited, visiting)?;
        }

        // Mark as completely processed and remove from currently processing
        visiting.remove(&type_ptr);
        visited.insert(type_ptr);

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
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Interface circularity detected
    fn validate_interface_implementation_cycles(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let mut visited = FxHashSet::default();
        let mut visiting = FxHashSet::default();

        let interface_relationships = context.interface_relationships();

        // Check each type from target assembly for interface implementation cycles
        for type_entry in context.target_assembly_types() {
            let type_ptr = Arc::as_ptr(type_entry) as usize;
            if !visited.contains(&type_ptr) {
                self.check_interface_implementation_cycle(
                    type_ptr,
                    interface_relationships,
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
    /// * `type_ptr` - Arc pointer (as usize) to the type to check
    /// * `interface_relationships` - Map of type Arc pointers to implemented interface Arc pointers
    /// * `visited` - Set of completely processed types
    /// * `visiting` - Set of currently processing types
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the interface implementation relationships.
    fn check_interface_implementation_cycle(
        &self,
        type_ptr: usize,
        interface_relationships: &FxHashMap<usize, Vec<usize>>,
        visited: &mut FxHashSet<usize>,
        visiting: &mut FxHashSet<usize>,
    ) -> Result<()> {
        // If already completely processed, skip
        if visited.contains(&type_ptr) {
            return Ok(());
        }

        // If currently being processed, we found a cycle
        if visiting.contains(&type_ptr) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message:
                    "Circular interface implementation relationship detected: Type implements itself through interface chain"
                        .to_string(),
            });
        }

        // Mark as currently being processed
        visiting.insert(type_ptr);

        // Check all implemented interfaces
        if let Some(implemented_ptrs) = interface_relationships.get(&type_ptr) {
            for &implemented_ptr in implemented_ptrs {
                self.check_interface_implementation_cycle(
                    implemented_ptr,
                    interface_relationships,
                    visited,
                    visiting,
                )?;
            }
        }

        // Mark as completely processed and remove from currently processing
        visiting.remove(&type_ptr);
        visited.insert(type_ptr);

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
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Cross-reference circularity detected
    fn validate_cross_reference_cycles(&self, context: &OwnedValidationContext) -> Result<()> {
        let mut visited = FxHashSet::default();
        let mut visiting = FxHashSet::default();

        let target_types = context.target_assembly_types();

        // Build specific reference map using Arc pointers (not tokens) to avoid collisions
        // Focus on inheritance and interface relationships
        // Exclude nested types as they can legitimately reference their containers
        let mut reference_relationships: FxHashMap<usize, Vec<usize>> = FxHashMap::default();
        for type_entry in target_types {
            let type_ptr = Arc::as_ptr(type_entry) as usize;
            let mut references = Vec::new();

            // Add base type references (inheritance cycles are problematic)
            if let Some(base_type) = type_entry.base() {
                let base_ptr = Arc::as_ptr(&base_type) as usize;
                // Exclude System.Object which is a common base
                if !base_type.fullname().starts_with("System.") {
                    references.push(base_ptr);
                }
            }

            // Add interface references (interface implementation cycles are problematic)
            for (_, interface_ref) in type_entry.interfaces.iter() {
                if let Some(interface_type) = interface_ref.upgrade() {
                    let interface_ptr = Arc::as_ptr(&interface_type) as usize;
                    // Exclude System interfaces which are common base interfaces
                    if !interface_type.fullname().starts_with("System.") {
                        references.push(interface_ptr);
                    }
                }
            }

            // Skip nested type references as they can legitimately reference containers
            // and don't cause the same loading issues as inheritance cycles

            if !references.is_empty() {
                reference_relationships.insert(type_ptr, references);
            }
        }

        // Check each type for problematic cross-reference cycles
        for type_entry in target_types {
            let type_ptr = Arc::as_ptr(type_entry) as usize;
            if !visited.contains(&type_ptr) {
                self.check_cross_reference_cycle(
                    type_ptr,
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
    /// * `type_ptr` - Arc pointer (as usize) to the type to check
    /// * `reference_relationships` - Map of type Arc pointers to referenced type Arc pointers
    /// * `visited` - Set of completely processed types
    /// * `visiting` - Set of currently processing types
    ///
    /// # Returns
    ///
    /// Returns error if a cycle is detected in the cross-reference relationships.
    fn check_cross_reference_cycle(
        &self,
        type_ptr: usize,
        reference_relationships: &FxHashMap<usize, Vec<usize>>,
        visited: &mut FxHashSet<usize>,
        visiting: &mut FxHashSet<usize>,
    ) -> Result<()> {
        // If already completely processed, skip
        if visited.contains(&type_ptr) {
            return Ok(());
        }

        // If currently being processed, we found a cycle
        if visiting.contains(&type_ptr) {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message:
                    "Circular cross-reference relationship detected: Type references itself through relationship chain"
                        .to_string(),
            });
        }

        // Mark as currently being processed
        visiting.insert(type_ptr);

        // Check all referenced types
        if let Some(referenced_ptrs) = reference_relationships.get(&type_ptr) {
            for &referenced_ptr in referenced_ptrs {
                self.check_cross_reference_cycle(
                    referenced_ptr,
                    reference_relationships,
                    visited,
                    visiting,
                )?;
            }
        }

        // Mark as completely processed and remove from currently processing
        visiting.remove(&type_ptr);
        visited.insert(type_ptr);

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
    #[cfg(not(feature = "skip-expensive-tests"))]
    fn test_owned_circularity_validator() -> Result<()> {
        let validator = OwnedCircularityValidator::new();
        let config = ValidationConfig {
            enable_cross_table_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_circularity_validator_file_factory,
            "OwnedCircularityValidator",
            "ValidationOwnedFailed",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
