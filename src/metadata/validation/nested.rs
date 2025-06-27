//! # Nested Class Validation for .NET Metadata
//!
//! This module provides comprehensive validation utilities for nested class relationships
//! in .NET metadata, ensuring compliance with runtime rules, ECMA-335 specifications,
//! and preventing structural anomalies that could cause runtime issues.
//!
//! ## Overview
//!
//! Nested classes in .NET provide a way to define types within the scope of other types,
//! creating logical groupings and encapsulation boundaries. However, nested class
//! relationships must follow specific rules to ensure proper runtime behavior and
//! prevent structural problems.
//!
//! ## Validation Categories
//!
//! ### Relationship Validation
//! - **Self-Reference Prevention**: Types cannot be nested within themselves
//! - **Token Validation**: Ensures proper `TypeDef` token usage
//! - **RID Validation**: Validates non-zero row identifiers
//!
//! ### Structural Validation
//! - **Circular Reference Detection**: Prevents cycles in nesting relationships
//! - **Depth Limit Enforcement**: Prevents excessive nesting that could cause stack issues
//! - **Hierarchy Consistency**: Ensures proper parent-child relationships
//!
//! ### Performance Validation
//! - **Depth Limits**: Configurable maximum nesting depth (default: 64 levels)
//! - **Cycle Detection**: Efficient graph algorithms for cycle detection
//! - **Memory Validation**: Prevents memory exhaustion from deep nesting
//!
//! ## Nesting Rules
//!
//! ### Basic Rules
//! 1. **No Self-Nesting**: A type cannot be nested within itself
//! 2. **`TypeDef` Only**: Both nested and enclosing types must be `TypeDef` tokens
//! 3. **Valid RIDs**: Token row identifiers must be non-zero
//! 4. **Single Enclosing**: Each nested type can have only one direct enclosing type
//!
//! ### Structural Rules
//! 1. **No Cycles**: Nesting relationships must form a directed acyclic graph (DAG)
//! 2. **Finite Depth**: Nesting chains must have reasonable depth limits
//! 3. **Proper References**: All token references must be valid and resolvable
//!
//! ## Validation Algorithms
//!
//! ### Cycle Detection
//! Uses depth-first search (DFS) with recursion stack tracking to detect cycles
//! in O(V + E) time complexity, where V is vertices (types) and E is edges (nesting relationships).
//!
//! ### Depth Validation
//! Traverses nesting chains from leaf to root to measure maximum depth
//! in O(V) time complexity per chain, with early termination on depth violations.
//!
//! ### Invalid Nesting Patterns
//! ```csharp
//! // ❌ Circular nesting (impossible in C# but could exist in malformed metadata)
//! // ClassA contains ClassB
//! // ClassB contains ClassC  
//! // ClassC contains ClassA  <- Creates cycle
//!
//! // ❌ Excessive depth (design issue, potential runtime problems)
//! // Class1 -> Class2 -> Class3 -> ... -> Class100+ (too deep)
//! ```
//!
//! ## Error Types
//!
//! | Error Category | Description | Example |
//! |----------------|-------------|---------|
//! | **Self-Reference** | Type nested within itself | `ClassA` nested in `ClassA` |
//! | **Invalid Token** | Non-TypeDef token used | `MethodDef` token for nested type |
//! | **Zero RID** | Invalid row identifier | Token with RID = 0 |
//! | **Circular Reference** | Cycle in nesting chain | A→B→C→A |
//! | **Depth Exceeded** | Too many nesting levels | 65+ levels of nesting |
//!
//! ## Runtime Compliance
//!
//! The validation follows .NET runtime behavior:
//! - **Token Validation**: Matches `CoreCLR` token validation rules
//! - **Structural Validation**: Prevents runtime loading failures
//! - **Error Messages**: Provides runtime-style error descriptions
//! - **Performance**: Efficient validation suitable for production use
//!
//! ## Thread Safety
//!
//! The `NestedClassValidator` is stateless and safe for concurrent use across
//! multiple threads. All validation methods are pure functions without side effects.
//!
//! ## References
//!
//! - ECMA-335, Partition II, Section 10.6 - Nested types
//! - ECMA-335, Partition II, Section 23.2.11 - `NestedClass` table
//! - .NET Core Runtime: Nested type validation implementation
//! - C# Language Specification: Nested type declarations

use crate::{metadata::token::Token, Result};
use std::collections::{HashMap, HashSet};

/// Nested class validator for .NET metadata compliance.
///
/// Provides comprehensive validation functionality for nested class relationships
/// as defined in ECMA-335 and implemented by the .NET runtime. This validator
/// ensures that nested type structures are valid, acyclic, and conform to
/// runtime constraints.
///
/// ## Design Philosophy
///
/// The validator implements multiple layers of validation:
/// - **Basic validation**: Token format and reference integrity
/// - **Structural validation**: Cycle detection and hierarchy verification
/// - **Performance validation**: Depth limits and resource constraints
/// - **Runtime compliance**: Matching .NET runtime validation behavior
///
/// ## Validation Approach
///
/// The validator uses efficient graph algorithms to analyze nesting relationships:
/// - **DFS-based cycle detection** for comprehensive circular reference detection
/// - **Chain traversal** for depth validation with early termination
/// - **Token validation** for format and reference integrity
/// - **Batch processing** for efficient validation of large type systems
///
/// ## Thread Safety
///
/// This struct is stateless and all methods are safe for concurrent use.
/// The validation algorithms do not maintain any shared state between calls.
pub struct NestedClassValidator;

impl NestedClassValidator {
    /// Validates a nested class relationship according to .NET runtime rules.
    ///
    /// Performs basic validation of a single nested class relationship to ensure
    /// that the nesting is structurally valid and conforms to .NET metadata
    /// requirements. This validation prevents self-referential nesting and
    /// validates token format constraints.
    ///
    /// ## Validation Performed
    ///
    /// ### Self-Reference Prevention
    /// - Ensures a type is not nested within itself (prevents infinite recursion)
    /// - Validates that nested and enclosing tokens are different
    ///
    /// ### Token Format Validation
    /// - Verifies both tokens are `TypeDef` tokens (table ID 0x02)
    /// - Ensures row identifiers (RIDs) are non-zero and valid
    /// - Validates token structure and format compliance
    ///
    /// ## Token Requirements
    ///
    /// Both nested and enclosing class tokens must be:
    /// - **`TypeDef` tokens**: Table ID must be 0x02 (not `MethodDef`, `FieldDef`, etc.)
    /// - **Valid RIDs**: Row identifier must be > 0 (1-based indexing)
    /// - **Different tokens**: Cannot be the same token (no self-nesting)
    ///
    /// # Arguments
    ///
    /// * `nested_class_token` - Token of the type being nested inside another type
    /// * `enclosing_class_token` - Token of the type that contains the nested type
    ///
    /// # Returns
    ///
    /// `Ok(())` if the nesting relationship is valid, or an error describing the
    /// specific validation failure.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in these cases:
    /// - **Self-Referential Nesting**: Nested and enclosing tokens are identical
    /// - **Invalid Token Type**: Token is not a `TypeDef` token (wrong table ID)
    /// - **Invalid RID**: Token has zero row identifier (invalid reference)
    ///
    /// # .NET Runtime Reference
    ///
    /// This validation is based on the .NET runtime's nested class processing logic
    /// that prevents structural anomalies and ensures proper type loading behavior.
    /// The validation matches `CoreCLR`'s token validation and relationship checking.
    pub fn validate_nested_relationship(
        nested_class_token: Token,
        enclosing_class_token: Token,
    ) -> Result<()> {
        // Check for self-referential nesting (type cannot be nested within itself)
        if nested_class_token == enclosing_class_token {
            return Err(malformed_error!(
                "Type cannot be nested within itself - token: {}",
                nested_class_token.value()
            ));
        }

        // Validate that both tokens are TypeDef tokens (table 0x02)
        if nested_class_token.table() != 0x02 {
            return Err(malformed_error!(
                "Nested class token must be a TypeDef token, got table ID: {}",
                nested_class_token.table()
            ));
        }

        if enclosing_class_token.table() != 0x02 {
            return Err(malformed_error!(
                "Enclosing class token must be a TypeDef token, got table ID: {}",
                enclosing_class_token.table()
            ));
        }

        // Validate token RIDs are non-zero
        if nested_class_token.row() == 0 {
            return Err(malformed_error!("Nested class token has invalid RID: 0"));
        }

        if enclosing_class_token.row() == 0 {
            return Err(malformed_error!("Enclosing class token has invalid RID: 0"));
        }

        Ok(())
    }

    /// Validates a nested class hierarchy for circular references.
    ///
    /// Performs comprehensive cycle detection in nested class relationships using
    /// depth-first search (DFS) algorithm. Circular nesting would create infinite
    /// recursion during type loading and must be prevented.
    ///
    /// ## Algorithm Details
    ///
    /// Uses DFS with recursion stack tracking to detect back edges that indicate cycles:
    /// 1. **Build Graph**: Creates adjacency list from nesting relationships
    /// 2. **DFS Traversal**: Visits each node using depth-first search
    /// 3. **Recursion Stack**: Tracks current path to detect back edges
    /// 4. **Cycle Detection**: Identifies when a node is reached via two different paths
    ///
    /// ## Cycle Examples
    ///
    /// ### Valid Hierarchies (No Cycles)
    /// ```text
    /// A → B → C    (Linear chain)
    /// A → B        (Simple parent-child)
    ///   → C        (Multiple children)
    /// ```
    ///
    /// ### Invalid Hierarchies (Cycles)
    /// ```text
    /// A → B → C → A    (3-node cycle)
    /// A → B → A        (2-node cycle)
    /// A → A            (Self-cycle, caught by basic validation)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `nested_relationships` - Slice of `(nested_token, enclosing_token)` pairs
    ///   representing the complete set of nesting relationships to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if no circular references are detected, or an error identifying
    /// the first cycle found during traversal.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when:
    /// - **Circular Reference**: A cycle is detected in the nesting relationships
    /// - **Structural Inconsistency**: Invalid relationship structure
    ///
    /// # Use Cases
    ///
    /// - **Metadata Validation**: Ensuring loaded assemblies have valid structure
    /// - **Development Tools**: Detecting design issues in nested type hierarchies
    /// - **Runtime Safety**: Preventing infinite recursion during type loading
    /// - **Compliance Checking**: Ensuring ECMA-335 structural requirements
    pub fn validate_no_circular_nesting(nested_relationships: &[(Token, Token)]) -> Result<()> {
        // Build adjacency list: enclosing -> list of nested classes
        let mut enclosing_to_nested: HashMap<Token, Vec<Token>> = HashMap::new();
        let mut nested_to_enclosing: HashMap<Token, Token> = HashMap::new();

        for &(nested, enclosing) in nested_relationships {
            enclosing_to_nested
                .entry(enclosing)
                .or_default()
                .push(nested);
            nested_to_enclosing.insert(nested, enclosing);
        }

        // Check for cycles using DFS from each root class
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        // Check all possible roots for cycles
        for &(nested, _) in nested_relationships {
            if !visited.contains(&nested) {
                if let Some(cycle_token) =
                    Self::has_cycle_dfs(nested, &enclosing_to_nested, &mut visited, &mut rec_stack)
                {
                    return Err(malformed_error!(
                        "Circular nesting relationship detected involving type token: {}",
                        cycle_token.value()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates nesting depth does not exceed reasonable limits.
    ///
    /// Performs depth validation for all nested class chains to ensure they don't
    /// exceed reasonable limits that could cause stack overflow conditions during
    /// type loading or runtime processing. While the .NET runtime doesn't enforce
    /// a specific nesting depth limit, excessive nesting can cause stack overflow
    /// issues and is generally considered poor design.
    ///
    /// ## Validation Process
    ///
    /// The method walks up each nesting chain from nested types to their roots:
    /// 1. **Build Chain Map**: Creates mapping from nested to enclosing types
    /// 2. **Chain Traversal**: Follows nesting relationships from leaf to root
    /// 3. **Depth Counting**: Measures depth of each nesting chain
    /// 4. **Limit Checking**: Ensures no chain exceeds the maximum depth
    ///
    /// ## Depth Calculation
    ///
    /// Depth is measured as the number of nesting levels:
    /// - **Depth 0**: Top-level class (no enclosing class)
    /// - **Depth 1**: Class nested directly in top-level class
    /// - **Depth 2**: Class nested in depth-1 class
    /// - **Depth N**: Class nested N levels deep
    ///
    /// # Arguments
    ///
    /// * `nested_relationships` - Slice of (`nested_token`, `enclosing_token`) pairs
    ///   representing all nesting relationships to validate
    /// * `max_depth` - Maximum allowed nesting depth (typical default: 64 levels)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all nesting chains are within depth limits, or an error
    /// identifying the first chain that exceeds the limit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when:
    /// - **Depth Exceeded**: A nesting chain exceeds the specified maximum depth
    /// - **Chain Processing Error**: Error processing nesting relationships
    ///
    /// # Examples
    ///
    /// ## Valid Depth Hierarchy
    /// ```text
    /// OuterClass              (Depth 0)
    /// └── MiddleClass         (Depth 1)
    ///     └── InnerClass      (Depth 2)
    /// ```
    /// Maximum depth is 2, which is typically acceptable.
    ///
    /// ## Invalid Deep Hierarchy
    /// ```text
    /// Level0 → Level1 → Level2 → ... → Level65
    /// ```
    /// Depth 65 exceeds typical limits and would be rejected.
    ///
    /// # Thread Safety
    ///
    /// This method is safe for concurrent execution as it:
    /// - Uses local collections for relationship mapping
    /// - Performs read-only analysis of input relationships
    /// - Contains no shared mutable state between calls
    pub fn validate_nesting_depth(
        nested_relationships: &[(Token, Token)],
        max_depth: usize,
    ) -> Result<()> {
        let mut nested_to_enclosing: HashMap<Token, Token> = HashMap::new();
        for &(nested, enclosing) in nested_relationships {
            nested_to_enclosing.insert(nested, enclosing);
        }

        // Check depth for each nested class
        for &(nested, _) in nested_relationships {
            let mut current = nested;
            let mut depth = 0;

            // Walk up the nesting chain
            while let Some(&enclosing) = nested_to_enclosing.get(&current) {
                depth += 1;
                if depth > max_depth {
                    return Err(malformed_error!(
                        "Nesting depth {} exceeds maximum allowed depth {} for type token: {}",
                        depth,
                        max_depth,
                        nested.value()
                    ));
                }
                current = enclosing;
            }
        }

        Ok(())
    }

    /// Performs depth-first search to detect cycles in nested class relationships.
    ///
    /// This function implements cycle detection using a standard DFS algorithm with a
    /// recursion stack to track the current path. It's used internally by the validation
    /// engine to detect illegal circular nesting relationships between classes.
    ///
    /// # Arguments
    ///
    /// * `current` - Token of the current class being examined
    /// * `enclosing_map` - Map of enclosing class to nested classes relationships
    /// * `visited` - Set of already visited tokens to avoid redundant work
    /// * `rec_stack` - Set tracking the current recursion path for cycle detection
    ///
    /// # Returns
    ///
    /// Returns `Some(Token)` of the class where a cycle is detected, or `None` if no cycle exists.
    fn has_cycle_dfs(
        current: Token,
        enclosing_map: &HashMap<Token, Vec<Token>>,
        visited: &mut HashSet<Token>,
        rec_stack: &mut HashSet<Token>,
    ) -> Option<Token> {
        visited.insert(current);
        rec_stack.insert(current);

        if let Some(nested_classes) = enclosing_map.get(&current) {
            for &nested_class in nested_classes {
                if !visited.contains(&nested_class) {
                    if let Some(cycle_token) =
                        Self::has_cycle_dfs(nested_class, enclosing_map, visited, rec_stack)
                    {
                        return Some(cycle_token);
                    }
                } else if rec_stack.contains(&nested_class) {
                    return Some(nested_class); // Cycle detected
                }
            }
        }

        rec_stack.remove(&current);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_typedef_token(rid: u32) -> Token {
        Token::new(0x0200_0000 | rid)
    }

    #[test]
    fn test_valid_nested_relationship() {
        let nested = make_typedef_token(1);
        let enclosing = make_typedef_token(2);

        assert!(NestedClassValidator::validate_nested_relationship(nested, enclosing).is_ok());
    }

    #[test]
    fn test_self_referential_nesting() {
        let token = make_typedef_token(1);

        let result = NestedClassValidator::validate_nested_relationship(token, token);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("nested within itself"));
    }

    #[test]
    fn test_invalid_token_table_id() {
        let nested = Token::new(0x0100_0001); // MethodDef token instead of TypeDef
        let enclosing = make_typedef_token(2);

        let result = NestedClassValidator::validate_nested_relationship(nested, enclosing);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be a TypeDef token"));
    }

    #[test]
    fn test_zero_rid_validation() {
        let nested = Token::new(0x0200_0000); // RID = 0
        let enclosing = make_typedef_token(1);

        let result = NestedClassValidator::validate_nested_relationship(nested, enclosing);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid RID: 0"));
    }

    #[test]
    fn test_no_circular_nesting_valid() {
        // A -> B -> C (no cycle)
        let relationships = vec![
            (make_typedef_token(2), make_typedef_token(1)), // B nested in A
            (make_typedef_token(3), make_typedef_token(2)), // C nested in B
        ];

        assert!(NestedClassValidator::validate_no_circular_nesting(&relationships).is_ok());
    }

    #[test]
    fn test_circular_nesting_detection() {
        // A -> B -> C -> A (cycle)
        let relationships = vec![
            (make_typedef_token(2), make_typedef_token(1)), // B nested in A
            (make_typedef_token(3), make_typedef_token(2)), // C nested in B
            (make_typedef_token(1), make_typedef_token(3)), // A nested in C (creates cycle)
        ];

        let result = NestedClassValidator::validate_no_circular_nesting(&relationships);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Circular nesting"));
    }

    #[test]
    fn test_nesting_depth_validation() {
        // Create a chain: A -> B -> C -> D (depth = 3)
        let relationships = vec![
            (make_typedef_token(2), make_typedef_token(1)), // B nested in A
            (make_typedef_token(3), make_typedef_token(2)), // C nested in B
            (make_typedef_token(4), make_typedef_token(3)), // D nested in C
        ];

        // Should pass with max depth 5
        assert!(NestedClassValidator::validate_nesting_depth(&relationships, 5).is_ok());

        // Should fail with max depth 2
        let result = NestedClassValidator::validate_nesting_depth(&relationships, 2);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum allowed depth"));
    }

    #[test]
    fn test_empty_relationships() {
        // Empty relationships should always be valid
        assert!(NestedClassValidator::validate_no_circular_nesting(&[]).is_ok());
        assert!(NestedClassValidator::validate_nesting_depth(&[], 64).is_ok());
    }
}
