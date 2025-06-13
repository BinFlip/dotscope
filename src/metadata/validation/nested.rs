//! Nested class validation for .NET metadata
//!
//! This module provides validation utilities for nested class relationships,
//! ensuring compliance with .NET runtime rules and metadata constraints.

use crate::{metadata::token::Token, Result};
use std::collections::{HashMap, HashSet};

/// Validator for nested class metadata
pub struct NestedClassValidator;

impl NestedClassValidator {
    /// Validates a nested class relationship according to .NET runtime rules
    ///
    /// # Arguments
    /// * `nested_class_token` - Token of the nested class
    /// * `enclosing_class_token` - Token of the enclosing class
    ///
    /// # Errors
    /// Returns an error if:
    /// - Nested class and enclosing class are the same type
    /// - Token values are invalid or malformed
    ///
    /// # .NET Runtime Reference
    /// Based on validation logic in nested class processing that prevents
    /// a type from being nested within itself.
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

    /// Validates a nested class hierarchy for circular references
    ///
    /// # Arguments
    /// * `nested_relationships` - Slice of (`nested_token`, `enclosing_token`) pairs
    ///
    /// # Errors
    /// Returns an error if circular nesting relationships are detected
    ///
    /// # Example
    /// ```ignore
    /// // This would be invalid:
    /// // ClassA nested in ClassB
    /// // ClassB nested in ClassC  
    /// // ClassC nested in ClassA  <- Creates a cycle
    /// ```
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

    /// Validates nesting depth does not exceed reasonable limits
    ///
    /// # Arguments
    /// * `nested_relationships` - Slice of (`nested_token`, `enclosing_token`) pairs
    /// * `max_depth` - Maximum allowed nesting depth (default: 64 levels)
    ///
    /// # Errors
    /// Returns an error if nesting depth exceeds the specified limit
    ///
    /// # Note
    /// While the .NET runtime doesn't enforce a specific nesting depth limit,
    /// excessive nesting can cause stack overflow issues and is generally
    /// considered poor design.
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
