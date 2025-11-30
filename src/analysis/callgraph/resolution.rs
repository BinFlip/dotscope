//! Call target resolution and Class Hierarchy Analysis (CHA).
//!
//! This module provides resolution of call targets for the call graph, including:
//! - Direct call resolution to method tokens
//! - Virtual call resolution using Class Hierarchy Analysis (CHA)
//! - Type hierarchy tracking for override analysis
//! - External method reference handling
//!
//! Class Hierarchy Analysis is a static analysis technique that determines all
//! possible runtime targets of a virtual method call by analyzing the type
//! hierarchy and finding all methods that override the declared target.

use std::collections::{HashMap, HashSet};

use crate::{
    metadata::{
        method::MethodModifiers, tables::TypeAttributes, token::Token, typesystem::TypeRegistry,
    },
    CilObject,
};

/// Resolves call targets using the assembly metadata and type hierarchy.
///
/// The resolver precomputes the type hierarchy and virtual dispatch tables
/// from the assembly metadata, enabling efficient resolution of both direct
/// and virtual method calls during call graph construction.
///
/// For virtual calls, Class Hierarchy Analysis (CHA) is used to determine
/// all possible runtime targets based on the type hierarchy.
#[derive(Debug)]
pub struct CallResolver {
    /// Map from virtual method token to all possible overriders.
    virtual_dispatch_table: HashMap<Token, Vec<Token>>,
    /// Map from method token to its declaring type.
    method_to_type: HashMap<Token, Token>,
    /// Type hierarchy: type token -> direct subtypes.
    type_subtypes: HashMap<Token, Vec<Token>>,
    /// Set of interface types.
    interfaces: HashSet<Token>,
    /// Set of sealed types (cannot be subclassed).
    sealed_types: HashSet<Token>,
}

impl CallResolver {
    /// Builds a call resolver from the assembly metadata.
    ///
    /// This constructor precomputes the type hierarchy and virtual dispatch
    /// tables by scanning all types and methods in the assembly. The computed
    /// data structures enable efficient O(1) lookup during call resolution.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to build the resolver from
    ///
    /// # Returns
    ///
    /// A new [`CallResolver`] instance with precomputed dispatch tables.
    #[must_use]
    pub fn new(assembly: &CilObject) -> Self {
        let mut resolver = Self {
            virtual_dispatch_table: HashMap::new(),
            method_to_type: HashMap::new(),
            type_subtypes: HashMap::new(),
            interfaces: HashSet::new(),
            sealed_types: HashSet::new(),
        };

        resolver.build_type_hierarchy(assembly);
        resolver.build_virtual_dispatch_table(assembly);

        resolver
    }

    /// Builds the type hierarchy from assembly metadata.
    fn build_type_hierarchy(&mut self, assembly: &CilObject) {
        let types = assembly.types();

        // First pass: identify interfaces and sealed types
        for type_info in types.all_types() {
            let token = type_info.token;

            // Check if interface
            if type_info.flags & TypeAttributes::INTERFACE != 0 {
                self.interfaces.insert(token);
            }

            // Check if sealed
            if type_info.flags & TypeAttributes::SEALED != 0 {
                self.sealed_types.insert(token);
            }

            // Map methods to their declaring type
            for (_, method_ref) in type_info.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    self.method_to_type.insert(method.token, token);
                }
            }
        }

        // Second pass: build subtype relationships
        for type_info in types.all_types() {
            if let Some(base) = type_info.base() {
                let base_token = base.token;
                self.type_subtypes
                    .entry(base_token)
                    .or_default()
                    .push(type_info.token);
            }
        }
    }

    /// Builds the virtual dispatch table for all virtual methods.
    fn build_virtual_dispatch_table(&mut self, assembly: &CilObject) {
        let methods = assembly.methods();
        let types = assembly.types();

        // Find all virtual methods and their overriders
        for entry in methods {
            let method = entry.value();

            // Skip non-virtual methods
            if !method.flags_modifiers.contains(MethodModifiers::VIRTUAL) {
                continue;
            }

            let method_token = method.token;
            let method_name = &method.name;

            // Get declaring type
            let Some(&declaring_type) = self.method_to_type.get(&method_token) else {
                continue;
            };

            // Find all overriders in derived types
            let mut overriders = vec![method_token]; // Include self
            self.find_overriders(&types, declaring_type, method_name, &mut overriders);

            if overriders.len() > 1 {
                self.virtual_dispatch_table.insert(method_token, overriders);
            }
        }
    }

    /// Recursively finds all methods that override a virtual method.
    fn find_overriders(
        &self,
        types: &TypeRegistry,
        type_token: Token,
        method_name: &str,
        overriders: &mut Vec<Token>,
    ) {
        // Get subtypes of this type
        let Some(subtypes) = self.type_subtypes.get(&type_token) else {
            return;
        };

        for &subtype_token in subtypes {
            // Find the type
            if let Some(subtype) = types.get(&subtype_token) {
                // Look for an overriding method
                for (_, method_ref) in subtype.methods.iter() {
                    if let Some(method) = method_ref.upgrade() {
                        if method.name == method_name
                            && method.flags_modifiers.contains(MethodModifiers::VIRTUAL)
                        {
                            if !overriders.contains(&method.token) {
                                overriders.push(method.token);
                            }
                            break;
                        }
                    }
                }
            }

            // Recurse into further derived types
            self.find_overriders(types, subtype_token, method_name, overriders);
        }
    }

    /// Resolves possible targets for a virtual call.
    ///
    /// Uses Class Hierarchy Analysis (CHA) to determine all methods that could
    /// be invoked at runtime due to virtual dispatch. This includes the declared
    /// method and all overriding methods in derived types.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the declared virtual method being called
    ///
    /// # Returns
    ///
    /// A vector of method tokens representing all possible runtime targets.
    /// If no overrides exist, returns a single-element vector containing the
    /// original method token.
    #[must_use]
    pub fn resolve_virtual(&self, method_token: Token) -> Vec<Token> {
        self.virtual_dispatch_table
            .get(&method_token)
            .cloned()
            .unwrap_or_else(|| vec![method_token])
    }

    /// Returns `true` if the method is virtual and has multiple possible targets.
    ///
    /// A polymorphic method is one where Class Hierarchy Analysis determined
    /// that more than one implementation could be invoked at runtime.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The method token to check
    ///
    /// # Returns
    ///
    /// `true` if the method has more than one possible runtime target,
    /// `false` otherwise.
    #[must_use]
    pub fn is_polymorphic(&self, method_token: Token) -> bool {
        self.virtual_dispatch_table
            .get(&method_token)
            .is_some_and(|targets| targets.len() > 1)
    }

    /// Returns the declaring type of a method.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The method token to look up
    ///
    /// # Returns
    ///
    /// The type token of the declaring type, or `None` if the method is not
    /// found in the resolver's index.
    #[must_use]
    pub fn declaring_type(&self, method_token: Token) -> Option<Token> {
        self.method_to_type.get(&method_token).copied()
    }

    /// Returns `true` if the type is an interface.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to check
    ///
    /// # Returns
    ///
    /// `true` if the type has the interface attribute, `false` otherwise.
    #[must_use]
    pub fn is_interface(&self, type_token: Token) -> bool {
        self.interfaces.contains(&type_token)
    }

    /// Returns `true` if the type is sealed (cannot be subclassed).
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to check
    ///
    /// # Returns
    ///
    /// `true` if the type has the sealed attribute, `false` otherwise.
    #[must_use]
    pub fn is_sealed(&self, type_token: Token) -> bool {
        self.sealed_types.contains(&type_token)
    }

    /// Returns all direct subtypes of a given type.
    ///
    /// Only returns types that directly inherit from the specified type,
    /// not transitive descendants.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to find subtypes for
    ///
    /// # Returns
    ///
    /// A vector of type tokens for all direct subtypes. Returns an empty
    /// vector if the type has no subtypes or is not found.
    #[must_use]
    pub fn subtypes(&self, type_token: Token) -> Vec<Token> {
        self.type_subtypes
            .get(&type_token)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns all types in the subtype hierarchy (transitive closure).
    ///
    /// Computes all types that inherit from the specified type, including
    /// indirect descendants through the entire inheritance chain.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token to find all subtypes for
    ///
    /// # Returns
    ///
    /// A vector of type tokens for all transitive subtypes. Returns an empty
    /// vector if the type has no subtypes.
    #[must_use]
    pub fn all_subtypes(&self, type_token: Token) -> Vec<Token> {
        let mut result = Vec::new();
        let mut worklist = vec![type_token];
        let mut visited = HashSet::new();

        while let Some(current) = worklist.pop() {
            if !visited.insert(current) {
                continue;
            }

            if let Some(subtypes) = self.type_subtypes.get(&current) {
                for &subtype in subtypes {
                    result.push(subtype);
                    worklist.push(subtype);
                }
            }
        }

        result
    }

    /// Returns statistics about the resolver state.
    ///
    /// Provides aggregate information about the precomputed type hierarchy
    /// and virtual dispatch tables.
    ///
    /// # Returns
    ///
    /// A [`ResolverStats`] structure containing counts and metrics about
    /// the resolver's state.
    #[must_use]
    pub fn stats(&self) -> ResolverStats {
        let polymorphic_methods = self
            .virtual_dispatch_table
            .values()
            .filter(|targets| targets.len() > 1)
            .count();

        let max_targets = self
            .virtual_dispatch_table
            .values()
            .map(Vec::len)
            .max()
            .unwrap_or(0);

        ResolverStats {
            total_methods: self.method_to_type.len(),
            virtual_methods: self.virtual_dispatch_table.len(),
            polymorphic_methods,
            max_targets,
            total_types: self.type_subtypes.len() + self.sealed_types.len(),
            interface_types: self.interfaces.len(),
            sealed_types: self.sealed_types.len(),
        }
    }
}

/// Statistics about the call resolver state.
#[derive(Debug, Clone, Default)]
pub struct ResolverStats {
    /// Total number of methods indexed.
    pub total_methods: usize,
    /// Number of virtual methods.
    pub virtual_methods: usize,
    /// Number of methods with multiple possible targets.
    pub polymorphic_methods: usize,
    /// Maximum number of targets for any virtual method.
    pub max_targets: usize,
    /// Total number of types indexed.
    pub total_types: usize,
    /// Number of interface types.
    pub interface_types: usize,
    /// Number of sealed types.
    pub sealed_types: usize,
}

#[cfg(test)]
mod tests {
    use crate::analysis::callgraph::ResolverStats;

    #[test]
    fn test_resolver_stats_default() {
        let stats = ResolverStats::default();
        assert_eq!(stats.total_methods, 0);
        assert_eq!(stats.virtual_methods, 0);
        assert_eq!(stats.polymorphic_methods, 0);
    }
}
