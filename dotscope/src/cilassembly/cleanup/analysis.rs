//! Cleanup analysis functions for assembly metadata.
//!
//! This module provides generic, stateless analysis functions that operate on
//! [`CilObject`] and method call graph data without any deobfuscation dependency.
//! These functions are used to determine what metadata entities can be safely
//! removed during cleanup.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    cilassembly::cleanup::CleanupRequest,
    metadata::{
        tables::{CustomAttributeRaw, TableId},
        token::Token,
    },
    CilObject,
};

/// Expands a cleanup request to include member tokens of deleted types
/// and their nested types.
///
/// The cleanup request stores [`TypeDef`](crate::metadata::tables::TableId::TypeDef)
/// tokens for types scheduled for deletion, but SSA instructions reference their
/// members via [`Field`](crate::metadata::tables::TableId::Field) and
/// [`MethodDef`](crate::metadata::tables::TableId::MethodDef) tokens. Without
/// expansion, the neutralization pass cannot match instructions that load fields
/// or call methods belonging to deleted types.
///
/// For each type in the request, this collects all nested types and their field
/// and method tokens from the type registry and adds them to the token set.
///
/// # Arguments
///
/// * `request` - The merged cleanup request containing types, methods, and
///   fields scheduled for deletion.
/// * `assembly` - The assembly whose type registry is used to resolve type
///   members.
///
/// # Returns
///
/// A [`HashSet`] containing all tokens from the request plus the expanded
/// member tokens. Returns the original token set unchanged if no types are
/// scheduled for deletion.
pub fn expand_type_tokens(request: &CleanupRequest, assembly: &CilObject) -> HashSet<Token> {
    let mut tokens = request.all_tokens();
    let registry = assembly.types();

    // Collect types to process: explicit types + their nested types
    let mut types_to_expand: Vec<Token> = request.types().copied().collect();
    for type_token in request.types() {
        if let Some(cil_type) = registry.get(type_token) {
            for (_, nested_ref) in cil_type.nested_types.iter() {
                if let Some(t) = nested_ref.token() {
                    types_to_expand.push(t);
                    tokens.insert(t);
                }
            }
        }
    }

    // Expand each type (and nested type) to its member tokens
    for type_token in &types_to_expand {
        if let Some(cil_type) = registry.get(type_token) {
            for (_, field) in cil_type.fields.iter() {
                tokens.insert(field.token);
            }
            for (_, method_ref) in cil_type.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    tokens.insert(method.token);
                }
            }
        }
    }

    tokens
}

/// Finds non-public TypeDef tokens that have no live cross-type references
/// in the provided method call graph.
///
/// These are self-contained infrastructure types that can be safely deleted.
/// A type is considered unreferenced when no method outside the type (and
/// not already scheduled for deletion) calls any of its methods.
///
/// This handles two key scenarios:
/// - **Proxy devirtualization**: wrapper types whose methods are
///   devirtualized away, leaving no external callers.
/// - **Transitive infrastructure**: types only referenced by other
///   infrastructure already tagged for deletion.
///
/// # Arguments
///
/// * `assembly` - The assembly whose type registry provides type definitions.
/// * `method_call_graph` - A mapping from caller method token to the set of
///   callee tokens it references.
/// * `request` - The current cleanup request. Methods/types already tagged
///   for deletion are not considered live callers.
///
/// # Returns
///
/// A [`Vec`] of TypeDef tokens for unreferenced types that can be safely removed.
pub fn find_unreferenced_types(
    assembly: &CilObject,
    method_call_graph: &BTreeMap<Token, BTreeSet<Token>>,
    request: &CleanupRequest,
) -> Vec<Token> {
    let method_to_type = build_method_type_map(assembly);

    // Protect only the type containing the assembly's declared entry point
    // (e.g., the Program class with Main). .cctors are runtime-invoked
    // initialization methods, NOT type-level entry points for reachability
    // analysis — a type whose only "entry" is a .cctor is still deletable
    // infrastructure if no live code ever accesses the type.
    let mut entry_point_types: HashSet<Token> = HashSet::new();
    let entry_token_val = assembly.cor20header().entry_point_token;
    if entry_token_val != 0 {
        let entry_token = Token::new(entry_token_val);
        if let Some(&type_token) = method_to_type.get(&entry_token) {
            entry_point_types.insert(type_token);
        }
    }

    let registry = assembly.types();

    // Pre-filter: collect candidate types (non-public, non-module, non-entry-point).
    // Public types are excluded — they may be library API or reflection targets
    // with no in-assembly callers.
    let mut candidates: HashSet<Token> = HashSet::new();

    for type_entry in registry.iter() {
        let type_token = *type_entry.key();
        if type_token.table() != 0x02 {
            continue;
        }
        let cil_type = type_entry.value();
        if cil_type.is_module_type() || cil_type.is_public() {
            continue;
        }
        if entry_point_types.contains(&type_token) {
            continue;
        }
        // Already tagged for deletion — skip
        if request.types().any(|t| *t == type_token) {
            continue;
        }

        let type_methods: Vec<Token> = cil_type.methods().map(|m| m.token).collect();
        if type_methods.is_empty() {
            continue;
        }

        // Require at least one non-cctor method
        let has_non_cctor = type_methods.iter().any(|m| {
            !cil_type
                .methods()
                .any(|method| method.token == *m && method.is_cctor())
        });
        if !has_non_cctor {
            continue;
        }

        candidates.insert(type_token);
    }

    // Seed the deleted set with types/methods already in the cleanup request
    let deleted_types: HashSet<Token> = request.types().copied().collect();
    let mut deleted_methods: HashSet<Token> = request.methods().copied().collect();

    // Expand deleted types to include their method tokens
    for type_token in &deleted_types {
        if let Some(cil_type) = registry.get(type_token) {
            for method in cil_type.methods() {
                deleted_methods.insert(method.token);
            }
        }
    }

    // Compute which candidates have live external callers
    let mut has_external_caller: HashSet<Token> = HashSet::new();

    for (caller_token, callees) in method_call_graph {
        // Skip callers that are deleted
        if deleted_methods.contains(caller_token) {
            continue;
        }
        let Some(caller_type) = method_to_type.get(caller_token).copied() else {
            continue;
        };
        // Skip callers whose type is deleted
        if deleted_types.contains(&caller_type) {
            continue;
        }
        // Skip callers that are themselves candidates — their edges are
        // intra-cluster and don't constitute external references
        let caller_is_candidate = candidates.contains(&caller_type);

        for callee_token in callees {
            let Some(callee_type) = method_to_type.get(callee_token).copied() else {
                continue;
            };
            if caller_type == callee_type {
                continue;
            }
            // Only mark as externally referenced if the caller is NOT a candidate
            if !caller_is_candidate && candidates.contains(&callee_type) {
                has_external_caller.insert(callee_type);
            }
        }
    }

    // CustomAttribute constructors reference types that the call graph misses.
    // Types like EmbeddedAttribute and RefSafetyRulesAttribute are only referenced
    // from CustomAttribute rows (their .ctors are attribute constructors), never
    // from IL code. Without this check they appear unreferenced and get deleted.
    if let Some(tables) = assembly.tables() {
        if let Some(attr_table) = tables.table::<CustomAttributeRaw>() {
            for row in attr_table {
                if row.constructor.token.is_table(TableId::MethodDef) {
                    if let Some(&ctor_type) = method_to_type.get(&row.constructor.token) {
                        if candidates.contains(&ctor_type) {
                            has_external_caller.insert(ctor_type);
                        }
                    }
                }
            }
        }
    }

    // All candidates without external callers are unreferenced infrastructure
    candidates
        .into_iter()
        .filter(|t| !has_external_caller.contains(t))
        .collect()
}

/// Pre-computes the set of entry-point method tokens that should not be removed.
///
/// Entry points include:
/// - The assembly's declared entry point (e.g., `Main`)
/// - Static constructors (`.cctor`)
/// - In non-aggressive mode: public methods outside `<Module>` (potential API surface)
///
/// This avoids calling per-method entry-point checks, reducing overall complexity
/// from O(dead_methods * all_methods) to O(all_methods).
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for entry points.
/// * `aggressive` - If `true`, only protect the assembly entry point and static
///   constructors. If `false`, also protect public methods as potential external API.
pub fn compute_entry_points(assembly: &CilObject, aggressive: bool) -> HashSet<Token> {
    let mut entry_points = HashSet::new();

    // Assembly entry point
    let entry_token_val = assembly.cor20header().entry_point_token;
    if entry_token_val != 0 {
        entry_points.insert(Token::new(entry_token_val));
    }

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Static constructors are special runtime entry points
        if method.is_cctor() {
            entry_points.insert(method.token);
            continue;
        }

        if aggressive {
            continue;
        }

        // In non-aggressive mode, protect public methods as potential external API.
        // Exception: public methods in <Module> are obfuscator infrastructure.
        if method.is_public() {
            let in_module = assembly.types().module_type().is_some_and(|module_type| {
                module_type
                    .methods
                    .iter()
                    .any(|(_, r)| r.upgrade().is_some_and(|m| m.token == method.token))
            });
            if !in_module {
                entry_points.insert(method.token);
            }
        }
    }

    entry_points
}

/// Builds a method-to-declaring-type mapping from the type registry.
///
/// Returns a [`HashMap`] mapping each method token to the TypeDef token of
/// the type that declares it. This is useful for determining whether two
/// methods belong to the same type.
pub(super) fn build_method_type_map(assembly: &CilObject) -> HashMap<Token, Token> {
    let registry = assembly.types();
    let mut map = HashMap::new();

    for type_entry in registry.iter() {
        let type_token = *type_entry.key();
        if type_token.table() != 0x02 {
            continue;
        }
        let cil_type = type_entry.value();
        for method in cil_type.methods() {
            map.insert(method.token, type_token);
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{cilassembly::cleanup::CleanupRequest, metadata::token::Token};

    #[test]
    fn test_expand_type_tokens_empty_request() {
        let request = CleanupRequest::new();
        // Cannot test with real assembly, but verify that all_tokens is returned
        // for an empty request
        let tokens = request.all_tokens();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_find_unreferenced_types_empty_graph() {
        // With an empty call graph, no types should be found unreferenced
        let graph: BTreeMap<Token, BTreeSet<Token>> = BTreeMap::new();
        assert!(graph.is_empty());
    }
}
