//! Loader Dependency Graph Module
//!
//! This module defines the [`LoaderGraph`] struct, which models the dependencies between metadata table loaders as a directed graph.
//! It provides methods for adding loaders, building dependency relationships, checking for cycles, and producing a topological execution plan for parallel loading.
//!
//! # Example
//! See the module-level docstring for a sample dependency graph and execution levels.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::{
    metadata::{loader::MetadataLoader, tables::TableId},
    Error::GraphError,
    Result,
};

/// A directed graph representing the dependencies between metadata loaders.
///
/// The `LoaderGraph` manages the relationships between all metadata table loaders, allowing for dependency analysis,
/// cycle detection, and parallel execution planning. Each loader is associated with a `TableId`, and dependencies are
/// tracked to ensure correct loading order.
///
/// ```rust, ignore
/// Level 0: [
///   Property (depends on: )
///   Field (depends on: )
///   AssemblyProcessor (depends on: )
///   AssemblyRef (depends on: )
///   Module (depends on: )
///   Param (depends on: )
///   Assembly (depends on: )
///   File (depends on: )
///   AssemblyOS (depends on: )
///   ModuleRef (depends on: )
/// ]
/// Level 1: [
///   TypeRef (depends on: AssemblyRef, ModuleRef)
///   FieldRVA (depends on: Field)
///   Constant (depends on: Property, Field, Param)
///   AssemblyRefProcessor (depends on: AssemblyRef)
///   AssemblyRefOS (depends on: AssemblyRef)
///   ExportedType (depends on: File, AssemblyRef)
///   ManifestResource (depends on: File, AssemblyRef)
///   FieldLayout (depends on: Field)
///   MethodDef (depends on: Param)
///   FieldMarshal (depends on: Param, Field)
/// ]
/// Level 2: [
///   TypeDef (depends on: MethodDef, Field)
/// ]
/// Level 3: [
///   ClassLayout (depends on: TypeDef)
///   TypeSpec (depends on: TypeRef, TypeDef)
///   DeclSecurity (depends on: TypeDef, MethodDef, Assembly)
/// ]
/// Level 4: [
///   Event (depends on: TypeRef, TypeSpec, TypeDef)
///   NestedClass (depends on: TypeSpec, TypeRef, TypeDef)
///   StandAloneSig (depends on: TypeDef, TypeSpec, MethodDef, TypeRef)
///   InterfaceImpl (depends on: TypeRef, TypeSpec, TypeDef)
///   PropertyMap (depends on: Property, TypeDef, TypeRef, TypeSpec)
///   MemberRef (depends on: TypeDef, MethodDef, TypeRef, TypeSpec, ModuleRef)
///   GenericParam (depends on: TypeSpec, MethodDef, TypeRef, TypeDef)
/// ]
/// Level 5: [
///   MethodImpl (depends on: MemberRef, TypeRef, TypeDef, MethodDef)
///   GenericParamConstraint (depends on: MemberRef, TypeRef, TypeSpec, MethodDef, GenericParam, TypeDef)
///   ImplMap (depends on: ModuleRef, Module, MemberRef, MethodDef)
///   MethodSpec (depends on: MemberRef, TypeDef, TypeSpec, MethodDef, TypeRef)
///   EventMap (depends on: Event)
/// ]
/// Level 6: [
///   CustomAttribute (depends on: TypeRef, Field, TypeDef, MemberRef, Param, InterfaceImpl, DeclSecurity, Property, TypeSpec, ExportedType, ManifestResource, AssemblyRef, MethodSpec, File, Event, ModuleRef, StandAloneSig, MethodDef, Module, GenericParamConstraint, GenericParam, Assembly)
///   MethodSemantics (depends on: PropertyMap, EventMap, Event, Property)
/// ]
/// ```
pub(crate) struct LoaderGraph<'a> {
    /// Maps a `TableId` to its loader
    loaders: HashMap<TableId, &'a dyn MetadataLoader>,
    /// Maps a `TableId` to the set of `TableIds` that depend on it
    dependents: HashMap<TableId, HashSet<TableId>>,
    /// Maps a `TableId` to the set of `TableIds` it depends on
    dependencies: HashMap<TableId, HashSet<TableId>>,
}

impl<'a> LoaderGraph<'a> {
    /// Create a new empty loader graph.
    pub fn new() -> Self {
        LoaderGraph {
            loaders: HashMap::new(),
            dependents: HashMap::new(),
            dependencies: HashMap::new(),
        }
    }

    /// Add a loader to the graph.
    ///
    /// # Arguments
    /// * `loader` - The loader to insert into the graph.
    pub fn add_loader(&mut self, loader: &'a dyn MetadataLoader) {
        let table_id = loader.table_id();
        self.loaders.insert(table_id, loader);

        self.dependents.entry(table_id).or_default();
        self.dependencies.entry(table_id).or_default();
    }

    /// Build the dependency relationships after all loaders have been added.
    ///
    /// # Errors
    /// Returns an error if a loader depends on a table for which no loader exists, or if a cycle is detected (in debug builds).
    pub fn build_relationships(&mut self) -> Result<()> {
        self.dependencies
            .values_mut()
            .for_each(std::collections::HashSet::clear);
        self.dependents
            .values_mut()
            .for_each(std::collections::HashSet::clear);

        for (table_id, loader) in &self.loaders {
            for dep_id in loader.dependencies() {
                if !self.loaders.contains_key(dep_id) {
                    return Err(GraphError(format!("Loader for table {:?} depends on table {:?}, but no loader for that table exists",
                        table_id,
                        dep_id
                    )));
                }

                self.dependencies.get_mut(table_id).unwrap().insert(*dep_id);
                self.dependents.get_mut(dep_id).unwrap().insert(*table_id);
            }
        }

        #[cfg(debug_assertions)]
        {
            // Only in debug builds, we check for circular dependencies and
            // generate the graph as string
            self.check_circular_dependencies()?;
            let _test = self.dump_execution_plan();
        }

        Ok(())
    }

    /// Check for circular dependencies in the graph.
    ///
    /// # Errors
    /// Returns an error if a cycle is detected.
    fn check_circular_dependencies(&self) -> Result<()> {
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();

        for &table_id in self.loaders.keys() {
            if !visited.contains(&table_id) {
                self.detect_cycle(table_id, &mut visited, &mut stack)?;
            }
        }

        Ok(())
    }

    /// Helper for circular dependency detection using recursion.
    fn detect_cycle(
        &self,
        table_id: TableId,
        visited: &mut HashSet<TableId>,
        stack: &mut HashSet<TableId>,
    ) -> Result<()> {
        visited.insert(table_id);
        stack.insert(table_id);

        if let Some(deps) = self.dependencies.get(&table_id) {
            for &dep_id in deps {
                if !visited.contains(&dep_id) {
                    self.detect_cycle(dep_id, visited, stack)?;
                } else if stack.contains(&dep_id) {
                    return Err(GraphError(format!(
                        "Circular dependency detected involving table {:?}",
                        dep_id
                    )));
                }
            }
        }

        stack.remove(&table_id);
        Ok(())
    }

    /// Get all loaders grouped by dependency level (topological sort).
    ///
    /// Returns a vector of vectors, where each inner vector contains loaders
    /// that can be executed in parallel at the same level.
    ///
    /// # Errors
    /// Returns an error if a valid topological order cannot be determined (e.g., due to cycles).
    pub fn topological_levels(&self) -> Result<Vec<Vec<&dyn MetadataLoader>>> {
        let mut result = Vec::new();
        let mut remaining = self.loaders.keys().copied().collect::<HashSet<_>>();

        while !remaining.is_empty() {
            let mut current_level = Vec::new();

            // Find all nodes with no dependencies within remaining set
            let ready_nodes = remaining
                .iter()
                .filter(|&table_id| {
                    if let Some(deps) = self.dependencies.get(table_id) {
                        deps.iter().all(|dep_id| !remaining.contains(dep_id))
                    } else {
                        true // No dependencies
                    }
                })
                .copied()
                .collect::<Vec<_>>();

            for table_id in &ready_nodes {
                if let Some(loader) = self.loaders.get(table_id) {
                    current_level.push(*loader);
                }
                remaining.remove(table_id);
            }

            if !current_level.is_empty() {
                result.push(current_level);
            } else if !remaining.is_empty() {
                return Err(GraphError(
                    "Unable to resolve dependency order, possible circular dependency".to_string(),
                ));
            }
        }

        Ok(result)
    }

    /// Dump the execution plan as a formatted string for debugging.
    ///
    /// Returns a string representation of the loader execution levels and their dependencies.
    pub fn dump_execution_plan(&self) -> String {
        // We unwrap, because this should only ever happen in debug builds here
        let levels = self.topological_levels().unwrap();
        let mut result = String::new();

        for (level_idx, level) in levels.iter().enumerate() {
            result.push_str("Level ");
            result.push_str(&level_idx.to_string());
            result.push_str(": [\n");
            for loader in level {
                let table_id = loader.table_id();
                let deps = self.dependencies.get(&table_id).map_or_else(
                    || "None".to_string(),
                    |d| {
                        d.iter()
                            .map(|id| format!("{:?}", id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                );

                result.push_str("  ");
                write!(result, "{table_id:?}").unwrap();
                result.push_str(" (depends on: ");
                result.push_str(&deps);
                result.push_str(")\n");
            }
            result.push_str("]\n");
        }

        result
    }
}
