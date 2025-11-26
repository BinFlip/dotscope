//! Dependency graph management for parallel metadata table loading.
//!
//! This module provides dependency tracking and execution planning for .NET metadata
//! table loaders. It enables efficient parallel loading by analyzing inter-table dependencies,
//! detecting cycles, and generating execution plans that maximize concurrency.
//!
//! # Core Components
//!
//! - [`LoaderGraph`]: Directed acyclic graph of loader dependencies
//! - [`LoaderKey`]: Identifier for table or special loaders
//!
//! # Loading Phases
//!
//! 1. **Level 0**: Independent tables (Assembly, Module, etc.)
//! 2. **Level 1-2**: Simple dependencies (TypeRef, MethodDef, etc.)
//! 3. **Level 3+**: Complex types (GenericParam, InterfaceImpl, etc.)
//! 4. **Final**: Cross-references (CustomAttribute, MethodSemantics)
//!
//! # Thread Safety
//!
//! - Construction: Single-threaded only
//! - Generated plans: Thread-safe for parallel execution
//!
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::{
    metadata::{loader::MetadataLoader, tables::TableId},
    Error::GraphError,
    Result,
};

/// Unique identifier for loaders in the dependency graph.
///
/// This enum distinguishes between regular table loaders and special cross-table loaders,
/// enabling the dependency graph to handle both types appropriately while maintaining
/// correct execution order and dependency relationships.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum LoaderKey {
    /// Regular loader that processes a specific metadata table
    Table(TableId),

    /// Special loader that operates across multiple tables
    ///
    /// Special loaders have unique properties:
    /// - Cannot be depended upon by other loaders
    /// - Run immediately when their dependencies are satisfied  
    /// - Execute before other loaders at the same dependency level
    Special {
        /// Sequence number for ordering multiple special loaders with same dependencies
        sequence: usize,
    },
}

/// A directed graph representing dependencies between metadata loaders.
///
/// Manages relationships between table loaders and special cross-table loaders,
/// enabling dependency analysis, cycle detection, and parallel execution planning.
///
/// # Lifecycle
///
/// 1. Create with `LoaderGraph::new()`
/// 2. Add loaders with `add_loader()`
/// 3. Build and validate with `build_relationships()`
/// 4. Generate execution plan with `topological_levels()`
///
/// # Thread Safety
///
/// Graph construction is single-threaded only. Generated execution plans are
/// thread-safe for coordinating parallel loader execution.
#[derive(Default)]
pub(crate) struct LoaderGraph<'a> {
    /// Maps a `LoaderKey` to its loader
    loaders: HashMap<LoaderKey, &'a dyn MetadataLoader>,
    /// Maps a `TableId` to the set of `LoaderKeys` that depend on it (reverse dependencies)
    dependents: HashMap<TableId, HashSet<LoaderKey>>,
    /// Maps a `LoaderKey` to the set of `TableIds` it depends on (forward dependencies)
    dependencies: HashMap<LoaderKey, HashSet<TableId>>,
    /// Counter for generating unique sequence numbers for special loaders
    special_counter: usize,
}

impl<'a> LoaderGraph<'a> {
    /// Creates a new empty loader graph.
    ///
    /// # Returns
    ///
    /// A new `LoaderGraph` with empty dependency mappings, ready for loader registration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a loader to the graph.
    ///
    /// The loader's key is determined by `table_id()` - returns `LoaderKey::Table` for
    /// regular loaders or `LoaderKey::Special` for cross-table loaders.
    /// Dependencies are not resolved until `build_relationships()` is called.
    ///
    /// # Arguments
    ///
    /// * `loader` - The metadata loader to register in the graph.
    pub fn add_loader(&mut self, loader: &'a dyn MetadataLoader) {
        let loader_key = if let Some(table_id) = loader.table_id() {
            LoaderKey::Table(table_id)
        } else {
            let key = LoaderKey::Special {
                sequence: self.special_counter,
            };
            self.special_counter += 1;
            key
        };

        self.loaders.insert(loader_key.clone(), loader);
        self.dependencies.entry(loader_key.clone()).or_default();

        // Only table loaders can be depended upon
        if let LoaderKey::Table(table_id) = loader_key {
            self.dependents.entry(table_id).or_default();
        }
    }

    /// Builds dependency relationships after all loaders have been added.
    ///
    /// Queries each loader for dependencies, validates all dependencies have loaders,
    /// and constructs bidirectional mappings. In debug builds, also performs cycle detection.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the dependency graph is valid and all relationships are built.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if a loader depends on a table without a registered loader,
    /// or if circular dependencies are detected (debug builds).
    pub fn build_relationships(&mut self) -> Result<()> {
        self.dependencies
            .values_mut()
            .for_each(std::collections::HashSet::clear);
        self.dependents
            .values_mut()
            .for_each(std::collections::HashSet::clear);

        for (loader_key, loader) in &self.loaders {
            for dep_table_id in loader.dependencies() {
                // Check if dependency is satisfied by any table loader
                let has_table_loader = self.loaders.keys().any(
                    |key| matches!(key, LoaderKey::Table(table_id) if table_id == dep_table_id),
                );

                if !has_table_loader {
                    return Err(GraphError(format!(
                        "Loader {:?} depends on table {:?}, but no loader for that table exists",
                        loader_key, dep_table_id
                    )));
                }

                // Add forward dependency (loader depends on table)
                self.dependencies
                    .get_mut(loader_key)
                    .ok_or_else(|| {
                        GraphError(format!(
                            "Internal error: loader {:?} not found in dependencies map",
                            loader_key
                        ))
                    })?
                    .insert(*dep_table_id);

                // Add reverse dependency (table has loader depending on it)
                self.dependents
                    .get_mut(dep_table_id)
                    .ok_or_else(|| {
                        GraphError(format!(
                            "Internal error: table {:?} not found in dependents map",
                            dep_table_id
                        ))
                    })?
                    .insert(loader_key.clone());
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

    /// Checks for circular dependencies using depth-first search with stack tracking.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the graph is acyclic.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if a circular dependency is detected.
    fn check_circular_dependencies(&self) -> Result<()> {
        // Note: Only need to check table loaders for cycles since special loaders
        // can only depend on tables but cannot be depended upon
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();

        for loader_key in self.loaders.keys() {
            if let LoaderKey::Table(table_id) = loader_key {
                if !visited.contains(table_id) {
                    self.detect_cycle(*table_id, &mut visited, &mut stack)?;
                }
            }
        }

        Ok(())
    }

    /// Recursive DFS helper for cycle detection.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID to start DFS traversal from.
    /// * `visited` - Set of all nodes visited during the entire cycle detection.
    /// * `stack` - Set of nodes currently in the DFS recursion stack.
    ///
    /// # Returns
    ///
    /// `Ok(())` if no cycle is reachable from this node.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if a back edge (cycle) is detected.
    fn detect_cycle(
        &self,
        table_id: TableId,
        visited: &mut HashSet<TableId>,
        stack: &mut HashSet<TableId>,
    ) -> Result<()> {
        visited.insert(table_id);
        stack.insert(table_id);

        let loader_key = LoaderKey::Table(table_id);
        if let Some(deps) = self.dependencies.get(&loader_key) {
            for &dep_id in deps {
                if !visited.contains(&dep_id) {
                    self.detect_cycle(dep_id, visited, stack)?;
                } else if stack.contains(&dep_id) {
                    return Err(GraphError(format!(
                        "Circular dependency detected involving table {dep_id:?}"
                    )));
                }
            }
        }

        stack.remove(&table_id);
        Ok(())
    }

    /// Returns loaders grouped by dependency level (topological sort).
    ///
    /// Computes execution levels where all loaders within a level can run in parallel.
    /// Level 0 contains independent loaders; level N contains loaders depending only on
    /// loaders from levels 0 through N-1.
    ///
    /// # Returns
    ///
    /// A vector of execution levels, where each level contains loaders that can run in parallel.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if circular dependencies prevent topological ordering.
    pub fn topological_levels(&self) -> Result<Vec<Vec<&'a dyn MetadataLoader>>> {
        let mut execution_levels = Vec::new();
        let mut unscheduled_loaders = self.loaders.keys().cloned().collect::<HashSet<_>>();
        let mut satisfied_dependencies = HashSet::new();

        while !unscheduled_loaders.is_empty() {
            // Phase 1: Find and schedule table loaders that are ready
            let ready_table_loaders =
                self.find_ready_loaders(&unscheduled_loaders, &satisfied_dependencies, |key| {
                    matches!(key, LoaderKey::Table(_))
                });

            let mut current_level = Vec::new();
            for loader_key in &ready_table_loaders {
                if let Some(loader) = self.loaders.get(loader_key) {
                    current_level.push(*loader);
                }
                unscheduled_loaders.remove(loader_key);

                // Mark this table as completed (special loaders can't be dependencies)
                if let LoaderKey::Table(table_id) = loader_key {
                    satisfied_dependencies.insert(*table_id);
                }
            }

            let table_progress = !current_level.is_empty();
            if table_progress {
                execution_levels.push(current_level);
            }

            // Phase 2: Find and schedule special loaders that are now ready
            let ready_special_loaders =
                self.find_ready_loaders(&unscheduled_loaders, &satisfied_dependencies, |key| {
                    matches!(key, LoaderKey::Special { .. })
                });

            let special_progress = !ready_special_loaders.is_empty();
            if special_progress {
                let mut special_level = Vec::new();
                for loader_key in &ready_special_loaders {
                    if let Some(loader) = self.loaders.get(loader_key) {
                        special_level.push(*loader);
                    }
                    unscheduled_loaders.remove(loader_key);
                }
                execution_levels.push(special_level);
            }

            // Check for deadlock: remaining loaders but no progress
            if !unscheduled_loaders.is_empty() && !table_progress && !special_progress {
                return Err(GraphError(
                    "Unable to resolve dependency order, possible circular dependency".to_string(),
                ));
            }
        }

        Ok(execution_levels)
    }

    /// Finds loaders that are ready to execute (all dependencies satisfied).
    ///
    /// # Arguments
    ///
    /// * `unscheduled` - Set of loaders not yet scheduled for execution.
    /// * `satisfied` - Set of table IDs whose loaders have completed.
    /// * `type_filter` - Predicate to filter loader types (table vs special).
    ///
    /// # Returns
    ///
    /// A vector of `LoaderKey`s for loaders whose dependencies are all satisfied.
    fn find_ready_loaders<F>(
        &self,
        unscheduled: &HashSet<LoaderKey>,
        satisfied: &HashSet<TableId>,
        type_filter: F,
    ) -> Vec<LoaderKey>
    where
        F: Fn(&LoaderKey) -> bool,
    {
        unscheduled
            .iter()
            .filter(|loader_key| {
                type_filter(loader_key)
                    && self
                        .dependencies
                        .get(loader_key)
                        .map(|deps| deps.iter().all(|dep| satisfied.contains(dep)))
                        .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Returns the execution plan as a formatted string for debugging.
    ///
    /// # Returns
    ///
    /// A formatted string showing each execution level and its loaders with dependencies.
    ///
    /// # Panics
    ///
    /// Panics if the graph is in an invalid state (should not happen after validation).
    pub fn dump_execution_plan(&self) -> String {
        // We unwrap, because this should only ever happen in debug builds here
        let levels = self.topological_levels().unwrap();
        let mut result = String::new();

        for (level_idx, level) in levels.iter().enumerate() {
            let _ = writeln!(result, "Level {level_idx}: [");
            for loader in level {
                // Find the LoaderKey for this loader
                let loader_key = self
                    .loaders
                    .iter()
                    .find(|(_, &l)| std::ptr::eq(*loader, l))
                    .map(|(key, _)| key)
                    .expect("Loader not found in graph");

                let deps = self.dependencies.get(loader_key).map_or_else(
                    || "None".to_string(),
                    |d| {
                        d.iter()
                            .map(|id| format!("{id:?}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                );

                let _ = writeln!(result, "  {loader_key:?} (depends on: {deps})");
            }
            let _ = writeln!(result, "]");
        }

        result
    }
}
