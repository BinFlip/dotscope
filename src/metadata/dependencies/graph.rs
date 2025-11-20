//! Assembly dependency graph implementation with cycle detection and topological sorting.
//!
//! This module provides the core dependency graph data structure that tracks relationships
//! between assemblies, detects circular dependencies, and generates optimal loading orders
//! for multi-assembly scenarios.

use std::collections::{hash_map::Entry, HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

use dashmap::DashMap;

use crate::{
    metadata::{dependencies::AssemblyDependency, identity::AssemblyIdentity},
    Error, Result,
};

/// Helper struct to group Tarjan's algorithm state and reduce function argument count
struct TarjanState {
    index_counter: usize,
    stack: Vec<AssemblyIdentity>,
    indices: HashMap<AssemblyIdentity, usize>,
    lowlinks: HashMap<AssemblyIdentity, usize>,
    on_stack: HashMap<AssemblyIdentity, bool>,
    sccs: Vec<Vec<AssemblyIdentity>>,
}

impl TarjanState {
    fn new() -> Self {
        Self {
            index_counter: 0,
            stack: Vec::new(),
            indices: HashMap::new(),
            lowlinks: HashMap::new(),
            on_stack: HashMap::new(),
            sccs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Color {
    White, // Unvisited
    Gray,  // Currently being processed
    Black, // Completely processed
}

/// Thread-safe dependency graph for tracking inter-assembly relationships.
///
/// This structure maintains a complete picture of assembly dependencies, enabling
/// cycle detection, topological sorting, and dependency analysis for multi-assembly
/// projects. It's designed for concurrent access and can be safely shared across
/// multiple threads during assembly loading and analysis.
///
/// # Architecture
///
/// The dependency graph uses several complementary data structures:
/// - **Dependencies**: Forward edges (A depends on B)
/// - **Dependents**: Reverse edges (B is depended on by A)  
/// - **Cached Results**: Topological order and cycle detection results
/// - **Thread Safety**: All operations are thread-safe with minimal locking
///
/// # Usage Patterns
///
/// ## Basic Dependency Tracking
///
/// ```rust,ignore
/// use dotscope::metadata::dependencies::{AssemblyDependencyGraph, AssemblyDependency};
///
/// let mut graph = AssemblyDependencyGraph::new();
///
/// // Add dependencies as they're discovered during metadata loading
/// graph.add_dependency(dependency1)?;
/// graph.add_dependency(dependency2)?;
///
/// // Check for circular dependencies
/// if let Some(cycle) = graph.find_cycles()? {
///     eprintln!("Circular dependency detected: {:?}", cycle);
/// }
/// ```
///
/// ## Loading Order Generation  
///
/// ```rust,ignore
/// // Generate optimal loading order
/// let load_order = graph.topological_order()?;
/// for identity in load_order {
///     println!("Load assembly: {}", identity.display_name());
/// }
/// ```
///
/// # Performance Characteristics
///
/// - **Add Dependency**: O(1) average case with hash maps
/// - **Cycle Detection**: O(V + E) using DFS-based algorithms  
/// - **Topological Sort**: O(V + E) using SCC-based approach with Tarjan's algorithm
/// - **Memory Usage**: O(V + E) where V = assemblies, E = dependencies
/// - **Concurrency**: Lock-free for reads, minimal locking for writes
///
/// # Thread Safety
///
/// All public methods are thread-safe and can be called concurrently:
/// - **DashMap**: Provides lock-free concurrent hash map operations
/// - **RwLock**: Protects cached results with reader-writer semantics
/// - **Arc**: Enables safe sharing across thread boundaries
/// - **Atomic Operations**: State updates are atomic where possible
pub struct AssemblyDependencyGraph {
    /// Forward dependency mapping: assembly -> [dependencies]
    ///
    /// Maps each assembly to the list of assemblies it depends on.
    /// This is the primary data structure for dependency traversal.
    dependencies: Arc<DashMap<AssemblyIdentity, Vec<AssemblyDependency>>>,

    /// Reverse dependency mapping: assembly -> [dependents]  
    ///
    /// Maps each assembly to the list of assemblies that depend on it.
    /// This enables efficient "reverse lookup" queries and validation.
    dependents: Arc<DashMap<AssemblyIdentity, Vec<AssemblyIdentity>>>,

    /// Cached topological ordering result
    ///
    /// Caches the result of topological sorting to avoid recomputation.
    /// Invalidated when new dependencies are added to the graph.
    cached_topology: Arc<RwLock<Option<Vec<AssemblyIdentity>>>>,

    /// Cached cycle detection result
    ///
    /// Caches the result of cycle detection to avoid recomputation.
    /// Invalidated when new dependencies are added to the graph.
    ///
    /// `None` = not yet computed, `Some(vec)` = computed (empty vec means no cycles)
    cached_cycles: Arc<RwLock<Option<Vec<AssemblyIdentity>>>>,
}

impl AssemblyDependencyGraph {
    /// Create a new empty dependency graph.
    ///
    /// Initializes all internal data structures for optimal performance
    /// with expected assembly counts. The graph will automatically resize
    /// as assemblies are added.
    ///
    /// # Returns
    /// A new empty dependency graph ready for use
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// assert_eq!(graph.assembly_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            dependencies: Arc::new(DashMap::new()),
            dependents: Arc::new(DashMap::new()),
            cached_topology: Arc::new(RwLock::new(None)),
            cached_cycles: Arc::new(RwLock::new(None)),
        }
    }

    /// Get all dependencies for a specific assembly.
    ///
    /// Returns a list of all assemblies that the specified assembly depends on.
    /// This includes both direct and the metadata about the dependency relationships.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to query dependencies for
    ///
    /// # Returns
    /// Vector of dependencies for the specified assembly (empty if none)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::dependencies::{AssemblyDependencyGraph, AssemblyIdentity};
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// let identity = AssemblyIdentity::parse("MyApp, Version=1.0.0.0")?;
    /// let deps = graph.get_dependencies(&identity);
    /// println!("MyApp depends on {} assemblies", deps.len());
    /// # Ok::<(), String>(())
    /// ```
    #[must_use]
    pub fn get_dependencies(&self, assembly: &AssemblyIdentity) -> Vec<AssemblyDependency> {
        self.dependencies
            .get(assembly)
            .map(|deps| deps.clone())
            .unwrap_or_default()
    }

    /// Get all assemblies that depend on the specified assembly.
    ///
    /// Returns a list of all assemblies that have declared a dependency on
    /// the specified assembly. This is the reverse lookup of dependencies.
    ///
    /// # Arguments
    /// * `assembly` - The assembly to query dependents for
    ///
    /// # Returns
    /// Vector of assembly identities that depend on the specified assembly
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let dependents = graph.get_dependents(&mscorlib_identity);
    /// println!("{} assemblies depend on mscorlib", dependents.len());
    /// ```
    #[must_use]
    pub fn get_dependents(&self, assembly: &AssemblyIdentity) -> Vec<AssemblyIdentity> {
        self.dependents
            .get(assembly)
            .map(|deps| deps.clone())
            .unwrap_or_default()
    }

    /// Get the total number of assemblies in the dependency graph.
    ///
    /// Counts the unique assemblies that are either sources or targets
    /// of dependency relationships in the graph.
    ///
    /// # Returns
    /// Total number of unique assemblies tracked in the graph
    #[must_use]
    pub fn assembly_count(&self) -> usize {
        let mut assemblies = HashSet::new();

        // Add all source assemblies
        for entry in self.dependencies.iter() {
            assemblies.insert(entry.key().clone());
        }

        // Add all target assemblies
        for entry in self.dependents.iter() {
            assemblies.insert(entry.key().clone());
        }

        assemblies.len()
    }

    /// Get the total number of dependency relationships in the graph.
    ///
    /// Counts the total number of dependency edges in the graph,
    /// providing insight into the complexity of the dependency structure.
    ///
    /// # Returns
    /// Total number of dependency relationships
    #[must_use]
    pub fn dependency_count(&self) -> usize {
        self.dependencies
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    /// Detect circular dependencies in the assembly graph.
    ///
    /// Uses a depth-first search algorithm to detect cycles in the dependency
    /// graph. Returns the first cycle found, or None if the graph is acyclic.
    /// Results are cached to improve performance on repeated calls.
    ///
    /// # Returns
    /// * `Ok(Some(cycle))` - Circular dependency found, returns the cycle path
    /// * `Ok(None)` - No circular dependencies detected
    /// * `Err(_)` - Error occurred during cycle detection
    ///
    /// # Algorithm
    /// Uses a modified DFS with three-color marking:
    /// - **White**: Unvisited nodes
    /// - **Gray**: Currently being processed (in recursion stack)  
    /// - **Black**: Completely processed
    ///
    /// A back edge from gray to gray indicates a cycle.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// if let Some(cycle) = graph.find_cycles()? {
    ///     eprintln!("Circular dependency: {:?}", cycle);
    ///     for assembly in cycle {
    ///         eprintln!("  -> {}", assembly.display_name());
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if cycle detection fails or if locking fails.
    pub fn find_cycles(&self) -> Result<Option<Vec<AssemblyIdentity>>> {
        // Check cache first
        {
            let cached = self
                .cached_cycles
                .read()
                .map_err(|_| Error::Error("Failed to acquire cycle cache lock".to_string()))?;
            if let Some(result) = cached.as_ref() {
                // Empty vec means no cycles, non-empty means cycles found
                return Ok(if result.is_empty() {
                    None
                } else {
                    Some(result.clone())
                });
            }
        }

        // Perform cycle detection
        let result = self.detect_cycles_dfs()?;

        // Cache result (store empty vec for no cycles, actual vec for cycles)
        {
            let mut cache = self.cached_cycles.write().map_err(|_| {
                Error::Error("Failed to acquire cycle cache lock for write".to_string())
            })?;
            *cache = Some(result.clone().unwrap_or_default());
        }

        Ok(result)
    }

    /// Generate a topological ordering of assemblies for loading.
    ///
    /// Uses a Strongly Connected Components (SCC) based approach to generate a valid
    /// loading order that can handle circular dependencies. Dependencies within the same
    /// SCC are grouped together, and SCCs are ordered topologically.
    ///
    /// # Returns
    /// * `Ok(order)` - Valid loading order, handling cycles through SCC grouping
    /// * `Err(_)` - Critical error occurred during ordering computation
    ///
    /// # Algorithm
    /// Implements SCC-based topological sorting:
    /// 1. Use Tarjan's algorithm to find all strongly connected components
    /// 2. Build a DAG of SCCs (condensation graph)
    /// 3. Topologically sort the SCC DAG using Kahn's algorithm
    /// 4. Flatten SCCs into a single assembly loading order
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let load_order = graph.topological_order()?;
    /// for (index, assembly) in load_order.iter().enumerate() {
    ///     println!("Load order {}: {}", index + 1, assembly.display_name());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if topological sorting fails or if the graph contains cycles.
    pub fn topological_order(&self) -> Result<Vec<AssemblyIdentity>> {
        // Check cache first
        {
            let cached = self
                .cached_topology
                .read()
                .map_err(|_| Error::Error("Failed to acquire topology cache lock".to_string()))?;
            if let Some(result) = cached.as_ref() {
                return Ok(result.clone());
            }
        }

        // Use SCC-based approach to handle circular dependencies
        let result = self.scc_based_order()?;

        // Cache result
        {
            let mut cache = self.cached_topology.write().map_err(|_| {
                Error::Error("Failed to acquire topology cache lock for write".to_string())
            })?;
            *cache = Some(result.clone());
        }

        Ok(result)
    }

    /// Generate loading order using Strongly Connected Components to handle circular dependencies.
    ///
    /// This approach uses Tarjan's algorithm to find SCCs and orders them topologically.
    /// Within each SCC, assemblies are ordered by priority heuristics (core assemblies first).
    fn scc_based_order(&self) -> Result<Vec<AssemblyIdentity>> {
        // Build adjacency list representation
        let mut adj_list: HashMap<AssemblyIdentity, Vec<AssemblyIdentity>> = HashMap::new();
        let mut all_nodes: HashSet<AssemblyIdentity> = HashSet::new();

        for entry in self.dependencies.iter() {
            let source = entry.key().clone();
            all_nodes.insert(source.clone());

            let targets: Vec<AssemblyIdentity> = entry
                .value()
                .iter()
                .map(|dep| dep.target_identity.clone())
                .collect();

            for target in &targets {
                all_nodes.insert(target.clone());
            }

            // Group all targets for this source and deduplicate
            let adj_entry = adj_list.entry(source).or_default();
            for target in targets {
                if !adj_entry.contains(&target) {
                    adj_entry.push(target);
                }
            }
        }

        // Ensure all nodes have an entry (even if no outgoing edges)
        for node in &all_nodes {
            adj_list.entry(node.clone()).or_default();
        }

        // Find SCCs using Tarjan's algorithm
        let sccs = Self::tarjan_scc(&adj_list)?;

        // Build SCC graph (DAG of SCCs)
        let scc_graph = Self::build_scc_graph(&sccs, &adj_list);

        // Topologically sort SCCs
        let scc_order = Self::topological_sort_sccs(&scc_graph);

        // Flatten SCCs into assembly order
        let mut result = Vec::new();
        for scc_id in scc_order {
            let scc_assemblies = &sccs[scc_id];
            result.extend(scc_assemblies.iter().cloned());
        }

        Ok(result)
    }

    /// Tarjan's algorithm for finding strongly connected components
    fn tarjan_scc(
        adj_list: &HashMap<AssemblyIdentity, Vec<AssemblyIdentity>>,
    ) -> Result<Vec<Vec<AssemblyIdentity>>> {
        let mut state = TarjanState::new();

        for node in adj_list.keys() {
            if !state.indices.contains_key(node) {
                Self::tarjan_strongconnect(node, adj_list, &mut state)?;
            }
        }

        Ok(state.sccs)
    }

    /// Recursive helper for Tarjan's algorithm
    fn tarjan_strongconnect(
        node: &AssemblyIdentity,
        adj_list: &HashMap<AssemblyIdentity, Vec<AssemblyIdentity>>,
        state: &mut TarjanState,
    ) -> Result<()> {
        // Set the depth index for this node
        state.indices.insert(node.clone(), state.index_counter);
        state.lowlinks.insert(node.clone(), state.index_counter);
        state.index_counter += 1;
        state.stack.push(node.clone());
        state.on_stack.insert(node.clone(), true);

        // Consider successors of node
        if let Some(successors) = adj_list.get(node) {
            for successor in successors {
                if !state.indices.contains_key(successor) {
                    // Successor has not yet been visited; recurse on it
                    Self::tarjan_strongconnect(successor, adj_list, state)?;
                    let successor_lowlink = state.lowlinks[successor];
                    let node_lowlink = state.lowlinks[node];
                    state
                        .lowlinks
                        .insert(node.clone(), node_lowlink.min(successor_lowlink));
                } else if *state.on_stack.get(successor).unwrap_or(&false) {
                    // Successor is in stack and hence in the current SCC
                    let successor_index = state.indices[successor];
                    let node_lowlink = state.lowlinks[node];
                    state
                        .lowlinks
                        .insert(node.clone(), node_lowlink.min(successor_index));
                }
            }
        }

        // If node is a root node, pop the stack and create an SCC
        if state.lowlinks[node] == state.indices[node] {
            let mut scc = Vec::new();
            loop {
                let w = state.stack.pop().ok_or_else(|| {
                    Error::Error("Stack underflow in Tarjan's algorithm".to_string())
                })?;
                state.on_stack.insert(w.clone(), false);
                scc.push(w.clone());
                if w == *node {
                    break;
                }
            }
            state.sccs.push(scc);
        }

        Ok(())
    }

    /// Build a DAG of SCCs from the individual SCCs
    fn build_scc_graph(
        sccs: &[Vec<AssemblyIdentity>],
        adj_list: &HashMap<AssemblyIdentity, Vec<AssemblyIdentity>>,
    ) -> HashMap<usize, Vec<usize>> {
        // Map each assembly to its SCC index
        let mut assembly_to_scc: HashMap<AssemblyIdentity, usize> = HashMap::new();
        for (scc_id, scc) in sccs.iter().enumerate() {
            for assembly in scc {
                assembly_to_scc.insert(assembly.clone(), scc_id);
            }
        }

        // Initialize all SCCs in the graph (even those with no outgoing edges)
        let mut scc_graph: HashMap<usize, HashSet<usize>> = HashMap::new();
        for scc_id in 0..sccs.len() {
            scc_graph.insert(scc_id, HashSet::new());
        }

        // Build SCC adjacency list
        // Note: For topological ordering, we want reverse dependencies (target -> source)
        // because we need to load dependencies before dependents
        for (source, targets) in adj_list {
            if let Some(&source_scc) = assembly_to_scc.get(source) {
                for target in targets {
                    if let Some(&target_scc) = assembly_to_scc.get(target) {
                        if source_scc != target_scc {
                            // target_scc should come before source_scc in loading order
                            scc_graph.entry(target_scc).or_default().insert(source_scc);
                        }
                    }
                }
            }
        }

        // Convert to Vec representation
        scc_graph
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect()
    }

    /// Topologically sort SCCs (which form a DAG)
    fn topological_sort_sccs(scc_graph: &HashMap<usize, Vec<usize>>) -> Vec<usize> {
        // All SCC IDs are the keys in scc_graph
        let all_scc_ids: Vec<usize> = scc_graph.keys().copied().collect();

        // Calculate in-degrees
        let mut in_degrees: HashMap<usize, usize> = HashMap::new();
        for &scc_id in &all_scc_ids {
            in_degrees.insert(scc_id, 0);
        }

        for targets in scc_graph.values() {
            for &target in targets {
                *in_degrees.entry(target).or_insert(0) += 1;
            }
        }

        // Apply Kahn's algorithm to the SCC DAG (which is guaranteed to be acyclic)
        let mut queue: VecDeque<usize> = VecDeque::new();
        for (&scc_id, &degree) in &in_degrees {
            if degree == 0 {
                queue.push_back(scc_id);
            }
        }

        let mut result = Vec::new();
        while let Some(scc_id) = queue.pop_front() {
            result.push(scc_id);

            if let Some(targets) = scc_graph.get(&scc_id) {
                for &target in targets {
                    if let Some(degree) = in_degrees.get_mut(&target) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(target);
                        }
                    }
                }
            }
        }

        result
    }

    /// Check if the dependency graph is empty.
    ///
    /// Returns true if no dependency relationships have been added to the graph.
    ///
    /// # Returns
    /// `true` if the graph contains no dependencies, `false` otherwise
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty() && self.dependents.is_empty()
    }

    /// Clear all dependencies from the graph.
    ///
    /// Removes all dependency relationships and resets the graph to an empty state.
    /// This operation is thread-safe and will invalidate all cached results.
    pub fn clear(&self) {
        self.dependencies.clear();
        self.dependents.clear();
        self.invalidate_caches();
    }

    /// Add a dependency relationship with explicit source identity.
    ///
    /// Records a dependency relationship where the source assembly identity
    /// is explicitly provided, avoiding the need for identity extraction.
    /// This is the preferred method for adding dependencies.
    ///
    /// # Arguments
    /// * `source_identity` - The identity of the source assembly
    /// * `dependency` - The dependency relationship to add
    ///
    /// # Returns
    /// * `Ok(())` - Dependency added successfully
    /// * `Err(_)` - Error occurred during dependency addition
    ///
    /// # Errors
    /// Returns an error if the dependency cannot be added.
    pub fn add_dependency_with_source(
        &self,
        source_identity: AssemblyIdentity,
        dependency: AssemblyDependency,
    ) -> Result<()> {
        let target_identity = dependency.target_identity.clone();

        // Add forward dependency (source depends on target)
        self.dependencies
            .entry(source_identity.clone())
            .or_default()
            .push(dependency);

        // Add reverse dependency (target is depended on by source)
        self.dependents
            .entry(target_identity)
            .or_default()
            .push(source_identity);

        // Invalidate cached results
        self.invalidate_caches();

        Ok(())
    }

    /// Invalidate all cached results.
    ///
    /// Called when the dependency graph is modified to ensure cached
    /// results are recalculated on next access.
    fn invalidate_caches(&self) {
        // Best effort invalidation - ignore lock failures
        if let Ok(mut cache) = self.cached_topology.write() {
            *cache = None;
        }
        if let Ok(mut cache) = self.cached_cycles.write() {
            *cache = None;
        }
    }

    /// Perform cycle detection using depth-first search.
    ///
    /// Implements a three-color DFS algorithm to detect cycles in the
    /// dependency graph. Returns the first cycle found.
    fn detect_cycles_dfs(&self) -> Result<Option<Vec<AssemblyIdentity>>> {
        let mut colors: HashMap<AssemblyIdentity, Color> = HashMap::new();
        let mut path: Vec<AssemblyIdentity> = Vec::new();

        // Initialize all nodes as white
        for entry in self.dependencies.iter() {
            colors.insert(entry.key().clone(), Color::White);
        }

        // Visit all white nodes
        for entry in self.dependencies.iter() {
            let node = entry.key().clone();
            if colors.get(&node) == Some(&Color::White) {
                if let Some(cycle) = self.dfs_visit(&node, &mut colors, &mut path)? {
                    return Ok(Some(cycle));
                }
            }
        }

        Ok(None)
    }

    /// Recursive DFS visit for cycle detection.
    ///
    /// Performs the recursive traversal for cycle detection, maintaining
    /// the current path and node colors.
    fn dfs_visit(
        &self,
        node: &AssemblyIdentity,
        colors: &mut HashMap<AssemblyIdentity, Color>,
        path: &mut Vec<AssemblyIdentity>,
    ) -> Result<Option<Vec<AssemblyIdentity>>> {
        colors.insert(node.clone(), Color::Gray);
        path.push(node.clone());

        // Visit all dependencies
        if let Some(deps) = self.dependencies.get(node) {
            for dependency in deps.iter() {
                let target = &dependency.target_identity;

                match colors.entry(target.clone()) {
                    Entry::Occupied(mut entry) => {
                        match entry.get() {
                            Color::Gray => {
                                // Found a cycle - extract the cycle path
                                if let Some(start_idx) = path.iter().position(|id| id == target) {
                                    let mut cycle = path[start_idx..].to_vec();
                                    cycle.push(target.clone()); // Complete the cycle
                                    return Ok(Some(cycle));
                                }
                            }
                            Color::White => {
                                entry.insert(Color::White); // Keep as white for recursion
                                if let Some(cycle) = self.dfs_visit(target, colors, path)? {
                                    return Ok(Some(cycle));
                                }
                            }
                            Color::Black => {
                                // Already processed, safe to ignore
                            }
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Color::White);
                        if let Some(cycle) = self.dfs_visit(target, colors, path)? {
                            return Ok(Some(cycle));
                        }
                    }
                }
            }
        }

        colors.insert(node.clone(), Color::Black);
        path.pop();
        Ok(None)
    }

    /// Check if the graph contains a specific assembly identity.
    ///
    /// This is useful for CilProject scenarios where you need to verify if an
    /// assembly is already tracked in the dependency graph before adding it.
    ///
    /// # Arguments
    ///
    /// * `identity` - The assembly identity to check for
    ///
    /// # Returns
    ///
    /// `true` if the assembly is present in the graph, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let graph = AssemblyDependencyGraph::new();
    /// let identity = AssemblyIdentity::parse("MyLib, Version=1.0.0.0")?;
    ///
    /// if !graph.contains_assembly(&identity) {
    ///     // Add assembly to graph
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn contains_assembly(&self, identity: &AssemblyIdentity) -> bool {
        self.dependencies.contains_key(identity)
    }

    /// Get all assembly identities currently tracked in the graph.
    ///
    /// Returns a vector containing all assembly identities that have been
    /// added to the dependency graph. This is useful for CilProject scenarios
    /// where you need to enumerate all known assemblies.
    ///
    /// # Returns
    ///
    /// Vector of all assembly identities in the graph.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let graph = AssemblyDependencyGraph::new();
    /// // ... add assemblies to graph ...
    ///
    /// for identity in graph.all_assemblies() {
    ///     println!("Assembly: {}", identity.display_name());
    /// }
    /// ```
    #[must_use]
    pub fn all_assemblies(&self) -> Vec<AssemblyIdentity> {
        self.dependencies
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if an assembly has any dependencies.
    ///
    /// Returns `true` if the specified assembly has at least one dependency,
    /// `false` if it has no dependencies or is not in the graph.
    ///
    /// # Arguments
    ///
    /// * `identity` - The assembly identity to check
    ///
    /// # Returns
    ///
    /// `true` if the assembly has dependencies, `false` otherwise.
    #[must_use]
    pub fn has_dependencies(&self, identity: &AssemblyIdentity) -> bool {
        self.dependencies
            .get(identity)
            .is_some_and(|deps| !deps.is_empty())
    }

    /// Check if an assembly has any dependents (other assemblies that depend on it).
    ///
    /// Returns `true` if other assemblies depend on the specified assembly,
    /// `false` if no assemblies depend on it or it's not in the graph.
    ///
    /// # Arguments
    ///
    /// * `identity` - The assembly identity to check
    ///
    /// # Returns
    ///
    /// `true` if the assembly has dependents, `false` otherwise.
    #[must_use]
    pub fn has_dependents(&self, identity: &AssemblyIdentity) -> bool {
        self.dependents
            .get(identity)
            .is_some_and(|deps| !deps.is_empty())
    }
}

impl Default for AssemblyDependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::dependencies::DependencyType,
        test::helpers::dependencies::{create_test_dependency, create_test_identity},
    };
    use std::thread;

    #[test]
    fn test_dependency_graph_creation() {
        let graph = AssemblyDependencyGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.assembly_count(), 0);
        assert_eq!(graph.dependency_count(), 0);
    }

    #[test]
    fn test_dependency_graph_add_dependency() {
        let graph = AssemblyDependencyGraph::new();
        let source = create_test_identity("App", 1, 0);
        let dependency = create_test_dependency("mscorlib", DependencyType::Reference);

        graph
            .add_dependency_with_source(source.clone(), dependency)
            .unwrap();

        assert!(!graph.is_empty());
        assert_eq!(graph.assembly_count(), 2); // App and mscorlib
        assert_eq!(graph.dependency_count(), 1);

        let deps = graph.get_dependencies(&source);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].target_identity.name, "mscorlib");
    }

    #[test]
    fn test_dependency_graph_reverse_lookup() {
        let graph = AssemblyDependencyGraph::new();
        let app = create_test_identity("App", 1, 0);
        let mscorlib = create_test_identity("mscorlib", 1, 0); // Match the version from create_test_dependency
        let dependency = create_test_dependency("mscorlib", DependencyType::Reference);

        graph
            .add_dependency_with_source(app.clone(), dependency)
            .unwrap();

        let dependents = graph.get_dependents(&mscorlib);
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0].name, "App");
    }

    #[test]
    fn test_dependency_graph_multiple_dependencies() {
        let graph = AssemblyDependencyGraph::new();
        let app = create_test_identity("App", 1, 0);

        let mscorlib_dep = create_test_dependency("mscorlib", DependencyType::Reference);
        let system_dep = create_test_dependency("System", DependencyType::Reference);
        let system_core_dep = create_test_dependency("System.Core", DependencyType::Reference);

        graph
            .add_dependency_with_source(app.clone(), mscorlib_dep)
            .unwrap();
        graph
            .add_dependency_with_source(app.clone(), system_dep)
            .unwrap();
        graph
            .add_dependency_with_source(app.clone(), system_core_dep)
            .unwrap();

        assert_eq!(graph.assembly_count(), 4); // App + 3 dependencies
        assert_eq!(graph.dependency_count(), 3);

        let deps = graph.get_dependencies(&app);
        assert_eq!(deps.len(), 3);

        let dep_names: Vec<String> = deps
            .iter()
            .map(|d| d.target_identity.name.clone())
            .collect();
        assert!(dep_names.contains(&"mscorlib".to_string()));
        assert!(dep_names.contains(&"System".to_string()));
        assert!(dep_names.contains(&"System.Core".to_string()));
    }

    #[test]
    fn test_dependency_graph_no_cycles_simple() {
        let graph = AssemblyDependencyGraph::new();
        let app = create_test_identity("App", 1, 0);
        let mscorlib_dep = create_test_dependency("mscorlib", DependencyType::Reference);

        graph.add_dependency_with_source(app, mscorlib_dep).unwrap();

        let cycles = graph.find_cycles().unwrap();
        assert!(cycles.is_none());
    }

    #[test]
    fn test_dependency_graph_cycle_detection() {
        let graph = AssemblyDependencyGraph::new();

        // Create A -> B -> C -> A cycle
        let a = create_test_identity("A", 1, 0);
        let b = create_test_identity("B", 1, 0);
        let c = create_test_identity("C", 1, 0);

        let b_dep = create_test_dependency("B", DependencyType::Reference);
        let c_dep = create_test_dependency("C", DependencyType::Reference);
        let a_dep = create_test_dependency("A", DependencyType::Reference);

        graph.add_dependency_with_source(a, b_dep).unwrap();
        graph.add_dependency_with_source(b, c_dep).unwrap();
        graph.add_dependency_with_source(c, a_dep).unwrap();

        let cycles = graph.find_cycles().unwrap();
        assert!(cycles.is_some());

        let cycle = cycles.unwrap();
        assert!(cycle.len() >= 3);
    }

    #[test]
    fn test_dependency_graph_self_cycle() {
        let graph = AssemblyDependencyGraph::new();
        let a = create_test_identity("A", 1, 0);
        let self_dep = create_test_dependency("A", DependencyType::Reference);

        graph.add_dependency_with_source(a, self_dep).unwrap();

        let cycles = graph.find_cycles().unwrap();
        assert!(cycles.is_some());

        let cycle = cycles.unwrap();
        assert_eq!(cycle.len(), 2); // A -> A
        assert_eq!(cycle[0].name, "A");
        assert_eq!(cycle[1].name, "A");
    }

    #[test]
    fn test_topological_sort_simple() {
        let graph = AssemblyDependencyGraph::new();
        let app = create_test_identity("App", 1, 0);
        let lib = create_test_identity("Lib", 1, 0);
        let _mscorlib = create_test_identity("mscorlib", 1, 0); // Match dependency version

        // App -> Lib -> mscorlib
        let lib_dep = create_test_dependency("Lib", DependencyType::Reference);
        let mscorlib_dep = create_test_dependency("mscorlib", DependencyType::Reference);

        graph
            .add_dependency_with_source(app.clone(), lib_dep)
            .unwrap();
        graph
            .add_dependency_with_source(lib.clone(), mscorlib_dep)
            .unwrap();

        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 3);

        // mscorlib should come before Lib, Lib before App
        let mscorlib_pos = order.iter().position(|id| id.name == "mscorlib").unwrap();
        let lib_pos = order.iter().position(|id| id.name == "Lib").unwrap();
        let app_pos = order.iter().position(|id| id.name == "App").unwrap();

        assert!(mscorlib_pos < lib_pos);
        assert!(lib_pos < app_pos);
    }

    #[test]
    fn test_topological_sort_with_cycle() {
        let graph = AssemblyDependencyGraph::new();
        let a = create_test_identity("A", 1, 0);
        let b = create_test_identity("B", 1, 0);

        // Create A -> B -> A cycle
        let b_dep = create_test_dependency("B", DependencyType::Reference);
        let a_dep = create_test_dependency("A", DependencyType::Reference);

        graph.add_dependency_with_source(a, b_dep).unwrap();
        graph.add_dependency_with_source(b, a_dep).unwrap();

        let result = graph.topological_order();
        assert!(result.is_ok());

        // SCC-based approach should succeed even with cycles
        let order = result.unwrap();
        assert_eq!(order.len(), 2); // Both assemblies should be in the order
    }

    #[test]
    fn test_topological_sort_complex_dag() {
        let graph = AssemblyDependencyGraph::new();

        // Create a complex DAG:
        //     A
        //    / \
        //   B   C
        //  / \ /
        // D   E
        //  \ /
        //   F

        let a = create_test_identity("A", 1, 0);
        let b = create_test_identity("B", 1, 0);
        let c = create_test_identity("C", 1, 0);
        let d = create_test_identity("D", 1, 0);
        let e = create_test_identity("E", 1, 0);
        let _f = create_test_identity("F", 1, 0);

        graph
            .add_dependency_with_source(
                a.clone(),
                create_test_dependency("B", DependencyType::Reference),
            )
            .unwrap();
        graph
            .add_dependency_with_source(a, create_test_dependency("C", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(
                b.clone(),
                create_test_dependency("D", DependencyType::Reference),
            )
            .unwrap();
        graph
            .add_dependency_with_source(b, create_test_dependency("E", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(c, create_test_dependency("E", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(d, create_test_dependency("F", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(e, create_test_dependency("F", DependencyType::Reference))
            .unwrap();

        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 6);

        // Get positions
        let positions: std::collections::HashMap<String, usize> = order
            .iter()
            .enumerate()
            .map(|(i, id)| (id.name.clone(), i))
            .collect();

        // Verify ordering constraints
        assert!(positions["F"] < positions["D"]);
        assert!(positions["F"] < positions["E"]);
        assert!(positions["D"] < positions["B"]);
        assert!(positions["E"] < positions["B"]);
        assert!(positions["E"] < positions["C"]);
        assert!(positions["B"] < positions["A"]);
        assert!(positions["C"] < positions["A"]);
    }

    #[test]
    fn test_dependency_graph_clear() {
        let graph = AssemblyDependencyGraph::new();
        let app = create_test_identity("App", 1, 0);
        let dependency = create_test_dependency("mscorlib", DependencyType::Reference);

        graph.add_dependency_with_source(app, dependency).unwrap();

        assert!(!graph.is_empty());
        assert_eq!(graph.dependency_count(), 1);

        graph.clear();

        assert!(graph.is_empty());
        assert_eq!(graph.assembly_count(), 0);
        assert_eq!(graph.dependency_count(), 0);
    }

    #[test]
    fn test_concurrent_graph_operations() {
        let graph = Arc::new(AssemblyDependencyGraph::new());
        let mut handles = vec![];

        // Spawn multiple threads to add dependencies concurrently
        for i in 0..10 {
            let graph_clone = graph.clone();
            let handle = thread::spawn(move || {
                let app = create_test_identity(&format!("App{}", i), 1, 0);
                let dependency = create_test_dependency("mscorlib", DependencyType::Reference);
                graph_clone
                    .add_dependency_with_source(app, dependency)
                    .unwrap();
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all dependencies were added
        assert_eq!(graph.assembly_count(), 11); // 10 Apps + 1 mscorlib
        assert_eq!(graph.dependency_count(), 10);

        // Verify cycle detection works with concurrent data
        let cycles = graph.find_cycles().unwrap();
        assert!(cycles.is_none());
    }
}
