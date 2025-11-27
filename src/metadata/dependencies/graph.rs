//! Assembly dependency graph implementation with cycle detection and topological sorting.
//!
//! This module provides the core dependency graph data structure that tracks relationships
//! between assemblies, detects circular dependencies, and generates optimal loading orders
//! for multi-assembly scenarios.

use std::collections::{hash_map::Entry, HashMap, HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, RwLock,
};

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
/// ```rust
/// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
///
/// let graph = AssemblyDependencyGraph::new();
/// assert!(graph.is_empty());
/// assert_eq!(graph.assembly_count(), 0);
///
/// // Check for circular dependencies (empty graph has no cycles)
/// let cycles = graph.find_cycles()?;
/// assert!(cycles.is_none());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Loading Order Generation  
///
/// ```rust
/// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
///
/// // Generate optimal loading order (empty graph)
/// let graph = AssemblyDependencyGraph::new();
/// let load_order = graph.topological_order()?;
/// assert!(load_order.is_empty());
/// # Ok::<(), dotscope::Error>(())
/// ```
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

    /// Cached count of unique assemblies in the graph
    ///
    /// Tracks the total number of unique assemblies (both sources and targets).
    /// Updated atomically when assemblies are added or removed.
    assembly_count: Arc<AtomicUsize>,
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
    /// ```rust
    /// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// assert_eq!(graph.assembly_count(), 0);
    /// assert!(graph.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            dependencies: Arc::new(DashMap::new()),
            dependents: Arc::new(DashMap::new()),
            cached_topology: Arc::new(RwLock::new(None)),
            cached_cycles: Arc::new(RwLock::new(None)),
            assembly_count: Arc::new(AtomicUsize::new(0)),
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
    /// ```rust
    /// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// let identity = AssemblyIdentity::new(
    ///     "MyApp".to_string(),
    ///     AssemblyVersion::new(1, 0, 0, 0),
    ///     None, None, None,
    /// );
    /// let deps = graph.get_dependencies(&identity);
    /// assert!(deps.is_empty()); // No dependencies in empty graph
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
    /// ```rust
    /// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// let mscorlib = AssemblyIdentity::new(
    ///     "mscorlib".to_string(),
    ///     AssemblyVersion::new(4, 0, 0, 0),
    ///     None, None, None,
    /// );
    /// let dependents = graph.get_dependents(&mscorlib);
    /// assert!(dependents.is_empty()); // No dependents in empty graph
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
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::dependencies::AssemblyDependencyGraph;
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// assert_eq!(graph.assembly_count(), 0);
    ///
    /// // After adding dependencies, count is updated automatically
    /// // (see add_dependency_with_source for examples)
    /// ```
    #[must_use]
    pub fn assembly_count(&self) -> usize {
        self.assembly_count.load(Ordering::Relaxed)
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
                .map_err(|_| Error::LockError("Failed to acquire cycle cache lock".to_string()))?;
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
                Error::LockError("Failed to acquire cycle cache lock for write".to_string())
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
            let cached = self.cached_topology.read().map_err(|_| {
                Error::LockError("Failed to acquire topology cache lock".to_string())
            })?;
            if let Some(result) = cached.as_ref() {
                return Ok(result.clone());
            }
        }

        // Use SCC-based approach to handle circular dependencies
        let result = self.scc_based_order()?;

        // Cache result
        {
            let mut cache = self.cached_topology.write().map_err(|_| {
                Error::LockError("Failed to acquire topology cache lock for write".to_string())
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
                    Error::GraphError("Stack underflow in Tarjan's algorithm".to_string())
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
        self.assembly_count.store(0, Ordering::Relaxed);
        self.invalidate_caches();
    }

    /// Add a dependency relationship with explicit source identity.
    ///
    /// Records a dependency relationship where the source assembly identity
    /// is explicitly provided, avoiding the need for identity extraction.
    /// This is the preferred method for adding dependencies.
    ///
    /// Duplicate dependencies (same source → same target) are automatically
    /// prevented to maintain graph integrity and accurate counts.
    ///
    /// # Arguments
    /// * `source_identity` - The identity of the source assembly
    /// * `dependency` - The dependency relationship to add
    ///
    /// # Returns
    /// * `Ok(())` - Dependency added successfully (or already exists)
    /// * `Err(_)` - Error occurred during dependency addition
    ///
    /// # Errors
    /// Returns an error if the dependency cannot be added.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use dotscope::metadata::dependencies::{AssemblyDependencyGraph, AssemblyDependency, DependencyType, VersionRequirement, DependencyResolutionState};
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    /// use dotscope::metadata::tables::AssemblyRef;
    ///
    /// let graph = AssemblyDependencyGraph::new();
    /// let source = AssemblyIdentity::new("MyApp".to_string(), AssemblyVersion::new(1, 0, 0, 0), None, None, None);
    /// let target = AssemblyIdentity::new("MyLib".to_string(), AssemblyVersion::new(2, 0, 0, 0), None, None, None);
    ///
    /// let assembly_ref = Arc::new(AssemblyRef {
    ///     rid: 1,
    ///     token: dotscope::metadata::token::Token::new(0x23000001),
    ///     offset: 0,
    ///     name: "MyLib".to_string(),
    ///     culture: None,
    ///     major_version: 2,
    ///     minor_version: 0,
    ///     build_number: 0,
    ///     revision_number: 0,
    ///     flags: 0,
    ///     identifier: None,
    ///     hash: None,
    ///     os_platform_id: std::sync::atomic::AtomicU32::new(0),
    ///     os_major_version: std::sync::atomic::AtomicU32::new(0),
    ///     os_minor_version: std::sync::atomic::AtomicU32::new(0),
    ///     processor: std::sync::atomic::AtomicU32::new(0),
    ///     custom_attributes: Arc::new(boxcar::Vec::new()),
    /// });
    ///
    /// let dep = AssemblyDependency {
    ///     source: dotscope::metadata::dependencies::DependencySource::AssemblyRef(assembly_ref),
    ///     target_identity: target,
    ///     dependency_type: DependencyType::Reference,
    ///     version_requirement: VersionRequirement::Compatible,
    ///     is_optional: false,
    ///     resolution_state: DependencyResolutionState::Unresolved,
    /// };
    ///
    /// // First add succeeds
    /// graph.add_dependency_with_source(&source, dep.clone())?;
    /// assert_eq!(graph.dependency_count(), 1);
    ///
    /// // Second add is prevented (duplicate)
    /// graph.add_dependency_with_source(&source, dep.clone())?;
    /// assert_eq!(graph.dependency_count(), 1); // Still 1, not 2
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_dependency_with_source(
        &self,
        source_identity: &AssemblyIdentity,
        dependency: AssemblyDependency,
    ) -> Result<()> {
        let target_identity = dependency.target_identity.clone();

        let mut source_is_new = false;
        let mut target_is_new = false;

        self.dependencies
            .entry(source_identity.clone())
            .and_modify(|deps| {
                if !deps.iter().any(|d| d.target_identity == target_identity) {
                    deps.push(dependency.clone());
                }
            })
            .or_insert_with(|| {
                source_is_new = true;
                vec![dependency]
            });

        self.dependents
            .entry(target_identity.clone())
            .and_modify(|deps| {
                if !deps.iter().any(|d| d == source_identity) {
                    deps.push(source_identity.clone());
                }
            })
            .or_insert_with(|| {
                target_is_new = true;
                vec![source_identity.clone()]
            });

        // Update assembly count - handle case where source and target are the same (self-reference)
        let new_assemblies =
            if source_is_new && target_is_new && source_identity == &target_identity {
                // Self-reference: only one new assembly
                1
            } else {
                // Different assemblies: count each new one
                usize::from(source_is_new) + usize::from(target_is_new)
            };

        if new_assemblies > 0 {
            self.assembly_count
                .fetch_add(new_assemblies, Ordering::Relaxed);
        }

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
            .add_dependency_with_source(&source, dependency)
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

        graph.add_dependency_with_source(&app, dependency).unwrap();

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
            .add_dependency_with_source(&app, mscorlib_dep)
            .unwrap();
        graph.add_dependency_with_source(&app, system_dep).unwrap();
        graph
            .add_dependency_with_source(&app, system_core_dep)
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

        graph
            .add_dependency_with_source(&app, mscorlib_dep)
            .unwrap();

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

        graph.add_dependency_with_source(&a, b_dep).unwrap();
        graph.add_dependency_with_source(&b, c_dep).unwrap();
        graph.add_dependency_with_source(&c, a_dep).unwrap();

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

        graph.add_dependency_with_source(&a, self_dep).unwrap();

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

        graph.add_dependency_with_source(&app, lib_dep).unwrap();
        graph
            .add_dependency_with_source(&lib, mscorlib_dep)
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

        graph.add_dependency_with_source(&a, b_dep).unwrap();
        graph.add_dependency_with_source(&b, a_dep).unwrap();

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
            .add_dependency_with_source(&a, create_test_dependency("B", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(&a, create_test_dependency("C", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(&b, create_test_dependency("D", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(&b, create_test_dependency("E", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(&c, create_test_dependency("E", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(&d, create_test_dependency("F", DependencyType::Reference))
            .unwrap();
        graph
            .add_dependency_with_source(&e, create_test_dependency("F", DependencyType::Reference))
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

        graph.add_dependency_with_source(&app, dependency).unwrap();

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
                    .add_dependency_with_source(&app, dependency)
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

    #[test]
    fn test_duplicate_dependency_prevention() {
        let graph = AssemblyDependencyGraph::new();
        let app = create_test_identity("MyApp", 1, 0);

        let dependency1 = create_test_dependency("MyLib", DependencyType::Reference);
        let dependency2 = create_test_dependency("MyLib", DependencyType::Reference);

        // Add the same dependency twice
        graph
            .add_dependency_with_source(&app, dependency1.clone())
            .unwrap();
        graph.add_dependency_with_source(&app, dependency2).unwrap();

        // Should only have 1 dependency, not 2
        assert_eq!(graph.dependency_count(), 1);

        // Verify the dependency was actually added
        let deps = graph.get_dependencies(&app);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].target_identity.name, "MyLib");

        // Verify reverse dependency only has 1 entry (check using target from dependency)
        let target = &dependency1.target_identity;
        let dependents = graph.get_dependents(target);
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0].name, "MyApp");
    }

    #[test]
    fn test_assembly_count_with_self_reference() {
        let graph = AssemblyDependencyGraph::new();

        // Create a self-referencing dependency (MyApp depends on MyApp)
        let app = create_test_identity("MyApp", 1, 0);

        // Create dependency where target is the same as source
        let mut self_dep = create_test_dependency("MyApp", DependencyType::Reference);
        // Override the target to match exactly
        self_dep.target_identity = app.clone();

        graph.add_dependency_with_source(&app, self_dep).unwrap();

        // Should count as only 1 assembly, not 2 (self-reference)
        assert_eq!(graph.assembly_count(), 1);
        assert_eq!(graph.dependency_count(), 1);
    }

    #[test]
    fn test_assembly_count_increments_correctly() {
        let graph = AssemblyDependencyGraph::new();
        assert_eq!(graph.assembly_count(), 0);

        let app = create_test_identity("MyApp", 1, 0);
        let lib1_dep = create_test_dependency("Lib1", DependencyType::Reference);
        let lib1_target = lib1_dep.target_identity.clone();

        // Add first dependency: MyApp -> Lib1 (2 new assemblies)
        graph.add_dependency_with_source(&app, lib1_dep).unwrap();
        assert_eq!(graph.assembly_count(), 2);

        // Add second dependency: MyApp -> Lib2 (1 new assembly, MyApp already exists)
        let lib2_dep = create_test_dependency("Lib2", DependencyType::Reference);
        graph.add_dependency_with_source(&app, lib2_dep).unwrap();
        assert_eq!(graph.assembly_count(), 3);

        // Add duplicate dependency: MyApp -> Lib1 again (0 new assemblies, duplicate)
        let lib1_dep2 = create_test_dependency("Lib1", DependencyType::Reference);
        // Override to use exact same target identity
        let mut lib1_dep2_fixed = lib1_dep2.clone();
        lib1_dep2_fixed.target_identity = lib1_target.clone();
        graph
            .add_dependency_with_source(&app, lib1_dep2_fixed)
            .unwrap();
        assert_eq!(graph.assembly_count(), 3); // Still 3, duplicate prevented
    }
}
