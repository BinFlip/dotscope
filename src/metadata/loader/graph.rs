//! Dependency graph management for parallel metadata table loading.
//!
//! This module provides sophisticated dependency tracking and execution planning for .NET metadata
//! table loaders. The internal dependency graph enables efficient parallel
//! loading by analyzing inter-table dependencies, detecting cycles, and generating optimal
//! execution plans that maximize concurrency while respecting load order constraints.
//!
//! # Architecture
//!
//! The dependency graph system implements a multi-stage approach to parallel loading coordination:
//!
//! ## Core Components
//!
//! - **Dependency Analysis**: Bidirectional relationship tracking between metadata tables
//! - **Cycle Detection**: Comprehensive validation using depth-first search algorithms
//! - **Topological Ordering**: Level-based execution planning for maximum parallelism
//! - **Load Coordination**: Safe execution plan generation for multi-threaded loading
//!
//! ## Graph Structure
//!
//! The dependency graph maintains three core data structures:
//! - **Loaders Map**: Associates [`crate::metadata::tables::TableId`] with loader implementations
//! - **Dependencies Map**: Forward dependency tracking (what each table depends on)
//! - **Dependents Map**: Reverse dependency tracking (what depends on each table)
//!
//! # Key Components
//!
//! - Internal dependency graph - Main dependency graph implementation
//! - Bidirectional dependency relationship management
//! - Kahn's algorithm-based topological sorting for execution planning
//! - Comprehensive cycle detection with detailed error reporting
//!
//! # Dependency Management
//!
//! The loader dependency system manages complex relationships between .NET metadata tables:
//!
//! ## Loading Phases
//!
//! 1. **Independent Tables**: Assembly, Module, basic reference tables (Level 0)
//! 2. **Simple Dependencies**: TypeRef, basic field/method tables (Level 1)
//! 3. **Complex Types**: TypeDef with method/field relationships (Level 2)
//! 4. **Advanced Structures**: Generic parameters, interfaces, nested types (Level 3+)
//! 5. **Cross-References**: Custom attributes, security attributes (Final Levels)
//!
//! ## Parallel Execution Strategy
//!
//! The graph enables efficient parallel loading through level-based execution:
//! - **Intra-Level Parallelism**: All loaders within the same level execute concurrently
//! - **Inter-Level Synchronization**: Complete all level N loaders before starting level N+1
//! - **Dependency Satisfaction**: Ensures all dependencies are resolved before dependent loading
//! - **Deadlock Prevention**: Cycle detection prevents circular dependency deadlocks
//!
//! # Usage Examples
//!
//! ## Basic Graph Construction
//!
//! ```rust,ignore
//! use dotscope::metadata::loader::graph::LoaderGraph;
//! use dotscope::metadata::loader::MetadataLoader;
//!
//! // Create dependency graph
//! let mut graph = LoaderGraph::new();
//!
//! # fn get_loaders() -> Vec<Box<dyn MetadataLoader>> { vec![] }
//! let loaders = get_loaders();
//!
//! // Register all metadata loaders
//! for loader in &loaders {
//!     graph.add_loader(loader.as_ref());
//! }
//!
//! // Build dependency relationships and validate
//! graph.build_relationships()?;
//!
//! // Generate execution plan for parallel loading
//! let execution_levels = graph.topological_levels()?;
//! println!("Execution plan has {} levels", execution_levels.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Parallel Execution Planning
//!
//! ```rust,ignore
//! use dotscope::metadata::loader::graph::LoaderGraph;
//!
//! # fn example_execution_planning(graph: LoaderGraph) -> dotscope::Result<()> {
//! // Generate optimal execution plan
//! let levels = graph.topological_levels()?;
//!
//! // Execute each level in parallel
//! for (level_num, level_loaders) in levels.iter().enumerate() {
//!     println!("Level {}: {} loaders can run in parallel",
//!              level_num, level_loaders.len());
//!     
//!     // All loaders in this level can execute concurrently
//!     for loader in level_loaders {
//!         println!("  - {:?} (ready to execute)", loader.table_id());
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Debug Visualization
//!
//! ```rust,ignore
//! use dotscope::metadata::loader::graph::LoaderGraph;
//!
//! # fn debug_example(graph: LoaderGraph) {
//! // Generate detailed execution plan for debugging
//! let execution_plan = graph.dump_execution_plan();
//! println!("Complete Execution Plan:\n{}", execution_plan);
//!
//! // Example output:
//! // Level 0: [
//! //   Assembly (depends on: )
//! //   Module (depends on: )
//! // ]
//! // Level 1: [
//! //   TypeRef (depends on: Assembly, Module)
//! //   MethodDef (depends on: Module)
//! // ]
//! # }
//! ```
//!
//! # Error Handling
//!
//! The graph system provides comprehensive error detection and reporting:
//!
//! ## Validation Errors
//! - **Missing Dependencies**: Loaders reference tables without corresponding loaders
//! - **Circular Dependencies**: Dependency cycles that would cause deadlocks
//! - **Graph Inconsistencies**: Internal state corruption or invalid configurations
//!
//! ## Debug Features
//! - Detailed cycle detection with specific table identification
//! - Execution plan validation in debug builds
//! - Comprehensive error messages for troubleshooting
//!
//!
//! # Thread Safety
//!
//! The internal dependency graph has specific thread safety characteristics:
//! - **Construction Phase**: Not thread-safe, must be built from single thread
//! - **Execution Phase**: Generated plans are thread-safe for coordination
//! - **Read-Only Operations**: Safe concurrent access after relationship building
//! - **Loader References**: Maintains safe references throughout execution lifecycle
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - MetadataLoader trait and parallel execution coordination
//! - [`crate::metadata::tables::TableId`] - Table identification for dependency relationships
//! - Internal loader context - Execution context for parallel loading
//! - [`crate::Error`] - Comprehensive error handling for graph validation failures
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Respects .NET metadata table interdependency requirements
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
pub enum LoaderKey {
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

/// A directed graph representing the dependencies between metadata loaders.
///
/// The `LoaderGraph` manages the relationships between all metadata table loaders and special cross-table loaders,
/// allowing for dependency analysis, cycle detection, and parallel execution planning. Each loader is associated
/// with a [`LoaderKey`] that distinguishes between regular table loaders and special cross-table loaders.
///
/// # Fields
///
/// - `loaders`: Maps each [`LoaderKey`] to its corresponding [`crate::metadata::loader::MetadataLoader`]
/// - `dependents`: Maps each table to the set of loader keys that depend on it (reverse dependencies)
/// - `dependencies`: Maps each loader key to the set of tables it depends on (forward dependencies)
/// - `special_counter`: Sequence counter for generating unique special loader keys
///
/// # Lifecycle
///
/// 1. **Construction**: Create empty graph with `LoaderGraph::new()`
/// 2. **Population**: Add loaders with `LoaderGraph::add_loader()`
/// 3. **Validation**: Build relationships and detect cycles with `LoaderGraph::build_relationships()`
/// 4. **Execution**: Generate execution plan with `LoaderGraph::topological_levels()`
///
/// # Thread Safety
///
/// [`LoaderGraph`] is not [`std::marker::Send`] or [`std::marker::Sync`] due to containing trait object references.
/// All graph modifications must be performed from a single thread during the setup phase.
/// However, the execution plans it generates can safely coordinate parallel loader execution.
///
/// ```rust, ignore
// Level 0: [
//   Table(ParamPtr) (depends on: )
//   Table(Field) (depends on: )
//   Table(MethodDebugInformation) (depends on: )
//   Table(ModuleRef) (depends on: )
//   Table(EncLog) (depends on: )
//   Table(Param) (depends on: )
//   Table(AssemblyRef) (depends on: )
//   Table(Module) (depends on: )
//   Table(Property) (depends on: )
//   Table(Assembly) (depends on: )
//   Table(AssemblyProcessor) (depends on: )
//   Table(File) (depends on: )
//   Table(FieldPtr) (depends on: )
//   Table(AssemblyOS) (depends on: )
//   Table(EventPtr) (depends on: )
//   Table(PropertyPtr) (depends on: )
//   Table(MethodPtr) (depends on: )
//   Table(LocalConstant) (depends on: )
//   Table(EncMap) (depends on: )
//   Table(Document) (depends on: )
//   Table(ImportScope) (depends on: )
//   Table(StateMachineMethod) (depends on: )
//   Table(LocalVariable) (depends on: )
// ]
// Level 1: [
//   Table(ExportedType) (depends on: File, AssemblyRef)
//   Table(FieldMarshal) (depends on: Param, Field)
//   Table(AssemblyRefProcessor) (depends on: AssemblyRef)
//   Table(ManifestResource) (depends on: File, AssemblyRef)
//   Table(MethodDef) (depends on: Param, ParamPtr)
//   Table(AssemblyRefOS) (depends on: AssemblyRef)
//   Table(FieldLayout) (depends on: Field)
//   Table(Constant) (depends on: Property, Field, Param)
//   Table(TypeRef) (depends on: ModuleRef, AssemblyRef)
//   Table(FieldRVA) (depends on: Field)
// ]
// Level 2: [
//   Table(TypeDef) (depends on: MethodPtr, TypeRef, MethodDef, FieldPtr, Field)
//   Table(LocalScope) (depends on: ImportScope, LocalConstant, LocalVariable, MethodDef)
// ]
// Level 3: [
//   Table(DeclSecurity) (depends on: TypeDef, MethodDef, Assembly)
//   Table(ClassLayout) (depends on: TypeDef)
//   Table(TypeSpec) (depends on: TypeDef, TypeRef)
// ]
// Level 4: [
//   Table(PropertyMap) (depends on: Property, TypeSpec, TypeRef, PropertyPtr, TypeDef)
//   Table(InterfaceImpl) (depends on: TypeSpec, TypeRef, TypeDef)
//   Table(Event) (depends on: TypeSpec, TypeRef, TypeDef)
//   Table(MemberRef) (depends on: ModuleRef, TypeSpec, TypeDef, TypeRef, MethodDef)
//   Table(NestedClass) (depends on: TypeDef, TypeRef, TypeSpec)
//   Table(GenericParam) (depends on: TypeDef, MethodDef, TypeRef, TypeSpec)
//   Table(StandAloneSig) (depends on: MethodDef, TypeDef, TypeSpec, TypeRef)
// ]
// Level 5: [
//   Special { sequence: 0 } (depends on: TypeDef, TypeRef, InterfaceImpl, TypeSpec)
// ]
// Level 6: [
//   Table(EventMap) (depends on: Event, EventPtr)
//   Table(MethodImpl) (depends on: TypeRef, MethodDef, TypeDef, MemberRef)
//   Table(ImplMap) (depends on: ModuleRef, Module, MemberRef, MethodDef)
//   Table(GenericParamConstraint) (depends on: GenericParam, TypeDef, TypeSpec, MethodDef, MemberRef, TypeRef)
//   Table(MethodSpec) (depends on: MethodDef, MemberRef, TypeDef, TypeSpec, TypeRef)
// ]
// Level 7: [
//   Table(CustomAttribute) (depends on: MethodSpec, Field, TypeSpec, Assembly, Param, TypeDef, Event, File, ExportedType, GenericParamConstraint, MemberRef, StandAloneSig, ModuleRef, AssemblyRef, MethodDef, DeclSecurity, TypeRef, ManifestResource, Module, InterfaceImpl, Property, GenericParam)
//   Table(CustomDebugInformation) (depends on: Param, MemberRef, TypeSpec, Module, DeclSecurity, StandAloneSig, InterfaceImpl, Event, MethodDef, File, GenericParam, LocalScope, Assembly, MethodSpec, ImportScope, TypeDef, ExportedType, ModuleRef, ManifestResource, Property, Document, GenericParamConstraint, Field, AssemblyRef, TypeRef, LocalConstant, LocalVariable)
//   Table(MethodSemantics) (depends on: PropertyMap, EventMap, Property, Event)
// ]
/// ```
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
    /// Create a new empty loader graph.
    ///
    /// # Returns
    ///
    /// A new `LoaderGraph` with empty dependency mappings, ready for loader registration.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::graph::LoaderGraph;
    ///
    /// let mut graph = LoaderGraph::new();
    /// // Add loaders and build relationships...
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called from any thread.
    pub fn new() -> Self {
        LoaderGraph {
            loaders: HashMap::new(),
            dependents: HashMap::new(),
            dependencies: HashMap::new(),
            special_counter: 0,
        }
    }

    /// Add a loader to the graph.
    ///
    /// Registers a metadata loader in the graph and initializes its dependency tracking structures.
    /// The loader's [`LoaderKey`] is determined by its `table_id()` method - regular table loaders
    /// get `LoaderKey::Table` keys, while special cross-table loaders get `LoaderKey::Special` keys.
    ///
    /// # Arguments
    ///
    /// * `loader` - The loader to insert into the graph. Must implement [`crate::metadata::loader::MetadataLoader`].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::graph::LoaderGraph;
    ///
    /// let mut graph = LoaderGraph::new();
    /// // Add a table loader
    /// graph.add_loader(&table_loader);
    /// // Add a special cross-table loader  
    /// graph.add_loader(&special_loader);
    /// ```
    ///
    /// # Notes
    ///
    /// - The loader must remain valid for the lifetime of the graph
    /// - Adding the same loader multiple times will overwrite the previous entry
    /// - Dependencies are not resolved until `LoaderGraph::build_relationships()` is called
    /// - Special loaders are assigned unique sequence numbers automatically
    ///
    /// # Thread Safety
    ///
    /// This method is not thread-safe and must be called from a single thread during graph construction.
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

    /// Build the dependency relationships after all loaders have been added.
    ///
    /// Analyzes all registered loaders to construct the complete dependency graph. This method:
    /// 1. Clears any existing dependency relationships
    /// 2. Queries each loader for its dependencies via [`crate::metadata::loader::MetadataLoader::dependencies`]
    /// 3. Validates that all dependencies have corresponding loaders
    /// 4. Constructs bidirectional dependency mappings
    /// 5. In debug builds, performs cycle detection and validates the execution plan
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the dependency graph is valid and acyclic
    /// * [`Err`]([`crate::Error::GraphError`]) if validation fails
    ///
    /// # Errors
    ///
    /// This method returns an error in the following cases:
    /// - **Missing Dependency**: A loader depends on a [`crate::metadata::tables::TableId`] for which no loader exists
    /// - **Circular Dependency**: The dependency graph contains cycles (debug builds only)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::graph::LoaderGraph;
    ///
    /// let mut graph = LoaderGraph::new();
    /// // Add all required loaders...
    /// graph.build_relationships()?;
    ///
    /// match graph.build_relationships() {
    ///     Ok(()) => println!("Dependency graph is valid"),
    ///     Err(e) => eprintln!("Graph validation failed: {}", e),
    /// }
    /// ```
    ///
    /// # Debug Features
    ///
    /// In debug builds, this method performs additional validation:
    /// - Comprehensive cycle detection using depth-first search
    /// - Execution plan generation and validation
    /// - Detailed error reporting for dependency issues
    ///
    /// # Thread Safety
    ///
    /// This method is not thread-safe and must be called from a single thread during graph construction.
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
                    .unwrap()
                    .insert(*dep_table_id);

                // Add reverse dependency (table has loader depending on it)
                self.dependents
                    .get_mut(dep_table_id)
                    .unwrap()
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

    /// Check for circular dependencies in the graph.
    ///
    /// Performs a comprehensive cycle detection using depth-first search with stack tracking.
    /// This method is essential for ensuring that the loader execution plan will not deadlock.
    ///
    /// # Algorithm
    ///
    /// Uses a modified DFS that maintains a recursion stack to detect back edges:
    /// 1. Mark each node as visited when first encountered
    /// 2. Add nodes to the recursion stack when entering their DFS subtree
    /// 3. If a dependency points to a node already in the stack, a cycle exists
    /// 4. Remove nodes from the stack when backtracking
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the graph is acyclic
    /// * [`Err`]([`crate::Error::GraphError`]) if any cycles are detected
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::GraphError`] with details about the detected cycle, including
    /// the [`crate::metadata::tables::TableId`] that creates the circular dependency.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // This method is typically called internally by build_relationships()
    /// // but can be used for explicit validation:
    /// if let Err(e) = graph.check_circular_dependencies() {
    ///     eprintln!("Cycle detected: {}", e);
    /// }
    /// ```
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

    /// Helper for circular dependency detection using recursion.
    ///
    /// Performs depth-first search starting from a specific node to detect cycles in the dependency graph.
    /// This is a recursive implementation that maintains both a visited set and a recursion stack.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The [`crate::metadata::tables::TableId`] to start DFS from
    /// * `visited` - Set of all nodes that have been visited during the entire cycle detection process
    /// * `stack` - Set of nodes currently in the DFS recursion stack (used to detect back edges)
    ///
    /// # Returns
    ///
    /// * `Ok(())` if no cycles are reachable from this node
    /// * [`Err`]([`crate::Error::GraphError`]) if a cycle is detected
    ///
    /// # Algorithm Details
    ///
    /// 1. **Entry**: Mark current node as visited and add to recursion stack
    /// 2. **Traversal**: For each dependency of the current node:
    ///    - If unvisited: Recursively explore the dependency
    ///    - If in stack: Cycle detected (back edge found)
    ///    - If visited but not in stack: Already explored, skip
    /// 3. **Exit**: Remove current node from recursion stack
    ///
    /// # Stack Safety
    ///
    /// For very deep dependency chains, this recursive implementation could potentially
    /// cause stack overflow. In practice, .NET metadata dependency graphs have limited depth.
    fn detect_cycle(
        &self,
        table_id: TableId,
        visited: &mut HashSet<TableId>,
        stack: &mut HashSet<TableId>,
    ) -> Result<()> {
        visited.insert(table_id);
        stack.insert(table_id);

        // Check dependencies of this table's loader
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

    /// Get all loaders grouped by dependency level (topological sort).
    ///
    /// Computes a topological ordering of all loaders, grouped into execution levels where
    /// all loaders within the same level can be executed concurrently. This implements
    /// a variant of Kahn's algorithm optimized for level-based parallel execution.
    ///
    /// # Algorithm
    ///
    /// 1. **Initialization**: Start with all registered loaders in the remaining set
    /// 2. **Level Generation**: For each level:
    ///    - Find all loaders with no unresolved dependencies
    ///    - Add these loaders to the current execution level
    ///    - Remove them from the remaining set
    /// 3. **Validation**: Ensure progress is made each iteration to detect cycles
    /// 4. **Completion**: Continue until all loaders are assigned to levels
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Vec<&dyn crate::metadata::loader::MetadataLoader>>)` - Vector of execution levels, where each level contains loaders that can run in parallel
    /// * [`Err`]([`crate::Error::GraphError`]) if the graph contains cycles or is otherwise invalid
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::GraphError`] if:
    /// - **Circular Dependencies**: The graph contains cycles that prevent topological ordering
    /// - **Inconsistent State**: Internal graph state is corrupted
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::graph::LoaderGraph;
    ///
    /// let graph = LoaderGraph::new();
    /// // ... add loaders and build relationships ...
    ///
    /// match graph.topological_levels() {
    ///     Ok(levels) => {
    ///         println!("Execution plan has {} levels", levels.len());
    ///         for (i, level) in levels.iter().enumerate() {
    ///             println!("Level {}: {} loaders can run in parallel", i, level.len());
    ///         }
    ///     }
    ///     Err(e) => eprintln!("Cannot generate execution plan: {}", e),
    /// }
    /// ```
    ///
    /// # Concurrency Benefits
    ///
    /// The returned execution levels enable efficient parallel processing:
    /// - **Level 0**: Independent loaders (no dependencies)
    /// - **Level N**: Loaders that depend only on loaders from levels 0 through N-1
    /// - **Parallelism**: All loaders within a single level can execute concurrently
    /// - **Synchronization**: Complete all loaders in level N before starting level N+1
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. The returned execution plan
    /// can be safely used to coordinate parallel loader execution across multiple threads.
    pub fn topological_levels(&self) -> Result<Vec<Vec<&'a dyn MetadataLoader>>> {
        let mut result = Vec::new();
        let mut remaining_loaders = self.loaders.keys().cloned().collect::<HashSet<_>>();
        let mut completed_tables = HashSet::new();

        while !remaining_loaders.is_empty() {
            let mut current_level = Vec::new();

            // Phase 1: Find table loaders that are ready (dependencies satisfied)
            let ready_table_loaders = remaining_loaders
                .iter()
                .filter(|loader_key| {
                    // Only consider table loaders in regular dependency resolution
                    if let LoaderKey::Table(_table_id) = loader_key {
                        if let Some(deps) = self.dependencies.get(loader_key) {
                            // All dependencies must be completed
                            deps.iter()
                                .all(|dep_table_id| completed_tables.contains(dep_table_id))
                        } else {
                            true // No dependencies
                        }
                    } else {
                        false // Special loaders handled separately
                    }
                })
                .cloned()
                .collect::<Vec<_>>();

            // Add ready table loaders to current level
            for loader_key in &ready_table_loaders {
                if let Some(loader) = self.loaders.get(loader_key) {
                    current_level.push(*loader);
                }
                remaining_loaders.remove(loader_key);

                // Mark this table as completed
                if let LoaderKey::Table(table_id) = loader_key {
                    completed_tables.insert(*table_id);
                }
            }

            // Track if we made progress in this iteration
            let table_progress = !current_level.is_empty();

            // Add the table loader level if it has any loaders
            if table_progress {
                result.push(current_level);
            }

            // Phase 2: Check for special loaders that are now ready after this level
            let ready_special_loaders = remaining_loaders
                .iter()
                .filter(|loader_key| {
                    if let LoaderKey::Special { .. } = loader_key {
                        if let Some(deps) = self.dependencies.get(loader_key) {
                            // All dependencies must be completed
                            deps.iter()
                                .all(|dep_table_id| completed_tables.contains(dep_table_id))
                        } else {
                            true // No dependencies
                        }
                    } else {
                        false // Only special loaders in this phase
                    }
                })
                .cloned()
                .collect::<Vec<_>>();

            // Track if we made progress with special loaders
            let special_progress = !ready_special_loaders.is_empty();

            // Create a separate level for special loaders if any are ready
            if special_progress {
                let mut special_level = Vec::new();
                for loader_key in &ready_special_loaders {
                    if let Some(loader) = self.loaders.get(loader_key) {
                        special_level.push(*loader);
                    }
                    remaining_loaders.remove(loader_key);
                    // Note: Special loaders don't mark any tables as completed since they can't be depended upon
                }
                result.push(special_level);
            }

            // Check for deadlock: if we have remaining loaders but made no progress
            if !remaining_loaders.is_empty() && !table_progress && !special_progress {
                return Err(GraphError(
                    "Unable to resolve dependency order, possible circular dependency".to_string(),
                ));
            }
        }

        Ok(result)
    }

    /// Dump the execution plan as a formatted string for debugging.
    ///
    /// Generates a comprehensive, human-readable representation of the loader execution plan,
    /// including dependency information for each loader. This method is primarily used for
    /// debugging and development to visualize the dependency graph structure.
    ///
    /// # Returns
    ///
    /// A formatted string containing:
    /// - **Execution Levels**: Each level numbered sequentially (0, 1, 2, ...)
    /// - **Loader Information**: For each loader, shows its [`crate::metadata::tables::TableId`] and dependencies
    /// - **Dependency Details**: Lists all tables that each loader depends on
    /// - **Parallel Groups**: Loaders within the same level can execute concurrently
    ///
    /// # Format Example
    ///
    /// ```text
    /// Level 0: [
    ///   Assembly (depends on: )
    ///   Module (depends on: )
    /// ]
    /// Level 1: [
    ///   TypeRef (depends on: Assembly, Module)
    ///   MethodDef (depends on: Module)
    /// ]
    /// ```
    ///
    /// # Panics
    ///
    /// This method panics if `LoaderGraph::topological_levels()` returns an error,
    /// which should only occur if the graph is in an invalid state. In production
    /// code, this should not happen as the graph is validated during construction.
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::loader::graph::LoaderGraph;
    ///
    /// let graph = LoaderGraph::new();
    /// // ... build complete graph ...
    ///
    /// println!("Execution Plan:\n{}", graph.dump_execution_plan());
    /// ```
    ///
    /// # Debug Features
    ///
    /// This method is particularly useful for:
    /// - **Development**: Understanding loader interdependencies
    /// - **Optimization**: Identifying opportunities for better parallelization
    /// - **Troubleshooting**: Diagnosing dependency-related issues
    /// - **Documentation**: Generating execution plan examples
    pub fn dump_execution_plan(&self) -> String {
        // We unwrap, because this should only ever happen in debug builds here
        let levels = self.topological_levels().unwrap();
        let mut result = String::new();

        for (level_idx, level) in levels.iter().enumerate() {
            result.push_str("Level ");
            result.push_str(&level_idx.to_string());
            result.push_str(": [\n");
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

                result.push_str("  ");
                write!(result, "{loader_key:?}").unwrap();
                result.push_str(" (depends on: ");
                result.push_str(&deps);
                result.push_str(")\n");
            }
            result.push_str("]\n");
        }

        result
    }
}
