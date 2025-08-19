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

/// A directed graph representing the dependencies between metadata loaders.
///
/// The `LoaderGraph` manages the relationships between all metadata table loaders, allowing for dependency analysis,
/// cycle detection, and parallel execution planning. Each loader is associated with a [`crate::metadata::tables::TableId`],
/// and dependencies are tracked to ensure correct loading order.
///
/// # Fields
///
/// - `loaders`: Maps each [`crate::metadata::tables::TableId`] to its corresponding [`crate::metadata::loader::MetadataLoader`]
/// - `dependents`: Maps each table to the set of tables that depend on it (reverse dependencies)
/// - `dependencies`: Maps each table to the set of tables it depends on (forward dependencies)
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
//   ModuleRef (depends on: )
//   LocalConstant (depends on: )
//   Param (depends on: )
//   AssemblyRef (depends on: )
//   Document (depends on: )
//   Assembly (depends on: )
//   StateMachineMethod (depends on: )
//   EncLog (depends on: )
//   Field (depends on: )
//   AssemblyOS (depends on: )
//   LocalVariable (depends on: )
//   MethodDebugInformation (depends on: )
//   ImportScope (depends on: )
//   PropertyPtr (depends on: )
//   Property (depends on: )
//   MethodPtr (depends on: )
//   File (depends on: )
//   Module (depends on: )
//   ParamPtr (depends on: )
//   FieldPtr (depends on: )
//   AssemblyProcessor (depends on: )
//   EventPtr (depends on: )
//   EncMap (depends on: )
// ]
// Level 1: [
//   Constant (depends on: Property, Param, Field)
//   FieldRVA (depends on: Field)
//   MethodDef (depends on: Param, ParamPtr)
//   ManifestResource (depends on: File, AssemblyRef)
//   FieldMarshal (depends on: Param, Field)
//   FieldLayout (depends on: Field)
//   AssemblyRefOS (depends on: AssemblyRef)
//   ExportedType (depends on: AssemblyRef, File)
//   AssemblyRefProcessor (depends on: AssemblyRef)
//   TypeRef (depends on: ModuleRef, AssemblyRef)
// ]
// Level 2: [
//   LocalScope (depends on: ImportScope, LocalConstant, MethodDef, LocalVariable)
//   TypeDef (depends on: FieldPtr, Field, MethodPtr, TypeRef, MethodDef)
// ]
// Level 3: [
//   DeclSecurity (depends on: TypeDef, Assembly, MethodDef)
//   ClassLayout (depends on: TypeDef)
//   TypeSpec (depends on: TypeDef, TypeRef)
// ]
// Level 4: [
//   GenericParam (depends on: TypeDef, TypeRef, TypeSpec, MethodDef)
//   PropertyMap (depends on: TypeSpec, PropertyPtr, TypeDef, TypeRef, Property)
//   NestedClass (depends on: TypeRef, TypeSpec, TypeDef)
//   InterfaceImpl (depends on: TypeDef, TypeRef, TypeSpec)
//   MemberRef (depends on: TypeRef, MethodDef, TypeSpec, ModuleRef, TypeDef)
//   StandAloneSig (depends on: MethodDef, TypeSpec, TypeDef, TypeRef)
//   Event (depends on: TypeDef, TypeSpec, TypeRef)
// ]
// Level 5: [
//   GenericParamConstraint (depends on: TypeRef, TypeSpec, GenericParam, MethodDef, MemberRef, TypeDef)
//   EventMap (depends on: Event, EventPtr)
//   MethodSpec (depends on: TypeDef, MemberRef, TypeSpec, TypeRef, MethodDef)
//   ImplMap (depends on: ModuleRef, MemberRef, Module, MethodDef)
//   MethodImpl (depends on: TypeRef, MemberRef, TypeDef, MethodDef)
// ]
// Level 6: [
//   CustomAttribute (depends on: MethodSpec, Module, File, ExportedType, TypeRef, TypeSpec, MethodDef, StandAloneSig, ModuleRef, Assembly, Field, InterfaceImpl, Param, ManifestResource, TypeDef, MemberRef, Property, DeclSecurity, Event, AssemblyRef, GenericParam, GenericParamConstraint)
//   CustomDebugInformation (depends on: Property, MethodSpec, Field, InterfaceImpl, MemberRef, LocalScope, AssemblyRef, LocalConstant, File, LocalVariable, StandAloneSig, TypeSpec, Event, MethodDef, ModuleRef, Param, Assembly, ImportScope, DeclSecurity, TypeDef, TypeRef, Module, ManifestResource, ExportedType, GenericParam, GenericParamConstraint, Document)
//   MethodSemantics (depends on: PropertyMap, EventMap, Event, Property)
// ]
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
        }
    }

    /// Add a loader to the graph.
    ///
    /// Registers a metadata loader in the graph and initializes its dependency tracking structures.
    /// The loader's [`crate::metadata::tables::TableId`] is extracted and used as its identifier.
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
    /// // Add a loader instance that implements MetadataLoader
    /// graph.add_loader(&some_loader);
    /// ```
    ///
    /// # Notes
    ///
    /// - The loader must remain valid for the lifetime of the graph
    /// - Adding the same loader multiple times will overwrite the previous entry
    /// - Dependencies are not resolved until `LoaderGraph::build_relationships()` is called
    ///
    /// # Thread Safety
    ///
    /// This method is not thread-safe and must be called from a single thread during graph construction.
    pub fn add_loader(&mut self, loader: &'a dyn MetadataLoader) {
        let table_id = loader.table_id();
        self.loaders.insert(table_id, loader);

        self.dependents.entry(table_id).or_default();
        self.dependencies.entry(table_id).or_default();
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

        for (table_id, loader) in &self.loaders {
            for dep_id in loader.dependencies() {
                if !self.loaders.contains_key(dep_id) {
                    return Err(GraphError(format!("Loader for table {table_id:?} depends on table {dep_id:?}, but no loader for that table exists"
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

        if let Some(deps) = self.dependencies.get(&table_id) {
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
                let table_id = loader.table_id();
                let deps = self.dependencies.get(&table_id).map_or_else(
                    || "None".to_string(),
                    |d| {
                        d.iter()
                            .map(|id| format!("{id:?}"))
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
