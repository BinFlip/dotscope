//! Core infrastructure for loading and processing .NET metadata tables in a dependency-aware and parallelized manner.
//!
//! This module provides the foundation for parallel metadata loading operations across all .NET metadata
//! tables as defined by ECMA-335. It exposes the [`crate::metadata::loader::MetadataLoader`] trait,
//! dependency graph construction, and parallel execution utilities for coordinating the loading of
//! 53 different metadata table types.
//!
//! # Architecture
//!
//! The loader system is built around several key concepts:
//!
//! - **Dependency Management**: Each loader declares its dependencies via [`crate::metadata::loader::MetadataLoader::dependencies`]
//! - **Graph Construction**: Dependencies are modeled as a directed acyclic graph using internal graph structures
//! - **Parallel Execution**: Loaders are executed in topologically sorted levels, enabling maximum parallelism
//! - **Context Sharing**: All loaders share a common context containing loaded table data
//!
//! # Execution Model
//!
//! 1. **Registration**: All loaders are statically registered in an internal loader registry
//! 2. **Graph Building**: Internal graph construction builds the dependency graph and validates for cycles
//! 3. **Level Generation**: The graph is topologically sorted into execution levels
//! 4. **Parallel Execution**: Each level is executed in parallel using rayon
//! 5. **Error Handling**: Any loader failure immediately aborts the entire process
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access during parallel loading:
//! - **Loaders**: All implementations must be [`std::marker::Send`] + [`std::marker::Sync`] for parallel execution
//! - **Context**: Internal context structures provide thread-safe access to shared metadata
//! - **Synchronization**: Level-based execution provides natural synchronization points between dependency levels
//! - **Static Data**: Internal loader registry and execution level cache are immutable after initialization
//! - **Error Isolation**: Loader failures are properly isolated and propagated without affecting concurrent operations
//!
//! # Integration
//!
//! This module integrates with:
//! - Internal graph module: Dependency graph and topological sorting for loader execution
//! - Internal data module: Contains data structures used by all loaders
//! - Internal context module: Provides context structures for sharing data between loaders
//! - [`crate::metadata::tables`]: All metadata table implementations and loader definitions
mod context;
mod data;
mod graph;

pub(crate) use context::LoaderContext;
pub(crate) use data::CilObjectData;

/// Static registry of all metadata table loaders.
///
/// This array contains references to all 45 metadata table loaders that are part of the .NET metadata
/// specification. Each loader is responsible for processing a specific metadata table type and declaring
/// its dependencies on other tables.
///
/// # Loader Categories
///
/// The loaders are organized into several functional categories:
/// - **Assembly Loaders**: [`crate::metadata::tables::Assembly`], [`crate::metadata::tables::AssemblyRef`], [`crate::metadata::tables::AssemblyOs`], [`crate::metadata::tables::AssemblyProcessor`], etc.
/// - **Type System Loaders**: [`crate::metadata::tables::TypeDefRaw`], [`crate::metadata::tables::TypeRefRaw`], [`crate::metadata::tables::TypeSpec`], [`crate::metadata::tables::InterfaceImpl`], etc.
/// - **Method Loaders**: [`crate::metadata::tables::MethodDefRaw`], [`crate::metadata::tables::MethodImpl`], [`crate::metadata::tables::MethodSpec`], [`crate::metadata::tables::MethodSemantics`], etc.
/// - **Field Loaders**: [`crate::metadata::tables::Field`], [`crate::metadata::tables::FieldLayout`], [`crate::metadata::tables::FieldMarshal`], [`crate::metadata::tables::FieldRva`], etc.
/// - **Property/Event Loaders**: [`crate::metadata::tables::Property`], [`crate::metadata::tables::PropertyMap`], [`crate::metadata::tables::Event`], [`crate::metadata::tables::EventMap`], etc.
/// - **Security/Attribute Loaders**: [`crate::metadata::tables::CustomAttribute`], [`crate::metadata::tables::DeclSecurity`], [`crate::metadata::tables::GenericParam`], etc.
/// - **Resource Loaders**: [`crate::metadata::tables::ManifestResource`], [`crate::metadata::tables::File`], [`crate::metadata::tables::ExportedType`], etc.
///
/// # Registration Requirements
///
/// All loaders in this array must:
/// - Implement the [`MetadataLoader`] trait
/// - Be [`Send`] + [`Sync`] for parallel execution
/// - Have `'static` lifetime for safe concurrent access
/// - Declare accurate dependencies via [`MetadataLoader::dependencies`]
///
/// # Execution Order
///
/// The actual execution order is determined dynamically by the dependency graph, not by the
/// order in this array. Internal graph construction analyzes dependencies and
/// creates a topological execution plan.
///
/// # Maintenance
///
/// When adding new metadata tables:
/// 1. Implement the corresponding loader with the [`MetadataLoader`] trait
/// 2. Add the loader to this array
/// 3. Update any loaders that depend on the new table
/// 4. Test that the dependency graph remains acyclic
static LOADERS: [&'static dyn MetadataLoader; 53] = [
    &crate::metadata::tables::AssemblyLoader,
    &crate::metadata::tables::AssemblyOsLoader,
    &crate::metadata::tables::AssemblyProcessorLoader,
    &crate::metadata::tables::AssemblyRefLoader,
    &crate::metadata::tables::AssemblyRefOsLoader,
    &crate::metadata::tables::AssemblyRefProcessorLoader,
    &crate::metadata::tables::ClassLayoutLoader,
    &crate::metadata::tables::ConstantLoader,
    &crate::metadata::tables::CustomAttributeLoader,
    &crate::metadata::tables::DeclSecurityLoader,
    &crate::metadata::tables::DocumentLoader,
    &crate::metadata::tables::MethodDebugInformationLoader,
    &crate::metadata::tables::LocalScopeLoader,
    &crate::metadata::tables::LocalVariableLoader,
    &crate::metadata::tables::LocalConstantLoader,
    &crate::metadata::tables::ImportScopeLoader,
    &crate::metadata::tables::StateMachineMethodLoader,
    &crate::metadata::tables::CustomDebugInformationLoader,
    &crate::metadata::tables::EncLogLoader,
    &crate::metadata::tables::EncMapLoader,
    &crate::metadata::tables::EventLoader,
    &crate::metadata::tables::EventMapLoader,
    &crate::metadata::tables::EventPtrLoader,
    &crate::metadata::tables::ExportedTypeLoader,
    &crate::metadata::tables::FieldLoader,
    &crate::metadata::tables::FieldPtrLoader,
    &crate::metadata::tables::MethodPtrLoader,
    &crate::metadata::tables::FieldLayoutLoader,
    &crate::metadata::tables::FieldMarshalLoader,
    &crate::metadata::tables::FieldRvaLoader,
    &crate::metadata::tables::FileLoader,
    &crate::metadata::tables::GenericParamLoader,
    &crate::metadata::tables::GenericParamConstraintLoader,
    &crate::metadata::tables::ImplMapLoader,
    &crate::metadata::tables::InterfaceImplLoader,
    &crate::metadata::tables::ManifestResourceLoader,
    &crate::metadata::tables::MemberRefLoader,
    &crate::metadata::tables::MethodDefLoader,
    &crate::metadata::tables::MethodImplLoader,
    &crate::metadata::tables::MethodSemanticsLoader,
    &crate::metadata::tables::MethodSpecLoader,
    &crate::metadata::tables::ModuleLoader,
    &crate::metadata::tables::ModuleRefLoader,
    &crate::metadata::tables::NestedClassLoader,
    &crate::metadata::tables::ParamLoader,
    &crate::metadata::tables::ParamPtrLoader,
    &crate::metadata::tables::PropertyLoader,
    &crate::metadata::tables::PropertyMapLoader,
    &crate::metadata::tables::PropertyPtrLoader,
    &crate::metadata::tables::StandAloneSigLoader,
    &crate::metadata::tables::TypeDefLoader,
    &crate::metadata::tables::TypeRefLoader,
    &crate::metadata::tables::TypeSpecLoader,
];

use crate::{metadata::tables::TableId, Result};
use rayon::prelude::*;
use std::sync::LazyLock;

/// Static cache of pre-computed execution levels for parallel loader execution.
///
/// This [`LazyLock`] contains the complete execution plan with loaders organized into dependency levels,
/// computed once on first access and reused for all subsequent metadata loading operations.
/// This optimization eliminates redundant graph construction and topological sorting when processing multiple assemblies.
///
/// # Initialization
///
/// The execution levels are computed by:
/// 1. Building the complete dependency graph from [`LOADERS`]
/// 2. Validating dependencies and checking for cycles
/// 3. Computing topological sort to generate execution levels
/// 4. Caching the final execution plan for all future use
///
/// # Thread Safety
///
/// [`LazyLock`] ensures thread-safe initialization even under concurrent access.
/// The cached execution levels are immutable after creation.
///
/// # Panics
///
/// Initialization will panic if:
/// - The static loader dependency graph contains cycles
/// - Required loaders are missing from the [`LOADERS`] array
///
/// These conditions indicate programming errors that should be caught during development.
static EXECUTION_LEVELS: LazyLock<Vec<Vec<&'static dyn MetadataLoader>>> = LazyLock::new(|| {
    let graph = build_dependency_graph(&LOADERS)
        .expect("Static loader dependency graph must be valid - check for missing loaders or circular dependencies");
    graph.topological_levels().expect(
        "Static loader dependency graph must be acyclic - check loader dependencies for cycles",
    )
});

/// Trait for metadata table loaders.
///
/// This trait defines the interface that all metadata table loaders must implement. Each loader
/// is responsible for processing a specific .NET metadata table type and integrating its data
/// into the shared [`LoaderContext`].
///
/// # Implementation Requirements
///
/// All implementations must:
/// - **Thread Safety**: Be [`Send`] + [`Sync`] for parallel execution across multiple threads
/// - **Dependency Declaration**: Accurately declare all table dependencies via [`MetadataLoader::dependencies`]
/// - **Error Handling**: Return appropriate errors for malformed or inconsistent metadata
/// - **Idempotency**: Support multiple calls to [`MetadataLoader::load`] without side effects
///
/// # Execution Context
///
/// Loaders execute within a controlled environment:
/// - **Shared State**: Access to all previously loaded tables via [`LoaderContext`]
/// - **Dependency Guarantee**: All declared dependencies are guaranteed to be loaded first
/// - **Parallel Execution**: Multiple loaders at the same dependency level run concurrently
/// - **Error Isolation**: Loader failures do not affect other concurrent loaders
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::loader::{MetadataLoader, LoaderContext};
/// use dotscope::metadata::tables::TableId;
/// use dotscope::Result;
///
/// struct MyTableLoader;
///
/// impl MetadataLoader for MyTableLoader {
///     fn load(&self, context: &LoaderContext) -> Result<()> {
///         // Access dependency data
///         let assembly_data = context.assemblies();
///         
///         // Process this table's data
///         // ...
///         
///         Ok(())
///     }
///     
///     fn table_id(&self) -> TableId {
///         TableId::MyTable
///     }
///     
///     fn dependencies(&self) -> &'static [TableId] {
///         &[TableId::Assembly, TableId::Module]
///     }
/// }
/// ```
pub(crate) trait MetadataLoader: Send + Sync {
    /// Load this metadata table using the provided [`LoaderContext`].
    ///
    /// This method processes the metadata for this loader's specific table type, integrating
    /// the parsed data into the shared context. The implementation should:
    ///
    /// 1. **Validate Input**: Check that required metadata streams and tables are available
    /// 2. **Parse Data**: Extract and validate table entries from the metadata streams
    /// 3. **Resolve Dependencies**: Use previously loaded table data for cross-references
    /// 4. **Update Context**: Store processed data in the appropriate context collections
    /// 5. **Error Handling**: Return descriptive errors for malformed or inconsistent metadata
    ///
    /// # Arguments
    ///
    /// * `context` - The [`LoaderContext`] containing all table maps for cross-references
    ///   and metadata streams for parsing
    ///
    /// # Returns
    ///
    /// * [`Ok`]`(())` if loading succeeds and all data is integrated into the context
    /// * [`Err`]([`crate::Error`]) if parsing fails, dependencies are missing, or data is invalid
    ///
    /// # Thread Safety
    ///
    /// This method may be called concurrently with other loaders at the same dependency level.
    /// The [`LoaderContext`] provides thread-safe access to shared data.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// fn load(&self, context: &LoaderContext) -> Result<()> {
    ///     // Get required metadata streams
    ///     let table_stream = context.table_stream()?;
    ///     let strings = context.strings_stream();
    ///     
    ///     // Parse table entries
    ///     for entry in table_stream.my_table_entries()? {
    ///         let name = strings.get_string(entry.name_index)?;
    ///         // Process entry...
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    fn load(&self, context: &LoaderContext) -> Result<()>;

    /// Get the ID of the table this loader processes.
    ///
    /// Returns the unique identifier for the metadata table that this loader is responsible
    /// for processing. This ID is used by the dependency graph system to:
    /// - **Track Dependencies**: Identify which loaders depend on this table
    /// - **Resolve Conflicts**: Ensure only one loader exists per table type
    /// - **Generate Execution Plan**: Create the topological ordering for parallel execution
    ///
    /// # Returns
    ///
    /// The [`crate::metadata::tables::TableId`] enum variant corresponding to this loader's table type.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::tables::TableId;
    ///
    /// fn table_id(&self) -> TableId {
    ///     TableId::Assembly  // This loader processes the Assembly table
    /// }
    /// ```
    ///
    /// # Consistency
    ///
    /// This method must always return the same value for a given loader instance.
    /// The returned ID should match the actual table type processed by [`MetadataLoader::load`].
    fn table_id(&self) -> TableId;

    /// Get dependencies this loader needs to be satisfied before loading.
    ///
    /// Declares all metadata tables that must be loaded and available in the [`LoaderContext`]
    /// before this loader can execute successfully. This information is used by the dependency
    /// graph to determine the correct execution order and enable parallel processing.
    ///
    /// # Dependency Types
    ///
    /// Dependencies typically fall into these categories:
    /// - **Direct References**: Tables directly referenced by this table's entries
    /// - **Indirect References**: Tables needed for resolving complex relationships
    /// - **Validation Dependencies**: Tables required for consistency checks
    /// - **Index Dependencies**: Tables that provide index validation for this table
    ///
    /// # Returns
    ///
    /// A static slice of [`crate::metadata::tables::TableId`] values representing all tables
    /// that must be loaded before this loader can execute. The slice may be empty if the
    /// loader has no dependencies (e.g., foundational tables like Assembly or Module).
    ///
    /// # Accuracy Requirements
    ///
    /// The returned dependencies must be:
    /// - **Complete**: Include all tables actually accessed during [`MetadataLoader::load`]
    /// - **Minimal**: Avoid unnecessary dependencies that would limit parallelism
    /// - **Static**: Always return the same dependencies for a given loader type
    /// - **Acyclic**: Not create circular dependencies with other loaders
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::tables::TableId;
    ///
    /// // A TypeDef loader that depends on MethodDef and Field tables
    /// fn dependencies(&self) -> &'static [TableId] {
    ///     &[TableId::MethodDef, TableId::Field]
    /// }
    ///
    /// // A foundational loader with no dependencies
    /// fn dependencies(&self) -> &'static [TableId] {
    ///     &[]  // Empty slice for tables like Assembly or Module
    /// }
    /// ```
    fn dependencies(&self) -> &'static [TableId];
}

/// Build a dependency graph from a collection of loaders.
///
/// Constructs a complete dependency graph from the provided loaders, validates the relationships,
/// and ensures the graph is acyclic. This function is the foundation of the parallel execution
/// system, enabling efficient metadata loading with maximum concurrency.
///
/// # Process
///
/// 1. **Graph Initialization**: Creates an empty [`graph::LoaderGraph`]
/// 2. **Loader Registration**: Adds each loader to the graph using [`graph::LoaderGraph::add_loader`]
/// 3. **Relationship Building**: Calls [`graph::LoaderGraph::build_relationships`] to:
///    - Query each loader for its dependencies via [`MetadataLoader::dependencies`]
///    - Validate that all dependencies have corresponding registered loaders
///    - Construct bidirectional dependency mappings for efficient traversal
/// 4. **Cycle Detection**: In debug builds, performs comprehensive cycle detection
/// 5. **Validation**: Ensures the graph can produce a valid topological ordering
///
/// # Arguments
///
/// * `loaders` - A slice of references to all metadata table loaders that should be included
///   in the dependency graph. Typically this is the [`LOADERS`] static array.
///
/// # Returns
///
/// * [`Ok`]([`graph::LoaderGraph`]) - A validated dependency graph ready for execution planning
/// * [`Err`]([`crate::Error`]) - If validation fails due to missing dependencies or cycles
///
/// # Errors
///
/// This function returns errors in the following cases:
/// - **Missing Dependency**: A loader declares a dependency on a table with no registered loader
/// - **Circular Dependency**: The dependency relationships form cycles (detected in debug builds)
/// - **Invalid State**: Internal graph construction fails due to inconsistent loader data
///
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::loader::{build_dependency_graph, LOADERS};
///
/// match build_dependency_graph(&LOADERS) {
///     Ok(graph) => {
///         let levels = graph.topological_levels()?;
///         println!("Graph has {} execution levels", levels.len());
///     }
///     Err(e) => eprintln!("Failed to build dependency graph: {}", e),
/// }
/// ```
///
/// # Thread Safety
///
/// This function is not thread-safe and should only be called during initialization.
/// The returned graph, however, can be safely used to coordinate parallel execution.
fn build_dependency_graph(
    loaders: &[&'static dyn MetadataLoader],
) -> Result<graph::LoaderGraph<'static>> {
    let mut graph = graph::LoaderGraph::new();

    for loader in loaders {
        graph.add_loader(*loader);
    }

    graph.build_relationships()?;
    Ok(graph)
}

/// Execute loaders in parallel respecting dependencies.
///
/// This is the main entry point for parallel metadata loading. It orchestrates the execution of all
/// registered metadata table loaders in dependency order, maximizing parallelism while ensuring
/// data consistency and integrity.
///
/// # Execution Strategy
///
/// 1. **Level Access**: Retrieves pre-computed execution levels from the static [`EXECUTION_LEVELS`] cache
/// 2. **Parallel Execution**: For each level:
///    - Executes all loaders in the level concurrently using [rayon]  
///    - Waits for all loaders in the level to complete before proceeding
///    - Immediately aborts on any loader failure
/// 3. **Result Aggregation**: Collects and validates results from all parallel executions
///
/// # Concurrency Model
///
/// - **Level Parallelism**: All loaders within a dependency level run concurrently
/// - **Level Synchronization**: Each level completes entirely before the next level begins
/// - **Thread Pool**: Uses rayon's global thread pool for automatic work distribution
/// - **Error Propagation**: Any loader failure immediately terminates all concurrent work
///
/// # Arguments
///
/// * `context` - The [`LoaderContext`] containing metadata streams and storage for loaded table data.
///   This context is shared across all loaders and provides thread-safe access to parsed metadata.
///
/// # Returns
///
/// * [`Ok`]`(())` - If all loaders execute successfully and integrate their data into the context
/// * [`Err`]([`crate::Error`]) - If any loader fails, dependency graph construction fails, or
///   execution planning fails
///
/// # Errors
///
/// This function can fail due to:
/// - **Loader Execution Errors**: Individual loader failures during metadata processing
/// - **Context Errors**: Issues accessing metadata streams or storing processed data
/// - **Concurrency Errors**: Resource contention or synchronization failures
///
/// Note: Dependency graph and topological sort errors are caught at static initialization time
/// and will panic during the first call to this function if the loader dependencies are invalid.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::loader::{LoaderContext, execute_loaders_in_parallel};
/// use dotscope::file::CilObject;
///
/// // Load .NET assembly file
/// let cil_object = CilObject::parse_file("example.dll")?;
///
/// // Create loader context
/// let context = LoaderContext::new(&cil_object)?;
///
/// // Execute all metadata loaders in parallel
/// match execute_loaders_in_parallel(&context) {
///     Ok(()) => {
///         println!("All metadata tables loaded successfully");
///         // Access loaded data via context methods
///         let assemblies = context.assemblies();
///         let types = context.type_defs();
///     }
///     Err(e) => eprintln!("Metadata loading failed: {}", e),
/// }
/// ```
///
/// # Thread Safety
///
/// This function coordinates thread-safe parallel execution. The [`LoaderContext`] provides
/// safe concurrent access to shared metadata, and the execution model ensures proper
/// synchronization between dependency levels.
///
/// # Resource Management
///
/// The function automatically manages CPU resources through rayon's thread pool and
/// ensures proper cleanup if any loader fails during execution.
pub(crate) fn execute_loaders_in_parallel(context: &LoaderContext) -> Result<()> {
    // Access pre-computed execution levels (computed once per process)
    let levels = &*EXECUTION_LEVELS;

    for level in levels {
        let results: Vec<Result<()>> = level
            .par_iter()
            .map(|loader| loader.load(context))
            .collect();

        // Check for any errors
        for result in results {
            result?;
        }
    }

    Ok(())
}
