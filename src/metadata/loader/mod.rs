//! Metadata Loader Module
//!
//! This module provides the core infrastructure for loading and processing .NET metadata tables in a dependency-aware and parallelized manner.
//! It exposes the `MetadataLoader` trait, dependency graph construction, and parallel execution utilities for all table loaders.
//!
//! # Modules
//! - `graph`: Dependency graph and topological sorting for loader execution.
//! - `data`: Contains the CilObjectData struct used by all loaders.
//! - All loaders for specific metadata tables are implemented in their own modules, such as `assembly`, `field`, `methoddef`, etc.
//!
//! # Re-exports
//! CilObjectData and execute_loaders_in_parallel exported for internal use only
//!
//! # Usage
//! Implement the `MetadataLoader` trait for each table loader, then use `build_dependency_graph` and `execute_loaders_in_parallel` to process metadata efficiently.
mod context;
mod data;
mod graph;

pub(crate) use context::LoaderContext;
pub(crate) use data::CilObjectData;

static LOADERS: [&'static dyn MetadataLoader; 43] = [
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

/// Trait for metadata table loaders.
///
/// Implement this trait for each loader that processes a specific metadata table.
/// The loader must declare its dependencies and provide a loading implementation.
pub(crate) trait MetadataLoader: Send + Sync {
    /// Load this metadata table using the provided `CilObjectData` and `LoaderContext`.
    ///
    /// # Arguments
    /// * `context` - The `LoaderContext` containing all table maps for cross-references.
    ///
    /// # Returns
    /// * `Result<()>` - Returns `Ok(())` if loading succeeds, or an error otherwise.
    fn load(&self, context: &LoaderContext) -> Result<()>;

    /// Get the ID of the table this loader processes.
    ///
    /// # Returns
    /// * `TableId` - The identifier of the metadata table handled by this loader.
    fn table_id(&self) -> TableId;

    /// Get dependencies this loader needs to be satisfied before loading.
    ///
    /// # Returns
    /// * `&'static [TableId]` - Slice of table IDs that must be loaded before this loader runs.
    fn dependencies(&self) -> &'static [TableId];
}

/// Build a dependency graph from a collection of loaders.
///
/// # Arguments
/// * `loaders` - A vector of references to all metadata table loaders.
///
/// # Returns
/// * `Result<LoaderGraph<'_>>` - The constructed dependency graph, or an error if cyclic dependencies are found.
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
/// This function executes all metadata table loaders in parallel, level by level, according to their dependencies.
/// If any loader fails, the process is aborted and the error is returned.
///
/// # Arguments
/// * `context` - The loader context containing all table maps for cross-references.
///
/// # Returns
/// * `Result<()>` - Returns `Ok(())` if all loaders succeed, or the first error encountered.
pub(crate) fn execute_loaders_in_parallel(context: &LoaderContext) -> Result<()> {
    // Build and execute the dependency graph
    let graph = build_dependency_graph(&LOADERS)?;
    let levels = graph.topological_levels()?;

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
