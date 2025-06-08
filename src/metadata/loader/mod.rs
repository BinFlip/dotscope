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
mod assembly;
mod assemblyos;
mod assemblyprocessor;
mod assemblyref;
mod assemblyrefos;
mod assemblyrefprocessor;
mod classlayout;
mod constant;
mod customattribute;
mod data;
mod declsecurity;
mod event;
mod eventmap;
mod exportedtype;
mod field;
mod fieldlayout;
mod fieldmarshal;
mod fieldrva;
mod file;
mod genericparam;
mod genericparamconstraint;
mod graph;
mod implmap;
mod interfaceimpl;
mod manifestresource;
mod memberref;
mod methoddef;
mod methodimpl;
mod methodsemantics;
mod methodspec;
mod module;
mod moduleref;
mod nestedclass;
mod param;
mod property;
mod propertymap;
mod standalonesig;
mod typedef;
mod typeref;
mod typespec;

pub(crate) use data::CilObjectData;

static LOADERS: [&'static dyn MetadataLoader; 38] = [
    &assembly::AssemblyLoader,
    &assemblyos::AssemblyOsLoader,
    &assemblyprocessor::AssemblyProcessorLoader,
    &assemblyref::AssemblyRefLoader,
    &assemblyrefos::AssemblyRefOsLoader,
    &assemblyrefprocessor::AssemblyRefProcessorLoader,
    &classlayout::ClassLayoutLoader,
    &constant::ConstantLoader,
    &customattribute::CustomAttributeLoader,
    &declsecurity::DeclSecurityLoader,
    &event::EventLoader,
    &eventmap::EventMapLoader,
    &exportedtype::ExportedTypeLoader,
    &field::FieldLoader,
    &fieldlayout::FieldLayoutLoader,
    &fieldmarshal::FieldMarshalLoader,
    &fieldrva::FieldRvaLoader,
    &file::FileLoader,
    &genericparam::GenericParamLoader,
    &genericparamconstraint::GenericParamConstraintLoader,
    &implmap::ImplMapLoader,
    &interfaceimpl::InterfaceImplLoader,
    &manifestresource::ManifestResourceLoader,
    &memberref::MemberRefLoader,
    &methoddef::MethodDefLoader,
    &methodimpl::MethodImplLoader,
    &methodsemantics::MethodSemanticsLoader,
    &methodspec::MethodSpecLoader,
    &module::ModuleLoader,
    &moduleref::ModuleRefLoader,
    &nestedclass::NestedClassLoader,
    &param::ParamLoader,
    &property::PropertyLoader,
    &propertymap::PropertyMapLoader,
    &standalonesig::StandAloneSigLoader,
    &typedef::TypeDefLoader,
    &typeref::TypeRefLoader,
    &typespec::TypeSpecLoader,
];

use crate::{metadata::streams::TableId, Result};
use rayon::prelude::*;

/// Trait for metadata table loaders.
///
/// Implement this trait for each loader that processes a specific metadata table.
/// The loader must declare its dependencies and provide a loading implementation.
trait MetadataLoader: Send + Sync {
    /// Load this metadata table using the provided `CilObjectData`.
    ///
    /// # Arguments
    /// * `data` - The `CilObjectData` containing shared state and metadata.
    ///
    /// # Returns
    /// * `Result<()>` - Returns `Ok(())` if loading succeeds, or an error otherwise.
    fn load(&self, data: &CilObjectData) -> Result<()>;

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
/// * `data` - The CIL object data shared by all loaders.
///
/// # Returns
/// * `Result<()>` - Returns `Ok(())` if all loaders succeed, or the first error encountered.
pub(crate) fn execute_loaders_in_parallel(data: &CilObjectData) -> Result<()> {
    // Build and execute the dependency graph
    let graph = build_dependency_graph(&LOADERS)?;
    let levels = graph.topological_levels()?;

    for level in levels {
        let results: Vec<Result<()>> = level.par_iter().map(|loader| loader.load(data)).collect();

        // Check for any errors
        for result in results {
            result?;
        }
    }

    Ok(())
}
