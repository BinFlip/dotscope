//! Project loading result types and statistics.
//!
//! This module provides unified result types for both legacy and new project loading APIs,
//! consolidating the various result and statistics types into a coherent interface.

use crate::{metadata::identity::AssemblyIdentity, project::CilProject};

/// Unified result of a project loading operation.
///
/// This type consolidates the functionality of the legacy `LoadResult` and the new
/// `ProjectLoadResult` types, providing a single interface for project loading results
/// regardless of which API was used to perform the loading.
///
/// # Usage
///
/// ```rust,ignore
/// use dotscope::project::{ProjectLoader, ProjectResult};
///
/// // From ProjectLoader API
/// let result: ProjectResult = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .build()?;
///
/// if result.is_complete_success() {
///     println!("Loaded {} assemblies successfully", result.success_count());
///     // Access the loaded project
///     for (identity, assembly) in result.project.iter() {
///         println!("Assembly: {} has {} types", identity.name, assembly.types().len());
///     }
/// } else {
///     println!("Loaded {} assemblies, {} failed",
///              result.success_count(), result.failure_count());
/// }
/// ```
#[derive(Debug)]
pub struct ProjectResult {
    /// The loaded project containing all successfully loaded assemblies
    pub project: CilProject,
    /// Successfully loaded assembly identities
    pub loaded_assemblies: Vec<AssemblyIdentity>,
    /// Dependencies that could not be found or loaded
    pub missing_dependencies: Vec<String>,
    /// Detailed failure information (file path -> error message)
    pub failed_loads: Vec<(String, String)>,
    /// Total number of successfully loaded assemblies
    pub loaded_count: usize,
    /// Total number of failed loading attempts
    pub failed_count: usize,
}

impl ProjectResult {
    /// Create a new empty project result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            project: CilProject::new(),
            loaded_assemblies: Vec::new(),
            missing_dependencies: Vec::new(),
            failed_loads: Vec::new(),
            loaded_count: 0,
            failed_count: 0,
        }
    }

    /// Create a new project result with an existing project.
    #[must_use]
    pub fn with_project(project: CilProject) -> Self {
        Self {
            project,
            loaded_assemblies: Vec::new(),
            missing_dependencies: Vec::new(),
            failed_loads: Vec::new(),
            loaded_count: 0,
            failed_count: 0,
        }
    }

    /// Check if the loading operation was completely successful (no failures).
    pub fn is_complete_success(&self) -> bool {
        self.failed_count == 0
    }

    /// Check if the loading operation had any failures.
    pub fn has_failures(&self) -> bool {
        self.failed_count > 0
    }

    /// Get the number of successfully loaded assemblies.
    pub fn success_count(&self) -> usize {
        self.loaded_count
    }

    /// Get the number of failed assembly loads.
    pub fn failure_count(&self) -> usize {
        self.failed_count
    }

    /// Record a successful assembly load.
    pub(crate) fn record_success(&mut self, identity: Option<AssemblyIdentity>) {
        if let Some(identity) = identity {
            self.loaded_assemblies.push(identity);
        }
        self.loaded_count += 1;
    }

    /// Record a failed assembly load.
    pub(crate) fn record_failure(&mut self, file_path: String, error_message: String) {
        self.failed_loads.push((file_path.clone(), error_message));
        self.missing_dependencies.push(file_path);
        self.failed_count += 1;
    }

    /// Create a ProjectResult from legacy LoadResult data.
    pub(crate) fn from_legacy(
        project: CilProject,
        loaded_assemblies: Vec<AssemblyIdentity>,
        missing_dependencies: Vec<String>,
        loaded_count: usize,
        failed_count: usize,
    ) -> Self {
        Self {
            project,
            loaded_assemblies,
            missing_dependencies: missing_dependencies.clone(),
            failed_loads: missing_dependencies
                .into_iter()
                .map(|dep| (dep.clone(), "Dependency not found".to_string()))
                .collect(),
            loaded_count,
            failed_count,
        }
    }
}

impl Default for ProjectResult {
    fn default() -> Self {
        Self::new()
    }
}
