//! Project loading result types and statistics.
//!
//! This module provides result types for project loading operations, tracking
//! successfully loaded assemblies, failures, and missing dependencies.

use crate::{metadata::identity::AssemblyIdentity, project::CilProject};

/// Result of a project loading operation.
///
/// Contains the loaded project along with statistics about the loading process,
/// including which assemblies were successfully loaded, which failed, and which
/// dependencies could not be found.
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
}

impl Default for ProjectResult {
    fn default() -> Self {
        Self::new()
    }
}
