//! Project loading result types and statistics.
//!
//! This module provides result types for project loading operations, tracking
//! successfully loaded assemblies, failures, and missing dependencies.

use crate::{
    metadata::{cilassemblyview::CilAssemblyView, identity::AssemblyIdentity},
    project::CilProject,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
};

/// A version mismatch between a required and actual assembly version.
///
/// This occurs when an assembly is found but its version doesn't satisfy the
/// version requirement from the dependency reference.
#[derive(Debug, Clone)]
pub struct VersionMismatch {
    /// The assembly identity that was required by a dependency
    pub required: AssemblyIdentity,
    /// The assembly identity that was actually found
    pub actual: AssemblyIdentity,
}

/// Result of a project loading operation.
///
/// Contains the loaded project along with statistics about the loading process,
/// including which assemblies were successfully loaded, which failed, and which
/// dependencies could not be found.
///
/// During loading, this struct also holds temporary state for discovery and
/// parallel loading phases. This state is cleaned up before the result is returned.
///
/// # Usage
///
/// ```rust,no_run
/// use dotscope::project::{ProjectLoader, ProjectResult};
///
/// # fn main() -> dotscope::Result<()> {
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
/// # Ok(())
/// # }
/// ```
pub struct ProjectResult {
    /// The loaded project containing all successfully loaded assemblies
    pub project: CilProject,
    /// Successfully loaded assembly identities
    pub loaded_assemblies: Vec<AssemblyIdentity>,
    /// Dependencies that could not be found or loaded
    pub missing_dependencies: Vec<String>,
    /// Detailed failure information (file path -> error message)
    pub failed_loads: Vec<(String, String)>,
    /// Version mismatches detected during dependency resolution
    pub version_mismatches: Vec<VersionMismatch>,
    /// Total number of successfully loaded assemblies
    pub loaded_count: usize,
    /// Total number of failed loading attempts
    pub failed_count: usize,

    // --- Internal state used during loading (cleared before return) ---
    /// Discovered assembly views pending full load
    pub(crate) pending_views: HashMap<AssemblyIdentity, CilAssemblyView>,
    /// Identity of the primary assembly
    pub(crate) primary_identity: Option<AssemblyIdentity>,
    /// Paths already processed during discovery
    pub(crate) processed_paths: HashSet<PathBuf>,
    /// Queue of paths to discover
    pub(crate) discovery_queue: VecDeque<PathBuf>,
}

impl std::fmt::Debug for ProjectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectResult")
            .field("project", &self.project)
            .field("loaded_assemblies", &self.loaded_assemblies)
            .field("missing_dependencies", &self.missing_dependencies)
            .field("failed_loads", &self.failed_loads)
            .field("version_mismatches", &self.version_mismatches)
            .field("loaded_count", &self.loaded_count)
            .field("failed_count", &self.failed_count)
            .field("pending_views_count", &self.pending_views.len())
            .finish_non_exhaustive()
    }
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
            version_mismatches: Vec::new(),
            loaded_count: 0,
            failed_count: 0,
            pending_views: HashMap::new(),
            primary_identity: None,
            processed_paths: HashSet::new(),
            discovery_queue: VecDeque::new(),
        }
    }

    // --- Discovery phase helpers (used by ProjectLoader) ---

    /// Check if an assembly identity is already discovered.
    pub(crate) fn has_compatible_version(&self, required: &AssemblyIdentity) -> bool {
        self.pending_views.keys().any(|id| id.satisfies(required))
    }

    /// Add a path to the discovery queue if not already processed.
    pub(crate) fn enqueue(&mut self, path: PathBuf) {
        if !self.processed_paths.contains(&path) {
            self.discovery_queue.push_back(path);
        }
    }

    /// Get the next path to process, marking it as processed.
    pub(crate) fn next_path(&mut self) -> Option<PathBuf> {
        while let Some(path) = self.discovery_queue.pop_front() {
            if !self.processed_paths.contains(&path) {
                self.processed_paths.insert(path.clone());
                return Some(path);
            }
        }
        None
    }

    /// Take the pending views for parallel loading, clearing internal state.
    pub(crate) fn take_pending_views(&mut self) -> HashMap<AssemblyIdentity, CilAssemblyView> {
        // Clear discovery state - no longer needed
        self.processed_paths.clear();
        self.discovery_queue.clear();
        std::mem::take(&mut self.pending_views)
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

    /// Record a version mismatch between required and actual assembly.
    pub(crate) fn record_version_mismatch(
        &mut self,
        required: AssemblyIdentity,
        actual: AssemblyIdentity,
    ) {
        self.version_mismatches
            .push(VersionMismatch { required, actual });
    }

    /// Check if there are any version mismatches.
    pub fn has_version_mismatches(&self) -> bool {
        !self.version_mismatches.is_empty()
    }

    /// Get the number of version mismatches.
    pub fn version_mismatch_count(&self) -> usize {
        self.version_mismatches.len()
    }

    /// Get all version mismatches.
    pub fn get_version_mismatches(&self) -> &[VersionMismatch] {
        &self.version_mismatches
    }
}

impl Default for ProjectResult {
    fn default() -> Self {
        Self::new()
    }
}
