//! ProjectLoader builder API for flexible assembly loading.
//!
//! This module provides the `ProjectLoader` builder-style API for loading .NET assemblies
//! with automatic dependency resolution, graceful fallback to single-assembly mode, and
//! progressive dependency addition.

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        identity::{AssemblyIdentity, AssemblyVersion},
        tables::AssemblyRefRaw,
        validation::ValidationConfig,
    },
    project::{context::ProjectContext, CilProject, ProjectResult},
    Error, Result,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Builder for creating and loading CilProject instances with flexible dependency management.
///
/// `ProjectLoader` provides a builder-style API for loading .NET assemblies with automatic
/// dependency resolution, graceful fallback to single-assembly mode, and progressive
/// dependency addition. This addresses the common scenario where individual assemblies
/// fail to load due to missing dependencies.
///
/// # Design Goals
///
/// - **Single Binary Support**: Handle individual assemblies gracefully when dependencies are missing
/// - **Progressive Loading**: Allow step-by-step addition of dependencies as they become available
/// - **Automatic Discovery**: Discover and load dependencies automatically when possible
/// - **Graceful Degradation**: Fall back to single-assembly analysis when cross-assembly resolution fails
///
/// # Usage Examples
///
/// ## Basic Single Assembly Loading
/// ```rust,ignore
/// use dotscope::project::ProjectLoader;
///
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .build()?;
/// ```
///
/// ## Multi-Assembly with Manual Dependencies
/// ```rust,ignore
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_dependency("MyLib.dll")?
///     .with_dependency("System.Core.dll")?
///     .build()?;
/// ```
///
/// ## Automatic Discovery with Search Path
/// ```rust,ignore
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_search_path("/path/to/dependencies")?
///     .auto_discover(true)
///     .build()?;
/// ```
pub struct ProjectLoader {
    /// Primary assembly file path - the main entry point
    primary_file: Option<PathBuf>,
    /// Additional dependency files to load
    dependency_files: Vec<PathBuf>,
    /// Search paths for automatic dependency discovery
    search_paths: Vec<PathBuf>,
    /// Whether to automatically discover and load dependencies
    auto_discover: bool,
    /// Whether to fail fast on missing dependencies or continue with partial loading
    strict_mode: bool,
    /// Validation configuration to apply during loading
    validation_config: Option<ValidationConfig>,
}

impl ProjectLoader {
    /// Create a new ProjectLoader builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primary_file: None,
            dependency_files: Vec::new(),
            search_paths: Vec::new(),
            auto_discover: false,
            strict_mode: false,
            validation_config: None,
        }
    }

    /// Set the primary assembly file.
    ///
    /// This is the main entry point of the project and will be loaded first.
    /// All dependency resolution will be performed relative to this assembly.
    ///
    /// # Arguments
    /// * `path` - Path to the primary assembly file (.exe or .dll)
    ///
    /// # Errors
    /// Returns an error if the path does not exist or is not readable.
    pub fn primary_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::Error(format!(
                "Primary file does not exist: {}",
                path.display()
            )));
        }
        self.primary_file = Some(path.to_path_buf());
        Ok(self)
    }

    /// Add a specific dependency file to load.
    ///
    /// Dependencies added through this method will be loaded regardless of
    /// whether they are discovered through automatic dependency analysis.
    ///
    /// # Arguments  
    /// * `path` - Path to the dependency assembly file
    ///
    /// # Errors
    /// Returns an error if the path does not exist or is not readable.
    pub fn with_dependency<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::Error(format!(
                "Dependency file does not exist: {}",
                path.display()
            )));
        }
        self.dependency_files.push(path.to_path_buf());
        Ok(self)
    }

    /// Add a search path for automatic dependency discovery.
    ///
    /// When auto-discovery is enabled, these paths will be searched for
    /// assemblies that match dependencies referenced by the primary assembly.
    ///
    /// # Arguments
    /// * `path` - Directory path to search for dependencies
    ///
    /// # Errors
    /// Returns an error if the path does not exist or is not a directory.
    pub fn with_search_path<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() || !path.is_dir() {
            return Err(Error::Error(format!(
                "Search path does not exist or is not a directory: {}",
                path.display()
            )));
        }
        self.search_paths.push(path.to_path_buf());
        Ok(self)
    }

    /// Enable or disable automatic dependency discovery.
    ///
    /// When enabled, the loader will analyze the primary assembly's references
    /// and attempt to locate and load matching assemblies from the search paths.
    ///
    /// # Arguments
    /// * `enabled` - Whether to enable automatic discovery
    #[must_use]
    pub fn auto_discover(mut self, enabled: bool) -> Self {
        self.auto_discover = enabled;
        self
    }

    /// Enable or disable strict mode.
    ///
    /// In strict mode, missing dependencies will cause the build to fail.
    /// In non-strict mode (default), missing dependencies are logged but
    /// the project will still be created with partial assembly loading.
    ///
    /// # Arguments
    /// * `strict` - Whether to enable strict mode
    #[must_use]
    pub fn strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Set validation configuration for the loaded assemblies.
    ///
    /// # Arguments
    /// * `config` - Validation configuration to apply
    #[must_use]
    pub fn with_validation(mut self, config: ValidationConfig) -> Self {
        self.validation_config = Some(config);
        self
    }

    /// Build the CilProject with the configured settings.
    ///
    /// This method performs the actual loading and returns a unified ProjectResult
    /// containing both the loaded project and loading statistics. The loading process includes:
    ///
    /// 1. Load the primary assembly
    /// 2. Load explicitly specified dependencies
    /// 3. Perform automatic dependency discovery (if enabled)
    /// 4. Apply validation (if configured)
    /// 5. Build the final project with dependency graph
    ///
    /// # Returns
    /// A `ProjectResult` containing the loaded project and metadata about
    /// the loading process (success/failure counts, missing dependencies, etc.)
    ///
    /// # Errors
    /// Returns an error if:
    /// - No primary file was specified
    /// - The primary file cannot be loaded
    /// - Strict mode is enabled and dependencies are missing
    /// - Validation fails (if validation is enabled)
    ///
    /// # Panics
    /// Panics if a worker thread panics during parallel assembly loading.
    pub fn build(self) -> Result<ProjectResult> {
        let primary_path = self.primary_file.clone().ok_or_else(|| {
            Error::Error(
                "No primary file specified. Use primary_file() to set the main assembly."
                    .to_string(),
            )
        })?;

        let project = CilProject::new();

        // Determine primary search directory (fallback when no explicit search paths)
        let primary_search_dir = primary_path
            .parent()
            .ok_or_else(|| {
                Error::Error("Cannot determine parent directory of root file".to_string())
            })?
            .to_path_buf();

        // Phase 1: Lightweight dependency discovery using CilAssemblyView
        let mut discovered_views: HashMap<AssemblyIdentity, CilAssemblyView> = HashMap::new();
        let mut discovery_queue: VecDeque<PathBuf> = VecDeque::new();
        let mut processed_files: HashSet<PathBuf> = HashSet::new();
        let mut missing_dependencies: HashSet<String> = HashSet::new();
        let mut primary_assembly_identity: Option<AssemblyIdentity> = None;

        // Start with the root assembly
        discovery_queue.push_back(primary_path.clone());

        // Add explicit dependencies to queue
        for dep_path in &self.dependency_files {
            discovery_queue.push_back(dep_path.clone());
        }

        // Discovery loop
        while let Some(current_path) = discovery_queue.pop_front() {
            if processed_files.contains(&current_path) {
                continue;
            }
            processed_files.insert(current_path.clone());

            match CilAssemblyView::from_path(&current_path) {
                Ok(view) => {
                    if let Ok(assembly_identity) = view.identity() {
                        // Track if this is the primary assembly
                        if current_path == primary_path {
                            primary_assembly_identity = Some(assembly_identity.clone());
                        }

                        let dependencies = Self::extract_dependencies_from_view(&view);
                        discovered_views.insert(assembly_identity.clone(), view);

                        // Queue dependencies for discovery if auto_discover is enabled
                        if self.auto_discover {
                            for dep_identity in dependencies {
                                if discovered_views.contains_key(&dep_identity) {
                                    continue;
                                }

                                let potential_paths =
                                    self.find_dependency_paths(&dep_identity, &primary_search_dir);

                                let mut found = false;
                                for potential_path in potential_paths {
                                    if potential_path.exists()
                                        && !processed_files.contains(&potential_path)
                                    {
                                        discovery_queue.push_back(potential_path);
                                        found = true;
                                        break;
                                    }
                                }

                                if !found {
                                    missing_dependencies.insert(dep_identity.name);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if let Some(file_name) = current_path.file_stem() {
                        missing_dependencies.insert(file_name.to_string_lossy().to_string());
                    }
                }
            }
        }

        // Phase 2: Load all discovered assemblies in parallel with ProjectContext coordination

        // Validate that we discovered at least the primary assembly
        if discovered_views.is_empty() {
            return Err(Error::Error(format!(
                "Failed to discover any assemblies, including the primary file: {}. \
                 This may indicate the file is corrupted or not a valid .NET assembly.",
                primary_path.display()
            )));
        }

        let project_context = Arc::new(ProjectContext::new(discovered_views.len()));
        let handles: Vec<_> = discovered_views
            .into_iter()
            .map(|(identity, view)| {
                let context = project_context.clone();
                let validation_config = self.validation_config.unwrap_or_default();
                std::thread::spawn(move || {
                    let result = CilObject::from_project(view, context.as_ref(), validation_config);
                    if let Err(ref e) = result {
                        context.break_all_barriers(&format!(
                            "Assembly {} failed to load: {}",
                            identity.name, e
                        ));
                    }
                    (identity, result)
                })
            })
            .collect();

        // Collect results and add to project
        let mut loaded_assemblies = Vec::new();
        let mut load_failures = Vec::new();

        for handle in handles {
            let (identity, result) = handle.join().unwrap();
            match result {
                Ok(cil_object) => {
                    if let Err(e) = project.add_assembly(cil_object) {
                        if self.strict_mode {
                            return Err(Error::Error(format!(
                                "Failed to add {} to project: {}",
                                identity.name, e
                            )));
                        }
                        load_failures.push((identity.name.clone(), e.to_string()));
                    } else {
                        // Set primary assembly if this matches the primary identity
                        if let Some(ref primary_id) = primary_assembly_identity {
                            if identity == *primary_id {
                                let _ = project.set_primary(identity.clone());
                            }
                        }
                        loaded_assemblies.push(identity);
                    }
                }
                Err(e) => {
                    if self.strict_mode {
                        return Err(Error::Error(format!(
                            "Failed to load {} in strict mode: {}",
                            identity.name, e
                        )));
                    }
                    load_failures.push((identity.name, e.to_string()));
                }
            }
        }

        // Build final result
        let mut result = ProjectResult::with_project(project);
        for identity in loaded_assemblies {
            result.record_success(Some(identity));
        }

        for (name, error) in load_failures {
            result.record_failure(name, error);
        }

        for missing in missing_dependencies {
            result.record_failure(missing, "Dependency not found".to_string());
        }

        Ok(result)
    }

    /// Extract dependencies from a CilAssemblyView.
    fn extract_dependencies_from_view(view: &CilAssemblyView) -> Vec<AssemblyIdentity> {
        let mut discovered_dependencies = Vec::new();

        if let (Some(tables), Some(strings), Some(blobs)) =
            (view.tables(), view.strings(), view.blobs())
        {
            if let Some(assembly_ref_table) = tables.table::<AssemblyRefRaw>() {
                for row in assembly_ref_table {
                    if let Ok(assembly_ref) = row.to_owned(strings, blobs) {
                        #[allow(clippy::cast_possible_truncation)]
                        let target_identity = AssemblyIdentity {
                            name: assembly_ref.name.clone(),
                            version: AssemblyVersion {
                                major: assembly_ref.major_version as u16,
                                minor: assembly_ref.minor_version as u16,
                                build: assembly_ref.build_number as u16,
                                revision: assembly_ref.revision_number as u16,
                            },
                            culture: assembly_ref.culture.clone(),
                            strong_name: assembly_ref.identifier.clone(),
                            processor_architecture: None,
                        };

                        discovered_dependencies.push(target_identity);
                    }
                }
            }
        }

        discovered_dependencies
    }

    /// Find potential file paths for a dependency.
    fn find_dependency_paths(
        &self,
        identity: &AssemblyIdentity,
        search_dir: &Path,
    ) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Search in configured search paths first
        for search_path in &self.search_paths {
            paths.push(search_path.join(format!("{}.dll", identity.name)));
            paths.push(search_path.join(format!("{}.exe", identity.name)));
        }

        // Search in primary search directory
        paths.push(search_dir.join(format!("{}.dll", identity.name)));
        paths.push(search_dir.join(format!("{}.exe", identity.name)));

        paths
    }
}

impl Default for ProjectLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_loader_basic_api() {
        // Test that the builder API compiles and has expected methods
        let _loader = ProjectLoader::new().auto_discover(true).strict_mode(false);

        // Test that Default works
        let _default_loader = ProjectLoader::default();
    }

    #[test]
    fn test_project_loader_validation_errors() {
        // Test that validation works for non-existent files
        let result = ProjectLoader::new().primary_file("/nonexistent/file.exe");

        assert!(result.is_err(), "Should fail for non-existent primary file");

        let result = ProjectLoader::new().with_dependency("/nonexistent/dep.dll");

        assert!(
            result.is_err(),
            "Should fail for non-existent dependency file"
        );

        let result = ProjectLoader::new().with_search_path("/nonexistent/directory");

        assert!(result.is_err(), "Should fail for non-existent search path");
    }

    #[test]
    fn test_project_loader_build_fails_without_primary() {
        // Test that build fails when no primary file is specified
        let result = ProjectLoader::new().build();

        assert!(
            result.is_err(),
            "Should fail when no primary file specified"
        );

        if let Err(e) = result {
            assert!(
                e.to_string().contains("No primary file specified"),
                "Error should mention missing primary file"
            );
        }
    }
}
