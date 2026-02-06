//! ProjectLoader builder API for flexible assembly loading.
//!
//! This module provides the `ProjectLoader` builder-style API for loading .NET assemblies
//! with automatic dependency resolution, graceful fallback to single-assembly mode, and
//! progressive dependency addition.

use crate::{
    file::File,
    metadata::{
        cilassemblyview::CilAssemblyView, cilobject::CilObject, identity::AssemblyIdentity,
        validation::ValidationConfig,
    },
    project::{context::ProjectContext, ProjectResult},
    Error, Result,
};
use std::{
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
/// # Usage Examples
///
/// ## Basic Single Assembly Loading
/// ```rust,no_run
/// use dotscope::project::ProjectLoader;
///
/// # fn main() -> dotscope::Result<()> {
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Multi-Assembly with Manual Dependencies
/// ```rust,no_run
/// use dotscope::project::ProjectLoader;
///
/// # fn main() -> dotscope::Result<()> {
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_dependency("MyLib.dll")?
///     .with_dependency("System.Core.dll")?
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Automatic Discovery with Search Path
/// ```rust,no_run
/// use dotscope::project::ProjectLoader;
///
/// # fn main() -> dotscope::Result<()> {
/// let result = ProjectLoader::new()
///     .primary_file("MyApp.exe")?
///     .with_search_path("/path/to/dependencies")?
///     .auto_discover(true)
///     .build()?;
/// # Ok(())
/// # }
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
            return Err(Error::Configuration(format!(
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
            return Err(Error::Configuration(format!(
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
            return Err(Error::Configuration(format!(
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
            Error::Configuration(
                "No primary file specified. Use primary_file() to set the main assembly."
                    .to_string(),
            )
        })?;

        let primary_search_dir = primary_path
            .parent()
            .ok_or_else(|| {
                Error::Configuration("Cannot determine parent directory of root file".to_string())
            })?
            .to_path_buf();

        let mut result = ProjectResult::new();

        // Phase 1: Discover assemblies and their dependencies
        self.discover_assemblies(&primary_path, &primary_search_dir, &mut result)?;

        // Phase 2: Load all discovered assemblies in parallel
        self.load_assemblies_parallel(&mut result)?;

        Ok(result)
    }

    /// Phase 1: Discover assemblies and their dependencies.
    ///
    /// Uses lightweight `File` -> `CilAssemblyView` loading to discover the dependency
    /// graph without fully loading assemblies as `CilObject` instances.
    fn discover_assemblies(
        &self,
        primary_path: &Path,
        search_dir: &Path,
        result: &mut ProjectResult,
    ) -> Result<()> {
        let validation_config = self
            .validation_config
            .unwrap_or_else(ValidationConfig::production);

        result.enqueue(primary_path.to_path_buf());
        for dep_path in &self.dependency_files {
            result.enqueue(dep_path.clone());
        }

        while let Some(current_path) = result.next_path() {
            let Some((view, identity)) = Self::load_assembly_view(&current_path, validation_config)
            else {
                if let Some(name) = current_path.file_stem() {
                    result.record_failure(
                        name.to_string_lossy().to_string(),
                        "Failed to load assembly".to_string(),
                    );
                }
                continue;
            };

            if current_path == primary_path {
                result.primary_identity = Some(identity.clone());
            }

            if result.pending_views.contains_key(&identity) {
                continue;
            }

            let dependencies = view.dependencies();
            result.pending_views.insert(identity, view);

            if self.auto_discover {
                self.resolve_dependencies(dependencies, search_dir, result);
            }
        }

        if result.pending_views.is_empty() {
            return Err(Error::Configuration(format!(
                "Failed to discover any assemblies, including the primary file: {}. \
                 This may indicate the file is corrupted or not a valid .NET assembly.",
                primary_path.display()
            )));
        }

        Ok(())
    }

    /// Try to load a file as a `CilAssemblyView` and extract its identity.
    ///
    /// Returns `None` if the file cannot be loaded or is not a CLR assembly.
    fn load_assembly_view(
        path: &Path,
        validation_config: ValidationConfig,
    ) -> Option<(CilAssemblyView, AssemblyIdentity)> {
        let file = File::from_path(path).ok()?;
        if !file.is_clr() {
            return None;
        }

        let view =
            CilAssemblyView::from_dotscope_file_with_validation(file, validation_config).ok()?;
        let identity = view.identity().ok().flatten()?;
        Some((view, identity))
    }

    /// Resolve dependencies and add them to the discovery queue.
    fn resolve_dependencies(
        &self,
        dependencies: Vec<AssemblyIdentity>,
        search_dir: &Path,
        result: &mut ProjectResult,
    ) {
        for required in dependencies {
            if result.has_compatible_version(&required) {
                continue;
            }

            match self.resolve_dependency(&required, search_dir) {
                Some((path, actual)) => {
                    if !actual.satisfies(&required) {
                        result.record_version_mismatch(required, actual);
                    }
                    result.enqueue(path);
                }
                None => {
                    result
                        .record_failure(required.name.clone(), "Dependency not found".to_string());
                }
            }
        }
    }

    /// Phase 2: Load all discovered assemblies in parallel.
    ///
    /// Creates `CilObject` instances from the discovered `CilAssemblyView`s using
    /// parallel loading with `ProjectContext` coordination for handling cycles.
    fn load_assemblies_parallel(&self, result: &mut ProjectResult) -> Result<()> {
        let views = result.take_pending_views();
        let primary_identity = result.primary_identity.clone();

        let project_context = Arc::new(ProjectContext::new(views.len())?);

        // Sort by assembly name to ensure deterministic loading order.
        // This prevents race conditions where HashMap's non-deterministic iteration
        // could cause barrier synchronization issues with cross-assembly dependencies.
        let mut sorted_views: Vec<_> = views.into_iter().collect();
        sorted_views.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));

        let handles: Vec<_> = sorted_views
            .into_iter()
            .map(|(identity, view)| {
                let context = project_context.clone();
                let validation_config = self.validation_config.unwrap_or_default();
                std::thread::spawn(move || {
                    let load_result =
                        CilObject::from_project(view, context.as_ref(), validation_config);
                    if let Err(ref e) = load_result {
                        context.break_all_barriers(&format!(
                            "Assembly {} failed to load: {}",
                            identity.name, e
                        ));
                    }
                    (identity, load_result)
                })
            })
            .collect();

        for handle in handles {
            let (identity, load_result) = match handle.join() {
                Ok(val) => val,
                Err(_) => {
                    result.record_failure(
                        "unknown".to_string(),
                        "assembly loading thread panicked".to_string(),
                    );
                    continue;
                }
            };
            match load_result {
                Ok(cil_object) => {
                    let is_primary = primary_identity
                        .as_ref()
                        .is_some_and(|primary_id| identity == *primary_id);

                    if let Err(e) = result.project.add_assembly(cil_object, is_primary) {
                        if self.strict_mode {
                            return Err(Error::Configuration(format!(
                                "Failed to add {} to project: {}",
                                identity.name, e
                            )));
                        }
                        result.record_failure(identity.name.clone(), e.to_string());
                    } else {
                        result.record_success(Some(identity));
                    }
                }
                Err(e) => {
                    if self.strict_mode {
                        return Err(Error::Configuration(format!(
                            "Failed to load {} in strict mode: {}",
                            identity.name, e
                        )));
                    }
                    result.record_failure(identity.name, e.to_string());
                }
            }
        }

        Ok(())
    }

    /// Resolve a dependency by finding an assembly file.
    ///
    /// This method searches for assembly files that match the required identity.
    /// It prefers compatible versions (same major, >= required) but will return
    /// the closest version match if no compatible version is found.
    ///
    /// Version selection priority:
    /// 1. Compatible version (same major, >= required) - returned immediately
    /// 2. Same major version but lower - closer to required is better
    /// 3. Different major version - closer to required major is better
    ///
    /// # Arguments
    ///
    /// * `required` - The assembly identity required by a dependency
    /// * `search_dir` - The primary search directory (typically the primary assembly's directory)
    ///
    /// # Returns
    ///
    /// * `Some((path, identity))` - An assembly with the matching name was found
    /// * `None` - No assembly with the matching name found in any search location
    fn resolve_dependency(
        &self,
        required: &AssemblyIdentity,
        search_dir: &Path,
    ) -> Option<(PathBuf, AssemblyIdentity)> {
        let candidate_paths = self.find_candidate_files(&required.name, search_dir);

        let mut best_match: Option<(PathBuf, AssemblyIdentity)> = None;

        for path in candidate_paths {
            let file = match File::from_path(&path) {
                Ok(f) if f.is_clr() => f,
                _ => continue,
            };

            let Ok(view) = CilAssemblyView::from_dotscope_file(file) else {
                continue;
            };

            let Ok(Some(identity)) = view.identity() else {
                continue;
            };

            if identity.satisfies(required) {
                return Some((path, identity));
            }

            let dominated = best_match.as_ref().is_some_and(|(_, best)| {
                best.version
                    .is_closer_to(&identity.version, &required.version)
            });

            if !dominated {
                best_match = Some((path, identity));
            }
        }

        best_match
    }

    /// Find candidate file paths for an assembly name.
    ///
    /// Returns paths to check for an assembly with the given name.
    /// Files are not validated at this stage - just path construction.
    fn find_candidate_files(&self, name: &str, search_dir: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        for search_path in &self.search_paths {
            paths.push(search_path.join(format!("{name}.dll")));
            paths.push(search_path.join(format!("{name}.exe")));
        }

        paths.push(search_dir.join(format!("{name}.dll")));
        paths.push(search_dir.join(format!("{name}.exe")));

        paths.into_iter().filter(|p| p.exists()).collect()
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
