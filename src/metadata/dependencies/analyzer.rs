//! Dependency analysis and extraction from .NET metadata.
//!
//! This module provides functionality to analyze .NET metadata tables and extract
//! dependency relationships that feed into the assembly dependency graph. It serves
//! as the bridge between raw metadata table entries and the structured dependency
//! representation used for multi-assembly analysis.

use std::sync::Arc;

use crate::metadata::{
    dependencies::{
        AssemblyDependency, AssemblyDependencyGraph, DependencyResolutionState, DependencySource,
        DependencyType, VersionRequirement,
    },
    identity::{AssemblyIdentity, AssemblyVersion, Identity},
    loader::LoaderContext,
    tables::{AssemblyRefRaw, File, FileRaw, ModuleRef, ModuleRefRaw},
};
use crate::Result;

/// Perform dependency analysis on a loaded assembly context.
///
/// This function analyzes the metadata tables in a LoaderContext to extract
/// dependency relationships and populate a dependency graph. It should be called
/// after all metadata table loaders have completed successfully.
///
/// # Arguments
/// * `context` - The loader context containing loaded metadata tables
/// * `dependency_graph` - The dependency graph to populate with discovered relationships
///
/// # Returns
/// * `Ok(())` - Dependency analysis completed successfully
/// * `Err(_)` - Error occurred during dependency analysis
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::dependencies::{AssemblyDependencyGraph, perform_dependency_analysis};
/// use dotscope::metadata::loader::LoaderContext;
///
/// let dependency_graph = Arc::new(AssemblyDependencyGraph::new());
///
/// // After loading metadata tables...
/// perform_dependency_analysis(&context, dependency_graph.clone())?;
///
/// // Now analyze the dependency graph
/// if let Some(cycles) = dependency_graph.find_cycles()? {
///     println!("Circular dependencies detected: {:?}", cycles);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub(crate) fn perform_dependency_analysis(
    context: &LoaderContext,
    dependency_graph: Arc<AssemblyDependencyGraph>,
) -> Result<()> {
    let analyzer = DependencyAnalyzer::new(dependency_graph);
    analyzer.analyze_all_dependencies(context)
}

/// Analyzer for extracting dependency relationships from .NET metadata.
///
/// This component processes metadata tables during assembly loading to identify
/// and extract dependency relationships. It works in coordination with the metadata
/// loader system to build the complete dependency graph as assemblies are processed.
///
/// # Integration with Loading Pipeline
///
/// The analyzer integrates with the metadata loading system:
/// 1. **Table Loaders** call analyzer methods as they process metadata
/// 2. **LoaderContext** provides access to metadata tables and storage
/// 3. **AssemblyDependencyGraph** receives the extracted dependencies
/// 4. **Concurrent Processing** ensures thread-safe dependency extraction
///
/// # Dependency Sources
///
/// The analyzer processes multiple metadata tables:
/// - **AssemblyRef**: External assembly references (primary source)
/// - **ModuleRef**: External module references (multi-module scenarios)
/// - **File**: File references (multi-file assemblies)
///
/// # Usage Patterns
///
/// ## Integration with Loaders
///
/// ```rust,ignore
/// // In a table loader (e.g., AssemblyRefLoader)
/// impl MetadataLoader for AssemblyRefLoader {
///     fn load(&self, context: &LoaderContext) -> Result<()> {
///         // ... existing loading logic ...
///         
///         // Extract dependencies for graph building
///         if let Some(analyzer) = &context.dependency_analyzer {
///             analyzer.analyze_assembly_references(context)?;
///         }
///         
///         Ok(())
///     }
/// }
/// ```
///
/// ## Standalone Analysis
///
/// ```rust,ignore
/// use dotscope::metadata::dependencies::{DependencyAnalyzer, AssemblyDependencyGraph};
///
/// let graph = AssemblyDependencyGraph::new();
/// let analyzer = DependencyAnalyzer::new(graph);
///
/// // Analyze specific metadata tables
/// analyzer.analyze_assembly_references(&context)?;
/// analyzer.analyze_module_references(&context)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// The analyzer is designed for concurrent operation:
/// - **Stateless Design**: No internal mutable state
/// - **Arc-based Sharing**: Safe sharing across threads
/// - **Lock-free Operations**: Minimal synchronization overhead
/// - **Concurrent Graph Updates**: Thread-safe dependency graph modifications
pub struct DependencyAnalyzer {
    /// Reference to the dependency graph being populated
    ///
    /// The analyzer adds discovered dependencies to this graph as it
    /// processes metadata tables. The graph handles thread synchronization
    /// and concurrent access from multiple analyzer instances.
    graph: Arc<AssemblyDependencyGraph>,
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer for the specified graph.
    ///
    /// The analyzer will add all discovered dependencies to the provided
    /// graph. Multiple analyzers can share the same graph for concurrent
    /// processing of different assemblies or metadata tables.
    ///
    /// # Arguments
    /// * `graph` - The dependency graph to populate with discovered dependencies
    ///
    /// # Returns
    /// A new analyzer instance ready to process metadata tables
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::dependencies::{DependencyAnalyzer, AssemblyDependencyGraph};
    ///
    /// let graph = Arc::new(AssemblyDependencyGraph::new());
    /// let analyzer = DependencyAnalyzer::new(graph);
    /// ```
    #[must_use]
    pub fn new(graph: Arc<AssemblyDependencyGraph>) -> Self {
        Self { graph }
    }

    /// Analyze AssemblyRef table entries to extract assembly dependencies.
    ///
    /// Processes all AssemblyRef entries in the metadata to identify external
    /// assembly dependencies. This is the primary source of dependency information
    /// for most .NET assemblies.
    ///
    /// # Arguments
    /// * `context` - Loader context with access to metadata tables and heaps
    ///
    /// # Returns
    /// * `Ok(())` - Analysis completed successfully
    /// * `Err(_)` - Error occurred during dependency analysis
    ///
    /// # Processing Logic
    ///
    /// For each AssemblyRef entry:
    /// 1. Extract target assembly identity (name, version, culture, strong name)
    /// 2. Determine dependency type (standard reference, friend assembly, etc.)
    /// 3. Create dependency relationship with source assembly context
    /// 4. Add to dependency graph for cycle detection and ordering
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Called from AssemblyRefLoader during metadata processing
    /// analyzer.analyze_assembly_references(&context)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub(crate) fn analyze_assembly_references(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blobs)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<AssemblyRefRaw>() {
                // Get the source assembly identity from the current context
                let source_identity = Self::extract_current_assembly_identity(context)?;

                for row in table {
                    // Convert raw AssemblyRef to owned representation
                    let assembly_ref = row.to_owned(strings, blobs)?;

                    // Extract target assembly identity
                    let target_identity = AssemblyIdentity::from_assembly_ref(&assembly_ref);

                    // Create dependency relationship
                    let dependency = AssemblyDependency {
                        source: DependencySource::AssemblyRef(assembly_ref),
                        target_identity,
                        dependency_type: DependencyType::Reference, // Standard assembly reference
                        version_requirement: VersionRequirement::Compatible, // Default policy
                        is_optional: false, // AssemblyRef dependencies are typically required
                        resolution_state: DependencyResolutionState::Unresolved, // Will be resolved lazily
                    };

                    // Add to dependency graph with explicit source identity
                    self.graph
                        .add_dependency_with_source(source_identity.clone(), dependency)?;
                }
            }
        }

        Ok(())
    }

    /// Analyze ModuleRef table entries to extract module dependencies.
    ///
    /// Processes ModuleRef entries to identify external module dependencies.
    /// This implementation focuses on tracking dependencies that represent
    /// cross-assembly relationships, filtering out native library references
    /// which don't represent .NET assembly dependencies.
    ///
    /// # ModuleRef Categories
    ///
    /// - **Native Libraries**: System DLLs like kernel32.dll, user32.dll (filtered out)
    /// - **External .NET Modules**: Modules from other assemblies (tracked)
    /// - **Intra-Assembly Modules**: .netmodule files in multi-module assemblies (tracked for completeness)
    /// - **Mixed-Mode Components**: Modules containing both managed and native code (tracked)
    ///
    /// # Arguments
    /// * `context` - Loader context with access to metadata tables and heaps
    ///
    /// # Returns
    /// * `Ok(())` - Analysis completed successfully  
    /// * `Err(_)` - Error occurred during dependency analysis
    ///
    /// # Processing Logic
    ///
    /// For each ModuleRef entry:
    /// 1. Classify module type based on naming conventions
    /// 2. Filter out pure native library references (no .NET dependency)
    /// 3. For .NET modules, create placeholder assembly identity
    /// 4. Create dependency relationship with appropriate classification
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Called during dependency analysis
    /// analyzer.analyze_module_references(&context)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub(crate) fn analyze_module_references(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings)) = (context.meta, context.strings) {
            if let Some(table) = header.table::<ModuleRefRaw>() {
                let source_identity = Self::extract_current_assembly_identity(context)?;

                for row in table {
                    // Convert raw ModuleRef to owned representation
                    let module_ref = row.to_owned(strings)?;

                    // Classify module reference type
                    let module_classification = Self::classify_module_ref(&module_ref);

                    match module_classification {
                        ModuleRefType::NativeLibrary => {
                            // Native libraries (kernel32.dll, user32.dll, etc.) don't represent
                            // .NET assembly dependencies, so we skip them for dependency tracking
                        }
                        ModuleRefType::NetModule => {
                            // .netmodule files are part of multi-module assemblies
                            // Create dependency with module context
                            let target_identity =
                                Self::create_module_assembly_identity(&module_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::ModuleRef(module_ref),
                                target_identity,
                                dependency_type: DependencyType::Reference,
                                version_requirement: VersionRequirement::Compatible,
                                is_optional: false,
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                        ModuleRefType::ExternalAssemblyModule => {
                            // Module from external assembly - create cross-assembly dependency
                            let target_identity =
                                Self::create_module_assembly_identity(&module_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::ModuleRef(module_ref),
                                target_identity,
                                dependency_type: DependencyType::Reference,
                                version_requirement: VersionRequirement::Compatible,
                                is_optional: false,
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                        ModuleRefType::Unknown => {
                            // Unknown module type - create dependency for completeness with warning
                            let target_identity =
                                Self::create_module_assembly_identity(&module_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::ModuleRef(module_ref),
                                target_identity,
                                dependency_type: DependencyType::Reference,
                                version_requirement: VersionRequirement::Any, // More flexible for unknown
                                is_optional: true, // Mark as optional since we're unsure
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Analyze File table entries to extract file dependencies.
    ///
    /// Processes File table entries to identify files that are part of
    /// multi-file assemblies. While most File entries represent intra-assembly
    /// components, some may indicate external dependencies that should be tracked.
    ///
    /// # File Entry Types
    ///
    /// - **Executable Modules**: .netmodule files with CONTAINS_META_DATA flag
    /// - **Resource Files**: .resources files with CONTAINS_NO_META_DATA flag
    /// - **Native Libraries**: Unmanaged DLLs referenced by the assembly
    /// - **Documentation Files**: XML documentation and other metadata files
    ///
    /// # Arguments
    /// * `context` - Loader context with access to metadata tables and heaps
    ///
    /// # Returns
    /// * `Ok(())` - Analysis completed successfully
    /// * `Err(_)` - Error occurred during dependency analysis
    ///
    /// # Processing Logic
    ///
    /// For each File entry:
    /// 1. Classify file type based on flags and extension
    /// 2. Determine if file represents external dependency
    /// 3. For external files, create appropriate dependency relationship
    /// 4. Track significant files for multi-assembly analysis
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Called during dependency analysis
    /// analyzer.analyze_file_references(&context)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub(crate) fn analyze_file_references(&self, context: &LoaderContext) -> Result<()> {
        if let (Some(header), Some(strings), Some(blobs)) =
            (context.meta, context.strings, context.blobs)
        {
            if let Some(table) = header.table::<FileRaw>() {
                let source_identity = Self::extract_current_assembly_identity(context)?;

                for row in table {
                    // Convert raw File to owned representation
                    let file_ref = row.to_owned(blobs, strings)?;

                    // Classify file type based on flags and characteristics
                    let file_classification = Self::classify_file_ref(&file_ref);

                    match file_classification {
                        FileRefType::IntraAssemblyModule => {
                            // .netmodule file that's part of this assembly
                            // Track for multi-module assembly completeness
                            let target_identity = Self::create_file_assembly_identity(&file_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::File(file_ref),
                                target_identity,
                                dependency_type: DependencyType::Reference,
                                version_requirement: VersionRequirement::Exact, // Same assembly, exact match
                                is_optional: false,
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                        FileRefType::ResourceFile => {
                            // Resource files (.resources, .resx, etc.)
                            // Track as resource dependencies
                            let target_identity = Self::create_file_assembly_identity(&file_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::File(file_ref),
                                target_identity,
                                dependency_type: DependencyType::Resource,
                                version_requirement: VersionRequirement::Compatible,
                                is_optional: true, // Resources are often optional
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                        FileRefType::ExternalAssemblyFile => {
                            // File from external assembly
                            let target_identity = Self::create_file_assembly_identity(&file_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::File(file_ref),
                                target_identity,
                                dependency_type: DependencyType::Reference,
                                version_requirement: VersionRequirement::Compatible,
                                is_optional: false,
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                        FileRefType::DocumentationFile => {
                            // Documentation files (.xml, .pdb, etc.)
                            // These are typically optional and don't affect loading
                        }
                        FileRefType::Unknown => {
                            // Unknown file type - track with caution
                            let target_identity = Self::create_file_assembly_identity(&file_ref);

                            let dependency = AssemblyDependency {
                                source: DependencySource::File(file_ref),
                                target_identity,
                                dependency_type: DependencyType::Reference,
                                version_requirement: VersionRequirement::Any,
                                is_optional: true, // Unknown files are treated as optional
                                resolution_state: DependencyResolutionState::Unresolved,
                            };

                            self.graph
                                .add_dependency_with_source(source_identity.clone(), dependency)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get a reference to the dependency graph being populated.
    ///
    /// Provides access to the dependency graph for querying current state,
    /// performing analysis, or coordinating with other components.
    ///
    /// # Returns
    /// Shared reference to the dependency graph
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let analyzer = DependencyAnalyzer::new(graph);
    /// let graph_ref = analyzer.dependency_graph();
    /// println!("Graph has {} dependencies", graph_ref.dependency_count());
    /// ```
    #[must_use]
    pub fn dependency_graph(&self) -> &Arc<AssemblyDependencyGraph> {
        &self.graph
    }

    /// Analyze all supported metadata tables for dependencies.
    ///
    /// Convenience method that runs analysis on all supported metadata tables
    /// in the appropriate order. This is useful for batch processing of
    /// complete assemblies.
    ///
    /// # Arguments
    /// * `context` - Loader context with access to metadata tables and heaps
    ///
    /// # Returns
    /// * `Ok(())` - All analyses completed successfully
    /// * `Err(_)` - Error occurred during dependency analysis
    ///
    /// # Processing Order
    ///
    /// 1. **AssemblyRef** - Primary external assembly dependencies
    /// 2. **ModuleRef** - External module dependencies  
    /// 3. **File** - File dependencies (mostly intra-assembly)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Analyze all dependency sources for an assembly
    /// analyzer.analyze_all_dependencies(&context)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub(crate) fn analyze_all_dependencies(&self, context: &LoaderContext) -> Result<()> {
        // Process in order of importance and complexity
        self.analyze_assembly_references(context)?;
        self.analyze_module_references(context)?;
        self.analyze_file_references(context)?;

        Ok(())
    }

    /// Classify a ModuleRef entry to determine its dependency significance.
    ///
    /// Analyzes the module name and characteristics to determine whether it represents
    /// a significant dependency for cross-assembly analysis or should be filtered out.
    ///
    /// # Classification Logic
    ///
    /// - **Native Libraries**: Win32 system DLLs, C runtime libraries (filtered out)
    /// - **.NET Modules**: .netmodule files, managed assemblies (tracked)
    /// - **Mixed Modules**: Components with both managed and native code (tracked)
    /// - **Unknown**: Unrecognized patterns (tracked with caution)
    ///
    /// # Arguments
    /// * `module_ref` - The ModuleRef entry to classify
    ///
    /// # Returns
    /// Classification enum indicating the module type and tracking recommendation
    fn classify_module_ref(module_ref: &ModuleRef) -> ModuleRefType {
        let name = &module_ref.name;

        // Check for common native library patterns
        if Self::is_native_library(name) {
            return ModuleRefType::NativeLibrary;
        }

        // Check for .NET module patterns
        if name.ends_with(".netmodule") {
            return ModuleRefType::NetModule;
        }

        // Check for potential external assembly modules
        if std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("dll") || ext.eq_ignore_ascii_case("exe"))
        {
            // This could be an external assembly module
            return ModuleRefType::ExternalAssemblyModule;
        }

        // Unknown pattern - track with caution
        ModuleRefType::Unknown
    }

    /// Check if a module name represents a native library rather than a .NET assembly.
    ///
    /// Uses common patterns and naming conventions to identify native system libraries
    /// that don't represent .NET assembly dependencies.
    ///
    /// # Arguments
    /// * `name` - Module name to check
    ///
    /// # Returns
    /// `true` if the module appears to be a native library, `false` otherwise
    fn is_native_library(name: &str) -> bool {
        // Common Windows system libraries
        const NATIVE_LIBRARIES: &[&str] = &[
            "kernel32.dll",
            "user32.dll",
            "gdi32.dll",
            "advapi32.dll",
            "ole32.dll",
            "oleaut32.dll",
            "shell32.dll",
            "comdlg32.dll",
            "comctl32.dll",
            "winmm.dll",
            "msvcrt.dll",
            "ntdll.dll",
            "ws2_32.dll",
            "wininet.dll",
            "crypt32.dll",
            "version.dll",
            "psapi.dll",
            "dbghelp.dll",
            "imagehlp.dll",
            "userenv.dll",
        ];
        const NATIVE_PREFIXES: &[&str] = &["msvcr", "msvcp", "vcruntime", "api-ms-", "ext-ms-"];

        // Convert to lowercase for case-insensitive matching
        let lower_name = name.to_lowercase();

        // Check exact matches first
        if NATIVE_LIBRARIES.iter().any(|&lib| lower_name == lib) {
            return true;
        }

        // Check common prefixes for system libraries
        if NATIVE_PREFIXES
            .iter()
            .any(|&prefix| lower_name.starts_with(prefix))
        {
            return true;
        }

        false
    }

    /// Create an assembly identity for a module reference.
    ///
    /// Since ModuleRef entries only contain module names, we need to create
    /// placeholder assembly identities. In a full implementation, this would
    /// involve resolving the module to its containing assembly.
    ///
    /// # Arguments
    /// * `module_ref` - The ModuleRef entry to create identity for
    ///
    /// # Returns
    /// AssemblyIdentity representing the target assembly containing the module
    fn create_module_assembly_identity(module_ref: &ModuleRef) -> AssemblyIdentity {
        // For now, create a placeholder identity based on the module name
        // In a full implementation, this would resolve to the actual assembly
        let assembly_name = if let Some(name_without_ext) = module_ref.name.strip_suffix(".dll") {
            name_without_ext.to_string()
        } else if let Some(name_without_ext) = module_ref.name.strip_suffix(".exe") {
            name_without_ext.to_string()
        } else if let Some(name_without_ext) = module_ref.name.strip_suffix(".netmodule") {
            name_without_ext.to_string()
        } else {
            module_ref.name.clone()
        };

        AssemblyIdentity {
            name: assembly_name,
            version: AssemblyVersion::new(0, 0, 0, 0), // Unknown version
            culture: None,
            strong_name: None,
            processor_architecture: None,
        }
    }

    /// Classify a File entry to determine its dependency significance.
    ///
    /// Analyzes the file flags, name, and characteristics to determine whether
    /// it represents a significant dependency for cross-assembly analysis.
    ///
    /// # Classification Logic
    ///
    /// - **Executable Modules**: Files with CONTAINS_META_DATA flag (.netmodule)
    /// - **Resource Files**: Files with CONTAINS_NO_META_DATA flag (.resources)
    /// - **External Files**: Files that may be from external assemblies
    /// - **Documentation**: Files that don't affect runtime behavior
    ///
    /// # Arguments
    /// * `file_ref` - The File entry to classify
    ///
    /// # Returns
    /// Classification enum indicating the file type and tracking recommendation
    fn classify_file_ref(file_ref: &File) -> FileRefType {
        // Check file attributes from the File table
        const CONTAINS_META_DATA: u32 = 0x0000;
        const CONTAINS_NO_META_DATA: u32 = 0x0001;

        let name = &file_ref.name;
        let flags = file_ref.flags;
        let path = std::path::Path::new(name);

        // Check for executable modules (.netmodule files)
        if flags == CONTAINS_META_DATA && name.ends_with(".netmodule") {
            return FileRefType::IntraAssemblyModule;
        }

        let Some(extension) = path.extension() else {
            return FileRefType::Unknown;
        };

        // Check for resource files
        if flags == CONTAINS_NO_META_DATA
            && (extension.eq_ignore_ascii_case("resources")
                || extension.eq_ignore_ascii_case("resx"))
        {
            return FileRefType::ResourceFile;
        }

        // Check for documentation files
        if extension.eq_ignore_ascii_case("xml")
            || extension.eq_ignore_ascii_case("pdb")
            || extension.eq_ignore_ascii_case("mdb")
        {
            return FileRefType::DocumentationFile;
        }

        // Check for potential external assembly files
        if extension.eq_ignore_ascii_case("dll") || extension.eq_ignore_ascii_case("exe") {
            return FileRefType::ExternalAssemblyFile;
        }

        // Unknown file type
        FileRefType::Unknown
    }

    /// Create an assembly identity for a file reference.
    ///
    /// Since File entries may represent components of multi-file assemblies
    /// or external files, we create appropriate identities based on context.
    ///
    /// # Arguments
    /// * `file_ref` - The File entry to create identity for
    ///
    /// # Returns
    /// AssemblyIdentity representing the target assembly containing the file
    fn create_file_assembly_identity(file_ref: &File) -> AssemblyIdentity {
        // For File entries, create identity based on the file name
        // In most cases, files are part of the same assembly (multi-file assemblies)
        let assembly_name = if let Some(name_without_ext) = file_ref.name.strip_suffix(".dll") {
            name_without_ext.to_string()
        } else if let Some(name_without_ext) = file_ref.name.strip_suffix(".exe") {
            name_without_ext.to_string()
        } else if let Some(name_without_ext) = file_ref.name.strip_suffix(".netmodule") {
            name_without_ext.to_string()
        } else if let Some(name_without_ext) = file_ref.name.strip_suffix(".resources") {
            // For resource files, use the base name
            name_without_ext.to_string()
        } else {
            // Use the file name as-is for other types
            file_ref.name.clone()
        };

        AssemblyIdentity {
            name: assembly_name,
            version: AssemblyVersion::new(0, 0, 0, 0), // Unknown version
            culture: None,
            strong_name: None,
            processor_architecture: None,
        }
    }

    /// Extract source assembly identity from a loaded assembly context.
    ///
    /// Uses the assembly metadata in the LoaderContext to determine the identity
    /// of the current assembly being processed. This provides the source identity
    /// needed for dependency relationships.
    ///
    /// # Arguments
    /// * `context` - Loader context with loaded assembly metadata
    ///
    /// # Returns
    /// AssemblyIdentity representing the current assembly being analyzed
    fn extract_current_assembly_identity(context: &LoaderContext) -> Result<AssemblyIdentity> {
        // Try to get the assembly from the context
        if let Some(assembly_lock) = context.assembly.get() {
            // Convert public key data to Identity if present
            let strong_name = if let Some(ref public_key_data) = assembly_lock.public_key {
                Some(Identity::from(public_key_data, true)?)
            } else {
                None
            };

            // Extract identity from the loaded assembly metadata
            #[allow(clippy::cast_possible_truncation)]
            Ok(AssemblyIdentity {
                name: assembly_lock.name.clone(),
                version: AssemblyVersion::new(
                    assembly_lock.major_version as u16,
                    assembly_lock.minor_version as u16,
                    assembly_lock.build_number as u16,
                    assembly_lock.revision_number as u16,
                ),
                culture: assembly_lock.culture.clone(),
                strong_name,
                processor_architecture: None, // TODO: Extract from processor info if available
            })
        } else {
            // Fallback to placeholder if assembly is not yet loaded
            Ok(AssemblyIdentity {
                name: "UnknownAssembly".to_string(),
                version: AssemblyVersion::new(0, 0, 0, 0),
                culture: None,
                strong_name: None,
                processor_architecture: None,
            })
        }
    }
}

/// Classification of ModuleRef entries for dependency tracking.
///
/// Categorizes module references based on their significance for
/// cross-assembly dependency analysis and resolution.
#[derive(Debug, Clone, PartialEq)]
enum ModuleRefType {
    /// Native library (Win32 DLL, C runtime, etc.)
    ///
    /// These don't represent .NET assembly dependencies and are
    /// typically filtered out of dependency tracking.
    NativeLibrary,

    /// .NET module file (.netmodule)
    ///
    /// Part of a multi-module assembly, should be tracked for
    /// completeness but may be intra-assembly rather than cross-assembly.
    NetModule,

    /// External assembly module
    ///
    /// Module from another .NET assembly that represents a
    /// cross-assembly dependency requiring resolution.
    ExternalAssemblyModule,

    /// Unknown module type
    ///
    /// Unrecognized pattern that should be tracked with caution
    /// and flexible resolution policies.
    Unknown,
}

/// Classification of File entries for dependency tracking.
///
/// Categorizes file references based on their significance for
/// cross-assembly dependency analysis and resolution.
#[derive(Debug, Clone, PartialEq)]
enum FileRefType {
    /// Intra-assembly module file (.netmodule)
    ///
    /// Module that's part of the current assembly in a multi-module
    /// assembly structure. Tracked for completeness.
    IntraAssemblyModule,

    /// Resource file (.resources, .resx)
    ///
    /// Files containing localized strings, images, or other
    /// non-executable resources. Tracked as resource dependencies.
    ResourceFile,

    /// External assembly file
    ///
    /// File from another assembly that represents a cross-assembly
    /// dependency requiring resolution.
    ExternalAssemblyFile,

    /// Documentation file (.xml, .pdb, .mdb)
    ///
    /// Files containing documentation or debug information that
    /// don't affect runtime behavior. Typically filtered out.
    DocumentationFile,

    /// Unknown file type
    ///
    /// Unrecognized file pattern that should be tracked with
    /// caution and flexible resolution policies.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::helpers::dependencies::{create_test_file, create_test_module_ref};

    #[test]
    fn test_dependency_analyzer_creation() {
        let graph = Arc::new(AssemblyDependencyGraph::new());
        let analyzer = DependencyAnalyzer::new(graph.clone());
        assert_eq!(analyzer.dependency_graph().assembly_count(), 0);
    }

    #[test]
    fn test_classify_module_ref_native_library() {
        let kernel32 = create_test_module_ref("kernel32.dll");
        let classification = DependencyAnalyzer::classify_module_ref(&kernel32);
        assert_eq!(classification, ModuleRefType::NativeLibrary);

        let user32 = create_test_module_ref("user32.dll");
        let classification = DependencyAnalyzer::classify_module_ref(&user32);
        assert_eq!(classification, ModuleRefType::NativeLibrary);

        let msvcrt = create_test_module_ref("msvcrt.dll");
        let classification = DependencyAnalyzer::classify_module_ref(&msvcrt);
        assert_eq!(classification, ModuleRefType::NativeLibrary);
    }

    #[test]
    fn test_classify_module_ref_net_module() {
        let netmodule = create_test_module_ref("MyModule.netmodule");
        let classification = DependencyAnalyzer::classify_module_ref(&netmodule);
        assert_eq!(classification, ModuleRefType::NetModule);
    }

    #[test]
    fn test_classify_module_ref_external_assembly() {
        let dll_module = create_test_module_ref("ExternalLibrary.dll");
        let classification = DependencyAnalyzer::classify_module_ref(&dll_module);
        assert_eq!(classification, ModuleRefType::ExternalAssemblyModule);

        let exe_module = create_test_module_ref("Application.exe");
        let classification = DependencyAnalyzer::classify_module_ref(&exe_module);
        assert_eq!(classification, ModuleRefType::ExternalAssemblyModule);
    }

    #[test]
    fn test_classify_module_ref_unknown() {
        let unknown_module = create_test_module_ref("SomeFile.unknown");
        let classification = DependencyAnalyzer::classify_module_ref(&unknown_module);
        assert_eq!(classification, ModuleRefType::Unknown);
    }

    #[test]
    fn test_is_native_library() {
        // Test exact matches
        assert!(DependencyAnalyzer::is_native_library("kernel32.dll"));
        assert!(DependencyAnalyzer::is_native_library("KERNEL32.DLL")); // Case insensitive
        assert!(DependencyAnalyzer::is_native_library("user32.dll"));
        assert!(DependencyAnalyzer::is_native_library("msvcrt.dll"));

        // Test prefix matches
        assert!(DependencyAnalyzer::is_native_library("msvcr120.dll"));
        assert!(DependencyAnalyzer::is_native_library("msvcp140.dll"));
        assert!(DependencyAnalyzer::is_native_library("vcruntime140.dll"));
        assert!(DependencyAnalyzer::is_native_library(
            "api-ms-win-core-kernel32-l1-1-0.dll"
        ));

        // Test non-native libraries
        assert!(!DependencyAnalyzer::is_native_library("System.dll"));
        assert!(!DependencyAnalyzer::is_native_library("MyAssembly.dll"));
        assert!(!DependencyAnalyzer::is_native_library("Module.netmodule"));
    }

    #[test]
    fn test_create_module_assembly_identity() {
        // Test .dll module
        let dll_module = create_test_module_ref("TestLibrary.dll");
        let identity = DependencyAnalyzer::create_module_assembly_identity(&dll_module);
        assert_eq!(identity.name, "TestLibrary");
        assert_eq!(identity.version, AssemblyVersion::new(0, 0, 0, 0));

        // Test .exe module
        let exe_module = create_test_module_ref("Application.exe");
        let identity = DependencyAnalyzer::create_module_assembly_identity(&exe_module);
        assert_eq!(identity.name, "Application");

        // Test .netmodule
        let netmodule = create_test_module_ref("Module.netmodule");
        let identity = DependencyAnalyzer::create_module_assembly_identity(&netmodule);
        assert_eq!(identity.name, "Module");

        // Test module without extension
        let no_ext_module = create_test_module_ref("SomeModule");
        let identity = DependencyAnalyzer::create_module_assembly_identity(&no_ext_module);
        assert_eq!(identity.name, "SomeModule");
    }

    #[test]
    fn test_classify_file_ref_intra_assembly_module() {
        let mut file = create_test_file("Module.netmodule");
        let file_mut = Arc::get_mut(&mut file).unwrap();
        file_mut.flags = 0x0000; // CONTAINS_META_DATA

        let classification = DependencyAnalyzer::classify_file_ref(&file);
        assert_eq!(classification, FileRefType::IntraAssemblyModule);
    }

    #[test]
    fn test_classify_file_ref_resource_file() {
        let mut resources_file = create_test_file("Strings.resources");
        let file_mut = Arc::get_mut(&mut resources_file).unwrap();
        file_mut.flags = 0x0001; // CONTAINS_NO_META_DATA

        let classification = DependencyAnalyzer::classify_file_ref(&resources_file);
        assert_eq!(classification, FileRefType::ResourceFile);

        let mut resx_file = create_test_file("Form.resx");
        let file_mut = Arc::get_mut(&mut resx_file).unwrap();
        file_mut.flags = 0x0001; // CONTAINS_NO_META_DATA

        let classification = DependencyAnalyzer::classify_file_ref(&resx_file);
        assert_eq!(classification, FileRefType::ResourceFile);
    }

    #[test]
    fn test_classify_file_ref_documentation_file() {
        let xml_file = create_test_file("Documentation.xml");
        let classification = DependencyAnalyzer::classify_file_ref(&xml_file);
        assert_eq!(classification, FileRefType::DocumentationFile);

        let pdb_file = create_test_file("Debug.pdb");
        let classification = DependencyAnalyzer::classify_file_ref(&pdb_file);
        assert_eq!(classification, FileRefType::DocumentationFile);

        let mdb_file = create_test_file("Debug.mdb");
        let classification = DependencyAnalyzer::classify_file_ref(&mdb_file);
        assert_eq!(classification, FileRefType::DocumentationFile);
    }

    #[test]
    fn test_classify_file_ref_external_assembly_file() {
        let dll_file = create_test_file("External.dll");
        let classification = DependencyAnalyzer::classify_file_ref(&dll_file);
        assert_eq!(classification, FileRefType::ExternalAssemblyFile);

        let exe_file = create_test_file("Application.exe");
        let classification = DependencyAnalyzer::classify_file_ref(&exe_file);
        assert_eq!(classification, FileRefType::ExternalAssemblyFile);
    }

    #[test]
    fn test_classify_file_ref_unknown() {
        let unknown_file = create_test_file("SomeFile.unknown");
        let classification = DependencyAnalyzer::classify_file_ref(&unknown_file);
        assert_eq!(classification, FileRefType::Unknown);
    }

    #[test]
    fn test_create_file_assembly_identity() {
        // Test .dll file
        let dll_file = create_test_file("TestLibrary.dll");
        let identity = DependencyAnalyzer::create_file_assembly_identity(&dll_file);
        assert_eq!(identity.name, "TestLibrary");
        assert_eq!(identity.version, AssemblyVersion::new(0, 0, 0, 0));

        // Test .exe file
        let exe_file = create_test_file("Application.exe");
        let identity = DependencyAnalyzer::create_file_assembly_identity(&exe_file);
        assert_eq!(identity.name, "Application");

        // Test .netmodule file
        let netmodule_file = create_test_file("Module.netmodule");
        let identity = DependencyAnalyzer::create_file_assembly_identity(&netmodule_file);
        assert_eq!(identity.name, "Module");

        // Test .resources file
        let resources_file = create_test_file("Strings.resources");
        let identity = DependencyAnalyzer::create_file_assembly_identity(&resources_file);
        assert_eq!(identity.name, "Strings");

        // Test file without extension
        let no_ext_file = create_test_file("SomeFile");
        let identity = DependencyAnalyzer::create_file_assembly_identity(&no_ext_file);
        assert_eq!(identity.name, "SomeFile");
    }
}
