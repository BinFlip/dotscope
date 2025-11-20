//! Dependency type definitions and data structures.
//!
//! This module provides the core data structures used throughout the dependency
//! tracking system, including dependency relationships, version requirements,
//! and source identification.

use crate::metadata::{
    identity::{AssemblyIdentity, AssemblyVersion},
    tables::{AssemblyRefRc, FileRc, ModuleRefRc},
};

/// Represents a dependency relationship between assemblies.
///
/// This structure captures all the information about how one assembly depends on another,
/// including the source of the dependency, version requirements, and dependency semantics.
/// It serves as the fundamental unit of dependency tracking in the multi-assembly system.
///
/// # Dependency Sources
///
/// Dependencies can originate from several metadata tables:
/// - **AssemblyRef**: Standard external assembly references (most common)
/// - **ModuleRef**: External module references in multi-module assemblies
/// - **File**: File references in multi-file assemblies
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as all contained data is either owned or
/// reference-counted through [`Arc`]. It can be safely shared across threads
/// and stored in concurrent collections.
#[derive(Debug, Clone)]
pub struct AssemblyDependency {
    /// The source of this dependency in the metadata
    ///
    /// Identifies which metadata table and specific entry created this dependency
    /// relationship. This enables tracing dependencies back to their origin for
    /// debugging and analysis purposes.
    pub source: DependencySource,

    /// The target assembly that this dependency references
    ///
    /// Complete identity information for the assembly being depended upon,
    /// including name, version, culture, and strong name details.
    pub target_identity: AssemblyIdentity,

    /// The type/nature of this dependency relationship
    ///
    /// Categorizes the dependency to enable different handling strategies
    /// for various types of inter-assembly relationships.
    pub dependency_type: DependencyType,

    /// Version binding requirements for this dependency
    ///
    /// Specifies how strict the version matching should be when resolving
    /// this dependency to an actual assembly file.
    pub version_requirement: VersionRequirement,

    /// Whether this dependency is optional
    ///
    /// Optional dependencies don't prevent assembly loading if they cannot
    /// be resolved, allowing for graceful degradation in functionality.
    pub is_optional: bool,

    /// Current resolution state of this dependency
    ///
    /// Tracks whether this dependency has been resolved through actual loading
    /// attempts, enabling lazy evaluation and more accurate classification.
    /// Initially set to `Unresolved` and updated when resolution is performed.
    pub resolution_state: DependencyResolutionState,
}

/// Source of a dependency relationship within .NET metadata.
///
/// This enum identifies which metadata table and specific entry generated
/// a dependency relationship. This information is crucial for:
/// - **Debugging**: Tracing dependency issues back to metadata source
/// - **Resolution**: Understanding dependency semantics and requirements
/// - **Validation**: Ensuring dependency relationships are semantically valid
/// - **Analysis**: Building comprehensive dependency reports
///
/// # Metadata Table Integration
///
/// Each variant corresponds to a specific .NET metadata table:
/// - [`DependencySource::AssemblyRef`] ↔ `AssemblyRef` table (0x23)
/// - [`DependencySource::ModuleRef`] ↔ `ModuleRef` table (0x1A)  
/// - [`DependencySource::File`] ↔ `File` table (0x26)
#[derive(Debug, Clone)]
pub enum DependencySource {
    /// Dependency from an `AssemblyRef` table entry
    ///
    /// This is the most common dependency source, representing a standard
    /// reference to an external assembly. Contains the complete `AssemblyRef`
    /// metadata including version, culture, and strong name information.
    AssemblyRef(AssemblyRefRc),

    /// Dependency from a `ModuleRef` table entry  
    ///
    /// Represents a reference to an external module, typically in multi-module
    /// assemblies or for P/Invoke scenarios. Less common in modern .NET applications.
    ModuleRef(ModuleRefRc),

    /// Dependency from a `File` table entry
    ///
    /// Represents a file within a multi-file assembly. These are intra-assembly
    /// dependencies rather than cross-assembly dependencies, but are tracked
    /// for completeness and assembly integrity verification.
    File(FileRc),
}

/// Classification of dependency relationship types.
///
/// This enum categorizes the nature of inter-assembly dependencies to enable
/// appropriate handling strategies. Different dependency types may require
/// different resolution policies, loading orders, or error handling approaches.
///
/// # Dependency Semantics
///
/// Each dependency type has specific semantic meaning in the .NET type system:
/// - **Reference**: Standard compile-time and runtime dependency
/// - **Friend**: Grants internal member access across assembly boundaries  
/// - **TypeForwarding**: Redirects type resolution to another assembly
/// - **Resource**: Dependency on external resource files
/// - **NativeLibrary**: Dependency on unmanaged code libraries
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyType {
    /// Standard assembly reference dependency
    ///
    /// The most common dependency type, representing a normal reference to
    /// types and members in an external assembly. These dependencies must
    /// be resolved for the assembly to load successfully.
    Reference,

    /// Friend assembly relationship  
    ///
    /// Special dependency that grants the referencing assembly access to
    /// internal (assembly-level) members of the target assembly. Established
    /// through the `[assembly: InternalsVisibleTo]` attribute.
    Friend,

    /// Type forwarding target
    ///
    /// Represents a type forwarding relationship where types that were
    /// previously defined in one assembly have been moved to another.
    /// The forwarding assembly redirects type resolution to the new location.
    TypeForwarding,

    /// Resource file dependency
    ///
    /// Dependency on external resource files that contain localized strings,
    /// images, or other non-code assets. These are typically satellite
    /// assemblies for internationalization.
    Resource,

    /// Native library dependency
    ///
    /// Dependency on unmanaged (native) code libraries accessed through
    /// P/Invoke or COM interop. These libraries are loaded by the runtime
    /// but not through the standard .NET assembly loading mechanism.
    NativeLibrary,
}

/// Version binding requirements for dependency resolution.
///
/// Specifies how strictly version numbers should be matched when resolving
/// dependencies to actual assembly files. This affects assembly loading
/// behavior and compatibility policies.
///
/// # .NET Version Binding
///
/// The .NET runtime supports various version binding policies:
/// - **Strong naming**: Exact version matching for strong-named assemblies
/// - **Policy redirects**: Version binding redirects in configuration files
/// - **Framework compatibility**: Automatic version binding for framework assemblies
/// - **Private assemblies**: Flexible version matching for private assemblies
///
/// # Resolution Strategy
///
/// Different requirements enable different resolution strategies:
/// - [`VersionRequirement::Exact`]: Strict matching for security-critical scenarios
/// - [`VersionRequirement::Compatible`]: Flexible matching for most dependencies
/// - [`VersionRequirement::Any`]: Maximum flexibility for development scenarios
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRequirement {
    /// Exact version match required
    ///
    /// The dependency resolution must find an assembly with exactly the
    /// specified version number. This is the default behavior for strong-named
    /// assemblies and provides maximum compatibility assurance.
    Exact,

    /// Compatible version acceptable
    ///
    /// The dependency can be satisfied by a compatible version, typically
    /// meaning the same or higher version with the same major version number.
    /// This enables updates and patches while maintaining compatibility.
    Compatible,

    /// Any version acceptable
    ///
    /// The dependency can be satisfied by any available version of the
    /// target assembly. This provides maximum flexibility but may introduce
    /// compatibility risks. Primarily used in development scenarios.
    Any,

    /// Minimum version requirement
    ///
    /// The dependency requires at least the specified version, but newer
    /// versions are acceptable. This is useful for assemblies that require
    /// specific functionality introduced in a particular version.
    Minimum(AssemblyVersion),
}

impl DependencySource {
    /// Get the display name for this dependency source.
    ///
    /// Returns a human-readable identifier for the dependency source,
    /// useful for debugging and error reporting.
    ///
    /// # Returns
    /// A string slice containing the source's display name
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            DependencySource::AssemblyRef(assembly_ref) => &assembly_ref.name,
            DependencySource::ModuleRef(module_ref) => &module_ref.name,
            DependencySource::File(file) => &file.name,
        }
    }

    /// Get the dependency type based on the source metadata.
    ///
    /// Analyzes the source metadata to determine the appropriate dependency
    /// type classification. This enables proper handling of different
    /// dependency relationship semantics.
    ///
    /// # Returns
    /// The dependency type that best represents this source's semantics
    #[must_use]
    pub fn dependency_type(&self) -> DependencyType {
        match self {
            DependencySource::AssemblyRef(_) | DependencySource::ModuleRef(_) => {
                DependencyType::Reference
            }
            DependencySource::File(_) => DependencyType::Resource, // Files are typically resources
        }
    }
}

/// Resolution state for lazy dependency analysis.
///
/// Tracks the current state of dependency resolution attempts, enabling
/// lazy evaluation and more accurate dependency classification based on
/// actual loading results rather than heuristic analysis.
///
/// # Resolution Lifecycle
///
/// Dependencies progress through several states:
/// 1. **Unresolved**: Initial state, no resolution attempted
/// 2. **ResolvedAs...**: Successfully resolved to specific type
/// 3. **ResolutionFailed**: Could not be resolved, with error details
///
/// # Lazy Resolution Benefits
///
/// This approach provides several advantages:
/// - **Accuracy**: Classification based on actual loading attempts
/// - **Performance**: Resolution only when needed
/// - **Debugging**: Detailed error information for failed resolutions
/// - **Flexibility**: Support for multiple resolution strategies
#[derive(Debug, Clone)]
pub enum DependencyResolutionState {
    /// Dependency has not been resolved yet
    ///
    /// Initial state for all dependencies. Resolution can be triggered
    /// by calling resolve methods on the dependency graph.
    Unresolved,

    /// Successfully resolved as a .NET assembly
    ///
    /// The dependency was successfully loaded and verified as a .NET assembly.
    /// Contains the complete assembly identity and verification status.
    ResolvedAsAssembly {
        /// The verified assembly identity
        identity: AssemblyIdentity,
        /// Whether the assembly's strong name was verified
        verified: bool,
    },

    /// Successfully resolved as a native library
    ///
    /// The dependency was identified as a native (unmanaged) library,
    /// typically accessed through P/Invoke or COM interop.
    ResolvedAsNativeLibrary {
        /// Path to the native library file, if found
        path: Option<std::path::PathBuf>,
        /// Whether the library's exports were verified
        exports_verified: bool,
    },

    /// Successfully resolved as a resource file
    ///
    /// The dependency was identified as a resource file containing
    /// non-executable data such as strings, images, or other assets.
    ResolvedAsResource {
        /// Type of resource (e.g., "resources", "resx", "png")
        resource_type: String,
        /// Size of the resource file in bytes, if available
        size_bytes: Option<u64>,
    },

    /// Resolution failed with detailed error information
    ///
    /// The dependency could not be resolved despite attempts. Contains
    /// detailed error information and suggestions for troubleshooting.
    ResolutionFailed {
        /// Description of the resolution failure
        error: String,
        /// Whether this failure should prevent assembly loading
        is_fatal: bool,
        /// Suggestions for resolving the dependency issue
        suggestions: Vec<String>,
    },
}

/// Context information for dependency resolution.
///
/// Provides configuration and environmental information needed for
/// dependency resolution attempts. This includes search paths,
/// version policies, and resolution strategies.
#[derive(Debug, Clone)]
pub struct DependencyResolveContext {
    /// Assembly search paths for resolution
    pub search_paths: Vec<std::path::PathBuf>,

    /// Whether to check the Global Assembly Cache
    pub check_gac: bool,

    /// Version binding policies to apply
    pub version_policies: Vec<String>, // Simplified for now
}

impl Default for DependencyResolveContext {
    fn default() -> Self {
        Self {
            search_paths: vec![],
            check_gac: true,
            version_policies: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::helpers::dependencies::create_test_assembly_ref;

    #[test]
    fn test_dependency_source_display_name() {
        let assembly_ref = create_test_assembly_ref("TestLib");
        let source = DependencySource::AssemblyRef(assembly_ref);
        assert_eq!(source.display_name(), "TestLib");
    }

    #[test]
    fn test_dependency_source_types() {
        let assembly_ref = create_test_assembly_ref("TestLib");
        let assembly_source = DependencySource::AssemblyRef(assembly_ref);
        assert_eq!(assembly_source.dependency_type(), DependencyType::Reference);
    }

    #[test]
    fn test_dependency_resolution_state_initial() {
        let state = DependencyResolutionState::Unresolved;
        matches!(state, DependencyResolutionState::Unresolved);
    }

    #[test]
    fn test_version_requirement_exact() {
        let req = VersionRequirement::Exact;
        assert_eq!(req, VersionRequirement::Exact);
    }

    #[test]
    fn test_version_requirement_minimum() {
        let version = AssemblyVersion::new(1, 2, 3, 4);
        let req = VersionRequirement::Minimum(version);
        match req {
            VersionRequirement::Minimum(v) => {
                assert_eq!(v.major, 1);
                assert_eq!(v.minor, 2);
            }
            _ => panic!("Expected Minimum version requirement"),
        }
    }
}
