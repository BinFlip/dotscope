//! Assembly identity system for multi-assembly .NET analysis.
//!
//! This module provides comprehensive assembly identification and version management
//! for .NET assemblies according to ECMA-335 specifications. It serves as the
//! foundation for cross-assembly resolution and multi-assembly project management.
//!
//! # Key Components
//!
//! - [`AssemblyIdentity`] - Complete assembly identification with name, version, culture, and strong name
//! - [`AssemblyVersion`] - Four-part version numbering (major.minor.build.revision)  
//! - [`ProcessorArchitecture`] - Processor architecture specification
//!
//! # Identity Components
//!
//! .NET assemblies are uniquely identified by the combination of:
//! - **Simple Name**: The primary assembly name (e.g., "mscorlib", "System.Core")
//! - **Version**: Four-part version number for binding and compatibility
//! - **Culture**: Localization culture (None for culture-neutral assemblies)
//! - **Strong Name**: Cryptographic identity for verification and GAC storage
//! - **Architecture**: Target processor architecture for platform-specific assemblies
//!
//! # Assembly Versioning
//!
//! Assembly versions follow the .NET convention of four 16-bit components:
//! - **Major**: Significant API changes, breaking compatibility
//! - **Minor**: Feature additions, backward compatible
//! - **Build**: Bug fixes and minor updates
//! - **Revision**: Emergency patches and hotfixes
//!
//! # Examples
//!
//! ## Creating Assembly Identities
//!
//! ```rust,ignore
//! use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//!
//! // Simple assembly without strong name
//! let simple = AssemblyIdentity::new(
//!     "MyLibrary",
//!     AssemblyVersion::new(1, 2, 3, 4),
//!     None,
//!     None,
//!     None,
//! );
//!
//! // Strong-named framework assembly
//! let mscorlib = AssemblyIdentity::parse(
//!     "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Parsing from Metadata
//!
//! ```rust,ignore
//! use dotscope::metadata::tables::AssemblyRef;
//! use dotscope::metadata::identity::AssemblyIdentity;
//!
//! // Parse from AssemblyRef table entry
//! let assembly_ref: AssemblyRef = // ... loaded from metadata
//! let identity = AssemblyIdentity::from_assembly_ref(&assembly_ref);
//!
//! // Parse from Assembly table entry  
//! let assembly: Assembly = // ... loaded from metadata
//! let identity = AssemblyIdentity::from_assembly(&assembly);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Version Parsing and Display
//!
//! ```rust,ignore
//! use dotscope::metadata::identity::AssemblyVersion;
//!
//! // Parse version string
//! let version = AssemblyVersion::parse("1.2.3.4")?;
//! assert_eq!(version.major, 1);
//! assert_eq!(version.minor, 2);
//!
//! // Display name generation
//! let identity = AssemblyIdentity::parse("System.Core, Version=3.5.0.0")?;
//! println!("Display name: {}", identity.display_name());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration with CilProject
//!
//! This identity system serves as the foundation for:
//! - **Multi-assembly dependency tracking** in AssemblyDependencyGraph
//! - **Cross-assembly type resolution** in GlobalTypeResolver  
//! - **Assembly loading and management** in CilProject container
//! - **Version binding and compatibility** analysis
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement [`Send`] and [`Sync`].
//! Assembly identities can be safely shared across threads and used as keys in
//! concurrent collections like [`DashMap`] and [`HashMap`].

use std::{fmt, str::FromStr};

use crate::{
    metadata::{
        identity::cryptographic::Identity,
        tables::{Assembly, AssemblyRef},
    },
    Error, Result,
};

/// Complete identity information for a .NET assembly.
///
/// Provides comprehensive identification for .NET assemblies including name, version,
/// culture, strong name, and architecture information. This serves as the primary
/// identifier for assemblies in multi-assembly analysis and cross-assembly resolution.
///
/// # Identity Components
///
/// - **Name**: Simple assembly name used for basic identification
/// - **Version**: Four-part version for compatibility and binding decisions
/// - **Culture**: Localization culture (None for culture-neutral assemblies)
/// - **Strong Name**: Cryptographic identity for verification and security
/// - **Architecture**: Target processor architecture specification
///
/// # Uniqueness
///
/// Two assemblies with identical identity components are considered the same assembly.
/// The combination of all components provides sufficient uniqueness for practical
/// assembly identification and resolution scenarios.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
///
/// // Create identity for a simple library
/// let identity = AssemblyIdentity {
///     name: "MyLibrary".to_string(),
///     version: AssemblyVersion::new(1, 0, 0, 0),
///     culture: None,
///     strong_name: None,
///     processor_architecture: None,
/// };
///
/// // Use as key in collections
/// let mut assembly_map = std::collections::HashMap::new();
/// assembly_map.insert(identity, assembly_data);
/// ```
#[derive(Debug, Clone)]
pub struct AssemblyIdentity {
    /// Simple assembly name (e.g., "mscorlib", "System.Core").
    ///
    /// The primary identifier used for basic assembly lookup and display.
    /// This name appears in assembly references and is used for file system
    /// resolution when no culture or architecture specificity is required.
    pub name: String,

    /// Four-part version number for compatibility and binding.
    ///
    /// Used by the .NET runtime for version binding decisions, compatibility
    /// analysis, and side-by-side deployment scenarios. Version policies can
    /// specify exact, minimum, or range-based version requirements.
    pub version: AssemblyVersion,

    /// Culture information for localized assemblies.
    ///
    /// Specifies the localization culture for satellite assemblies containing
    /// culture-specific resources. `None` indicates a culture-neutral assembly
    /// that contains the default/fallback resources and executable code.
    ///
    /// # Examples
    /// - `None` - Culture-neutral assembly (default)
    /// - `Some("en-US")` - US English localized assembly
    /// - `Some("fr-FR")` - French (France) localized assembly
    pub culture: Option<String>,

    /// Cryptographic strong name identity.
    ///
    /// Provides cryptographic verification for assembly integrity and origin.
    /// Strong-named assemblies can be stored in the Global Assembly Cache (GAC)
    /// and provide security guarantees about assembly authenticity.
    ///
    /// Uses the existing cryptographic [`Identity`] system for public key
    /// or token-based identification.
    pub strong_name: Option<Identity>,

    /// Target processor architecture specification.
    ///
    /// Indicates the processor architecture for which the assembly was compiled.
    /// Used for platform-specific assemblies and deployment scenarios requiring
    /// architecture-specific code or optimizations.
    pub processor_architecture: Option<ProcessorArchitecture>,
}

impl PartialEq for AssemblyIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.version == other.version
            && self.culture == other.culture
            && self.processor_architecture == other.processor_architecture
        // Note: strong_name is excluded from equality comparison
        // This allows assemblies with different strong name representations
        // (PubKey vs Token) to be considered equal for dependency resolution
    }
}

impl Eq for AssemblyIdentity {}

impl std::hash::Hash for AssemblyIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.version.hash(state);
        self.culture.hash(state);
        self.processor_architecture.hash(state);
        // Note: strong_name is excluded from hash calculation
        // This ensures assemblies with different strong name representations
        // hash to the same value for consistent HashMap behavior
    }
}

/// Four-part version numbering for .NET assemblies.
///
/// Implements the standard .NET assembly versioning scheme with four 16-bit components.
/// This versioning system supports semantic versioning concepts while maintaining
/// compatibility with .NET runtime version binding and resolution mechanisms.
///
/// # Version Components
///
/// - **Major**: Significant API changes, potentially breaking compatibility
/// - **Minor**: Feature additions, maintaining backward compatibility  
/// - **Build**: Bug fixes, patches, and minor improvements
/// - **Revision**: Emergency fixes and hotfixes
///
/// # Version Comparison
///
/// Versions are compared component-wise in order: major, minor, build, revision.
/// This ordering enables proper version precedence and compatibility analysis
/// for assembly binding and dependency resolution.
///
/// # Examples
///
/// ```rust,ignore
/// use dotscope::metadata::identity::AssemblyVersion;
///
/// // Create version programmatically
/// let version = AssemblyVersion::new(1, 2, 3, 4);
/// assert_eq!(version.to_string(), "1.2.3.4");
///
/// // Parse from string representation
/// let parsed = AssemblyVersion::parse("2.0.0.0")?;
/// assert!(parsed > version);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssemblyVersion {
    /// Major version component.
    ///
    /// Indicates significant changes that may break compatibility with previous versions.
    /// Typically incremented for major feature releases or API redesigns.
    pub major: u16,

    /// Minor version component.
    ///
    /// Indicates feature additions that maintain backward compatibility.
    /// New functionality is added without breaking existing public APIs.
    pub minor: u16,

    /// Build version component.
    ///
    /// Indicates bug fixes, performance improvements, and minor feature updates.
    /// Changes at this level should not affect public API compatibility.
    pub build: u16,

    /// Revision version component.
    ///
    /// Indicates emergency fixes, security patches, and critical hotfixes.
    /// Typically used for minimal changes addressing urgent issues.
    pub revision: u16,
}

/// Processor architecture specification for .NET assemblies.
///
/// Indicates the target processor architecture for platform-specific assemblies.
/// This information guides deployment decisions and runtime loading behavior
/// for architecture-sensitive code and optimizations.
///
/// # Architecture Types
///
/// - **MSIL**: Managed code, architecture-neutral (most common)
/// - **X86**: 32-bit Intel x86 architecture
/// - **IA64**: Intel Itanium 64-bit architecture  
/// - **AMD64**: 64-bit x86-64 architecture (Intel/AMD)
/// - **ARM**: ARM processor architecture
/// - **ARM64**: 64-bit ARM architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessorArchitecture {
    /// Microsoft Intermediate Language - architecture neutral.
    ///
    /// Managed code that can run on any processor architecture supported
    /// by the .NET runtime. This is the most common architecture type
    /// for typical .NET assemblies.
    MSIL,

    /// 32-bit Intel x86 architecture.
    ///
    /// Platform-specific assemblies compiled for 32-bit Intel x86 processors.
    /// May contain P/Invoke calls or unsafe code specific to this architecture.
    X86,

    /// Intel Itanium 64-bit architecture.
    ///
    /// Platform-specific assemblies for Intel Itanium processors.
    /// Largely deprecated but may appear in legacy enterprise environments.
    IA64,

    /// 64-bit x86-64 architecture (Intel/AMD).
    ///
    /// Platform-specific assemblies for modern 64-bit Intel and AMD processors.
    /// Common for performance-critical code requiring 64-bit optimizations.
    AMD64,

    /// ARM processor architecture.
    ///
    /// Platform-specific assemblies for ARM processors, common in mobile
    /// and embedded scenarios where .NET Core/5+ provides ARM support.
    ARM,

    /// 64-bit ARM architecture.
    ///
    /// Platform-specific assemblies for 64-bit ARM processors, increasingly
    /// common with ARM-based servers and Apple Silicon support.
    ARM64,
}

impl AssemblyIdentity {
    /// Create a new assembly identity with the specified components.
    ///
    /// This constructor provides a convenient way to create assembly identities
    /// programmatically with all required and optional components.
    ///
    /// # Arguments
    ///
    /// * `name` - Simple assembly name for identification
    /// * `version` - Four-part version number
    /// * `culture` - Optional culture for localized assemblies
    /// * `strong_name` - Optional cryptographic identity
    /// * `processor_architecture` - Optional architecture specification
    ///
    /// # Returns
    ///
    /// A new `AssemblyIdentity` with the specified components.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let identity = AssemblyIdentity::new(
    ///     "MyLibrary",
    ///     AssemblyVersion::new(1, 0, 0, 0),
    ///     None,
    ///     None,
    ///     None,
    /// );
    /// ```
    pub fn new(
        name: impl Into<String>,
        version: AssemblyVersion,
        culture: Option<String>,
        strong_name: Option<Identity>,
        processor_architecture: Option<ProcessorArchitecture>,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            culture,
            strong_name,
            processor_architecture,
        }
    }

    /// Create assembly identity from an AssemblyRef table entry.
    ///
    /// Extracts complete assembly identity information from a metadata
    /// AssemblyRef entry, including version, culture, and strong name data.
    /// This is the primary method for creating identities during metadata loading.
    ///
    /// # Arguments
    ///
    /// * `assembly_ref` - AssemblyRef table entry from metadata
    ///
    /// # Returns
    ///
    /// Complete `AssemblyIdentity` derived from the AssemblyRef data.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// let assembly_ref = // ... loaded from metadata
    /// let identity = AssemblyIdentity::from_assembly_ref(&assembly_ref);
    /// ```
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_assembly_ref(assembly_ref: &AssemblyRef) -> Self {
        Self {
            name: assembly_ref.name.clone(),
            version: AssemblyVersion::new(
                assembly_ref.major_version as u16,
                assembly_ref.minor_version as u16,
                assembly_ref.build_number as u16,
                assembly_ref.revision_number as u16,
            ),
            culture: assembly_ref.culture.clone(),
            strong_name: assembly_ref.identifier.clone(),
            processor_architecture: None, // TODO: Extract from processor field if available
        }
    }

    /// Create assembly identity from an Assembly table entry.
    ///
    /// Extracts complete assembly identity information from a metadata
    /// Assembly entry for the current assembly being analyzed.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Assembly table entry from metadata
    ///
    /// # Returns
    ///
    /// Complete `AssemblyIdentity` derived from the Assembly data.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// let assembly = // ... loaded from metadata
    /// let identity = AssemblyIdentity::from_assembly(&assembly);
    /// ```
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_assembly(assembly: &Assembly) -> Self {
        Self {
            name: assembly.name.clone(),
            version: AssemblyVersion::new(
                assembly.major_version as u16,
                assembly.minor_version as u16,
                assembly.build_number as u16,
                assembly.revision_number as u16,
            ),
            culture: assembly.culture.clone(),
            strong_name: assembly
                .public_key
                .as_ref()
                .and_then(|key| Identity::from(key, true).ok()),
            processor_architecture: None, // TODO: Extract from flags if available
        }
    }

    /// Parse assembly identity from display name string.
    ///
    /// Parses .NET assembly display names in the standard format used by
    /// the .NET runtime and development tools. Supports both simple names
    /// and fully-qualified names with version, culture, and public key token.
    ///
    /// # Arguments
    ///
    /// * `display_name` - Assembly display name string to parse
    ///
    /// # Returns
    ///
    /// * `Ok(AssemblyIdentity)` - Successfully parsed identity
    /// * `Err(Error)` - Parsing failed due to invalid format
    ///
    /// # Format
    ///
    /// ```text
    /// AssemblyName[, Version=Major.Minor.Build.Revision][, Culture=culture][, PublicKeyToken=token]
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::AssemblyIdentity;
    ///
    /// // Simple name only
    /// let simple = AssemblyIdentity::parse("MyLibrary")?;
    ///
    /// // Full specification
    /// let full = AssemblyIdentity::parse(
    ///     "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if the display name cannot be parsed.
    pub fn parse(display_name: &str) -> Result<Self> {
        let mut version = AssemblyVersion::new(0, 0, 0, 0);
        let mut culture = None;
        let mut strong_name = None;
        let mut processor_architecture = None;

        // Split on commas and process each part
        let parts: Vec<&str> = display_name.split(',').map(str::trim).collect();

        if parts.is_empty() {
            return Err(Error::Error("Empty assembly display name".to_string()));
        }

        // First part is always the assembly name
        let name = parts[0].to_string();

        // Process optional components
        for part in parts.iter().skip(1) {
            if let Some(value) = part.strip_prefix("Version=") {
                version = AssemblyVersion::parse(value)?;
            } else if let Some(value) = part.strip_prefix("Culture=") {
                if value != "neutral" {
                    culture = Some(value.to_string());
                }
            } else if let Some(value) = part.strip_prefix("PublicKeyToken=") {
                if value != "null" && !value.is_empty() {
                    // Parse hex token to bytes and create Identity
                    if let Ok(token_bytes) = hex::decode(value) {
                        if token_bytes.len() == 8 {
                            // Convert 8 bytes to u64 token
                            let mut token_array = [0u8; 8];
                            token_array.copy_from_slice(&token_bytes);
                            let token = u64::from_le_bytes(token_array);
                            strong_name = Some(Identity::Token(token));
                        }
                    }
                }
            } else if let Some(value) = part.strip_prefix("ProcessorArchitecture=") {
                processor_architecture = ProcessorArchitecture::parse(value).ok();
            }
        }

        Ok(Self {
            name,
            version,
            culture,
            strong_name,
            processor_architecture,
        })
    }

    /// Generate display name string for this assembly identity.
    ///
    /// Creates a .NET-compatible assembly display name that includes all
    /// available identity components. This format is compatible with .NET
    /// runtime assembly loading and resolution mechanisms.
    ///
    /// # Returns
    ///
    /// A formatted display name string suitable for assembly loading.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
    ///
    /// let identity = AssemblyIdentity::new(
    ///     "MyLibrary",
    ///     AssemblyVersion::new(1, 2, 3, 4),
    ///     Some("en-US".to_string()),
    ///     None,
    ///     None,
    /// );
    ///
    /// let display_name = identity.display_name();
    /// // Result: "MyLibrary, Version=1.2.3.4, Culture=en-US, PublicKeyToken=null"
    /// ```
    #[must_use]
    pub fn display_name(&self) -> String {
        let mut parts = vec![self.name.clone()];

        // Add version
        parts.push(format!("Version={}", self.version));

        // Add culture
        let culture_str = self.culture.as_deref().unwrap_or("neutral");
        parts.push(format!("Culture={}", culture_str));

        // Add public key token
        let token_str = match &self.strong_name {
            Some(Identity::Token(token)) => format!("{:016x}", token),
            Some(Identity::PubKey(_) | Identity::EcmaKey(_)) | None => "null".to_string(),
        };
        parts.push(format!("PublicKeyToken={}", token_str));

        // Add processor architecture if specified
        if let Some(arch) = &self.processor_architecture {
            parts.push(format!("ProcessorArchitecture={}", arch));
        }

        parts.join(", ")
    }

    /// Get the simple assembly name without version or culture information.
    ///
    /// Returns just the primary assembly name component for cases where
    /// version and culture information is not needed.
    ///
    /// # Returns
    ///
    /// The simple assembly name string.
    #[must_use]
    pub fn simple_name(&self) -> &str {
        &self.name
    }

    /// Check if this assembly is strong-named.
    ///
    /// Strong-named assemblies have cryptographic identity that can be verified
    /// and are eligible for Global Assembly Cache (GAC) storage.
    ///
    /// # Returns
    ///
    /// `true` if the assembly has a strong name, `false` otherwise.
    #[must_use]
    pub fn is_strong_named(&self) -> bool {
        self.strong_name.is_some()
    }

    /// Check if this assembly is culture-neutral.
    ///
    /// Culture-neutral assemblies contain the default resources and executable
    /// code, while culture-specific assemblies contain localized resources.
    ///
    /// # Returns
    ///
    /// `true` if the assembly is culture-neutral, `false` if culture-specific.
    #[must_use]
    pub fn is_culture_neutral(&self) -> bool {
        self.culture.is_none()
    }
}

impl AssemblyVersion {
    /// Create a new assembly version with the specified components.
    ///
    /// # Arguments
    ///
    /// * `major` - Major version component
    /// * `minor` - Minor version component  
    /// * `build` - Build version component
    /// * `revision` - Revision version component
    ///
    /// # Returns
    ///
    /// A new `AssemblyVersion` with the specified components.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let version = AssemblyVersion::new(1, 2, 3, 4);
    /// assert_eq!(version.major, 1);
    /// assert_eq!(version.minor, 2);
    /// ```
    #[must_use]
    pub const fn new(major: u16, minor: u16, build: u16, revision: u16) -> Self {
        Self {
            major,
            minor,
            build,
            revision,
        }
    }

    /// Parse assembly version from string representation.
    ///
    /// Supports various version string formats:
    /// - "1.2.3.4" - Full four-part version
    /// - "1.2.3" - Three-part version (revision defaults to 0)
    /// - "1.2" - Two-part version (build and revision default to 0)
    /// - "1" - Single component (others default to 0)
    ///
    /// # Arguments
    ///
    /// * `version_str` - Version string to parse
    ///
    /// # Returns
    ///
    /// * `Ok(AssemblyVersion)` - Successfully parsed version
    /// * `Err(Error)` - Parsing failed due to invalid format
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use dotscope::metadata::identity::AssemblyVersion;
    ///
    /// let full = AssemblyVersion::parse("1.2.3.4")?;
    /// let partial = AssemblyVersion::parse("2.0")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns an error if the version string has an invalid format.
    pub fn parse(version_str: &str) -> Result<Self> {
        let parts: Vec<&str> = version_str.split('.').collect();

        if parts.is_empty() || parts.len() > 4 {
            return Err(Error::Error(format!(
                "Invalid version format: {}",
                version_str
            )));
        }

        let mut components = [0u16; 4];

        for (i, part) in parts.iter().enumerate() {
            components[i] = part
                .parse::<u16>()
                .map_err(|_| Error::Error(format!("Invalid version component: {}", part)))?;
        }

        Ok(Self::new(
            components[0],
            components[1],
            components[2],
            components[3],
        ))
    }
}

impl ProcessorArchitecture {
    /// Parse processor architecture from string representation.
    ///
    /// Supports standard .NET processor architecture names:
    /// - "MSIL" or "msil" - Microsoft Intermediate Language
    /// - "x86" or "X86" - 32-bit Intel x86
    /// - "IA64" or "ia64" - Intel Itanium 64-bit
    /// - "AMD64" or "amd64" or "x64" - 64-bit x86-64
    /// - "ARM" or "arm" - ARM architecture
    /// - "ARM64" or "arm64" - 64-bit ARM architecture
    ///
    /// # Arguments
    ///
    /// * `arch_str` - Architecture string to parse
    ///
    /// # Returns
    ///
    /// * `Ok(ProcessorArchitecture)` - Successfully parsed architecture
    /// * `Err(Error)` - Parsing failed due to unrecognized architecture
    ///
    /// # Errors
    /// Returns an error if the architecture string is not recognized.
    pub fn parse(arch_str: &str) -> Result<Self> {
        match arch_str.to_lowercase().as_str() {
            "msil" => Ok(Self::MSIL),
            "x86" => Ok(Self::X86),
            "ia64" => Ok(Self::IA64),
            "amd64" | "x64" => Ok(Self::AMD64),
            "arm" => Ok(Self::ARM),
            "arm64" => Ok(Self::ARM64),
            _ => Err(Error::Error(format!(
                "Unknown processor architecture: {}",
                arch_str
            ))),
        }
    }
}

// Display implementations
impl fmt::Display for AssemblyVersion {
    /// Format assembly version as standard dotted notation.
    ///
    /// Produces version strings in the format "major.minor.build.revision"
    /// compatible with .NET version string conventions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

impl fmt::Display for ProcessorArchitecture {
    /// Format processor architecture as string.
    ///
    /// Uses standard .NET processor architecture names for consistency
    /// with runtime and development tool conventions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let arch_str = match self {
            Self::MSIL => "MSIL",
            Self::X86 => "x86",
            Self::IA64 => "IA64",
            Self::AMD64 => "AMD64",
            Self::ARM => "ARM",
            Self::ARM64 => "ARM64",
        };
        write!(f, "{}", arch_str)
    }
}

impl fmt::Display for AssemblyIdentity {
    /// Format assembly identity as display name.
    ///
    /// Delegates to the `display_name()` method for consistent formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// String parsing support
impl FromStr for AssemblyVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl FromStr for AssemblyIdentity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl FromStr for ProcessorArchitecture {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}
