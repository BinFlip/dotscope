//! Import declaration types for Portable PDB `ImportScope` format.
//!
//! This module defines all the types used to represent import declarations
//! from Portable PDB files. These types provide structured access to the
//! import information that defines namespace and type visibility within
//! debugging scopes.
//!
//! # Key Components
//!
//! - [`crate::metadata::importscope::types::ImportKind`] - Enumeration of all supported import declaration types
//! - [`crate::metadata::importscope::types::ImportDeclaration`] - Structured representation of individual import declarations
//! - [`crate::metadata::importscope::types::ImportsInfo`] - Container for all imports in a scope with iterator support
//!
//! # Import Declaration Types
//!
//! The Portable PDB format supports 9 different import declaration types:
//! - **Namespace Imports**: Direct namespace access and assembly-qualified namespace access
//! - **Type Imports**: Specific type member imports
//! - **XML Namespace**: XML namespace imports with prefix support
//! - **Alias Definitions**: Various forms of alias definitions for assemblies, namespaces, and types
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement [`std::marker::Send`] and [`std::marker::Sync`].
//! The import declaration types contain only owned data and can be safely shared across threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::importscope::parser`] - Binary parsing of imports blobs using these types
//! - [`crate::metadata::tables`] - ImportScope table processing and token resolution
//! - [`crate::metadata::token`] - Metadata token representation for type and assembly references

use crate::metadata::token::Token;

/// Import declaration kinds as defined in the Portable PDB format specification.
///
/// These constants define the different types of import declarations that can appear
/// in an imports blob. Each kind determines the structure and parameters of the
/// following import data.
///
/// # Format Specification
///
/// Each import kind corresponds to a specific binary format in the imports blob:
/// - Values 1-9 are defined by the Portable PDB specification
/// - Each kind has different parameter requirements (namespace, assembly, type, alias)
/// - Kind values are encoded as compressed unsigned integers in the blob
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::importscope::ImportKind;
///
/// // Convert from blob data
/// let kind = ImportKind::from_u32(1);
/// assert_eq!(kind, Some(ImportKind::ImportNamespace));
///
/// // Check kind values
/// assert_eq!(ImportKind::ImportType as u8, 3);
/// ```
///
/// # Thread Safety
///
/// [`ImportKind`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ImportKind {
    /// Import namespace members
    ImportNamespace = 1,
    /// Import namespace members from specific assembly
    ImportAssemblyNamespace = 2,
    /// Import type members
    ImportType = 3,
    /// Import XML namespace with prefix
    ImportXmlNamespace = 4,
    /// Import assembly reference alias from ancestor scope
    ImportAssemblyReferenceAlias = 5,
    /// Define assembly alias
    DefineAssemblyAlias = 6,
    /// Define namespace alias
    DefineNamespaceAlias = 7,
    /// Define namespace alias from specific assembly
    DefineAssemblyNamespaceAlias = 8,
    /// Define type alias
    DefineTypeAlias = 9,
}

impl ImportKind {
    /// Create an `ImportKind` from a compressed unsigned integer value.
    ///
    /// # Arguments
    /// * `value` - The kind value from the imports blob (1-9)
    ///
    /// # Returns
    /// * [`Some`](ImportKind) - Valid import kind
    /// * [`None`] - Invalid or unsupported kind value
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(ImportKind::ImportNamespace),
            2 => Some(ImportKind::ImportAssemblyNamespace),
            3 => Some(ImportKind::ImportType),
            4 => Some(ImportKind::ImportXmlNamespace),
            5 => Some(ImportKind::ImportAssemblyReferenceAlias),
            6 => Some(ImportKind::DefineAssemblyAlias),
            7 => Some(ImportKind::DefineNamespaceAlias),
            8 => Some(ImportKind::DefineAssemblyNamespaceAlias),
            9 => Some(ImportKind::DefineTypeAlias),
            _ => None,
        }
    }
}

/// Represents a single import declaration from the imports blob.
///
/// Each variant corresponds to a specific import kind and contains the appropriate
/// parameters for that declaration type. String fields contain resolved UTF-8 data
/// from the heap, while token fields contain unresolved metadata tokens.
///
/// # Data Resolution
///
/// - **String Fields**: Resolved from blob heap indices during parsing
/// - **Token Fields**: Unresolved metadata tokens that require additional processing
/// - **Assembly References**: [`crate::metadata::token::Token`] values for AssemblyRef table entries
/// - **Type References**: [`crate::metadata::token::Token`] values with TypeDefOrRefOrSpecEncoded encoding
///
/// # Usage Patterns
///
/// Import declarations are typically processed in batch during scope analysis:
/// - Namespace imports affect symbol resolution scope
/// - Type imports provide direct type member access
/// - Alias definitions create local naming shortcuts
///
/// # Thread Safety
///
/// [`ImportDeclaration`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportDeclaration {
    /// Import namespace members
    ImportNamespace {
        /// Namespace name (resolved from blob heap)
        namespace: String,
    },
    /// Import namespace members from specific assembly
    ImportAssemblyNamespace {
        /// Assembly reference token
        assembly_ref: Token,
        /// Namespace name (resolved from blob heap)
        namespace: String,
    },
    /// Import type members
    ImportType {
        /// Type reference token (`TypeDefOrRefOrSpecEncoded`)
        type_ref: Token,
    },
    /// Import XML namespace with prefix
    ImportXmlNamespace {
        /// XML namespace alias (resolved from blob heap)
        alias: String,
        /// XML namespace URI (resolved from blob heap)
        namespace: String,
    },
    /// Import assembly reference alias from ancestor scope
    ImportAssemblyReferenceAlias {
        /// Alias name (resolved from blob heap)
        alias: String,
    },
    /// Define assembly alias
    DefineAssemblyAlias {
        /// Alias name (resolved from blob heap)
        alias: String,
        /// Assembly reference token
        assembly_ref: Token,
    },
    /// Define namespace alias
    DefineNamespaceAlias {
        /// Alias name (resolved from blob heap)
        alias: String,
        /// Namespace name (resolved from blob heap)
        namespace: String,
    },
    /// Define namespace alias from specific assembly
    DefineAssemblyNamespaceAlias {
        /// Alias name (resolved from blob heap)
        alias: String,
        /// Assembly reference token
        assembly_ref: Token,
        /// Namespace name (resolved from blob heap)
        namespace: String,
    },
    /// Define type alias
    DefineTypeAlias {
        /// Alias name (resolved from blob heap)
        alias: String,
        /// Type reference token (`TypeDefOrRefOrSpecEncoded`)
        type_ref: Token,
    },
}

/// Complete imports information containing all parsed import declarations.
///
/// This struct represents the fully parsed contents of an imports blob,
/// providing structured access to all import declarations within a scope.
///
/// # Container Features
///
/// - **Iteration Support**: Implements [`IntoIterator`] for both owned and borrowed access
/// - **Length Operations**: Provides [`Self::len`] and [`Self::is_empty`] for size queries
/// - **Default Construction**: Supports empty initialization via [`Default`] trait
/// - **Cloning**: Supports deep cloning of all contained import declarations
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::importscope::{ImportsInfo, ImportDeclaration};
///
/// let mut imports = ImportsInfo::new();
/// assert!(imports.is_empty());
///
/// // Process imports after parsing
/// for declaration in &imports {
///     match declaration {
///         ImportDeclaration::ImportNamespace { namespace } => {
///             println!("Import namespace: {}", namespace);
///         }
///         _ => println!("Other import type"),
///     }
/// }
/// ```
///
/// # Thread Safety
///
/// [`ImportsInfo`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportsInfo {
    /// All import declarations in the blob
    pub declarations: Vec<ImportDeclaration>,
}

impl ImportsInfo {
    /// Create a new empty `ImportsInfo`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::importscope::ImportsInfo;
    ///
    /// let imports = ImportsInfo::new();
    /// assert!(imports.is_empty());
    /// assert_eq!(imports.len(), 0);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn new() -> Self {
        Self {
            declarations: Vec::new(),
        }
    }

    /// Create `ImportsInfo` with the given declarations.
    ///
    /// # Arguments
    /// * `declarations` - Vector of import declarations to store
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::importscope::{ImportsInfo, ImportDeclaration};
    ///
    /// let decl = ImportDeclaration::ImportNamespace {
    ///     namespace: "System".to_string(),
    /// };
    /// let imports = ImportsInfo::with_declarations(vec![decl]);
    /// assert_eq!(imports.len(), 1);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn with_declarations(declarations: Vec<ImportDeclaration>) -> Self {
        Self { declarations }
    }

    /// Get the number of import declarations.
    ///
    /// # Returns
    /// The total count of import declarations in this scope.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn len(&self) -> usize {
        self.declarations.len()
    }

    /// Check if there are no import declarations.
    ///
    /// # Returns
    /// `true` if no import declarations are present, `false` otherwise.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.declarations.is_empty()
    }

    /// Get an iterator over the import declarations.
    ///
    /// # Returns
    /// An iterator yielding references to all import declarations.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn iter(&self) -> std::slice::Iter<ImportDeclaration> {
        self.declarations.iter()
    }
}

impl Default for ImportsInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for ImportsInfo {
    type Item = ImportDeclaration;
    type IntoIter = std::vec::IntoIter<ImportDeclaration>;

    fn into_iter(self) -> Self::IntoIter {
        self.declarations.into_iter()
    }
}

impl<'a> IntoIterator for &'a ImportsInfo {
    type Item = &'a ImportDeclaration;
    type IntoIter = std::slice::Iter<'a, ImportDeclaration>;

    fn into_iter(self) -> Self::IntoIter {
        self.declarations.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_kind_from_u32() {
        assert_eq!(ImportKind::from_u32(1), Some(ImportKind::ImportNamespace));
        assert_eq!(ImportKind::from_u32(9), Some(ImportKind::DefineTypeAlias));
        assert_eq!(ImportKind::from_u32(0), None);
        assert_eq!(ImportKind::from_u32(10), None);
    }

    #[test]
    fn test_import_kind_values() {
        assert_eq!(ImportKind::ImportNamespace as u8, 1);
        assert_eq!(ImportKind::ImportAssemblyNamespace as u8, 2);
        assert_eq!(ImportKind::DefineTypeAlias as u8, 9);
    }

    #[test]
    fn test_imports_info_new() {
        let info = ImportsInfo::new();
        assert!(info.is_empty());
        assert_eq!(info.len(), 0);
    }

    #[test]
    fn test_imports_info_with_declarations() {
        let decl = ImportDeclaration::ImportNamespace {
            namespace: "System".to_string(),
        };
        let info = ImportsInfo::with_declarations(vec![decl]);
        assert!(!info.is_empty());
        assert_eq!(info.len(), 1);
    }
}
