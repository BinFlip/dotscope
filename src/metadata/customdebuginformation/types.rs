//! Custom debug information types for Portable PDB format.
//!
//! This module defines all the types used to represent custom debug information
//! from Portable PDB files. These types provide structured access to various
//! kinds of debugging metadata that can be embedded in .NET assemblies according
//! to the Portable PDB specification.
//!
//! # Architecture
//!
//! The module implements a type-safe representation of custom debug information
//! with strong GUID-based typing and format-aware parsing. The architecture includes:
//!
//! - **Kind Identification**: GUID-based debug information type identification
//! - **Structured Data**: Type-safe access to different debug information formats
//! - **Format Support**: Built-in support for standard .NET debug information types
//! - **Extensibility**: Unknown format handling for future compatibility
//!
//! # Key Components
//!
//! - [`crate::metadata::customdebuginformation::types::CustomDebugKind`] - GUID-based debug information type enumeration
//! - [`crate::metadata::customdebuginformation::types::CustomDebugInfo`] - Parsed debug information data structures
//! - GUID mapping functions for standard Microsoft debug information types
//!
//! # Supported Debug Information Types
//!
//! ## Source Link Information
//! Provides JSON-formatted source server mapping information for symbol servers.
//! GUID: `CC110556-A091-4D38-9FEC-25AB9A351A6A`
//!
//! ## Embedded Source Files
//! Contains full source file content embedded directly in the PDB.
//! GUID: `0E8A571B-6926-466E-B4AD-8AB04611F5FE`
//!
//! ## Compilation Metadata
//! Stores compiler and build-time metadata information.
//! GUID: `B5FEEC05-8CD0-4A83-96DA-466284BB4BD8`
//!
//! ## Compilation Options
//! Contains the compiler options used during compilation.
//! GUID: `B1C2ABE1-8BF0-497A-A9B1-02FA8571E544`
//!
//! # Usage Examples
//!
//! ## Working with Debug Information Types
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::{CustomDebugKind, CustomDebugInfo};
//!
//! // Create from a known GUID
//! let sourcelink_guid = [0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D,
//!                        0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35, 0x1A, 0x6A];
//! let kind = CustomDebugKind::from_guid(sourcelink_guid);
//! assert_eq!(kind, CustomDebugKind::SourceLink);
//!
//! // Create debug information
//! let debug_info = CustomDebugInfo::SourceLink {
//!     document: r#"{"documents":{"src/main.cs":"https://example.com/src/main.cs"}}"#.to_string(),
//! };
//!
//! // Access information
//! println!("Debug info kind: {:?}", debug_info.kind());
//! println!("Is known type: {}", debug_info.is_known());
//! println!("Data size: {} bytes", debug_info.data_size());
//! ```
//!
//! ## Pattern Matching on Debug Information
//!
//! ```rust
//! use dotscope::metadata::customdebuginformation::CustomDebugInfo;
//!
//! # fn process_debug_info(debug_info: CustomDebugInfo) {
//! match debug_info {
//!     CustomDebugInfo::SourceLink { document } => {
//!         println!("Source Link JSON: {}", document);
//!     }
//!     CustomDebugInfo::EmbeddedSource { filename, content, .. } => {
//!         println!("Embedded source '{}': {} chars", filename, content.len());
//!     }
//!     CustomDebugInfo::CompilationMetadata { metadata } => {
//!         println!("Compilation metadata: {}", metadata);
//!     }
//!     CustomDebugInfo::CompilationOptions { options } => {
//!         println!("Compiler options: {}", options);
//!     }
//!     CustomDebugInfo::Unknown { kind, data } => {
//!         println!("Unknown debug info {:?}: {} bytes", kind, data.len());
//!     }
//! }
//! # }
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement [`std::marker::Send`] and [`std::marker::Sync`].
//! The debug information types contain only owned data and can be safely shared across threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customdebuginformation::parser`] - Parsing implementation using these types
//! - [`crate::metadata::streams::Guid`] - GUID heap access for debug information type identification
//! - [`crate::metadata::streams::Blob`] - Blob heap access for debug information data
//! - [`crate::metadata::tables`] - CustomDebugInformation table integration
//!
//! # Standards Compliance
//!
//! - **Portable PDB**: Full compliance with Portable PDB custom debug information specification
//! - **Microsoft Standards**: Support for all standard Microsoft debug information GUIDs
//! - **Extensibility**: Forward compatibility with unknown debug information types
//! - **Type Safety**: Strong typing prevents GUID/data format mismatches
//!
//! # Serialization
//!
//! The types in this module implement [`std::fmt::Display`] for human-readable output.
//! Serde serialization is not currently supported but could be added as an optional
//! feature in the future if needed for JSON/YAML export functionality.

/// Well-known GUID constants for custom debug information types.
///
/// These GUIDs are defined by Microsoft for the Portable PDB specification.
/// See: <https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md>
pub mod debug_guids {
    /// Source Link GUID: CC110556-A091-4D38-9FEC-25AB9A351A6A
    ///
    /// Contains JSON mapping source files to repository URLs for debugging.
    pub const SOURCE_LINK: [u8; 16] = [
        0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D, 0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35, 0x1A,
        0x6A,
    ];

    /// Embedded Source GUID: 0E8A571B-6926-466E-B4AD-8AB04611F5FE
    ///
    /// Contains complete source file content embedded in the PDB.
    pub const EMBEDDED_SOURCE: [u8; 16] = [
        0x1B, 0x57, 0x8A, 0x0E, 0x26, 0x69, 0x6E, 0x46, 0xB4, 0xAD, 0x8A, 0xB0, 0x46, 0x11, 0xF5,
        0xFE,
    ];

    /// Compilation Metadata GUID: B5FEEC05-8CD0-4A83-96DA-466284BB4BD8
    ///
    /// Stores compiler and build-time metadata information.
    pub const COMPILATION_METADATA: [u8; 16] = [
        0x05, 0xEC, 0xFE, 0xB5, 0xD0, 0x8C, 0x83, 0x4A, 0x96, 0xDA, 0x46, 0x62, 0x84, 0xBB, 0x4B,
        0xD8,
    ];

    /// Compilation Options GUID: B1C2ABE1-8BF0-497A-A9B1-02FA8571E544
    ///
    /// Contains the compiler options used during compilation.
    pub const COMPILATION_OPTIONS: [u8; 16] = [
        0xE1, 0xAB, 0xC2, 0xB1, 0xF0, 0x8B, 0x7A, 0x49, 0xA9, 0xB1, 0x02, 0xFA, 0x85, 0x71, 0xE5,
        0x44,
    ];
}

/// Well-known custom debug information kinds identified by GUID.
///
/// These constants represent the standard GUIDs used to identify different
/// types of custom debug information in Portable PDB files. Each kind
/// determines the format and interpretation of the associated blob data
/// according to the Portable PDB specification.
///
/// The GUID-based identification system allows tools and compilers to store
/// custom debugging metadata in a standardized way while maintaining
/// compatibility with existing debugging infrastructure.
///
/// # GUID Format
///
/// All GUIDs are stored in little-endian byte order as defined by the
/// Portable PDB specification. The mapping between GUID strings and
/// byte arrays follows Microsoft's standard GUID encoding.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::customdebuginformation::CustomDebugKind;
///
/// // Create from known GUID bytes
/// let sourcelink_guid = [0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D,
///                        0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35, 0x1A, 0x6A];
/// let kind = CustomDebugKind::from_guid(sourcelink_guid);
/// assert_eq!(kind, CustomDebugKind::SourceLink);
///
/// // Convert back to GUID bytes
/// let guid_bytes = kind.to_guid_bytes();
/// assert_eq!(guid_bytes, sourcelink_guid);
/// ```
///
/// # Thread Safety
///
/// [`CustomDebugKind`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomDebugKind {
    /// Source Link information for source file mapping
    /// GUID: CC110556-A091-4D38-9FEC-25AB9A351A6A
    SourceLink,

    /// Embedded source file content
    /// GUID: 0E8A571B-6926-466E-B4AD-8AB04611F5FE
    EmbeddedSource,

    /// Compilation metadata and options
    /// GUID: B5FEEC05-8CD0-4A83-96DA-466284BB4BD8
    CompilationMetadata,

    /// Compilation options used by the compiler
    /// GUID: B1C2ABE1-8BF0-497A-A9B1-02FA8571E544
    CompilationOptions,

    /// Unknown or unsupported debug information kind
    Unknown([u8; 16]),
}

impl CustomDebugKind {
    /// Create a `CustomDebugKind` from a GUID byte array.
    ///
    /// This method maps standard Microsoft debug information GUIDs to their
    /// corresponding enum variants. Unknown GUIDs are preserved in the
    /// [`CustomDebugKind::Unknown`] variant for future compatibility.
    ///
    /// # Arguments
    /// * `guid_bytes` - The 16-byte GUID identifying the debug information kind
    ///
    /// # Returns
    /// The corresponding [`CustomDebugKind`] variant
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugKind;
    ///
    /// // Known Source Link GUID
    /// let sourcelink_guid = [0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D,
    ///                        0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35, 0x1A, 0x6A];
    /// let kind = CustomDebugKind::from_guid(sourcelink_guid);
    /// assert_eq!(kind, CustomDebugKind::SourceLink);
    ///
    /// // Unknown GUID
    /// let unknown_guid = [0x00; 16];
    /// let kind = CustomDebugKind::from_guid(unknown_guid);
    /// assert!(matches!(kind, CustomDebugKind::Unknown(_)));
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn from_guid(guid_bytes: [u8; 16]) -> Self {
        // Use named constants from debug_guids module for maintainability
        if guid_bytes == debug_guids::SOURCE_LINK {
            CustomDebugKind::SourceLink
        } else if guid_bytes == debug_guids::EMBEDDED_SOURCE {
            CustomDebugKind::EmbeddedSource
        } else if guid_bytes == debug_guids::COMPILATION_METADATA {
            CustomDebugKind::CompilationMetadata
        } else if guid_bytes == debug_guids::COMPILATION_OPTIONS {
            CustomDebugKind::CompilationOptions
        } else {
            CustomDebugKind::Unknown(guid_bytes)
        }
    }

    /// Get the GUID bytes for this debug information kind.
    ///
    /// Converts the debug information kind back to its corresponding
    /// 16-byte GUID representation for storage or comparison purposes.
    ///
    /// # Returns
    /// The 16-byte GUID as a byte array
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::CustomDebugKind;
    ///
    /// let kind = CustomDebugKind::SourceLink;
    /// let guid_bytes = kind.to_guid_bytes();
    ///
    /// // Verify round-trip conversion
    /// let recovered_kind = CustomDebugKind::from_guid(guid_bytes);
    /// assert_eq!(kind, recovered_kind);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn to_guid_bytes(&self) -> [u8; 16] {
        match self {
            CustomDebugKind::SourceLink => debug_guids::SOURCE_LINK,
            CustomDebugKind::EmbeddedSource => debug_guids::EMBEDDED_SOURCE,
            CustomDebugKind::CompilationMetadata => debug_guids::COMPILATION_METADATA,
            CustomDebugKind::CompilationOptions => debug_guids::COMPILATION_OPTIONS,
            CustomDebugKind::Unknown(bytes) => *bytes,
        }
    }
}

/// Represents parsed custom debug information from a debug blob.
///
/// Each variant corresponds to a specific debug information kind and contains
/// the appropriate parsed data for that type. This provides structured access
/// to various debugging metadata formats according to the Portable PDB specification.
///
/// The enum design ensures type safety by matching debug information kinds
/// with their expected data formats, preventing misinterpretation of blob data.
///
/// # Format Details
///
/// Different debug information types use different blob formats:
/// - **SourceLink**: UTF-8 JSON document with source server mappings
/// - **EmbeddedSource**: UTF-8 source file content with optional filename
/// - **CompilationMetadata**: UTF-8 text containing compilation metadata
/// - **CompilationOptions**: UTF-8 text containing compiler options
/// - **Unknown**: Raw binary data for unsupported or future formats
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::customdebuginformation::{CustomDebugInfo, CustomDebugKind};
///
/// // Create Source Link debug information
/// let source_link = CustomDebugInfo::SourceLink {
///     document: r#"{"documents":{"Program.cs":"https://github.com/user/repo/raw/main/Program.cs"}}"#.to_string(),
/// };
///
/// // Access debug information properties
/// assert_eq!(source_link.kind(), CustomDebugKind::SourceLink);
/// assert!(source_link.is_known());
/// println!("Source Link JSON size: {} bytes", source_link.data_size());
///
/// // Pattern match on debug information
/// match source_link {
///     CustomDebugInfo::SourceLink { document } => {
///         println!("Source Link document: {}", document);
///     }
///     _ => unreachable!(),
/// }
/// ```
///
/// # Thread Safety
///
/// [`CustomDebugInfo`] is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomDebugInfo {
    /// Source Link mapping information
    SourceLink {
        /// JSON document with source server mappings
        document: String,
    },

    /// Embedded source file content.
    ///
    /// # Blob Format (Portable PDB Specification)
    ///
    /// The blob format is:
    /// - **int32 format**: Compression indicator
    ///   - `0`: Raw uncompressed UTF-8 text follows
    ///   - `> 0`: Deflate-compressed data, value is decompressed byte size
    /// - **bytes content**: Source file content (raw or compressed)
    ///
    /// # Note on Filename
    ///
    /// The filename is NOT stored in the EmbeddedSource blob itself. It is obtained
    /// from the parent Document row in the CustomDebugInformation table. The `filename`
    /// field here is provided for convenience but must be populated separately by the
    /// caller using the Document table lookup.
    EmbeddedSource {
        /// Original filename of the embedded source.
        ///
        /// **Note**: This is NOT parsed from the blob. The filename comes from the
        /// parent Document row and should be set by the caller after parsing.
        /// Defaults to empty string when parsed directly from blob data.
        filename: String,
        /// UTF-8 source file content (decompressed if originally compressed)
        content: String,
        /// Whether the original blob data was compressed with deflate
        was_compressed: bool,
    },

    /// Compilation metadata information
    CompilationMetadata {
        /// Metadata as UTF-8 text
        metadata: String,
    },

    /// Compilation options used by the compiler
    CompilationOptions {
        /// Options as UTF-8 text
        options: String,
    },

    /// Unknown or unsupported debug information
    Unknown {
        /// The debug information kind
        kind: CustomDebugKind,
        /// Raw blob data
        data: Vec<u8>,
    },
}

impl CustomDebugInfo {
    /// Get the debug information kind for this data.
    ///
    /// Extracts the debug information kind from the parsed data structure,
    /// enabling callers to determine the type of debug information without
    /// pattern matching on the enum variants.
    ///
    /// # Returns
    /// The [`CustomDebugKind`] that this debug information represents
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::customdebuginformation::{CustomDebugInfo, CustomDebugKind};
    ///
    /// let debug_info = CustomDebugInfo::SourceLink {
    ///     document: "{}".to_string(),
    /// };
    ///
    /// assert_eq!(debug_info.kind(), CustomDebugKind::SourceLink);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn kind(&self) -> CustomDebugKind {
        match self {
            CustomDebugInfo::SourceLink { .. } => CustomDebugKind::SourceLink,
            CustomDebugInfo::EmbeddedSource { .. } => CustomDebugKind::EmbeddedSource,
            CustomDebugInfo::CompilationMetadata { .. } => CustomDebugKind::CompilationMetadata,
            CustomDebugInfo::CompilationOptions { .. } => CustomDebugKind::CompilationOptions,
            CustomDebugInfo::Unknown { kind, .. } => *kind,
        }
    }

    /// Check if this is a known debug information type.
    ///
    /// # Returns
    /// `true` if this is a known type, `false` for unknown types
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, CustomDebugInfo::Unknown { .. })
    }

    /// Get the size of the debug data in bytes.
    ///
    /// # Returns
    /// The size of the debug data
    #[must_use]
    pub fn data_size(&self) -> usize {
        match self {
            CustomDebugInfo::SourceLink { document } => document.len(),
            CustomDebugInfo::EmbeddedSource { content, .. } => content.len(),
            CustomDebugInfo::CompilationMetadata { metadata } => metadata.len(),
            CustomDebugInfo::CompilationOptions { options } => options.len(),
            CustomDebugInfo::Unknown { data, .. } => data.len(),
        }
    }

    /// Check if this embedded source was compressed in the original blob.
    ///
    /// # Returns
    /// - `Some(true)` if this is `EmbeddedSource` and was compressed
    /// - `Some(false)` if this is `EmbeddedSource` and was not compressed
    /// - `None` if this is not an `EmbeddedSource` variant
    #[must_use]
    pub fn was_compressed(&self) -> Option<bool> {
        match self {
            CustomDebugInfo::EmbeddedSource { was_compressed, .. } => Some(*was_compressed),
            _ => None,
        }
    }
}

impl std::fmt::Display for CustomDebugKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomDebugKind::SourceLink => write!(f, "SourceLink"),
            CustomDebugKind::EmbeddedSource => write!(f, "EmbeddedSource"),
            CustomDebugKind::CompilationMetadata => write!(f, "CompilationMetadata"),
            CustomDebugKind::CompilationOptions => write!(f, "CompilationOptions"),
            CustomDebugKind::Unknown(guid) => {
                // Format GUID as standard hex representation
                write!(
                    f,
                    "Unknown({:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X})",
                    guid[3], guid[2], guid[1], guid[0],
                    guid[5], guid[4],
                    guid[7], guid[6],
                    guid[8], guid[9],
                    guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
                )
            }
        }
    }
}

impl std::fmt::Display for CustomDebugInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomDebugInfo::SourceLink { document } => {
                write!(f, "SourceLink({} bytes)", document.len())
            }
            CustomDebugInfo::EmbeddedSource {
                filename,
                content,
                was_compressed,
            } => {
                let compression = if *was_compressed {
                    "compressed"
                } else {
                    "uncompressed"
                };
                if filename.is_empty() {
                    write!(
                        f,
                        "EmbeddedSource({} bytes, {})",
                        content.len(),
                        compression
                    )
                } else {
                    write!(
                        f,
                        "EmbeddedSource('{}', {} bytes, {})",
                        filename,
                        content.len(),
                        compression
                    )
                }
            }
            CustomDebugInfo::CompilationMetadata { metadata } => {
                write!(f, "CompilationMetadata({} bytes)", metadata.len())
            }
            CustomDebugInfo::CompilationOptions { options } => {
                write!(f, "CompilationOptions({} bytes)", options.len())
            }
            CustomDebugInfo::Unknown { kind, data } => {
                write!(f, "Unknown({}, {} bytes)", kind, data.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_debug_kind_from_guid() {
        // Test Source Link GUID
        let sourcelink_guid = [
            0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D, 0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35,
            0x1A, 0x6A,
        ];
        assert_eq!(
            CustomDebugKind::from_guid(sourcelink_guid),
            CustomDebugKind::SourceLink
        );

        // Test Embedded Source GUID
        let embedded_guid = [
            0x1B, 0x57, 0x8A, 0x0E, 0x26, 0x69, 0x6E, 0x46, 0xB4, 0xAD, 0x8A, 0xB0, 0x46, 0x11,
            0xF5, 0xFE,
        ];
        assert_eq!(
            CustomDebugKind::from_guid(embedded_guid),
            CustomDebugKind::EmbeddedSource
        );

        // Test unknown GUID
        let unknown_guid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        assert_eq!(
            CustomDebugKind::from_guid(unknown_guid),
            CustomDebugKind::Unknown(unknown_guid)
        );
    }

    #[test]
    fn test_custom_debug_kind_to_guid_bytes() {
        let kind = CustomDebugKind::SourceLink;
        let expected = [
            0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D, 0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35,
            0x1A, 0x6A,
        ];
        assert_eq!(kind.to_guid_bytes(), expected);
    }

    #[test]
    fn test_custom_debug_info_kind() {
        let source_link = CustomDebugInfo::SourceLink {
            document: "{}".to_string(),
        };
        assert_eq!(source_link.kind(), CustomDebugKind::SourceLink);
        assert!(source_link.is_known());
        assert_eq!(source_link.data_size(), 2);
    }

    #[test]
    fn test_unknown_debug_info() {
        let unknown_guid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let unknown = CustomDebugInfo::Unknown {
            kind: CustomDebugKind::Unknown(unknown_guid),
            data: vec![1, 2, 3, 4],
        };
        assert!(!unknown.is_known());
        assert_eq!(unknown.data_size(), 4);
    }

    #[test]
    fn test_custom_debug_kind_display() {
        assert_eq!(format!("{}", CustomDebugKind::SourceLink), "SourceLink");
        assert_eq!(
            format!("{}", CustomDebugKind::EmbeddedSource),
            "EmbeddedSource"
        );
        assert_eq!(
            format!("{}", CustomDebugKind::CompilationMetadata),
            "CompilationMetadata"
        );
        assert_eq!(
            format!("{}", CustomDebugKind::CompilationOptions),
            "CompilationOptions"
        );

        // Test unknown GUID display
        let unknown_guid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let display = format!("{}", CustomDebugKind::Unknown(unknown_guid));
        assert!(display.starts_with("Unknown("));
        assert!(display.contains("-"));
    }

    #[test]
    fn test_custom_debug_info_display() {
        // Test SourceLink display
        let source_link = CustomDebugInfo::SourceLink {
            document: "{}".to_string(),
        };
        assert_eq!(format!("{}", source_link), "SourceLink(2 bytes)");

        // Test EmbeddedSource display (uncompressed, no filename)
        let embedded = CustomDebugInfo::EmbeddedSource {
            filename: String::new(),
            content: "test content".to_string(),
            was_compressed: false,
        };
        assert_eq!(
            format!("{}", embedded),
            "EmbeddedSource(12 bytes, uncompressed)"
        );

        // Test EmbeddedSource display (compressed, with filename)
        let embedded_with_name = CustomDebugInfo::EmbeddedSource {
            filename: "test.cs".to_string(),
            content: "test".to_string(),
            was_compressed: true,
        };
        assert_eq!(
            format!("{}", embedded_with_name),
            "EmbeddedSource('test.cs', 4 bytes, compressed)"
        );

        // Test CompilationMetadata display
        let metadata = CustomDebugInfo::CompilationMetadata {
            metadata: "metadata".to_string(),
        };
        assert_eq!(format!("{}", metadata), "CompilationMetadata(8 bytes)");

        // Test CompilationOptions display
        let options = CustomDebugInfo::CompilationOptions {
            options: "options".to_string(),
        };
        assert_eq!(format!("{}", options), "CompilationOptions(7 bytes)");
    }
}
