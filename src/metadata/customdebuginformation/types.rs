//! Custom debug information types for Portable PDB format.
//!
//! This module defines all the types used to represent custom debug information
//! from Portable PDB files. These types provide structured access to various
//! kinds of debugging metadata that can be embedded in .NET assemblies.

/// Well-known custom debug information kinds identified by GUID.
///
/// These constants represent the standard GUIDs used to identify different
/// types of custom debug information in Portable PDB files. Each kind
/// determines the format and interpretation of the associated blob data.
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
    /// # Arguments
    /// * `guid_bytes` - The 16-byte GUID identifying the debug information kind
    ///
    /// # Returns
    /// The corresponding [`CustomDebugKind`] variant
    #[must_use]
    pub fn from_guid(guid_bytes: [u8; 16]) -> Self {
        match guid_bytes {
            // Source Link: CC110556-A091-4D38-9FEC-25AB9A351A6A
            [0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D, 0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35, 0x1A, 0x6A] => {
                CustomDebugKind::SourceLink
            }
            // Embedded Source: 0E8A571B-6926-466E-B4AD-8AB04611F5FE
            [0x1B, 0x57, 0x8A, 0x0E, 0x26, 0x69, 0x6E, 0x46, 0xB4, 0xAD, 0x8A, 0xB0, 0x46, 0x11, 0xF5, 0xFE] => {
                CustomDebugKind::EmbeddedSource
            }
            // Compilation Metadata: B5FEEC05-8CD0-4A83-96DA-466284BB4BD8
            [0x05, 0xEC, 0xFE, 0xB5, 0xD0, 0x8C, 0x83, 0x4A, 0x96, 0xDA, 0x46, 0x62, 0x84, 0xBB, 0x4B, 0xD8] => {
                CustomDebugKind::CompilationMetadata
            }
            // Compilation Options: B1C2ABE1-8BF0-497A-A9B1-02FA8571E544
            [0xE1, 0xAB, 0xC2, 0xB1, 0xF0, 0x8B, 0x7A, 0x49, 0xA9, 0xB1, 0x02, 0xFA, 0x85, 0x71, 0xE5, 0x44] => {
                CustomDebugKind::CompilationOptions
            }
            // Unknown GUID
            bytes => CustomDebugKind::Unknown(bytes),
        }
    }

    /// Get the GUID bytes for this debug information kind.
    ///
    /// # Returns
    /// The 16-byte GUID as a byte array
    #[must_use]
    pub fn to_guid_bytes(&self) -> [u8; 16] {
        match self {
            CustomDebugKind::SourceLink => [
                0x56, 0x05, 0x11, 0xCC, 0x91, 0xA0, 0x38, 0x4D, 0x9F, 0xEC, 0x25, 0xAB, 0x9A, 0x35,
                0x1A, 0x6A,
            ],
            CustomDebugKind::EmbeddedSource => [
                0x1B, 0x57, 0x8A, 0x0E, 0x26, 0x69, 0x6E, 0x46, 0xB4, 0xAD, 0x8A, 0xB0, 0x46, 0x11,
                0xF5, 0xFE,
            ],
            CustomDebugKind::CompilationMetadata => [
                0x05, 0xEC, 0xFE, 0xB5, 0xD0, 0x8C, 0x83, 0x4A, 0x96, 0xDA, 0x46, 0x62, 0x84, 0xBB,
                0x4B, 0xD8,
            ],
            CustomDebugKind::CompilationOptions => [
                0xE1, 0xAB, 0xC2, 0xB1, 0xF0, 0x8B, 0x7A, 0x49, 0xA9, 0xB1, 0x02, 0xFA, 0x85, 0x71,
                0xE5, 0x44,
            ],
            CustomDebugKind::Unknown(bytes) => *bytes,
        }
    }
}

/// Represents parsed custom debug information from a debug blob.
///
/// Each variant corresponds to a specific debug information kind and contains
/// the appropriate parsed data for that type. This provides structured access
/// to various debugging metadata formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomDebugInfo {
    /// Source Link mapping information
    SourceLink {
        /// JSON document with source server mappings
        document: String,
    },

    /// Embedded source file content
    EmbeddedSource {
        /// Original filename of the embedded source
        filename: String,
        /// UTF-8 source file content
        content: String,
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
    /// # Returns
    /// The [`CustomDebugKind`] that this debug information represents
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
}
