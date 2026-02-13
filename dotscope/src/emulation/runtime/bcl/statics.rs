//! BCL static field value resolution.
//!
//! This module provides known values for common Base Class Library static fields
//! that are accessed during emulation. Unlike method hooks, static field access
//! is a simple value lookup rather than a call interception.
//!
//! # Overview
//!
//! When the emulator encounters a `ldsfld` instruction referencing an external
//! BCL static field (via MemberRef), it needs to provide a value. This module
//! provides known values for commonly used BCL static fields.
//!
//! # Supported Static Fields
//!
//! | Type | Field | Value |
//! |------|-------|-------|
//! | `System.BitConverter` | `IsLittleEndian` | `true` (for little-endian systems) |
//!
//! # Example
//!
//! ```rust,ignore
//! use dotscope::emulation::runtime::bcl::statics;
//!
//! // Resolve a BCL static field
//! if let Some(value) = statics::get_static_field("System", "BitConverter", "IsLittleEndian") {
//!     // value is EmValue::Bool(true) on little-endian systems
//! }
//! ```

use crate::emulation::EmValue;

/// Resolves a known BCL static field value by namespace, type, and field name.
///
/// This function provides concrete values for commonly used BCL static fields
/// that would normally be provided by the .NET runtime.
///
/// # Arguments
///
/// * `namespace` - The .NET namespace (e.g., "System")
/// * `type_name` - The type name (e.g., "BitConverter")
/// * `field_name` - The field name (e.g., "IsLittleEndian")
///
/// # Returns
///
/// `Some(EmValue)` if the field is known, `None` otherwise.
///
/// # Supported Fields
///
/// - `System.BitConverter.IsLittleEndian` - Returns `true` for little-endian systems
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::emulation::runtime::bcl::statics;
///
/// let value = statics::get_static_field("System", "BitConverter", "IsLittleEndian");
/// assert_eq!(value, Some(EmValue::Bool(true))); // On little-endian systems
/// ```
#[must_use]
pub fn get_bcl_static_field(namespace: &str, type_name: &str, field_name: &str) -> Option<EmValue> {
    match (namespace, type_name, field_name) {
        // System.BitConverter.IsLittleEndian - returns true for little-endian systems
        // This is commonly used by obfuscators to determine byte ordering for
        // encryption/decryption operations.
        ("System", "BitConverter", "IsLittleEndian") => {
            Some(EmValue::Bool(cfg!(target_endian = "little")))
        }

        // Add more known BCL static fields here as needed
        // Examples that could be added in the future:
        // - System.Environment.NewLine
        // - System.String.Empty
        // - System.Type.EmptyTypes
        // - System.DBNull.Value
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitconverter_is_little_endian() {
        let value = get_bcl_static_field("System", "BitConverter", "IsLittleEndian");
        assert!(value.is_some());

        // On most modern systems, this should be true
        if cfg!(target_endian = "little") {
            assert_eq!(value, Some(EmValue::Bool(true)));
        } else {
            assert_eq!(value, Some(EmValue::Bool(false)));
        }
    }

    #[test]
    fn test_unknown_field_returns_none() {
        assert!(get_bcl_static_field("System", "BitConverter", "UnknownField").is_none());
        assert!(get_bcl_static_field("System", "UnknownType", "SomeField").is_none());
        assert!(get_bcl_static_field("UnknownNamespace", "SomeType", "SomeField").is_none());
    }
}
