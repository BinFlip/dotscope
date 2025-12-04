//! Utilities for handling .NET enum types across the metadata system.
//!
//! This module provides centralized functionality for determining enum underlying types
//! and parsing enum values from binary data. It's used by custom attributes, security
//! permissions, and other metadata parsers that need to handle enum values.

use crate::{
    file::parser::Parser,
    metadata::{
        signatures::TypeSignature,
        typesystem::{CilTypeRc, TypeRegistry},
    },
    Result,
};
use std::sync::Arc;

/// Utilities for working with .NET enum types
pub struct EnumUtils;

impl EnumUtils {
    /// Determines if a type name represents an enum using TypeRegistry lookup
    ///
    /// # Arguments
    /// * `type_name` - Full type name to check
    /// * `registry` - Type registry for cross-assembly lookups
    ///
    /// # Returns
    /// `true` if the type is an enum, `false` otherwise
    pub fn is_enum_type_by_name(type_name: &str, registry: &Arc<TypeRegistry>) -> bool {
        if let Some(type_ref) = registry.resolve_type_global(type_name) {
            Self::is_enum_type(&type_ref, Some(registry))
        } else {
            false
        }
    }

    /// Determines if a type is an enum by checking for System.Enum inheritance
    /// and the presence of a `value__` field.
    ///
    /// # Arguments
    /// * `type_ref` - The type to check
    /// * `registry` - Optional type registry for cross-assembly lookups
    ///
    /// # Returns
    /// `true` if the type is an enum, `false` otherwise
    pub fn is_enum_type(type_ref: &CilTypeRc, registry: Option<&Arc<TypeRegistry>>) -> bool {
        // Check for value__ field (required for enums per ECMA-335)
        let has_value_field = type_ref.fields.iter().any(|(_, field)| {
            field.name == "value__" && (field.flags & 0x10) == 0 // Not static
        });

        if !has_value_field {
            return false;
        }

        // Check inheritance from System.Enum
        if let Some(parent_type) = type_ref.base() {
            parent_type.name == "Enum" && parent_type.namespace == "System"
        } else {
            // Try registry-based lookup if available
            if let Some(reg) = registry {
                Self::check_enum_inheritance_with_registry(type_ref, reg)
            } else {
                false
            }
        }
    }

    /// Gets the underlying type size of an enum by name using TypeRegistry lookup
    ///
    /// # Arguments
    /// * `type_name` - Full type name of the enum
    /// * `registry` - Type registry for cross-assembly lookups
    ///
    /// # Returns
    /// Size in bytes (1, 2, 4, or 8), or 0 if cannot be determined
    pub fn get_enum_underlying_type_size_by_name(
        type_name: &str,
        registry: &Arc<TypeRegistry>,
    ) -> usize {
        if let Some(type_ref) = registry.resolve_type_global(type_name) {
            Self::get_enum_underlying_type_size(&type_ref)
        } else {
            0
        }
    }

    /// Gets the underlying type size of an enum in bytes.
    ///
    /// This follows ECMA-335: "An enum shall have exactly one instance field,
    /// and the type of that field defines the underlying type of the enumeration."
    ///
    /// # Arguments
    /// * `type_ref` - The enum type to analyze
    ///
    /// # Returns
    /// Size in bytes (1, 2, 4, or 8), or 0 if cannot be determined
    pub fn get_enum_underlying_type_size(type_ref: &CilTypeRc) -> usize {
        for (_, field) in type_ref.fields.iter() {
            if field.flags & 0x10 != 0 {
                // Skip static fields
                continue;
            }
            if field.name == "value__" {
                return match &field.signature.base {
                    // 1-byte types
                    TypeSignature::I1 | TypeSignature::U1 | TypeSignature::Boolean => 1,
                    // 2-byte types
                    TypeSignature::I2 | TypeSignature::U2 | TypeSignature::Char => 2,
                    // 4-byte types
                    TypeSignature::I4 | TypeSignature::U4 | TypeSignature::R4 => 4,
                    // 8-byte types
                    TypeSignature::I8 | TypeSignature::U8 | TypeSignature::R8 => 8,
                    // Platform-dependent types
                    TypeSignature::I | TypeSignature::U => {
                        if cfg!(target_pointer_width = "64") {
                            8
                        } else {
                            4
                        }
                    }
                    _ => 0,
                };
            }
        }
        0
    }

    /// Parses an enum value from binary data based on its underlying type size.
    ///
    /// # Arguments
    /// * `parser` - The parser to read from
    /// * `size_bytes` - Size of the underlying type in bytes
    ///
    /// # Returns
    /// The enum value as an i64, or an error if parsing fails
    pub fn parse_enum_value(parser: &mut Parser, size_bytes: usize) -> Result<i64> {
        match size_bytes {
            1 => Ok(i64::from(parser.read_le::<u8>()?)),
            2 => Ok(i64::from(parser.read_le::<u16>()?)),
            4 => Ok(i64::from(parser.read_le::<i32>()?)),
            8 => parser.read_le::<i64>(),
            _ => Err(malformed_error!(
                "Invalid enum underlying type size: {} bytes",
                size_bytes
            )),
        }
    }

    /// Formats an enum value for display purposes.
    ///
    /// # Arguments
    /// * `type_name` - Name of the enum type
    /// * `value` - The enum value
    ///
    /// # Returns
    /// A formatted string representation
    pub fn format_enum_value(type_name: &str, value: i64) -> String {
        format!("{type_name}({value})")
    }

    /// Helper method to check enum inheritance using the type registry
    fn check_enum_inheritance_with_registry(
        type_ref: &CilTypeRc,
        registry: &Arc<TypeRegistry>,
    ) -> bool {
        Self::check_enum_inheritance_with_registry_recursive(type_ref, registry, 0)
    }

    /// Recursive helper with depth limit for enum inheritance checking
    fn check_enum_inheritance_with_registry_recursive(
        type_ref: &CilTypeRc,
        registry: &Arc<TypeRegistry>,
        depth: u32,
    ) -> bool {
        const MAX_INHERITANCE_DEPTH: u32 = 32;

        if depth >= MAX_INHERITANCE_DEPTH {
            return false;
        }

        if let Some(base_type) = type_ref.base() {
            if base_type.name == "Enum" && base_type.namespace == "System" {
                return true;
            }

            let base_fullname = format!("{}.{}", base_type.namespace, base_type.name);
            if let Some(resolved_base) = registry.resolve_type_global(&base_fullname) {
                if resolved_base.name == "Enum" && resolved_base.namespace == "System" {
                    return true;
                }

                return Self::check_enum_inheritance_with_registry_recursive(
                    &resolved_base,
                    registry,
                    depth + 1,
                );
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_enum_value() {
        assert_eq!(
            EnumUtils::format_enum_value("System.AttributeTargets", 1),
            "System.AttributeTargets(1)"
        );
        assert_eq!(EnumUtils::format_enum_value("MyEnum", -1), "MyEnum(-1)");
    }
}
