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

use crate::{
    assembly::{INSTRUCTIONS, INSTRUCTIONS_FE, INSTRUCTIONS_FE_MAX, INSTRUCTIONS_MAX},
    emulation::{memory::ManagedHeap, tokens, EmValue},
};

/// Resolves a known BCL static field value by namespace, type, and field name.
///
/// Some fields (like `String.Empty`) require heap allocation, so the managed
/// heap is provided for those cases.
///
/// # Arguments
///
/// * `namespace` - The .NET namespace (e.g., "System")
/// * `type_name` - The type name (e.g., "BitConverter")
/// * `field_name` - The field name (e.g., "IsLittleEndian")
/// * `heap` - The managed heap for allocating string/object values
///
/// # Returns
///
/// `Some(EmValue)` if the field is known, `None` otherwise.
#[must_use]
pub fn get_bcl_static_field(
    namespace: &str,
    type_name: &str,
    field_name: &str,
    heap: &ManagedHeap,
) -> Option<EmValue> {
    match (namespace, type_name, field_name) {
        ("System", "BitConverter", "IsLittleEndian") => {
            Some(EmValue::Bool(cfg!(target_endian = "little")))
        }
        ("System", "String", "Empty") => heap.alloc_string("").ok().map(EmValue::ObjectRef),
        ("System", "IntPtr", "Zero") => Some(EmValue::NativeInt(0)),
        ("System", "IntPtr", "Size") => Some(EmValue::I32(8)),
        ("System", "UIntPtr", "Zero") => Some(EmValue::NativeUInt(0)),
        ("System", "UIntPtr", "Size") => Some(EmValue::I32(8)),
        ("System", "Environment", "NewLine") => {
            heap.alloc_string("\r\n").ok().map(EmValue::ObjectRef)
        }
        ("System", "Type", "EmptyTypes") => heap
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, Vec::new())
            .ok()
            .map(EmValue::ObjectRef),
        ("System", "Byte", "MaxValue") => Some(EmValue::I32(255)),
        ("System", "Byte", "MinValue") => Some(EmValue::I32(0)),
        ("System", "SByte", "MaxValue") => Some(EmValue::I32(127)),
        ("System", "SByte", "MinValue") => Some(EmValue::I32(-128)),
        ("System", "Int16", "MaxValue") => Some(EmValue::I32(i32::from(i16::MAX))),
        ("System", "Int16", "MinValue") => Some(EmValue::I32(i32::from(i16::MIN))),
        ("System", "UInt16", "MaxValue") => Some(EmValue::I32(i32::from(u16::MAX))),
        ("System", "UInt16", "MinValue") => Some(EmValue::I32(0)),
        ("System", "Int32", "MaxValue") => Some(EmValue::I32(i32::MAX)),
        ("System", "Int32", "MinValue") => Some(EmValue::I32(i32::MIN)),
        // Bit pattern: 0xFFFFFFFF stored as i32(-1)
        ("System", "UInt32", "MaxValue") => Some(EmValue::I32(-1)),
        ("System", "UInt32", "MinValue") => Some(EmValue::I32(0)),
        ("System", "Int64", "MaxValue") => Some(EmValue::I64(i64::MAX)),
        ("System", "Int64", "MinValue") => Some(EmValue::I64(i64::MIN)),
        ("System", "UInt64", "MaxValue") => Some(EmValue::I64(-1)), // bit pattern
        ("System", "UInt64", "MinValue") => Some(EmValue::I64(0)),
        ("System", "Double", "NaN") => Some(EmValue::F64(f64::NAN)),
        ("System", "Double", "PositiveInfinity") => Some(EmValue::F64(f64::INFINITY)),
        ("System", "Double", "NegativeInfinity") => Some(EmValue::F64(f64::NEG_INFINITY)),
        ("System", "Double", "MaxValue") => Some(EmValue::F64(f64::MAX)),
        ("System", "Double", "MinValue") => Some(EmValue::F64(f64::MIN)),
        ("System", "Double", "Epsilon") => Some(EmValue::F64(f64::EPSILON)),
        ("System", "Single", "NaN") => Some(EmValue::F32(f32::NAN)),
        ("System", "Single", "PositiveInfinity") => Some(EmValue::F32(f32::INFINITY)),
        ("System", "Single", "NegativeInfinity") => Some(EmValue::F32(f32::NEG_INFINITY)),
        ("System", "Single", "MaxValue") => Some(EmValue::F32(f32::MAX)),
        ("System", "Single", "MinValue") => Some(EmValue::F32(f32::MIN)),
        ("System", "Single", "Epsilon") => Some(EmValue::F32(f32::EPSILON)),
        ("System", "Boolean", "TrueString") => {
            heap.alloc_string("True").ok().map(EmValue::ObjectRef)
        }
        ("System", "Boolean", "FalseString") => {
            heap.alloc_string("False").ok().map(EmValue::ObjectRef)
        }
        ("System", "Char", "MaxValue") => Some(EmValue::Char(char::MAX)),
        ("System", "Char", "MinValue") => Some(EmValue::Char('\0')),
        ("System", "Decimal", "Zero") => Some(EmValue::I64(0)),
        ("System", "Decimal", "One") => Some(EmValue::I64(1)),
        ("System", "Decimal", "MinusOne") => Some(EmValue::I64(-1)),
        ("System.Threading.Tasks", "Task", "CompletedTask") => heap
            .alloc_object(tokens::system::TASK)
            .ok()
            .map(EmValue::ObjectRef),
        ("System.Reflection.Emit", "OpCodes", name) => {
            opcode_value_from_field_name(name).map(|value| EmValue::ValueType {
                type_token: tokens::system::OPCODE,
                fields: vec![EmValue::I32(i32::from(value))],
            })
        }

        _ => None,
    }
}

/// Maps a .NET `OpCodes` field name (e.g. `"Ldarg_0"`) to the CIL opcode u16 value.
///
/// The mapping works by converting the PascalCase_Underscore field name to the
/// lowercase dot-separated mnemonic used in the instruction tables, then searching
/// the `INSTRUCTIONS` and `INSTRUCTIONS_FE` tables for a match.
fn opcode_value_from_field_name(field_name: &str) -> Option<u16> {
    // Handle special cases where .NET field names don't follow the simple conversion.
    // Prefix instructions have a trailing dot in their mnemonic but not in the field name.
    let mnemonic: String = match field_name {
        "Tailcall" => "tail.".into(),
        "Volatile" => "volatile.".into(),
        "Unaligned" => "unaligned.".into(),
        "Constrained" => "constrained.".into(),
        "Readonly" => "readonly.".into(),
        _ => {
            // Convert PascalCase_Underscore to lowercase dot-separated mnemonic:
            // "Ldarg_0" → "ldarg.0", "Br_S" → "br.s", "Ldc_I4_1" → "ldc.i4.1"
            field_name
                .chars()
                .map(|c| {
                    if c == '_' {
                        '.'
                    } else {
                        c.to_ascii_lowercase()
                    }
                })
                .collect()
        }
    };

    // Search single-byte opcode table
    for (idx, instr) in INSTRUCTIONS.iter().enumerate() {
        if idx < usize::from(INSTRUCTIONS_MAX) && instr.instr == mnemonic {
            return Some(idx as u16);
        }
    }

    // Search two-byte (0xFE prefix) opcode table
    for (idx, instr) in INSTRUCTIONS_FE.iter().enumerate() {
        if idx < usize::from(INSTRUCTIONS_FE_MAX) && instr.instr == mnemonic {
            return Some(0xFE00 | idx as u16);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::emulation::memory::ManagedHeap;

    use super::*;

    fn heap() -> ManagedHeap {
        ManagedHeap::new(1024 * 1024)
    }

    #[test]
    fn test_bitconverter_is_little_endian() {
        let h = heap();
        let value = get_bcl_static_field("System", "BitConverter", "IsLittleEndian", &h);
        assert!(value.is_some());
        if cfg!(target_endian = "little") {
            assert_eq!(value, Some(EmValue::Bool(true)));
        } else {
            assert_eq!(value, Some(EmValue::Bool(false)));
        }
    }

    #[test]
    fn test_string_empty() {
        let h = heap();
        let value = get_bcl_static_field("System", "String", "Empty", &h);
        assert!(value.is_some());
        if let Some(EmValue::ObjectRef(href)) = value {
            let s = h.get_string(href).unwrap();
            assert_eq!(&*s, "");
        } else {
            panic!("Expected ObjectRef for String.Empty");
        }
    }

    #[test]
    fn test_intptr_zero() {
        let h = heap();
        assert_eq!(
            get_bcl_static_field("System", "IntPtr", "Zero", &h),
            Some(EmValue::NativeInt(0))
        );
        assert_eq!(
            get_bcl_static_field("System", "IntPtr", "Size", &h),
            Some(EmValue::I32(8))
        );
    }

    #[test]
    fn test_numeric_bounds() {
        let h = heap();
        assert_eq!(
            get_bcl_static_field("System", "Int32", "MaxValue", &h),
            Some(EmValue::I32(i32::MAX))
        );
        assert_eq!(
            get_bcl_static_field("System", "Int32", "MinValue", &h),
            Some(EmValue::I32(i32::MIN))
        );
        assert_eq!(
            get_bcl_static_field("System", "Byte", "MaxValue", &h),
            Some(EmValue::I32(255))
        );
    }

    #[test]
    fn test_unknown_field_returns_none() {
        let h = heap();
        assert!(get_bcl_static_field("System", "BitConverter", "UnknownField", &h).is_none());
        assert!(get_bcl_static_field("System", "UnknownType", "SomeField", &h).is_none());
        assert!(get_bcl_static_field("UnknownNamespace", "SomeType", "SomeField", &h).is_none());
    }
}
