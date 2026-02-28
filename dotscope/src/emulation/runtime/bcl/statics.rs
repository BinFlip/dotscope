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

use crate::emulation::{memory::ManagedHeap, EmValue};

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
        // ── System.BitConverter ────────────────────────────────────
        ("System", "BitConverter", "IsLittleEndian") => {
            Some(EmValue::Bool(cfg!(target_endian = "little")))
        }

        // ── System.String ──────────────────────────────────────────
        ("System", "String", "Empty") => heap.alloc_string("").ok().map(EmValue::ObjectRef),

        // ── System.IntPtr ──────────────────────────────────────────
        ("System", "IntPtr", "Zero") => Some(EmValue::NativeInt(0)),
        ("System", "IntPtr", "Size") => Some(EmValue::I32(8)),

        // ── System.UIntPtr ─────────────────────────────────────────
        ("System", "UIntPtr", "Zero") => Some(EmValue::NativeUInt(0)),
        ("System", "UIntPtr", "Size") => Some(EmValue::I32(8)),

        // ── System.Environment ─────────────────────────────────────
        ("System", "Environment", "NewLine") => {
            heap.alloc_string("\r\n").ok().map(EmValue::ObjectRef)
        }

        // ── System.Type ────────────────────────────────────────────
        ("System", "Type", "EmptyTypes") => heap
            .alloc_array_with_values(crate::metadata::typesystem::CilFlavor::Object, Vec::new())
            .ok()
            .map(EmValue::ObjectRef),

        // ── System.Byte ────────────────────────────────────────────
        ("System", "Byte", "MaxValue") => Some(EmValue::I32(255)),
        ("System", "Byte", "MinValue") => Some(EmValue::I32(0)),

        // ── System.SByte ───────────────────────────────────────────
        ("System", "SByte", "MaxValue") => Some(EmValue::I32(127)),
        ("System", "SByte", "MinValue") => Some(EmValue::I32(-128)),

        // ── System.Int16 ───────────────────────────────────────────
        ("System", "Int16", "MaxValue") => Some(EmValue::I32(i32::from(i16::MAX))),
        ("System", "Int16", "MinValue") => Some(EmValue::I32(i32::from(i16::MIN))),

        // ── System.UInt16 ──────────────────────────────────────────
        ("System", "UInt16", "MaxValue") => Some(EmValue::I32(i32::from(u16::MAX))),
        ("System", "UInt16", "MinValue") => Some(EmValue::I32(0)),

        // ── System.Int32 ───────────────────────────────────────────
        ("System", "Int32", "MaxValue") => Some(EmValue::I32(i32::MAX)),
        ("System", "Int32", "MinValue") => Some(EmValue::I32(i32::MIN)),

        // ── System.UInt32 ──────────────────────────────────────────
        // Bit pattern: 0xFFFFFFFF stored as i32(-1)
        ("System", "UInt32", "MaxValue") => Some(EmValue::I32(-1)),
        ("System", "UInt32", "MinValue") => Some(EmValue::I32(0)),

        // ── System.Int64 ───────────────────────────────────────────
        ("System", "Int64", "MaxValue") => Some(EmValue::I64(i64::MAX)),
        ("System", "Int64", "MinValue") => Some(EmValue::I64(i64::MIN)),

        // ── System.UInt64 ──────────────────────────────────────────
        ("System", "UInt64", "MaxValue") => Some(EmValue::I64(-1)), // bit pattern
        ("System", "UInt64", "MinValue") => Some(EmValue::I64(0)),

        // ── System.Double ──────────────────────────────────────────
        ("System", "Double", "NaN") => Some(EmValue::F64(f64::NAN)),
        ("System", "Double", "PositiveInfinity") => Some(EmValue::F64(f64::INFINITY)),
        ("System", "Double", "NegativeInfinity") => Some(EmValue::F64(f64::NEG_INFINITY)),
        ("System", "Double", "MaxValue") => Some(EmValue::F64(f64::MAX)),
        ("System", "Double", "MinValue") => Some(EmValue::F64(f64::MIN)),
        ("System", "Double", "Epsilon") => Some(EmValue::F64(f64::EPSILON)),

        // ── System.Single ──────────────────────────────────────────
        ("System", "Single", "NaN") => Some(EmValue::F32(f32::NAN)),
        ("System", "Single", "PositiveInfinity") => Some(EmValue::F32(f32::INFINITY)),
        ("System", "Single", "NegativeInfinity") => Some(EmValue::F32(f32::NEG_INFINITY)),
        ("System", "Single", "MaxValue") => Some(EmValue::F32(f32::MAX)),
        ("System", "Single", "MinValue") => Some(EmValue::F32(f32::MIN)),
        ("System", "Single", "Epsilon") => Some(EmValue::F32(f32::EPSILON)),

        // ── System.Boolean ─────────────────────────────────────────
        ("System", "Boolean", "TrueString") => {
            heap.alloc_string("True").ok().map(EmValue::ObjectRef)
        }
        ("System", "Boolean", "FalseString") => {
            heap.alloc_string("False").ok().map(EmValue::ObjectRef)
        }

        // ── System.Char ────────────────────────────────────────────
        ("System", "Char", "MaxValue") => Some(EmValue::Char(char::MAX)),
        ("System", "Char", "MinValue") => Some(EmValue::Char('\0')),

        // ── System.Decimal ─────────────────────────────────────────
        ("System", "Decimal", "Zero") => Some(EmValue::I64(0)),
        ("System", "Decimal", "One") => Some(EmValue::I64(1)),
        ("System", "Decimal", "MinusOne") => Some(EmValue::I64(-1)),

        _ => None,
    }
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
