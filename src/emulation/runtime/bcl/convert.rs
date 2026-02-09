//! `System.Convert` method hooks for type conversion operations.
//!
//! This module provides hook implementations for the `System.Convert` class, which
//! provides methods for converting between base data types. These conversions are
//! heavily used in obfuscation, especially Base64 encoding/decoding for payload hiding.
//!
//! # Overview
//!
//! The `System.Convert` class provides static methods for converting a base data type
//! to another base data type. This module implements the most commonly used conversions.
//!
//! # Emulated .NET Methods
//!
//! ## Base64 Operations (Critical for Deobfuscation)
//!
//! | Method | Description |
//! |--------|-------------|
//! | `ToBase64String(byte[])` | Encodes bytes to Base64 string |
//! | `FromBase64String(string)` | Decodes Base64 string to bytes |
//!
//! ## Numeric Conversions
//!
//! | Method | Target Type | Notes |
//! |--------|-------------|-------|
//! | `ToByte` | `byte` (u8) | Unsigned 8-bit |
//! | `ToSByte` | `sbyte` (i8) | Signed 8-bit |
//! | `ToInt16` | `short` (i16) | Signed 16-bit |
//! | `ToUInt16` | `ushort` (u16) | Unsigned 16-bit |
//! | `ToInt32` | `int` (i32) | Signed 32-bit, parses strings |
//! | `ToUInt32` | `uint` (u32) | Unsigned 32-bit |
//! | `ToInt64` | `long` (i64) | Signed 64-bit, parses strings |
//! | `ToUInt64` | `ulong` (u64) | Unsigned 64-bit |
//! | `ToSingle` | `float` (f32) | 32-bit float, parses strings |
//! | `ToDouble` | `double` (f64) | 64-bit float, parses strings |
//!
//! ## Other Conversions
//!
//! | Method | Target Type | Notes |
//! |--------|-------------|-------|
//! | `ToChar` | `char` (u16) | Unicode character |
//! | `ToBoolean` | `bool` | Parses "true"/"false" strings |
//! | `ToString` | `string` | Converts any type to string |
//!
//! # Deobfuscation Use Cases
//!
//! ## Base64 Payload Extraction
//!
//! Many obfuscators encode payloads as Base64 strings in resources or code:
//!
//! ```csharp
//! // Common obfuscation pattern
//! string encoded = "SGVsbG8gV29ybGQ=";  // Hidden in metadata
//! byte[] payload = Convert.FromBase64String(encoded);
//! // payload is now the decrypted data
//! ```
//!
//! ## String-to-Number Decryption
//!
//! Control flow obfuscation often uses string parsing:
//!
//! ```csharp
//! string key = GetObfuscatedKey();  // Returns "12345"
//! int state = Convert.ToInt32(key);
//! switch (state) { ... }
//! ```
//!
//! # Implementation Notes
//!
//! - Base64 encoding/decoding is implemented without external dependencies
//! - Numeric conversions follow CIL truncation semantics (no overflow exceptions)
//! - String parsing returns 0 on failure (silent error handling for analysis)

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    utils::{base64_decode, base64_encode},
};

/// Registers all `System.Convert` method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `Convert.ToBase64String` / `Convert.FromBase64String` (Base64 encoding)
/// - `Convert.ToByte`, `ToSByte`, `ToInt16`, `ToUInt16` (8/16-bit conversions)
/// - `Convert.ToInt32`, `ToUInt32`, `ToInt64`, `ToUInt64` (32/64-bit conversions)
/// - `Convert.ToSingle`, `ToDouble` (floating-point conversions)
/// - `Convert.ToChar`, `ToBoolean`, `ToString` (other conversions)
pub fn register(manager: &mut HookManager) {
    // Base64 operations
    manager.register(
        Hook::new("System.Convert.ToBase64String")
            .match_name("System", "Convert", "ToBase64String")
            .pre(to_base64_string_pre),
    );

    manager.register(
        Hook::new("System.Convert.FromBase64String")
            .match_name("System", "Convert", "FromBase64String")
            .pre(from_base64_string_pre),
    );

    // 8-bit conversions
    manager.register(
        Hook::new("System.Convert.ToByte")
            .match_name("System", "Convert", "ToByte")
            .pre(to_byte_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToSByte")
            .match_name("System", "Convert", "ToSByte")
            .pre(to_sbyte_pre),
    );

    // 16-bit conversions
    manager.register(
        Hook::new("System.Convert.ToInt16")
            .match_name("System", "Convert", "ToInt16")
            .pre(to_int16_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToUInt16")
            .match_name("System", "Convert", "ToUInt16")
            .pre(to_uint16_pre),
    );

    // 32-bit conversions
    manager.register(
        Hook::new("System.Convert.ToInt32")
            .match_name("System", "Convert", "ToInt32")
            .pre(to_int32_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToUInt32")
            .match_name("System", "Convert", "ToUInt32")
            .pre(to_uint32_pre),
    );

    // 64-bit conversions
    manager.register(
        Hook::new("System.Convert.ToInt64")
            .match_name("System", "Convert", "ToInt64")
            .pre(to_int64_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToUInt64")
            .match_name("System", "Convert", "ToUInt64")
            .pre(to_uint64_pre),
    );

    // Floating-point conversions
    manager.register(
        Hook::new("System.Convert.ToSingle")
            .match_name("System", "Convert", "ToSingle")
            .pre(to_single_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToDouble")
            .match_name("System", "Convert", "ToDouble")
            .pre(to_double_pre),
    );

    // Other conversions
    manager.register(
        Hook::new("System.Convert.ToChar")
            .match_name("System", "Convert", "ToChar")
            .pre(to_char_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToBoolean")
            .match_name("System", "Convert", "ToBoolean")
            .pre(to_boolean_pre),
    );

    manager.register(
        Hook::new("System.Convert.ToString")
            .match_name("System", "Convert", "ToString")
            .pre(to_string_pre),
    );
}

/// Hook for `System.Convert.ToBase64String` method.
///
/// Converts a byte array to its Base64 string representation. This is commonly
/// used by obfuscators to encode encrypted data for storage in strings.
///
/// # Handled Overloads
///
/// - `Convert.ToBase64String(Byte[]) -> String`
/// - `Convert.ToBase64String(Byte[], Base64FormattingOptions) -> String`
/// - `Convert.ToBase64String(Byte[], Int32, Int32) -> String`
/// - `Convert.ToBase64String(Byte[], Int32, Int32, Base64FormattingOptions) -> String`
///
/// # Parameters
///
/// - `inArray`: The input byte array to encode.
/// - `offset`: The starting position within the input array.
/// - `length`: The number of elements to convert.
/// - `options`: Formatting options (e.g., insert line breaks).
///
/// # Returns
///
/// A Base64-encoded string representation of the byte array.
fn to_base64_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Some(bytes) = thread.heap_mut().get_byte_array(*handle) {
            let encoded = base64_encode(&bytes);
            match thread.heap_mut().alloc_string(&encoded) {
                Ok(str_handle) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(str_handle)))
                }
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Convert.FromBase64String` method.
///
/// Decodes a Base64 string to a byte array. **Critical for deobfuscation** as many
/// obfuscators store encrypted payloads as Base64-encoded strings.
///
/// # Handled Overloads
///
/// - `Convert.FromBase64String(String) -> Byte[]`
///
/// # Parameters
///
/// - `s`: The Base64-encoded string to decode.
///
/// # Returns
///
/// A byte array containing the decoded data, or `null` if decoding fails.
fn from_base64_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(EmValue::Null));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            if let Some(decoded) = base64_decode(&s) {
                match thread.heap_mut().alloc_byte_array(&decoded) {
                    Ok(arr_handle) => {
                        return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_handle)))
                    }
                    Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.Convert.ToByte` method.
///
/// # Handled Overloads
///
/// - `Convert.ToByte(Boolean) -> Byte`
/// - `Convert.ToByte(Byte) -> Byte`
/// - `Convert.ToByte(Char) -> Byte`
/// - `Convert.ToByte(Double) -> Byte`
/// - `Convert.ToByte(Int16) -> Byte`
/// - `Convert.ToByte(Int32) -> Byte`
/// - `Convert.ToByte(Int64) -> Byte`
/// - `Convert.ToByte(Object) -> Byte`
/// - `Convert.ToByte(SByte) -> Byte`
/// - `Convert.ToByte(Single) -> Byte`
/// - `Convert.ToByte(String) -> Byte`
/// - `Convert.ToByte(UInt16) -> Byte`
/// - `Convert.ToByte(UInt32) -> Byte`
/// - `Convert.ToByte(UInt64) -> Byte`
///
/// # Parameters
///
/// - `value`: The value to convert to `Byte`.
///
/// # Returns
///
/// The converted unsigned 8-bit integer value.
fn to_byte_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_u8.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_u8_cil().into()))
}

/// Hook for `System.Convert.ToSByte` method.
///
/// # Handled Overloads
///
/// - `Convert.ToSByte(Boolean) -> SByte`
/// - `Convert.ToSByte(Byte) -> SByte`
/// - `Convert.ToSByte(Char) -> SByte`
/// - `Convert.ToSByte(Double) -> SByte`
/// - `Convert.ToSByte(Int16) -> SByte`
/// - `Convert.ToSByte(Int32) -> SByte`
/// - `Convert.ToSByte(Int64) -> SByte`
/// - `Convert.ToSByte(Object) -> SByte`
/// - `Convert.ToSByte(SByte) -> SByte`
/// - `Convert.ToSByte(Single) -> SByte`
/// - `Convert.ToSByte(String) -> SByte`
/// - `Convert.ToSByte(UInt16) -> SByte`
/// - `Convert.ToSByte(UInt32) -> SByte`
/// - `Convert.ToSByte(UInt64) -> SByte`
///
/// # Parameters
///
/// - `value`: The value to convert to `SByte`.
///
/// # Returns
///
/// The converted signed 8-bit integer value.
fn to_sbyte_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i8.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_i8_cil().into()))
}

/// Hook for `System.Convert.ToInt16` method.
///
/// # Handled Overloads
///
/// - `Convert.ToInt16(Boolean) -> Int16`
/// - `Convert.ToInt16(Byte) -> Int16`
/// - `Convert.ToInt16(Char) -> Int16`
/// - `Convert.ToInt16(Double) -> Int16`
/// - `Convert.ToInt16(Int16) -> Int16`
/// - `Convert.ToInt16(Int32) -> Int16`
/// - `Convert.ToInt16(Int64) -> Int16`
/// - `Convert.ToInt16(Object) -> Int16`
/// - `Convert.ToInt16(SByte) -> Int16`
/// - `Convert.ToInt16(Single) -> Int16`
/// - `Convert.ToInt16(String) -> Int16`
/// - `Convert.ToInt16(UInt16) -> Int16`
/// - `Convert.ToInt16(UInt32) -> Int16`
/// - `Convert.ToInt16(UInt64) -> Int16`
///
/// # Parameters
///
/// - `value`: The value to convert to `Int16`.
///
/// # Returns
///
/// The converted signed 16-bit integer value.
fn to_int16_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i16.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_i16_cil().into()))
}

/// Hook for `System.Convert.ToUInt16` method.
///
/// # Handled Overloads
///
/// - `Convert.ToUInt16(Boolean) -> UInt16`
/// - `Convert.ToUInt16(Byte) -> UInt16`
/// - `Convert.ToUInt16(Char) -> UInt16`
/// - `Convert.ToUInt16(Double) -> UInt16`
/// - `Convert.ToUInt16(Int16) -> UInt16`
/// - `Convert.ToUInt16(Int32) -> UInt16`
/// - `Convert.ToUInt16(Int64) -> UInt16`
/// - `Convert.ToUInt16(Object) -> UInt16`
/// - `Convert.ToUInt16(SByte) -> UInt16`
/// - `Convert.ToUInt16(Single) -> UInt16`
/// - `Convert.ToUInt16(String) -> UInt16`
/// - `Convert.ToUInt16(UInt16) -> UInt16`
/// - `Convert.ToUInt16(UInt32) -> UInt16`
/// - `Convert.ToUInt16(UInt64) -> UInt16`
///
/// # Parameters
///
/// - `value`: The value to convert to `UInt16`.
///
/// # Returns
///
/// The converted unsigned 16-bit integer value.
fn to_uint16_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_u16.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_u16_cil().into()))
}

/// Hook for `System.Convert.ToInt32` method.
///
/// Also supports parsing strings to integers, which is commonly used in obfuscation.
///
/// # Handled Overloads
///
/// - `Convert.ToInt32(Boolean) -> Int32`
/// - `Convert.ToInt32(Byte) -> Int32`
/// - `Convert.ToInt32(Char) -> Int32`
/// - `Convert.ToInt32(Double) -> Int32`
/// - `Convert.ToInt32(Int16) -> Int32`
/// - `Convert.ToInt32(Int32) -> Int32`
/// - `Convert.ToInt32(Int64) -> Int32`
/// - `Convert.ToInt32(Object) -> Int32`
/// - `Convert.ToInt32(SByte) -> Int32`
/// - `Convert.ToInt32(Single) -> Int32`
/// - `Convert.ToInt32(String) -> Int32`
/// - `Convert.ToInt32(String, Int32) -> Int32` (with base)
/// - `Convert.ToInt32(UInt16) -> Int32`
/// - `Convert.ToInt32(UInt32) -> Int32`
/// - `Convert.ToInt32(UInt64) -> Int32`
///
/// # Parameters
///
/// - `value`: The value to convert to `Int32`.
/// - `fromBase`: The base of the number in the string (2, 8, 10, or 16).
///
/// # Returns
///
/// The converted signed 32-bit integer value.
fn to_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i32.into()));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap_mut().get_string(*handle) {
            if let Ok(n) = s.parse::<i32>() {
                return PreHookResult::Bypass(Some(n.into()));
            }
        }
        return PreHookResult::Bypass(Some(0_i32.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_i32_cil().into()))
}

/// Hook for `System.Convert.ToUInt32` method.
///
/// # Handled Overloads
///
/// - `Convert.ToUInt32(Boolean) -> UInt32`
/// - `Convert.ToUInt32(Byte) -> UInt32`
/// - `Convert.ToUInt32(Char) -> UInt32`
/// - `Convert.ToUInt32(Double) -> UInt32`
/// - `Convert.ToUInt32(Int16) -> UInt32`
/// - `Convert.ToUInt32(Int32) -> UInt32`
/// - `Convert.ToUInt32(Int64) -> UInt32`
/// - `Convert.ToUInt32(Object) -> UInt32`
/// - `Convert.ToUInt32(SByte) -> UInt32`
/// - `Convert.ToUInt32(Single) -> UInt32`
/// - `Convert.ToUInt32(String) -> UInt32`
/// - `Convert.ToUInt32(String, Int32) -> UInt32` (with base)
/// - `Convert.ToUInt32(UInt16) -> UInt32`
/// - `Convert.ToUInt32(UInt32) -> UInt32`
/// - `Convert.ToUInt32(UInt64) -> UInt32`
///
/// # Parameters
///
/// - `value`: The value to convert to `UInt32`.
/// - `fromBase`: The base of the number in the string (2, 8, 10, or 16).
///
/// # Returns
///
/// The converted unsigned 32-bit integer value.
fn to_uint32_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i32.into()));
    }
    // Store as i32 with u32 bit pattern (CIL semantics)
    // Bit-cast from u32 to i32 preserves the bit pattern - wrapping is intentional
    #[allow(clippy::cast_possible_wrap)]
    let value = ctx.args[0].to_u32_cil() as i32;
    PreHookResult::Bypass(Some(value.into()))
}

/// Hook for `System.Convert.ToInt64` method.
///
/// Also supports parsing strings to long integers.
///
/// # Handled Overloads
///
/// - `Convert.ToInt64(Boolean) -> Int64`
/// - `Convert.ToInt64(Byte) -> Int64`
/// - `Convert.ToInt64(Char) -> Int64`
/// - `Convert.ToInt64(Double) -> Int64`
/// - `Convert.ToInt64(Int16) -> Int64`
/// - `Convert.ToInt64(Int32) -> Int64`
/// - `Convert.ToInt64(Int64) -> Int64`
/// - `Convert.ToInt64(Object) -> Int64`
/// - `Convert.ToInt64(SByte) -> Int64`
/// - `Convert.ToInt64(Single) -> Int64`
/// - `Convert.ToInt64(String) -> Int64`
/// - `Convert.ToInt64(String, Int32) -> Int64` (with base)
/// - `Convert.ToInt64(UInt16) -> Int64`
/// - `Convert.ToInt64(UInt32) -> Int64`
/// - `Convert.ToInt64(UInt64) -> Int64`
///
/// # Parameters
///
/// - `value`: The value to convert to `Int64`.
/// - `fromBase`: The base of the number in the string (2, 8, 10, or 16).
///
/// # Returns
///
/// The converted signed 64-bit integer value.
fn to_int64_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i64.into()));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap_mut().get_string(*handle) {
            if let Ok(n) = s.parse::<i64>() {
                return PreHookResult::Bypass(Some(n.into()));
            }
        }
        return PreHookResult::Bypass(Some(0_i64.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_i64_cil().into()))
}

/// Hook for `System.Convert.ToUInt64` method.
///
/// # Handled Overloads
///
/// - `Convert.ToUInt64(Boolean) -> UInt64`
/// - `Convert.ToUInt64(Byte) -> UInt64`
/// - `Convert.ToUInt64(Char) -> UInt64`
/// - `Convert.ToUInt64(Double) -> UInt64`
/// - `Convert.ToUInt64(Int16) -> UInt64`
/// - `Convert.ToUInt64(Int32) -> UInt64`
/// - `Convert.ToUInt64(Int64) -> UInt64`
/// - `Convert.ToUInt64(Object) -> UInt64`
/// - `Convert.ToUInt64(SByte) -> UInt64`
/// - `Convert.ToUInt64(Single) -> UInt64`
/// - `Convert.ToUInt64(String) -> UInt64`
/// - `Convert.ToUInt64(String, Int32) -> UInt64` (with base)
/// - `Convert.ToUInt64(UInt16) -> UInt64`
/// - `Convert.ToUInt64(UInt32) -> UInt64`
/// - `Convert.ToUInt64(UInt64) -> UInt64`
///
/// # Parameters
///
/// - `value`: The value to convert to `UInt64`.
/// - `fromBase`: The base of the number in the string (2, 8, 10, or 16).
///
/// # Returns
///
/// The converted unsigned 64-bit integer value.
fn to_uint64_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_i64.into()));
    }
    // Store as i64 with u64 bit pattern (CIL semantics)
    // Bit-cast from u64 to i64 preserves the bit pattern - wrapping is intentional
    #[allow(clippy::cast_possible_wrap)]
    let value = ctx.args[0].to_u64_cil() as i64;
    PreHookResult::Bypass(Some(value.into()))
}

/// Hook for `System.Convert.ToSingle` method.
///
/// # Handled Overloads
///
/// - `Convert.ToSingle(Boolean) -> Single`
/// - `Convert.ToSingle(Byte) -> Single`
/// - `Convert.ToSingle(Double) -> Single`
/// - `Convert.ToSingle(Int16) -> Single`
/// - `Convert.ToSingle(Int32) -> Single`
/// - `Convert.ToSingle(Int64) -> Single`
/// - `Convert.ToSingle(Object) -> Single`
/// - `Convert.ToSingle(SByte) -> Single`
/// - `Convert.ToSingle(Single) -> Single`
/// - `Convert.ToSingle(String) -> Single`
/// - `Convert.ToSingle(UInt16) -> Single`
/// - `Convert.ToSingle(UInt32) -> Single`
/// - `Convert.ToSingle(UInt64) -> Single`
///
/// # Parameters
///
/// - `value`: The value to convert to `Single`.
///
/// # Returns
///
/// The converted 32-bit floating-point value.
fn to_single_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0.0_f32.into()));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap_mut().get_string(*handle) {
            if let Ok(f) = s.parse::<f32>() {
                return PreHookResult::Bypass(Some(f.into()));
            }
        }
        return PreHookResult::Bypass(Some(0.0_f32.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_f32_cil().into()))
}

/// Hook for `System.Convert.ToDouble` method.
///
/// # Handled Overloads
///
/// - `Convert.ToDouble(Boolean) -> Double`
/// - `Convert.ToDouble(Byte) -> Double`
/// - `Convert.ToDouble(Double) -> Double`
/// - `Convert.ToDouble(Int16) -> Double`
/// - `Convert.ToDouble(Int32) -> Double`
/// - `Convert.ToDouble(Int64) -> Double`
/// - `Convert.ToDouble(Object) -> Double`
/// - `Convert.ToDouble(SByte) -> Double`
/// - `Convert.ToDouble(Single) -> Double`
/// - `Convert.ToDouble(String) -> Double`
/// - `Convert.ToDouble(UInt16) -> Double`
/// - `Convert.ToDouble(UInt32) -> Double`
/// - `Convert.ToDouble(UInt64) -> Double`
///
/// # Parameters
///
/// - `value`: The value to convert to `Double`.
///
/// # Returns
///
/// The converted 64-bit floating-point value.
fn to_double_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0.0_f64.into()));
    }

    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap_mut().get_string(*handle) {
            if let Ok(f) = s.parse::<f64>() {
                return PreHookResult::Bypass(Some(f.into()));
            }
        }
        return PreHookResult::Bypass(Some(0.0_f64.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_f64_cil().into()))
}

/// Hook for `System.Convert.ToChar` method.
///
/// # Handled Overloads
///
/// - `Convert.ToChar(Byte) -> Char`
/// - `Convert.ToChar(Int16) -> Char`
/// - `Convert.ToChar(Int32) -> Char`
/// - `Convert.ToChar(Int64) -> Char`
/// - `Convert.ToChar(Object) -> Char`
/// - `Convert.ToChar(SByte) -> Char`
/// - `Convert.ToChar(String) -> Char`
/// - `Convert.ToChar(UInt16) -> Char`
/// - `Convert.ToChar(UInt32) -> Char`
/// - `Convert.ToChar(UInt64) -> Char`
///
/// # Parameters
///
/// - `value`: The value to convert to `Char`.
///
/// # Returns
///
/// The converted Unicode character (stored as `UInt16`).
fn to_char_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(0_u16.into()));
    }
    // Char is stored as u16 in I32 (CIL semantics)
    PreHookResult::Bypass(Some(ctx.args[0].to_u16_cil().into()))
}

/// Hook for `System.Convert.ToBoolean` method.
///
/// Supports parsing "true"/"false" strings (case-insensitive) and "1" as true.
///
/// # Handled Overloads
///
/// - `Convert.ToBoolean(Boolean) -> Boolean`
/// - `Convert.ToBoolean(Byte) -> Boolean`
/// - `Convert.ToBoolean(Double) -> Boolean`
/// - `Convert.ToBoolean(Int16) -> Boolean`
/// - `Convert.ToBoolean(Int32) -> Boolean`
/// - `Convert.ToBoolean(Int64) -> Boolean`
/// - `Convert.ToBoolean(Object) -> Boolean`
/// - `Convert.ToBoolean(SByte) -> Boolean`
/// - `Convert.ToBoolean(Single) -> Boolean`
/// - `Convert.ToBoolean(String) -> Boolean`
/// - `Convert.ToBoolean(UInt16) -> Boolean`
/// - `Convert.ToBoolean(UInt32) -> Boolean`
/// - `Convert.ToBoolean(UInt64) -> Boolean`
///
/// # Parameters
///
/// - `value`: The value to convert to `Boolean`.
///
/// # Returns
///
/// `true` if the value is non-zero, "true", or "1"; otherwise `false`.
fn to_boolean_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return PreHookResult::Bypass(Some(false.into()));
    }

    // String parsing needs special handling
    if let EmValue::ObjectRef(handle) = &ctx.args[0] {
        if let Ok(s) = thread.heap().get_string(*handle) {
            return PreHookResult::Bypass(Some(
                (s.eq_ignore_ascii_case("true") || &*s == "1").into(),
            ));
        }
        return PreHookResult::Bypass(Some(false.into()));
    }
    PreHookResult::Bypass(Some(ctx.args[0].to_bool_cil().into()))
}

/// Hook for `System.Convert.ToString` method.
///
/// # Handled Overloads
///
/// - `Convert.ToString(Boolean) -> String`
/// - `Convert.ToString(Byte) -> String`
/// - `Convert.ToString(Char) -> String`
/// - `Convert.ToString(Double) -> String`
/// - `Convert.ToString(Int16) -> String`
/// - `Convert.ToString(Int32) -> String`
/// - `Convert.ToString(Int32, Int32) -> String` (with base)
/// - `Convert.ToString(Int64) -> String`
/// - `Convert.ToString(Int64, Int32) -> String` (with base)
/// - `Convert.ToString(Object) -> String`
/// - `Convert.ToString(SByte) -> String`
/// - `Convert.ToString(Single) -> String`
/// - `Convert.ToString(String) -> String`
/// - `Convert.ToString(UInt16) -> String`
/// - `Convert.ToString(UInt32) -> String`
/// - `Convert.ToString(UInt64) -> String`
///
/// # Parameters
///
/// - `value`: The value to convert to `String`.
/// - `toBase`: The base to use for numeric conversion (2, 8, 10, or 16).
///
/// # Returns
///
/// The string representation of the value.
fn to_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.is_empty() {
        return match thread.heap_mut().alloc_string("") {
            Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
            Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
        };
    }

    let s = match &ctx.args[0] {
        EmValue::I32(n) => n.to_string(),
        EmValue::I64(n) => n.to_string(),
        EmValue::F32(f) => f.to_string(),
        EmValue::F64(f) => f.to_string(),
        EmValue::ObjectRef(handle) => {
            if let Ok(existing) = thread.heap_mut().get_string(*handle) {
                existing.to_string()
            } else {
                String::new()
            }
        }
        // Null and other types convert to empty string
        _ => String::new(),
    };

    match thread.heap_mut().alloc_string(&s) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 15);
    }

    #[test]
    fn test_to_base64_string_hook() {
        let mut thread = create_test_thread();
        let data = thread.heap_mut().alloc_byte_array(b"Hello").unwrap();

        let args = [EmValue::ObjectRef(data)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "ToBase64String",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = to_base64_string_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(&*thread.heap().get_string(handle).unwrap(), "SGVsbG8=");
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_from_base64_string_hook() {
        let mut thread = create_test_thread();
        let encoded = thread.heap_mut().alloc_string("SGVsbG8=").unwrap();

        let args = [EmValue::ObjectRef(encoded)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "FromBase64String",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = from_base64_string_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            assert_eq!(
                thread.heap().get_byte_array(handle),
                Some(b"Hello".to_vec())
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_to_int32_hook() {
        let mut thread = create_test_thread();

        // From i32
        let args = [EmValue::I32(42)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "ToInt32",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = to_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));

        // From string
        let s = thread.heap_mut().alloc_string("123").unwrap();
        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "ToInt32",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = to_int32_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(123)))
        ));
    }

    #[test]
    fn test_to_boolean_hook() {
        let mut thread = create_test_thread();

        // From i32
        let args = [EmValue::I32(0)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "ToBoolean",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = to_boolean_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(false)))
        ));

        let args = [EmValue::I32(1)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "ToBoolean",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = to_boolean_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));

        // From string
        let s = thread.heap_mut().alloc_string("true").unwrap();
        let args = [EmValue::ObjectRef(s)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Convert",
            "ToBoolean",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = to_boolean_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::Bool(true)))
        ));
    }
}
