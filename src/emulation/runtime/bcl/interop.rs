//! `System.Runtime.InteropServices.Marshal` and pointer method hooks.
//!
//! This module provides hook implementations for interop-related methods used in
//! obfuscated .NET assemblies for accessing unmanaged memory, P/Invoke operations,
//! and pointer arithmetic. These are critical for anti-tamper and native code interaction.
//!
//! # Overview
//!
//! The `Marshal` class and pointer types (`IntPtr`, `UIntPtr`) are heavily used by
//! obfuscators to access raw memory, read PE headers, and implement anti-tamper checks.
//!
//! # Emulated .NET Methods
//!
//! ## Marshal Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Marshal.GetHINSTANCE(Module)` | Returns PE image base address |
//! | `Marshal.Copy(IntPtr, byte[], int, int)` | Copies from unmanaged to managed |
//! | `Marshal.ReadByte(IntPtr)` | Reads a byte from unmanaged memory |
//! | `Marshal.ReadInt32(IntPtr)` | Reads a 32-bit integer |
//! | `Marshal.WriteByte(IntPtr, byte)` | Writes a byte to unmanaged memory |
//! | `Marshal.WriteInt32(IntPtr, int)` | Writes a 32-bit integer |
//!
//! ## IntPtr Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `IntPtr.op_Explicit` | Type conversion operators |
//! | `IntPtr.Add(IntPtr, int)` | Pointer arithmetic |
//! | `IntPtr.ToInt32()` | Convert to 32-bit integer |
//! | `IntPtr.ToInt64()` | Convert to 64-bit integer |
//!
//! ## UIntPtr Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `UIntPtr.op_Explicit` | Type conversion operators |
//!
//! # Deobfuscation Use Cases
//!
//! ## Anti-Tamper Checks
//!
//! Many obfuscators read the PE image to verify checksums or locate encrypted code:
//!
//! ```csharp
//! Module mod = typeof(MyClass).Module;
//! IntPtr imageBase = Marshal.GetHINSTANCE(mod);  // <-- Returns PE image base
//! byte[] header = new byte[4096];
//! Marshal.Copy(imageBase, header, 0, 4096);  // <-- Reads PE header
//! ```
//!
//! ## ConfuserEx Anti-Tamper
//!
//! ConfuserEx uses `GetHINSTANCE` to locate the PE sections containing encrypted
//! method bodies. The hook returns the actual image base from the PE file.
//!
//! # Address Space
//!
//! These hooks interact with the [`AddressSpace`] to simulate unmanaged memory.
//! The PE image is mapped into the address space, allowing reads of actual PE data.
//!
//! [`AddressSpace`]: crate::emulation::memory::AddressSpace

use crate::emulation::{
    runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
    thread::EmulationThread,
    EmValue,
};

/// Registers all interop method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `Marshal.GetHINSTANCE`, `Marshal.Copy`, `Marshal.ReadByte/Int32`, `Marshal.WriteByte/Int32`
/// - `IntPtr.op_Explicit`, `IntPtr.Add`, `IntPtr.ToInt32/64`
/// - `UIntPtr.op_Explicit`
pub fn register(manager: &mut HookManager) {
    // Marshal methods
    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.GetHINSTANCE")
            .match_name("System.Runtime.InteropServices", "Marshal", "GetHINSTANCE")
            .pre(marshal_get_hinstance_pre),
    );

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.Copy")
            .match_name("System.Runtime.InteropServices", "Marshal", "Copy")
            .pre(marshal_copy_pre),
    );

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadByte")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadByte")
            .pre(marshal_read_byte_pre),
    );

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.ReadInt32")
            .match_name("System.Runtime.InteropServices", "Marshal", "ReadInt32")
            .pre(marshal_read_int32_pre),
    );

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteByte")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteByte")
            .pre(marshal_write_byte_pre),
    );

    manager.register(
        Hook::new("System.Runtime.InteropServices.Marshal.WriteInt32")
            .match_name("System.Runtime.InteropServices", "Marshal", "WriteInt32")
            .pre(marshal_write_int32_pre),
    );

    // IntPtr methods
    manager.register(
        Hook::new("System.IntPtr.op_Explicit")
            .match_name("System", "IntPtr", "op_Explicit")
            .pre(intptr_op_explicit_pre),
    );

    manager.register(
        Hook::new("System.IntPtr.Add")
            .match_name("System", "IntPtr", "Add")
            .pre(intptr_add_pre),
    );

    manager.register(
        Hook::new("System.IntPtr.ToInt32")
            .match_name("System", "IntPtr", "ToInt32")
            .pre(intptr_to_int32_pre),
    );

    manager.register(
        Hook::new("System.IntPtr.ToInt64")
            .match_name("System", "IntPtr", "ToInt64")
            .pre(intptr_to_int64_pre),
    );

    // UIntPtr methods
    manager.register(
        Hook::new("System.UIntPtr.op_Explicit")
            .match_name("System", "UIntPtr", "op_Explicit")
            .pre(uintptr_op_explicit_pre),
    );
}

/// Hook for `System.Runtime.InteropServices.Marshal.GetHINSTANCE` method.
///
/// Returns the PE base address for the module's assembly image.
///
/// # Handled Overloads
///
/// - `Marshal.GetHINSTANCE(Module) -> IntPtr`
///
/// # Parameters
///
/// - `m`: The module whose HINSTANCE is requested
fn marshal_get_hinstance_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Try to get actual image base from the assembly
    let image_base = thread
        .assembly()
        .map(|asm| asm.file().imagebase())
        .unwrap_or(0x0040_0000); // Default Windows image base

    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::NativeInt(image_base as i64)))
}

/// Hook for `System.Runtime.InteropServices.Marshal.Copy` method.
///
/// Copies data between managed byte arrays and unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.Copy(IntPtr, Byte[], Int32, Int32) -> void` (unmanaged to managed)
/// - `Marshal.Copy(Byte[], Int32, IntPtr, Int32) -> void` (managed to unmanaged)
/// - `Marshal.Copy(IntPtr, Char[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Int16[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Int32[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Int64[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Single[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, Double[], Int32, Int32) -> void`
/// - `Marshal.Copy(IntPtr, IntPtr[], Int32, Int32) -> void`
///
/// # Parameters
///
/// - `source`: Source pointer or array
/// - `destination`: Destination array or pointer
/// - `startIndex`: Starting index in the array
/// - `length`: Number of elements to copy
fn marshal_copy_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 4 {
        return PreHookResult::Bypass(None);
    }

    // Check first arg type to determine which overload
    let src_addr = match &ctx.args[0] {
        EmValue::UnmanagedPtr(a) => Some(*a),
        EmValue::NativeInt(a) => Some(*a as u64),
        _ => None,
    };

    if let Some(src_addr) = src_addr {
        // Overload: Copy(IntPtr source, byte[] dest, int startIndex, int length)
        let dst_ref = match &ctx.args[1] {
            EmValue::ObjectRef(r) => *r,
            _ => return PreHookResult::Bypass(None),
        };
        let start_idx = match &ctx.args[2] {
            EmValue::I32(v) => *v as usize,
            _ => return PreHookResult::Bypass(None),
        };
        let length = match &ctx.args[3] {
            EmValue::I32(v) => *v as usize,
            _ => return PreHookResult::Bypass(None),
        };

        if let Ok(bytes) = thread.address_space().read(src_addr, length) {
            for (i, &byte) in bytes.iter().enumerate() {
                let _ = thread.heap_mut().set_array_element(
                    dst_ref,
                    start_idx + i,
                    EmValue::I32(i32::from(byte)),
                );
            }
        }
        return PreHookResult::Bypass(None);
    }

    // Overload: Copy(byte[] source, int startIndex, IntPtr dest, int length)
    let EmValue::ObjectRef(src_ref) = &ctx.args[0] else {
        return PreHookResult::Bypass(None);
    };
    let start_idx = match &ctx.args[1] {
        EmValue::I32(v) => *v as usize,
        _ => return PreHookResult::Bypass(None),
    };
    let dest_addr = match &ctx.args[2] {
        EmValue::UnmanagedPtr(a) => *a,
        EmValue::NativeInt(a) => *a as u64,
        _ => return PreHookResult::Bypass(None),
    };
    let length = match &ctx.args[3] {
        EmValue::I32(v) => *v as usize,
        _ => return PreHookResult::Bypass(None),
    };

    let mut bytes = Vec::with_capacity(length);
    for i in 0..length {
        #[allow(clippy::cast_sign_loss)]
        let byte_val = thread
            .heap()
            .get_array_element(*src_ref, start_idx + i)
            .map(|elem| match elem {
                EmValue::I32(v) => v as u8,
                _ => 0,
            })
            .unwrap_or(0);
        bytes.push(byte_val);
    }

    let _ = thread.address_space().write(dest_addr, &bytes);
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadByte` method.
///
/// Reads a single byte from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadByte(IntPtr) -> Byte`
/// - `Marshal.ReadByte(IntPtr, Int32) -> Byte`
/// - `Marshal.ReadByte(Object, Int32) -> Byte`
///
/// # Parameters
///
/// - `ptr`: Pointer to read from
/// - `ofs`: Byte offset to add to ptr (optional)
/// - `o`: Object in unmanaged memory to read from (overload 3)
fn marshal_read_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let addr = match ctx.args.first() {
        Some(EmValue::UnmanagedPtr(a)) => *a,
        Some(EmValue::NativeInt(a)) => *a as u64,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    if let Ok(bytes) = thread.address_space().read(addr, 1) {
        PreHookResult::Bypass(Some(EmValue::I32(i32::from(bytes[0]))))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.ReadInt32` method.
///
/// Reads a 32-bit signed integer from unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.ReadInt32(IntPtr) -> Int32`
/// - `Marshal.ReadInt32(IntPtr, Int32) -> Int32`
/// - `Marshal.ReadInt32(Object, Int32) -> Int32`
///
/// # Parameters
///
/// - `ptr`: Pointer to read from
/// - `ofs`: Byte offset to add to ptr (optional)
/// - `o`: Object in unmanaged memory to read from (overload 3)
fn marshal_read_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let addr = match ctx.args.first() {
        Some(EmValue::UnmanagedPtr(a)) => *a,
        Some(EmValue::NativeInt(a)) => *a as u64,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    if let Ok(bytes) = thread.address_space().read(addr, 4) {
        let value = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        PreHookResult::Bypass(Some(EmValue::I32(value)))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteByte` method.
///
/// Writes a single byte to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteByte(IntPtr, Byte) -> void`
/// - `Marshal.WriteByte(IntPtr, Int32, Byte) -> void`
/// - `Marshal.WriteByte(Object, Int32, Byte) -> void`
///
/// # Parameters
///
/// - `ptr`: Pointer to write to
/// - `ofs`: Byte offset to add to ptr (overloads 2-3)
/// - `val`: Byte value to write
/// - `o`: Object in unmanaged memory to write to (overload 3)
fn marshal_write_byte_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(None);
    }

    let addr = match &ctx.args[0] {
        EmValue::UnmanagedPtr(a) => *a,
        EmValue::NativeInt(a) => *a as u64,
        _ => return PreHookResult::Bypass(None),
    };

    let value = match &ctx.args[1] {
        EmValue::I32(v) => *v as u8,
        _ => return PreHookResult::Bypass(None),
    };

    let _ = thread.address_space().write(addr, &[value]);
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.InteropServices.Marshal.WriteInt32` method.
///
/// Writes a 32-bit signed integer to unmanaged memory.
///
/// # Handled Overloads
///
/// - `Marshal.WriteInt32(IntPtr, Int32) -> void`
/// - `Marshal.WriteInt32(IntPtr, Int32, Int32) -> void`
/// - `Marshal.WriteInt32(Object, Int32, Int32) -> void`
///
/// # Parameters
///
/// - `ptr`: Pointer to write to
/// - `ofs`: Byte offset to add to ptr (overloads 2-3)
/// - `val`: 32-bit value to write
/// - `o`: Object in unmanaged memory to write to (overload 3)
fn marshal_write_int32_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(None);
    }

    let addr = match &ctx.args[0] {
        EmValue::UnmanagedPtr(a) => *a,
        EmValue::NativeInt(a) => *a as u64,
        _ => return PreHookResult::Bypass(None),
    };

    let value = match &ctx.args[1] {
        EmValue::I32(v) => *v,
        _ => return PreHookResult::Bypass(None),
    };

    let _ = thread.address_space().write(addr, &value.to_le_bytes());
    PreHookResult::Bypass(None)
}

/// Hook for `System.IntPtr.op_Explicit` operator method.
///
/// Converts between IntPtr and various integer/pointer types.
///
/// # Handled Overloads
///
/// - `IntPtr.op_Explicit(IntPtr) -> Int32`
/// - `IntPtr.op_Explicit(IntPtr) -> Int64`
/// - `IntPtr.op_Explicit(IntPtr) -> void*`
/// - `IntPtr.op_Explicit(Int32) -> IntPtr`
/// - `IntPtr.op_Explicit(Int64) -> IntPtr`
/// - `IntPtr.op_Explicit(void*) -> IntPtr`
///
/// # Parameters
///
/// - `value`: The value to convert
fn intptr_op_explicit_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = if let Some(arg) = ctx.args.first() {
        match arg {
            EmValue::NativeInt(v) => EmValue::NativeInt(*v),
            EmValue::NativeUInt(v) => EmValue::NativeInt(*v as i64),
            EmValue::I32(v) => EmValue::NativeInt(i64::from(*v)),
            EmValue::I64(v) => EmValue::NativeInt(*v),
            EmValue::UnmanagedPtr(v) => EmValue::NativeInt(*v as i64),
            _ => arg.clone(),
        }
    } else {
        EmValue::NativeInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.IntPtr.Add` method.
///
/// Adds an offset to a pointer value.
///
/// # Handled Overloads
///
/// - `IntPtr.Add(IntPtr, Int32) -> IntPtr`
///
/// # Parameters
///
/// - `pointer`: The pointer to add to
/// - `offset`: The offset to add
fn intptr_add_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
    }

    let ptr = match &ctx.args[0] {
        EmValue::NativeInt(v) => *v,
        EmValue::UnmanagedPtr(v) => *v as i64,
        _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
    };

    let offset = match &ctx.args[1] {
        EmValue::I32(v) => i64::from(*v),
        EmValue::I64(v) => *v,
        _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(ptr))),
    };

    PreHookResult::Bypass(Some(EmValue::NativeInt(ptr.wrapping_add(offset))))
}

/// Hook for `System.IntPtr.ToInt32` method.
///
/// Converts the pointer value to a 32-bit signed integer.
///
/// # Handled Overloads
///
/// - `IntPtr.ToInt32() -> Int32`
fn intptr_to_int32_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let value = match ctx.this {
        Some(EmValue::NativeInt(v)) => *v as i32,
        Some(EmValue::UnmanagedPtr(v)) => *v as i32,
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::I32(value)))
}

/// Hook for `System.IntPtr.ToInt64` method.
///
/// Converts the pointer value to a 64-bit signed integer.
///
/// # Handled Overloads
///
/// - `IntPtr.ToInt64() -> Int64`
fn intptr_to_int64_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let value = match ctx.this {
        Some(EmValue::NativeInt(v)) => *v,
        Some(EmValue::UnmanagedPtr(v)) => *v as i64,
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::I64(value)))
}

/// Hook for `System.UIntPtr.op_Explicit` operator method.
///
/// Converts between UIntPtr and various integer/pointer types.
///
/// # Handled Overloads
///
/// - `UIntPtr.op_Explicit(UIntPtr) -> UInt32`
/// - `UIntPtr.op_Explicit(UIntPtr) -> UInt64`
/// - `UIntPtr.op_Explicit(UIntPtr) -> void*`
/// - `UIntPtr.op_Explicit(UInt32) -> UIntPtr`
/// - `UIntPtr.op_Explicit(UInt64) -> UIntPtr`
/// - `UIntPtr.op_Explicit(void*) -> UIntPtr`
///
/// # Parameters
///
/// - `value`: The value to convert
fn uintptr_op_explicit_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = if let Some(arg) = ctx.args.first() {
        match arg {
            EmValue::NativeUInt(v) => EmValue::NativeUInt(*v),
            EmValue::NativeInt(v) => EmValue::NativeUInt(*v as u64),
            EmValue::I32(v) => EmValue::NativeUInt(*v as u64),
            EmValue::I64(v) => EmValue::NativeUInt(*v as u64),
            EmValue::UnmanagedPtr(v) => EmValue::NativeUInt(*v),
            _ => arg.clone(),
        }
    } else {
        EmValue::NativeUInt(0)
    };
    PreHookResult::Bypass(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulation::runtime::hook::HookManager;
    use crate::metadata::token::Token;
    use crate::test::emulation::create_test_thread;

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 11);
    }

    #[test]
    fn test_gethinstance_hook() {
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.InteropServices",
            "Marshal",
            "GetHINSTANCE",
        );

        let mut thread = create_test_thread();

        // Without an assembly, returns default Windows image base
        let result = marshal_get_hinstance_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => {
                assert_eq!(v, 0x0040_0000);
            }
            _ => panic!("Expected Bypass with NativeInt"),
        }
    }

    #[test]
    fn test_intptr_op_explicit_hook() {
        let args = [EmValue::I32(42)];
        let ctx = HookContext::new(Token::new(0x0A000001), "System", "IntPtr", "op_Explicit")
            .with_args(&args);

        let mut thread = create_test_thread();

        let result = intptr_op_explicit_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with NativeInt(42)"),
        }
    }

    #[test]
    fn test_intptr_add_hook() {
        let args = [EmValue::NativeInt(0x1000), EmValue::I32(0x100)];
        let ctx =
            HookContext::new(Token::new(0x0A000001), "System", "IntPtr", "Add").with_args(&args);

        let mut thread = create_test_thread();

        let result = intptr_add_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::NativeInt(v))) => assert_eq!(v, 0x1100),
            _ => panic!("Expected Bypass with NativeInt(0x1100)"),
        }
    }

    #[test]
    fn test_intptr_to_int32_hook() {
        let ctx = HookContext::new(Token::new(0x0A000001), "System", "IntPtr", "ToInt32")
            .with_this(Some(&EmValue::NativeInt(42)));

        let mut thread = create_test_thread();

        let result = intptr_to_int32_pre(&ctx, &mut thread);
        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with I32(42)"),
        }
    }
}
