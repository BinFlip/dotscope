//! `System.Runtime.CompilerServices.RuntimeHelpers` and `System.Object` method hooks.
//!
//! This module provides hook implementations for `RuntimeHelpers` and `Object` methods
//! commonly used by obfuscators for array initialization, hash code computation,
//! equality checks, and runtime support operations.
//!
//! # Overview
//!
//! `RuntimeHelpers` provides low-level runtime support methods. The most important
//! for deobfuscation is `InitializeArray`, which is used by the C# compiler to
//! efficiently initialize arrays from embedded data.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `InitializeArray(Array, RuntimeFieldHandle)` | Copies FieldRVA data to array |
//! | `GetHashCode(object)` | Returns identity hash code |
//! | `Equals(object, object)` | Reference equality check |
//! | `GetObjectValue(object)` | Returns object (boxes value types) |
//! | `RunClassConstructor(RuntimeTypeHandle)` | Runs static constructor (no-op) |
//! | `RunModuleConstructor(ModuleHandle)` | Runs module constructor (no-op) |
//! | `Object.Equals(object)` | Instance reference/value equality |
//! | `Object.Equals(object, object)` | Static reference/value equality |
//!
//! # Deobfuscation Use Cases
//!
//! ## Static Array Initialization
//!
//! The C# compiler uses `InitializeArray` for static array literals:
//!
//! ```csharp
//! // This C# code:
//! static byte[] data = { 0x01, 0x02, 0x03 };
//!
//! // Compiles to IL like:
//! // ldsfld byte[] ::data
//! // ldtoken RuntimeFieldHandle (points to embedded data)
//! // call RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle)
//! ```
//!
//! The hook reads the actual embedded data from the PE file's FieldRVA table.
//!
//! ## ConfuserEx String Encryption
//!
//! ConfuserEx stores encrypted string data in static arrays initialized via
//! `InitializeArray`. This hook extracts the encrypted data for analysis.
//!
//! # Implementation Notes
//!
//! - `InitializeArray` reads from the actual PE file via `thread.assembly()`
//! - Hash codes are based on heap reference IDs for consistency
//! - Constructor runners are no-ops (we don't track static initialization)

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::{tables::FieldRvaRaw, typesystem::CilFlavor},
};

/// Registers all `RuntimeHelpers` method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `RuntimeHelpers.InitializeArray` - Copy FieldRVA data to array
/// - `RuntimeHelpers.GetHashCode` - Identity hash code
/// - `RuntimeHelpers.Equals` - Reference equality
/// - `RuntimeHelpers.GetObjectValue` - Return object (box value types)
/// - `RuntimeHelpers.RunClassConstructor` - No-op
/// - `RuntimeHelpers.RunModuleConstructor` - No-op
/// - `Object.Equals` - Reference/value equality (instance and static)
pub fn register(manager: &mut HookManager) {
    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "InitializeArray",
            )
            .pre(runtime_helpers_initialize_array_pre),
    );

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "GetHashCode",
            )
            .pre(runtime_helpers_get_hash_code_pre),
    );

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.Equals")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "Equals",
            )
            .pre(runtime_helpers_equals_pre),
    );

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.GetObjectValue")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "GetObjectValue",
            )
            .pre(runtime_helpers_get_object_value_pre),
    );

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "RunClassConstructor",
            )
            .pre(runtime_helpers_run_class_constructor_pre),
    );

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.RunModuleConstructor")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "RunModuleConstructor",
            )
            .pre(runtime_helpers_run_module_constructor_pre),
    );

    // System.Object.Equals - handles both instance and static overloads.
    // Critical for ConfuserEx anti-tamper: Assembly.GetExecutingAssembly().Equals(...)
    manager.register(
        Hook::new("System.Object.Equals")
            .match_name("System", "Object", "Equals")
            .pre(object_equals_pre),
    );
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray` method.
///
/// Provides a fast way to initialize an array from data stored in a module.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle) -> void`
///
/// # Parameters
///
/// - `array`: The array to be initialized
/// - `fldHandle`: A field handle that specifies the location of the data for the array
fn runtime_helpers_initialize_array_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // RuntimeHelpers.InitializeArray(Array array, RuntimeFieldHandle fldHandle)
    // args[0] = array (ObjectRef)
    // args[1] = field handle (NativeInt/I32 containing token value)

    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(None);
    }

    // Get the array reference
    let array_ref = match &ctx.args[0] {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the field token from the RuntimeFieldHandle
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let field_token = match &ctx.args[1] {
        EmValue::I32(v) => (*v).cast_unsigned(),
        EmValue::NativeInt(v) | EmValue::I64(v) => *v as u32,
        _ => return PreHookResult::Bypass(None),
    };

    // Need assembly access to read FieldRVA data
    let Some(assembly) = thread.assembly() else {
        return PreHookResult::Bypass(None);
    };

    // Look up the RVA for this field token in the FieldRVA table
    let Some(tables) = assembly.tables() else {
        return PreHookResult::Bypass(None);
    };

    let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() else {
        return PreHookResult::Bypass(None);
    };

    // Find the RVA for this field token
    let mut rva: Option<u32> = None;
    for row in fieldrva_table {
        // Convert field index to full token (table 0x04 = Field)
        let row_token = row.field | 0x0400_0000;
        if row_token == field_token && row.rva > 0 {
            rva = Some(row.rva);
            break;
        }
    }

    let Some(rva) = rva else {
        // Field not found in RVA table - may not have embedded data
        return PreHookResult::Bypass(None);
    };

    // Convert RVA to file offset and read data
    let file = assembly.file();
    let Ok(file_offset) = file.rva_to_offset(rva as usize) else {
        return PreHookResult::Bypass(None);
    };

    let pe_data = file.data();
    if file_offset >= pe_data.len() {
        return PreHookResult::Bypass(None);
    }

    // Get the array length and element type
    let array_len = thread.heap().get_array_length(array_ref).unwrap_or(0);
    if array_len == 0 {
        return PreHookResult::Bypass(None);
    }

    let element_type = thread
        .heap()
        .get_array_element_type(array_ref)
        .unwrap_or(CilFlavor::U1);

    // Calculate element size in bytes
    let Some(element_size) = element_type.element_size(ctx.pointer_size) else {
        return PreHookResult::Bypass(None);
    };

    // Calculate total bytes to read
    let total_bytes = array_len * element_size;
    let bytes_to_read = total_bytes.min(pe_data.len() - file_offset);

    // Read the bytes from the PE file
    let data = &pe_data[file_offset..file_offset + bytes_to_read];

    // Set each element in the array based on element type
    for i in 0..array_len {
        let byte_offset = i * element_size;
        if byte_offset + element_size > data.len() {
            break;
        }

        let value = match element_type {
            CilFlavor::Boolean | CilFlavor::I1 | CilFlavor::U1 => {
                EmValue::I32(i32::from(data[byte_offset]))
            }
            CilFlavor::Char | CilFlavor::I2 | CilFlavor::U2 => {
                let bytes = [data[byte_offset], data[byte_offset + 1]];
                EmValue::I32(i32::from(i16::from_le_bytes(bytes)))
            }
            CilFlavor::I4 | CilFlavor::U4 => {
                let bytes = [
                    data[byte_offset],
                    data[byte_offset + 1],
                    data[byte_offset + 2],
                    data[byte_offset + 3],
                ];
                EmValue::I32(i32::from_le_bytes(bytes))
            }
            CilFlavor::R4 => {
                let bytes = [
                    data[byte_offset],
                    data[byte_offset + 1],
                    data[byte_offset + 2],
                    data[byte_offset + 3],
                ];
                EmValue::F32(f32::from_le_bytes(bytes))
            }
            CilFlavor::I8 | CilFlavor::U8 => {
                let bytes = [
                    data[byte_offset],
                    data[byte_offset + 1],
                    data[byte_offset + 2],
                    data[byte_offset + 3],
                    data[byte_offset + 4],
                    data[byte_offset + 5],
                    data[byte_offset + 6],
                    data[byte_offset + 7],
                ];
                EmValue::I64(i64::from_le_bytes(bytes))
            }
            CilFlavor::R8 => {
                let bytes = [
                    data[byte_offset],
                    data[byte_offset + 1],
                    data[byte_offset + 2],
                    data[byte_offset + 3],
                    data[byte_offset + 4],
                    data[byte_offset + 5],
                    data[byte_offset + 6],
                    data[byte_offset + 7],
                ];
                EmValue::F64(f64::from_le_bytes(bytes))
            }
            // For other types, treat as bytes
            _ => EmValue::I32(i32::from(data[byte_offset])),
        };

        let _ = thread.heap_mut().set_array_element(array_ref, i, value);
    }

    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode` method.
///
/// Returns a hash code for an object based on its identity.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.GetHashCode(Object) -> Int32`
///
/// # Parameters
///
/// - `o`: An object
fn runtime_helpers_get_hash_code_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // Return a hash based on the object reference ID
    let result = if let Some(EmValue::ObjectRef(r)) = ctx.args.first() {
        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
        let hash = r.id() as i32;
        EmValue::I32(hash)
    } else {
        EmValue::I32(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.Equals` method.
///
/// Determines whether the specified object instances are the same instance.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.Equals(Object, Object) -> Boolean`
///
/// # Parameters
///
/// - `o1`: The first object to compare
/// - `o2`: The second object to compare
fn runtime_helpers_equals_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    if ctx.args.len() < 2 {
        return PreHookResult::Bypass(Some(EmValue::I32(0))); // false
    }

    // Reference equality
    let equal = match (&ctx.args[0], &ctx.args[1]) {
        (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => a.id() == b.id(),
        (EmValue::Null, EmValue::Null) => true,
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.GetObjectValue` method.
///
/// Boxes a value type. For reference types, returns the object unchanged.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.GetObjectValue(Object) -> Object`
///
/// # Parameters
///
/// - `obj`: The value type to be boxed (or reference type to return)
fn runtime_helpers_get_object_value_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // For reference types, return as-is
    // For value types, this would box them (we just return as-is)
    let result = if let Some(arg) = ctx.args.first() {
        arg.clone()
    } else {
        EmValue::Null
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor` method.
///
/// Runs a class constructor (static constructor).
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.RunClassConstructor(RuntimeTypeHandle) -> void`
///
/// # Parameters
///
/// - `type`: A type handle that specifies the class constructor to run
fn runtime_helpers_run_class_constructor_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // We don't actually run the static constructor
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.RunModuleConstructor` method.
///
/// Runs a module constructor.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.RunModuleConstructor(ModuleHandle) -> void`
///
/// # Parameters
///
/// - `module`: A handle that specifies the module constructor to run
fn runtime_helpers_run_module_constructor_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // We don't actually run the module constructor
    PreHookResult::Bypass(None)
}

/// Hook for `System.Object.Equals` method.
///
/// Handles both the instance and static overloads:
///
/// - `object.Equals(object) -> bool` (instance, virtual)
/// - `Object.Equals(object, object) -> bool` (static)
///
/// Uses reference equality for object references and value equality for
/// primitives. This is critical for ConfuserEx anti-tamper checks which call
/// `Assembly.GetExecutingAssembly().Equals(Assembly.GetCallingAssembly())`.
/// Without this hook, the call returns a Symbolic value, and depending on
/// how ControlFlow protection restructures branches, the anti-tamper check
/// may incorrectly fail, causing decryptors to return null.
fn object_equals_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Instance overload: this.Equals(other)
    if let Some(this) = ctx.this {
        let other = if ctx.args.is_empty() {
            &EmValue::Null
        } else {
            &ctx.args[0]
        };
        let equal = this.clr_equals(other);
        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))));
    }

    // Static overload: Object.Equals(a, b)
    if ctx.args.len() >= 2 {
        let equal = ctx.args[0].clr_equals(&ctx.args[1]);
        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))));
    }

    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::{runtime::hook::HookManager, HeapRef},
        metadata::{token::Token, typesystem::PointerSize},
    };

    #[test]
    fn test_register_hooks() {
        let mut manager = HookManager::new();
        register(&mut manager);
        assert_eq!(manager.len(), 7);
    }

    #[test]
    fn test_get_hash_code_hook() {
        let obj_ref = HeapRef::new(42);
        let args = [EmValue::ObjectRef(obj_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "GetHashCode",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::test::emulation::create_test_thread();
        let result = runtime_helpers_get_hash_code_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with I32(42)"),
        }
    }

    #[test]
    fn test_equals_hook_same_reference() {
        let obj1 = HeapRef::new(1);
        let obj2 = HeapRef::new(1);
        let args = [EmValue::ObjectRef(obj1), EmValue::ObjectRef(obj2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "Equals",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::test::emulation::create_test_thread();
        let result = runtime_helpers_equals_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 1), // true
            _ => panic!("Expected Bypass with I32(1)"),
        }
    }

    #[test]
    fn test_equals_hook_different_references() {
        let obj1 = HeapRef::new(1);
        let obj2 = HeapRef::new(2);
        let args = [EmValue::ObjectRef(obj1), EmValue::ObjectRef(obj2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "Equals",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::test::emulation::create_test_thread();
        let result = runtime_helpers_equals_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 0), // false
            _ => panic!("Expected Bypass with I32(0)"),
        }
    }

    #[test]
    fn test_get_object_value_hook() {
        let args = [EmValue::I32(42)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "GetObjectValue",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::test::emulation::create_test_thread();
        let result = runtime_helpers_get_object_value_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with I32(42)"),
        }
    }
}
