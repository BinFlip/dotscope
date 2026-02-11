//! Native/P/Invoke hook support for Windows API emulation.
//!
//! This module provides hooks for emulating Platform Invocation Services (P/Invoke)
//! calls to native Windows DLLs. P/Invoke is the .NET mechanism for calling unmanaged code,
//! and is commonly used by obfuscators and packers for:
//!
//! - Memory manipulation (`VirtualProtect`, `VirtualAlloc`)
//! - Anti-debugging checks (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`)
//! - Dynamic code loading (`LoadLibrary`, `GetProcAddress`)
//! - Process/thread introspection (`GetCurrentProcess`, `GetCurrentThread`)
//!
//! # Overview
//!
//! Native hooks are registered with the [`HookManager`](super::HookManager) using the
//! [`register`] function. They use the [`NativeMethodMatcher`](super::NativeMethodMatcher)
//! to match P/Invoke calls by DLL name and function name.
//!
//! # Default Hooks
//!
//! The following native hooks are registered by default via [`register`]:
//!
//! ## Memory Management (kernel32.dll)
//! - `VirtualProtect` - Changes memory page protection (returns success, tracks protection)
//! - `VirtualAlloc` - Allocates virtual memory from the address space
//! - `VirtualFree` - Frees virtual memory (validates but doesn't actually free)
//!
//! ## Module Loading (kernel32.dll)
//! - `GetModuleHandleA/W` - Returns fake module handle (0x0040_0000 for current module)
//! - `GetProcAddress` - Returns fake function pointer
//! - `LoadLibraryA/W` - Returns fake module handle
//!
//! ## Anti-Debug Bypass (kernel32.dll)
//! - `IsDebuggerPresent` - Always returns FALSE (no debugger)
//! - `CheckRemoteDebuggerPresent` - Writes FALSE to output, returns success
//!
//! ## Process/Thread Handles (kernel32.dll)
//! - `GetCurrentProcess` - Returns pseudo-handle (-1)
//! - `GetCurrentThread` - Returns pseudo-handle (-2)
//!
//! # Examples
//!
//! ## Using Native Hooks
//!
//! ```ignore
//! use dotscope::emulation::runtime::{HookManager, native};
//!
//! let mut manager = HookManager::new();
//! native::register(&mut manager);
//!
//! // VirtualProtect, IsDebuggerPresent, etc. are now hooked
//! ```
//!
//! ## Adding Custom Native Hooks
//!
//! ```ignore
//! use dotscope::emulation::{Hook, PreHookResult, EmValue};
//!
//! let mut manager = HookManager::new();
//!
//! manager.register(
//!     Hook::new("custom-get-tick-count")
//!         .match_native("kernel32", "GetTickCount")
//!         .pre(|_ctx, _thread| {
//!             // Return a fixed tick count for deterministic emulation
//!             PreHookResult::Bypass(Some(EmValue::I32(12345678)))
//!         })
//! );
//! ```
//!
//! # Use Cases
//!
//! ## Deobfuscation
//!
//! Many obfuscators use P/Invoke calls for:
//!
//! - **Anti-tamper**: `VirtualProtect` to modify code section permissions
//! - **Anti-debug**: `IsDebuggerPresent` to detect analysis
//! - **Dynamic unpacking**: `VirtualAlloc` to allocate memory for decrypted code
//!
//! The default hooks are designed to allow these operations to succeed while
//! bypassing protection checks.
//!
//! ## ConfuserEx Anti-Tamper
//!
//! The `VirtualProtect` hook specifically returns 0x20 (PAGE_EXECUTE_READ) as the
//! old protection value. This is important because ConfuserEx's anti-tamper checks
//! if the old protection was 0x40 (PAGE_EXECUTE_READWRITE) and skips decryption
//! if so. By returning 0x20, the decryption path is taken.

use crate::emulation::{
    memory::MemoryProtection,
    runtime::{Hook, HookManager, HookPriority, PreHookResult},
    EmValue,
};

/// Registers all default native P/Invoke hooks with the hook manager.
///
/// This function registers hooks for common Windows API functions used by
/// obfuscators and packers. Call this to enable P/Invoke emulation.
///
/// # Arguments
///
/// * `manager` - The hook manager to register hooks with
///
/// # Registered Hooks
///
/// **Memory Management:**
/// - `kernel32!VirtualProtect`
/// - `kernel32!VirtualAlloc`
/// - `kernel32!VirtualFree`
///
/// **Module Loading:**
/// - `kernel32!GetModuleHandleA`
/// - `kernel32!GetModuleHandleW`
/// - `kernel32!GetProcAddress`
/// - `kernel32!LoadLibraryA`
/// - `kernel32!LoadLibraryW`
///
/// **Anti-Debug Bypass:**
/// - `kernel32!IsDebuggerPresent`
/// - `kernel32!CheckRemoteDebuggerPresent`
///
/// **Process/Thread Handles:**
/// - `kernel32!GetCurrentProcess`
/// - `kernel32!GetCurrentThread`
pub fn register(manager: &mut HookManager) {
    // Memory management hooks
    register_virtual_protect(manager);
    register_virtual_alloc(manager);
    register_virtual_free(manager);

    // Module loading hooks
    register_get_module_handle(manager);
    register_get_proc_address(manager);
    register_load_library(manager);

    // Anti-debug bypass hooks
    register_is_debugger_present(manager);
    register_check_remote_debugger_present(manager);

    // Process/thread handle hooks
    register_get_current_process(manager);
    register_get_current_thread(manager);
}

/// Registers the VirtualProtect hook.
fn register_virtual_protect(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-virtual-protect")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "VirtualProtect")
            .pre(|ctx, thread| {
                // VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
                // Returns BOOL: 1 = success, 0 = failure
                let args = ctx.args;

                // Validate we have enough arguments
                if args.len() < 4 {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Validate lpAddress is not null
                let lp_address = match &args[0] {
                    EmValue::UnmanagedPtr(addr) if *addr != 0 => *addr,
                    EmValue::NativeInt(addr) if *addr > 0 => (*addr).cast_unsigned(),
                    EmValue::NativeUInt(addr) if *addr > 0 => *addr,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Validate dwSize is non-zero
                #[allow(clippy::cast_possible_truncation)]
                let dw_size = match &args[1] {
                    EmValue::I32(size) if *size > 0 => (*size).cast_unsigned() as usize,
                    EmValue::NativeInt(size) if *size > 0 => (*size).cast_unsigned() as usize,
                    EmValue::NativeUInt(size) if *size > 0 => *size as usize,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Get the new protection value
                #[allow(clippy::cast_possible_truncation)]
                let fl_new_protect = match &args[2] {
                    EmValue::I32(p) => (*p).cast_unsigned(),
                    EmValue::NativeInt(p) => (*p).cast_unsigned() as u32,
                    EmValue::NativeUInt(p) => *p as u32,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Check if address range is valid
                let space = thread.address_space();
                if !space.is_valid(lp_address) || !space.is_valid(lp_address + dw_size as u64 - 1) {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Convert new protection to our format and set it, getting old protection back
                let new_protection = MemoryProtection::from_windows(fl_new_protect);
                let old_protection = space
                    .set_protection(lp_address, dw_size, new_protection)
                    .unwrap_or(MemoryProtection::READ_EXECUTE);

                // Convert old protection back to Windows constant
                let old_protect_windows = old_protection.to_windows();

                // Write old protection value to the out parameter
                let old_protect_value = EmValue::I32(old_protect_windows.cast_signed());
                match &args[3] {
                    EmValue::ManagedPtr(ptr) => {
                        if thread
                            .store_through_pointer(ptr, old_protect_value)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    EmValue::UnmanagedPtr(addr) if *addr != 0 => {
                        let old_protect_bytes = old_protect_windows.to_le_bytes();
                        if thread
                            .address_space()
                            .write(*addr, &old_protect_bytes)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    EmValue::NativeInt(addr) if *addr > 0 => {
                        let old_protect_bytes = old_protect_windows.to_le_bytes();
                        if thread
                            .address_space()
                            .write((*addr).cast_unsigned(), &old_protect_bytes)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    EmValue::NativeUInt(addr) if *addr > 0 => {
                        let old_protect_bytes = old_protect_windows.to_le_bytes();
                        if thread
                            .address_space()
                            .write(*addr, &old_protect_bytes)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    _ => {
                        // lpflOldProtect is null - technically allowed but unusual
                    }
                }

                // VirtualProtect returns BOOL (int32), 1 = success
                PreHookResult::Bypass(Some(EmValue::I32(1)))
            }),
    );
}

/// Registers the VirtualAlloc hook.
fn register_virtual_alloc(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-virtual-alloc")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "VirtualAlloc")
            .pre(|ctx, thread| {
                // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
                // Returns pointer to allocated memory, or NULL on failure
                let args = ctx.args;

                // Extract and validate dwSize
                #[allow(clippy::cast_possible_truncation)]
                let size = match args.get(1) {
                    Some(EmValue::I32(size)) if *size > 0 => (*size).cast_unsigned() as usize,
                    Some(EmValue::NativeInt(size)) if *size > 0 => (*size).cast_unsigned() as usize,
                    Some(EmValue::NativeUInt(size)) if *size > 0 => *size as usize,
                    _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
                };

                // Validate flAllocationType (arg 2) - must be non-zero
                #[allow(clippy::cast_possible_truncation)]
                let alloc_type = match args.get(2) {
                    Some(EmValue::I32(t)) if *t != 0 => (*t).cast_unsigned(),
                    Some(EmValue::NativeInt(t)) if *t != 0 => (*t).cast_unsigned() as u32,
                    _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
                };

                // MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000
                // At least one of these must be set
                if (alloc_type & 0x3000) == 0 {
                    return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
                }

                // Allocate from address space
                match thread.address_space().alloc_unmanaged(size) {
                    Ok(addr) => PreHookResult::Bypass(Some(EmValue::NativeInt(addr.cast_signed()))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
                }
            }),
    );
}

/// Registers the VirtualFree hook.
fn register_virtual_free(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-virtual-free")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "VirtualFree")
            .pre(|ctx, thread| {
                // VirtualFree(lpAddress, dwSize, dwFreeType)
                // Returns BOOL: 1 = success, 0 = failure
                let args = ctx.args;

                // Validate we have enough arguments
                if args.is_empty() {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Validate lpAddress is not null
                let lp_address = match &args[0] {
                    EmValue::UnmanagedPtr(addr) if *addr != 0 => *addr,
                    EmValue::NativeInt(addr) if *addr > 0 => (*addr).cast_unsigned(),
                    EmValue::NativeUInt(addr) if *addr > 0 => *addr,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Validate dwFreeType (arg 2) if provided
                // MEM_DECOMMIT = 0x4000, MEM_RELEASE = 0x8000
                if let Some(free_type) = args.get(2) {
                    #[allow(clippy::cast_possible_truncation)]
                    let ft = match free_type {
                        EmValue::I32(t) => (*t).cast_unsigned(),
                        EmValue::NativeInt(t) => (*t).cast_unsigned() as u32,
                        _ => 0,
                    };

                    // If MEM_RELEASE (0x8000), dwSize must be 0
                    if (ft & 0x8000) != 0 {
                        #[allow(clippy::cast_possible_truncation)]
                        let dw_size = args
                            .get(1)
                            .and_then(|v| match v {
                                EmValue::I32(s) => Some((*s).cast_unsigned()),
                                EmValue::NativeInt(s) => Some((*s).cast_unsigned() as u32),
                                _ => None,
                            })
                            .unwrap_or(0);

                        if dw_size != 0 {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                }

                // Check if address is valid
                if !thread.address_space().is_valid(lp_address) {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Return success (we don't actually free memory)
                PreHookResult::Bypass(Some(EmValue::I32(1)))
            }),
    );
}

/// Registers GetModuleHandle hooks (both A and W variants).
fn register_get_module_handle(manager: &mut HookManager) {
    // GetModuleHandleA
    manager.register(
        Hook::new("native-get-module-handle-a")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetModuleHandleA")
            .pre(|ctx, _thread| {
                // GetModuleHandle(lpModuleName)
                // If NULL, return base of current module
                let is_null = ctx.args.first().is_none_or(|v| {
                    v.is_null()
                        || matches!(v, EmValue::NativeInt(0))
                        || matches!(v, EmValue::NativeUInt(0))
                        || matches!(v, EmValue::UnmanagedPtr(0))
                });

                if is_null {
                    // Return a fake module base for the current module
                    PreHookResult::Bypass(Some(EmValue::NativeInt(0x0040_0000)))
                } else {
                    // Return a fake handle for other modules
                    PreHookResult::Bypass(Some(EmValue::NativeInt(0x7FFE_0000)))
                }
            }),
    );

    // GetModuleHandleW
    manager.register(
        Hook::new("native-get-module-handle-w")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetModuleHandleW")
            .pre(|ctx, _thread| {
                let is_null = ctx.args.first().is_none_or(|v| {
                    v.is_null()
                        || matches!(v, EmValue::NativeInt(0))
                        || matches!(v, EmValue::NativeUInt(0))
                        || matches!(v, EmValue::UnmanagedPtr(0))
                });

                if is_null {
                    PreHookResult::Bypass(Some(EmValue::NativeInt(0x0040_0000)))
                } else {
                    PreHookResult::Bypass(Some(EmValue::NativeInt(0x7FFE_0000)))
                }
            }),
    );
}

/// Registers the GetProcAddress hook.
fn register_get_proc_address(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-get-proc-address")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetProcAddress")
            .pre(|_ctx, _thread| {
                // GetProcAddress(hModule, lpProcName)
                // Return a fake function pointer
                PreHookResult::Bypass(Some(EmValue::NativeInt(0x7FFE_1000)))
            }),
    );
}

/// Registers LoadLibrary hooks (both A and W variants).
fn register_load_library(manager: &mut HookManager) {
    // LoadLibraryA
    manager.register(
        Hook::new("native-load-library-a")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "LoadLibraryA")
            .pre(|_ctx, _thread| {
                // LoadLibrary(lpLibFileName)
                // Return a fake module handle
                PreHookResult::Bypass(Some(EmValue::NativeInt(0x7FFE_2000)))
            }),
    );

    // LoadLibraryW
    manager.register(
        Hook::new("native-load-library-w")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "LoadLibraryW")
            .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::NativeInt(0x7FFE_2000)))),
    );
}

/// Registers the IsDebuggerPresent hook.
fn register_is_debugger_present(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-is-debugger-present")
            .with_priority(HookPriority::HIGHEST) // Anti-debug bypass should have highest priority
            .match_native("kernel32", "IsDebuggerPresent")
            .pre(|_ctx, _thread| {
                // IsDebuggerPresent() returns BOOL
                // Return FALSE to indicate no debugger
                PreHookResult::Bypass(Some(EmValue::I32(0)))
            }),
    );
}

/// Registers the CheckRemoteDebuggerPresent hook.
fn register_check_remote_debugger_present(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-check-remote-debugger-present")
            .with_priority(HookPriority::HIGHEST)
            .match_native("kernel32", "CheckRemoteDebuggerPresent")
            .pre(|ctx, thread| {
                // CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent)
                // Returns BOOL: 1 = success, 0 = failure
                let args = ctx.args;

                // Validate we have enough arguments
                if args.len() < 2 {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Validate hProcess is a valid handle (-1 for current process, or non-null)
                match &args[0] {
                    EmValue::NativeInt(-1) => {} // Current process pseudo-handle is valid
                    EmValue::NativeInt(h) if *h > 0 => {}
                    EmValue::NativeUInt(h) if *h > 0 => {}
                    EmValue::UnmanagedPtr(h) if *h > 0 => {}
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                }

                // Get output pointer address - must be valid
                let output_addr = match &args[1] {
                    EmValue::UnmanagedPtr(addr) if *addr != 0 => *addr,
                    EmValue::NativeInt(addr) if *addr > 0 => (*addr).cast_unsigned(),
                    EmValue::NativeUInt(addr) if *addr > 0 => *addr,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Write FALSE (0) to the output parameter
                let false_bytes = 0u32.to_le_bytes();

                let space = thread.address_space();
                if !space.is_valid(output_addr) {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                if space.write(output_addr, &false_bytes).is_err() {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Return TRUE for success
                PreHookResult::Bypass(Some(EmValue::I32(1)))
            }),
    );
}

/// Registers the GetCurrentProcess hook.
fn register_get_current_process(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-get-current-process")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetCurrentProcess")
            .pre(|_ctx, _thread| {
                // GetCurrentProcess() returns HANDLE
                // Return pseudo-handle -1 (0xFFFFFFFFFFFFFFFF)
                PreHookResult::Bypass(Some(EmValue::NativeInt(-1)))
            }),
    );
}

/// Registers the GetCurrentThread hook.
fn register_get_current_thread(manager: &mut HookManager) {
    manager.register(
        Hook::new("native-get-current-thread")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetCurrentThread")
            .pre(|_ctx, _thread| {
                // GetCurrentThread() returns HANDLE
                // Return pseudo-handle -2 (0xFFFFFFFFFFFFFFFE)
                PreHookResult::Bypass(Some(EmValue::NativeInt(-2)))
            }),
    );
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::{HookContext, HookManager, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    use super::register;

    fn create_native_context<'a>(dll: &'a str, function: &'a str) -> HookContext<'a> {
        HookContext::native(Token::new(0x06000001), dll, function, PointerSize::Bit64)
    }

    #[test]
    fn test_native_hooks_registered() {
        let mut manager = HookManager::new();
        register(&mut manager);

        // Should have at least 12 hooks (one for each function, with A/W variants)
        assert!(manager.len() >= 12);
    }

    #[test]
    fn test_is_debugger_present_hook() {
        let mut manager = HookManager::new();
        register(&mut manager);

        let mut thread = create_test_thread();
        let context = create_native_context("kernel32", "IsDebuggerPresent").with_args(&[]);

        let hook = manager.find_matching(&context, &thread);
        assert!(hook.is_some(), "Should find IsDebuggerPresent hook");

        if let Some(h) = hook {
            let result = h.execute_pre(&context, &mut thread);
            assert!(matches!(
                result,
                Some(PreHookResult::Bypass(Some(EmValue::I32(0))))
            ));
        }
    }

    #[test]
    fn test_get_current_process_hook() {
        let mut manager = HookManager::new();
        register(&mut manager);

        let mut thread = create_test_thread();
        let context = create_native_context("kernel32", "GetCurrentProcess").with_args(&[]);

        let hook = manager.find_matching(&context, &thread);
        assert!(hook.is_some(), "Should find GetCurrentProcess hook");

        if let Some(h) = hook {
            let result = h.execute_pre(&context, &mut thread);
            assert!(matches!(
                result,
                Some(PreHookResult::Bypass(Some(EmValue::NativeInt(-1))))
            ));
        }
    }

    #[test]
    fn test_get_module_handle_null() {
        let mut manager = HookManager::new();
        register(&mut manager);

        let mut thread = create_test_thread();
        let args = [EmValue::NativeInt(0)];
        let context = create_native_context("kernel32", "GetModuleHandleA").with_args(&args);

        let hook = manager.find_matching(&context, &thread);
        assert!(hook.is_some(), "Should find GetModuleHandleA hook");

        if let Some(h) = hook {
            let result = h.execute_pre(&context, &mut thread);
            assert!(matches!(
                result,
                Some(PreHookResult::Bypass(Some(EmValue::NativeInt(0x0040_0000))))
            ));
        }
    }
}
