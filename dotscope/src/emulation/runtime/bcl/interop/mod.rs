//! `System.Runtime.InteropServices` namespace BCL method hooks.
//!
//! This module provides hook implementations for .NET interop types used for
//! native memory manipulation, marshalling, and pinned object access during
//! emulation.
//!
//! # Organization
//!
//! | Module | .NET Type(s) | Description |
//! |--------|-------------|-------------|
//! | [`marshal`] | `System.Runtime.InteropServices.Marshal`, `System.IntPtr`, `System.UIntPtr` | Native memory copy, allocation, and pointer operations |
//! | [`gchandle`] | `System.Runtime.InteropServices.GCHandle` | Pinned object management for native interop |
//!
//! # Deobfuscation Relevance
//!
//! Interop operations are commonly used by obfuscators for:
//! - **Marshal.Copy**: Transferring decrypted data between managed and unmanaged memory
//! - **Marshal.GetHINSTANCE**: Anti-tamper checks that read the PE header from memory
//! - **GCHandle.Alloc/AddrOfPinnedObject**: Pinning byte arrays for native code access
//!   during runtime unpacking or JIT hook installation
//! - **IntPtr arithmetic**: Pointer-based array access patterns to bypass bounds checking

mod gchandle;
mod marshal;

use crate::{emulation::runtime::hook::HookManager, Result};

/// Registers all `System.Runtime.InteropServices` namespace hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install hooks for
/// `Marshal`, `IntPtr`, `UIntPtr`, and `GCHandle`.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    marshal::register(manager)?;
    gchandle::register(manager)?;
    Ok(())
}
