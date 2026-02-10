//! Base Class Library (BCL) method hooks for .NET emulation.
//!
//! This module provides hook implementations for common .NET Framework Base Class Library
//! methods that cannot be emulated by executing their actual bytecode. These hooks are
//! essential for deobfuscation analysis as many obfuscators rely on string manipulation,
//! encoding, cryptographic operations, and array handling.
//!
//! # Overview
//!
//! When analyzing obfuscated .NET assemblies, the emulator encounters calls to BCL methods
//! that would normally be provided by the .NET runtime. Since we are analyzing statically
//! (without actually running on the CLR), these hooks provide compatible behavior that
//! allows the emulation to continue while capturing relevant information for analysis.
//!
//! # Organization
//!
//! Hooks are organized by their .NET namespace:
//!
//! | Module | .NET Namespace | Description |
//! |--------|----------------|-------------|
//! | [`appdomain`] | `System` | `AppDomain` and `Assembly` operations |
//! | [`array`] | `System` | `Array` and `Buffer` operations |
//! | [`convert`] | `System` | `Convert` type conversion methods |
//! | [`crypto`] | `System.Security.Cryptography` | Hash and encryption algorithms |
//! | [`gchandle`] | `System.Runtime.InteropServices` | `GCHandle` pinned object handling |
//! | [`interop`] | `System.Runtime.InteropServices` | `Marshal` and `IntPtr` operations |
//! | [`math`] | `System` / `System.Numerics` | Math functions and bit operations |
//! | [`reflection`] | `System.Reflection` | Type and method inspection |
//! | [`runtime`] | `System.Runtime.CompilerServices` | `RuntimeHelpers` support methods |
//! | [`stream`] | `System.IO` | Stream and `BinaryReader` operations |
//! | [`string`] | `System` | `String` manipulation methods |
//! | [`text`] | `System.Text` | Text encoding/decoding operations |
//!
//! # Limitations
//!
//! These hooks provide simplified implementations that may differ from actual .NET behavior:
//!
//! - **Stream operations**: Do not maintain actual stream state; return sensible defaults
//! - **Reflection**: Return symbolic objects rather than actual runtime type information
//! - **Cryptographic operations**: Hash functions work correctly, but symmetric encryption
//!   hooks capture keys/IVs for analysis rather than performing actual encryption
//! - **Assembly loading**: Captures assembly bytes but returns fake `Assembly` objects
//!
//! # Usage
//!
//! Register all BCL hooks with a [`HookManager`] to enable method interception during
//! emulation:
//!
//! ```rust,ignore
//! use dotscope::emulation::runtime::{HookManager, bcl};
//!
//! let mut manager = HookManager::new();
//! bcl::register_hooks(&mut manager);
//!
//! // The manager can then be used with an emulation controller
//! ```
//!
//! # Deobfuscation Support
//!
//! These hooks are specifically designed to support deobfuscation of protected .NET
//! assemblies. Common obfuscation techniques that these hooks help defeat include:
//!
//! - **String encryption**: `Encoding.GetString`, `Convert.FromBase64String`
//! - **Resource encryption**: `Assembly.GetManifestResourceStream`, cryptographic transforms
//! - **Dynamic loading**: `Assembly.Load(byte[])` captures unpacked assemblies
//! - **Control flow flattening**: Math operations for state variable manipulation
//! - **Anti-tamper**: `Marshal.GetHINSTANCE`, `RuntimeHelpers.InitializeArray`
//!
//! [`HookManager`]: crate::emulation::runtime::HookManager

mod appdomain;
mod array;
mod convert;
mod crypto;
mod gchandle;
mod interop;
mod math;
mod reflection;
mod runtime;
mod statics;
mod stream;
mod string;
mod text;

pub use statics::get_bcl_static_field;

use crate::emulation::runtime::hook::HookManager;

/// Registers all BCL method hooks with the given hook manager.
///
/// This is the primary way to register BCL method implementations. All method
/// interception is handled through hooks, which can bypass original methods
/// or modify their results.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Example
///
/// ```rust,ignore
/// use dotscope::emulation::runtime::{HookManager, bcl};
///
/// let mut manager = HookManager::new();
/// bcl::register_hooks(&mut manager);
///
/// // Manager now contains hooks for:
/// // - System.Array, System.Buffer
/// // - System.String
/// // - System.Math
/// // - System.Convert
/// // - System.Text.Encoding
/// // - System.Security.Cryptography.*
/// // - System.Runtime.InteropServices.*
/// // - System.Reflection.*
/// // - System.IO.Stream, System.IO.BinaryReader
/// // - And more...
/// ```
///
/// # Registered Categories
///
/// | Category | Methods |
/// |----------|---------|
/// | Array | `Array.Copy`, `Array.Clear`, `Array.Clone`, `Buffer.BlockCopy` |
/// | String | `String.Concat`, `String.Substring`, `String.Replace`, etc. |
/// | Math | `Math.Abs`, `Math.Min`, `Math.Max`, `Math.Pow`, trigonometric functions |
/// | Convert | `Convert.ToBase64String`, `Convert.FromBase64String`, type conversions |
/// | Encoding | `Encoding.GetBytes`, `Encoding.GetString` for UTF-8, ASCII, Unicode |
/// | Crypto | MD5, SHA1, SHA256 hashing; AES/DES key capture |
/// | Interop | `Marshal.Copy`, `Marshal.GetHINSTANCE`, `IntPtr` operations |
/// | Reflection | `Type.GetMethod`, `MethodBase.Invoke`, `Module.ResolveMethod` |
/// | AppDomain | `AppDomain.GetCurrentDomain`, `Assembly.Load`, `Assembly.GetExecutingAssembly` |
/// | GCHandle | `GCHandle.Alloc`, `GCHandle.AddrOfPinnedObject`, `GCHandle.Free` |
/// | Runtime | `RuntimeHelpers.InitializeArray`, `RuntimeHelpers.GetHashCode` |
/// | Stream | `MemoryStream`, `BinaryReader` operations |
///
/// [`HookManager`]: crate::emulation::runtime::HookManager
pub fn register_hooks(manager: &mut HookManager) {
    register(manager);
}

/// Alias for [`register_hooks`] - registers all BCL method hooks.
pub fn register(manager: &mut HookManager) {
    // Fully migrated modules (hook-based)
    math::register(manager);
    gchandle::register(manager);
    runtime::register(manager);
    reflection::register(manager);
    interop::register(manager);
    appdomain::register(manager);
    convert::register(manager);
    text::register(manager);
    array::register(manager);
    string::register(manager);
    stream::register(manager);
    crypto::register(manager);
}
