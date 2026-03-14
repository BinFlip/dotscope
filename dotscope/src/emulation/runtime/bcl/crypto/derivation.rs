//! Key derivation hooks for the CIL emulation engine.
//!
//! This module provides hook implementations for password-based key derivation functions
//! (KDFs) used by .NET obfuscators to derive encryption keys from passwords. Obfuscators
//! commonly embed a password string in the assembly and use a KDF to produce the actual
//! AES or DES key used for decryption.
//!
//! # Covered APIs
//!
//! ## PBKDF1 (PasswordDeriveBytes)
//!
//! - `PasswordDeriveBytes..ctor(string/byte[], byte[])` — stores password and salt
//! - `PasswordDeriveBytes.GetBytes(int)` — derives key bytes using PBKDF1 with SHA1
//! - Requires the `legacy-crypto` feature (PBKDF1 is deprecated)
//!
//! ## PBKDF2 (Rfc2898DeriveBytes)
//!
//! - `Rfc2898DeriveBytes..ctor(string/byte[], byte[], int)` — stores password, salt, iterations
//! - `Rfc2898DeriveBytes.GetBytes(int)` — derives key bytes using PBKDF2-HMAC-SHA1
//! - Always available (PBKDF2 is the recommended standard)
//!
//! # Implementation Notes
//!
//! Key derivation is fully implemented using the `pbkdf2` and `hmac` crates.
//! The constructor hooks store derivation parameters on the heap object, and the
//! `GetBytes` hooks compute the derived key on demand.

#[cfg(feature = "legacy-crypto")]
use crate::utils::derive_pbkdf1_key;
use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    utils::derive_pbkdf2_key,
    Result,
};

/// Registers all key derivation hooks (`PasswordDeriveBytes` and `Rfc2898DeriveBytes`).
///
/// Called by the parent `crypto::register()` to wire up PBKDF1 and PBKDF2 hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.PasswordDeriveBytes..ctor")
            .match_name(
                "System.Security.Cryptography",
                "PasswordDeriveBytes",
                ".ctor",
            )
            .pre(password_derive_bytes_ctor_pre),
    )?;

    #[cfg(feature = "legacy-crypto")]
    manager.register(
        Hook::new("System.Security.Cryptography.PasswordDeriveBytes.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "PasswordDeriveBytes",
                "GetBytes",
            )
            .pre(password_derive_bytes_get_bytes_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.Rfc2898DeriveBytes..ctor")
            .match_name(
                "System.Security.Cryptography",
                "Rfc2898DeriveBytes",
                ".ctor",
            )
            .pre(rfc2898_derive_bytes_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes")
            .match_name(
                "System.Security.Cryptography",
                "Rfc2898DeriveBytes",
                "GetBytes",
            )
            .pre(rfc2898_derive_bytes_get_bytes_pre),
    )?;

    Ok(())
}

/// Hook for `System.Security.Cryptography.PasswordDeriveBytes..ctor` constructor.
///
/// Initializes PBKDF1-based key derivation with password and salt.
///
/// # Handled Overloads
///
/// - `PasswordDeriveBytes..ctor(String, Byte[]) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[]) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], String, Int32) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], String, Int32) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(String, Byte[], String, Int32, CspParameters) -> void`
/// - `PasswordDeriveBytes..ctor(Byte[], Byte[], String, Int32, CspParameters) -> void`
///
/// # Parameters
///
/// - `password`: Password string or byte array
/// - `salt`: Salt byte array
/// - `hashName`: Hash algorithm name (optional, default SHA1)
/// - `iterations`: Number of iterations (optional, default 100)
/// - `cspParams`: Cryptographic service provider parameters (optional)
#[cfg(feature = "legacy-crypto")]
fn password_derive_bytes_ctor_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => return PreHookResult::Bypass(None),
    };

    let password: Vec<u8> = match ctx.args.first() {
        Some(EmValue::ObjectRef(pwd_ref)) => {
            if let Some(s) = thread.heap().get_string_opt(*pwd_ref) {
                s.as_bytes().to_vec()
            } else {
                try_hook!(thread.heap().get_byte_array(*pwd_ref)).unwrap_or_default()
            }
        }
        _ => Vec::new(),
    };

    let salt: Vec<u8> = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(salt_ref)) => {
            try_hook!(thread.heap().get_byte_array(*salt_ref)).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let iterations: u32 = 100;

    try_hook!(thread
        .heap()
        .replace_with_key_derivation(heap_ref, password, salt, iterations, "SHA1"));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.PasswordDeriveBytes.GetBytes` method.
///
/// Derives key bytes using PBKDF1 algorithm.
///
/// # Handled Overloads
///
/// - `PasswordDeriveBytes.GetBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `cb`: Number of pseudo-random key bytes to generate
#[cfg(feature = "legacy-crypto")]
fn password_derive_bytes_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let size = ctx
        .args
        .first()
        .map(usize::try_from)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(16);

    let heap_ref = if let Some(EmValue::ObjectRef(hr)) = ctx.this {
        *hr
    } else {
        let zeros = vec![0u8; size];
        match thread.heap().alloc_byte_array(&zeros) {
            Ok(handle) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    };

    let params = thread.heap().get_key_derivation_params(heap_ref);

    let derived_key = match params {
        Ok(Some((password, salt, iterations, _hash_algorithm))) => {
            derive_pbkdf1_key(&password, &salt, iterations, size)
        }
        _ => vec![0u8; size],
    };

    match thread.heap().alloc_byte_array(&derived_key) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Security.Cryptography.Rfc2898DeriveBytes..ctor` constructor.
///
/// Initializes PBKDF2-based key derivation with password, salt, and iterations.
///
/// # Handled Overloads
///
/// - `Rfc2898DeriveBytes..ctor(String, Byte[]) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Byte[], Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Int32, Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(Byte[], Byte[], Int32) -> void`
/// - `Rfc2898DeriveBytes..ctor(String, Byte[], Int32, HashAlgorithmName) -> void`
/// - `Rfc2898DeriveBytes..ctor(Byte[], Byte[], Int32, HashAlgorithmName) -> void`
///
/// # Parameters
///
/// - `password`: Password string or byte array
/// - `salt`: Salt byte array or salt size in bytes
/// - `iterations`: Number of iterations (default 1000)
/// - `hashAlgorithm`: Hash algorithm name (optional, default SHA1)
fn rfc2898_derive_bytes_ctor_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let heap_ref = match ctx.this {
        Some(EmValue::ObjectRef(hr)) => *hr,
        _ => return PreHookResult::Bypass(None),
    };

    let password: Vec<u8> = match ctx.args.first() {
        Some(EmValue::ObjectRef(pwd_ref)) => {
            if let Some(s) = thread.heap().get_string_opt(*pwd_ref) {
                s.as_bytes().to_vec()
            } else {
                try_hook!(thread.heap().get_byte_array(*pwd_ref)).unwrap_or_default()
            }
        }
        _ => Vec::new(),
    };

    let salt: Vec<u8> = match ctx.args.get(1) {
        Some(EmValue::ObjectRef(salt_ref)) => {
            try_hook!(thread.heap().get_byte_array(*salt_ref)).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    // Intentional cast: iteration count is always positive in crypto operations
    #[allow(clippy::cast_sign_loss)]
    let iterations: u32 = match ctx.args.get(2) {
        Some(val) => i32::try_from(val).unwrap_or(1000) as u32,
        None => 1000,
    };

    let hash_algorithm = "SHA1";

    try_hook!(thread.heap().replace_with_key_derivation(
        heap_ref,
        password,
        salt,
        iterations,
        hash_algorithm,
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes` method.
///
/// Derives key bytes using PBKDF2 algorithm.
///
/// # Handled Overloads
///
/// - `Rfc2898DeriveBytes.GetBytes(Int32) -> Byte[]`
///
/// # Parameters
///
/// - `cb`: Number of pseudo-random key bytes to generate
fn rfc2898_derive_bytes_get_bytes_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let size = ctx
        .args
        .first()
        .map(usize::try_from)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(16);

    let heap_ref = if let Some(EmValue::ObjectRef(hr)) = ctx.this {
        *hr
    } else {
        let zeros = vec![0u8; size];
        match thread.heap().alloc_byte_array(&zeros) {
            Ok(handle) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    };

    let params = thread.heap().get_key_derivation_params(heap_ref);

    let derived_key = match params {
        Ok(Some((password, salt, iterations, hash_algorithm))) => {
            derive_pbkdf2_key(&password, &salt, iterations, size, &hash_algorithm)
        }
        _ => vec![0u8; size],
    };

    match thread.heap().alloc_byte_array(&derived_key) {
        Ok(handle) => PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_rfc2898_derive_bytes_get_bytes_hook() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(24)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "Rfc2898DeriveBytes",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::rfc2898_derive_bytes_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(bytes.len(), 24);
        } else {
            panic!("Expected ObjectRef");
        }
    }
}

#[cfg(test)]
#[cfg(feature = "legacy-crypto")]
mod legacy_tests {
    use crate::{
        emulation::{
            runtime::hook::{HookContext, PreHookResult},
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        test::emulation::create_test_thread,
    };

    #[test]
    fn test_password_derive_bytes_get_bytes_hook() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(32)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Security.Cryptography",
            "PasswordDeriveBytes",
            "GetBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = super::password_derive_bytes_get_bytes_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(handle))) = result {
            let bytes = thread.heap().get_byte_array(handle).unwrap().unwrap();
            assert_eq!(bytes.len(), 32);
        } else {
            panic!("Expected ObjectRef");
        }
    }
}
