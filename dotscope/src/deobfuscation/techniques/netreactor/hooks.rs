//! .NET Reactor-specific emulation hooks.
//!
//! Provides hooks for bypassing or instrumenting .NET Reactor protection
//! infrastructure during emulation:
//!
//! - **Trial check bypass** ([`create_trial_bypass_hook`]) — short-circuits
//!   trial guard methods identified structurally during detection so the
//!   emulator can run past `DateTime`-based time bombs.
//! - **Anti-tamper bypass** ([`create_antitamper_bypass_hook`]) — forces
//!   `RSACryptoServiceProvider::VerifyHash` to true so the NecroBit init
//!   path doesn't abort on integrity verification.
//! - **Resource-decryption shim capture**
//!   ([`create_resources_load_shim_hook`]) — intercepts the resolver
//!   type's reflective `Assembly.Load(byte[])` wrappers so the decrypted
//!   bytes are captured even though the emulator's `Type.GetMethod` BCL
//!   stub can't resolve `Assembly::Load` against a real BCL `Type`.
//!
//! All three follow the same shape: `match_runtime` filters by
//! detection-supplied method tokens, then `pre` produces the desired
//! return value (and, for the resource hook, sideeffects into
//! `CaptureContext`).

use std::{collections::HashSet, sync::Arc};

use crate::{
    emulation::{
        AssemblyLoadMethod, CaptureSource, EmValue, EmulationThread, Hook, HookContext,
        HookPriority, PreHookResult,
    },
    metadata::{tables::TableId, token::Token, typesystem::CilFlavor},
};

/// Creates a hook that bypasses RSA signature verification (anti-tamper).
///
/// .NET Reactor's anti-tamper protection reads the assembly file, computes a
/// hash, and verifies it against an embedded RSA signature. During emulation
/// the hash computation uses stub data (TransformBlock/TransformFinalBlock are
/// hooked), so the verification always fails with "TestApp is tampered."
///
/// This hook overrides `RSACryptoServiceProvider::VerifyHash` to return `true`,
/// allowing the init method to proceed past the anti-tamper check and continue
/// with NecroBit body decryption.
#[must_use]
pub fn create_antitamper_bypass_hook() -> Hook {
    Hook::new("netreactor-antitamper-bypass")
        .with_priority(HookPriority::HIGHEST)
        .match_name(
            "System.Security.Cryptography",
            "RSACryptoServiceProvider",
            "VerifyHash",
        )
        .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(1))))
}

/// Creates a hook that bypasses trial/time-bomb check methods.
///
/// After detection identifies trial guard methods by their behavioral pattern
/// (DateTime construction + TimeSpan comparison + throw), this hook stubs them
/// out during emulation to prevent expired-trial exceptions.
///
/// Returns an appropriate default value based on the method's return type.
///
/// # Arguments
///
/// * `tokens` - Set of trial check method tokens to bypass.
#[must_use]
pub fn create_trial_bypass_hook(tokens: HashSet<Token>) -> Hook {
    let tokens = Arc::new(tokens);

    Hook::new("netreactor-trial-bypass")
        .with_priority(HookPriority::HIGHEST)
        .match_runtime("trial-token-check", {
            let tokens = Arc::clone(&tokens);
            move |ctx: &HookContext<'_>, _thread: &EmulationThread| {
                let is_methoddef = ctx.method_token.is_table(TableId::MethodDef);
                is_methoddef && tokens.contains(&ctx.method_token)
            }
        })
        .pre(|ctx, _thread| {
            let return_value = match ctx.return_type {
                None | Some(CilFlavor::Void) => None,
                Some(
                    CilFlavor::Boolean
                    | CilFlavor::I1
                    | CilFlavor::U1
                    | CilFlavor::I2
                    | CilFlavor::U2
                    | CilFlavor::Char
                    | CilFlavor::I4
                    | CilFlavor::U4
                    | CilFlavor::TypedRef { .. }
                    | CilFlavor::Unknown,
                ) => Some(EmValue::I32(0)),
                Some(CilFlavor::I8 | CilFlavor::U8) => Some(EmValue::I64(0)),
                Some(CilFlavor::R4) => Some(EmValue::F32(0.0)),
                Some(CilFlavor::R8) => Some(EmValue::F64(0.0)),
                Some(
                    CilFlavor::I
                    | CilFlavor::U
                    | CilFlavor::Pointer
                    | CilFlavor::ByRef
                    | CilFlavor::FnPtr { .. }
                    | CilFlavor::Pinned,
                ) => Some(EmValue::NativeInt(0)),
                Some(
                    CilFlavor::String
                    | CilFlavor::Object
                    | CilFlavor::Class
                    | CilFlavor::Interface
                    | CilFlavor::Array { .. }
                    | CilFlavor::GenericInstance
                    | CilFlavor::GenericParameter { .. },
                ) => Some(EmValue::Null),
                Some(CilFlavor::ValueType) => Some(EmValue::I32(0)),
            };
            PreHookResult::Bypass(return_value)
        })
}

/// Creates a hook that intercepts NR's reflective `Assembly.Load(byte[])`
/// shim methods and captures the byte-array argument as a
/// `CapturedAssembly`.
///
/// NR's resource decrypter materialises the decrypted assembly via
/// reflection (`Type.GetMethod("Load", new[] { typeof(byte[]) })` then
/// `MethodBase.Invoke`), which the emulator's BCL stubs cannot resolve to
/// the real `Assembly::Load` hook. Detection identifies the static
/// `(byte[]) -> object` wrappers on the resolver type; this hook bypasses
/// them, persists the bytes via `CaptureContext::capture_assembly`, and
/// returns a fake `Assembly` reference so the caller's continuation
/// (typically `stsfld <assembly_cache_field>`) sees a non-null value.
///
/// `assembly_typeref_token` must be the assembly-specific TypeRef token
/// for `[mscorlib]System.Reflection.Assembly` (NR shifts the TypeRef
/// ordering when it injects rows, so a hardcoded token would collide
/// with `System.Attribute` on this sample). Use
/// [`find_assembly_typeref`](super::resources::find_assembly_typeref) to
/// resolve it.
///
/// # Arguments
///
/// * `tokens` - MethodDef tokens of the reflective shim methods to
///   intercept (vetted by detection).
/// * `assembly_typeref_token` - Sample-local TypeRef token for
///   `[mscorlib]System.Reflection.Assembly`, used as the type of the
///   fake object returned to the caller.
#[must_use]
pub fn create_resources_load_shim_hook(
    tokens: HashSet<Token>,
    assembly_typeref_token: Token,
) -> Hook {
    let tokens = Arc::new(tokens);
    Hook::new("netreactor-resources-load-shim")
        .with_priority(HookPriority::HIGHEST)
        .match_runtime("nr-resources-load-shim-token-check", {
            let tokens = Arc::clone(&tokens);
            move |ctx: &HookContext<'_>, _thread: &EmulationThread| {
                tokens.contains(&ctx.method_token)
            }
        })
        .pre(move |ctx, thread: &mut EmulationThread| {
            // Read the byte[] argument off the heap and persist it via the
            // capture context. The dispatcher's wrapper signature is
            // `(byte[]) -> object`; an empty-array read isn't necessarily
            // an error (some dispatcher paths probe with stub buffers),
            // but the real decrypted payload always arrives non-empty.
            let bytes_opt = match ctx.args.first() {
                Some(EmValue::ObjectRef(arr_ref)) => {
                    thread.heap().get_byte_array(*arr_ref).ok().flatten()
                }
                _ => None,
            };
            if let Some(bytes) = bytes_opt {
                let source = CaptureSource::new(
                    thread.current_method().unwrap_or(Token::new(0)),
                    thread.id(),
                    thread.current_offset().unwrap_or(0),
                    0,
                );
                thread.capture().capture_assembly(
                    bytes,
                    source,
                    AssemblyLoadMethod::LoadBytes,
                    None,
                );
            }

            match thread.heap_mut().alloc_object(assembly_typeref_token) {
                Ok(asm_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        })
}
